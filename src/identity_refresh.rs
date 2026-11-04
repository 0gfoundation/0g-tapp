//! Best-effort publication hints. This worker never participates in key release.
//! One worker, one request in flight, and bounded input/pending queues prevent an
//! unavailable verifier from creating a task for every local key request.

use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{sync::mpsc, time::Instant};

const CAPACITY: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Target {
    pub app_id: String,
    pub node_signer: String,
}

pub(crate) type Refresh =
    Arc<dyn Fn(Target) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct IdentityRefresh {
    tx: mpsc::Sender<Target>,
}

#[derive(Clone, Copy)]
struct Settings {
    debounce: Duration,
    retry: Duration,
    timeout: Duration,
    attempts: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            debounce: Duration::from_millis(100),
            retry: Duration::from_secs(1),
            // Let the common client's 90s cold-verification deadline finish;
            // this worker remains bounded and never delays key release.
            timeout: Duration::from_secs(95),
            attempts: 3,
        }
    }
}

struct Pending {
    due: Instant,
    attempts: u32,
}

impl IdentityRefresh {
    pub(crate) fn start(refresh: Refresh) -> Self {
        Self::start_with(refresh, Settings::default())
    }

    fn start_with(refresh: Refresh, settings: Settings) -> Self {
        let (tx, rx) = mpsc::channel(CAPACITY);
        tokio::spawn(run(rx, refresh, settings));
        Self { tx }
    }

    /// No network wait, and never wait for room while a key/cache lock is held.
    pub(crate) fn enqueue(&self, app_id: String, node_signer: String) -> bool {
        if self
            .tx
            .try_send(Target {
                app_id,
                node_signer,
            })
            .is_err()
        {
            tracing::warn!(
                "Scan identity refresh queue unavailable; readiness checks may retry the refresh"
            );
            return false;
        }
        true
    }
}

fn merge(pending: &mut BTreeMap<Target, Pending>, target: Target, settings: Settings) {
    let due = Instant::now() + settings.debounce;
    if let Some(old) = pending.get_mut(&target) {
        old.due = old.due.min(due);
        // A new publication gets its own bounded retry budget.
        old.attempts = 0;
    } else if pending.len() < CAPACITY {
        pending.insert(target, Pending { due, attempts: 0 });
    } else {
        tracing::warn!(
            "Scan identity refresh pending queue full; readiness checks may retry the refresh"
        );
    }
}

async fn run(mut rx: mpsc::Receiver<Target>, refresh: Refresh, settings: Settings) {
    let mut pending = BTreeMap::<Target, Pending>::new();
    let mut open = true;
    loop {
        let next = pending
            .iter()
            .min_by_key(|(_, entry)| entry.due)
            .map(|(target, entry)| (target.clone(), entry.due));
        let Some((target, due)) = next else {
            if !open {
                return;
            }
            match rx.recv().await {
                Some(target) => merge(&mut pending, target, settings),
                None => open = false,
            }
            continue;
        };
        tokio::select! {
            message = rx.recv(), if open => {
                match message {
                    Some(target) => merge(&mut pending, target, settings),
                    None => open = false,
                }
            }
            _ = tokio::time::sleep_until(due) => {
                let mut entry = pending.remove(&target).expect("pending target exists");
                entry.attempts += 1;
                let result = tokio::time::timeout(settings.timeout, refresh(target.clone())).await;
                match result {
                    Ok(Ok(())) => {}
                    failure => {
                        if entry.attempts < settings.attempts {
                            entry.due = Instant::now() + settings.retry * (1 << (entry.attempts - 1));
                            pending.insert(target, entry);
                        } else {
                            // Do not log an upstream body, URL, pin, or any key material.
                            let timed_out = failure.is_err();
                            tracing::warn!(timed_out, "Scan identity refresh retry budget exhausted; readiness checks may retry it");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use tokio::sync::Notify;

    fn settings() -> Settings {
        Settings {
            debounce: Duration::from_millis(10),
            retry: Duration::from_millis(20),
            timeout: Duration::from_millis(100),
            attempts: 3,
        }
    }

    async fn until(notify: &Notify, condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let changed = notify.notified();
                if condition() {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("refresh worker made progress");
    }

    #[tokio::test]
    async fn coalesces_pending_hints_and_does_not_wait_for_the_request() {
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let refresh: Refresh = {
            let (calls, entered, release) = (calls.clone(), entered.clone(), release.clone());
            Arc::new(move |_| {
                let (calls, entered, release) = (calls.clone(), entered.clone(), release.clone());
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    entered.notify_one();
                    release.notified().await;
                    Ok(())
                })
            })
        };
        let notifier = IdentityRefresh::start_with(refresh, settings());
        for _ in 0..20 {
            assert!(notifier.enqueue("app".into(), "node".into()));
        }
        until(&entered, || calls.load(Ordering::SeqCst) == 1).await;
        // Even while external verification is blocked, publication remains nonblocking.
        assert!(notifier.enqueue("app".into(), "node".into()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.notify_one();
        until(&entered, || calls.load(Ordering::SeqCst) == 2).await;
        release.notify_one();
    }

    #[tokio::test]
    async fn retries_are_bounded_and_do_not_starve_other_apps() {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let changed = Arc::new(Notify::new());
        let refresh: Refresh = {
            let (calls, changed) = (calls.clone(), changed.clone());
            Arc::new(move |target| {
                let (calls, changed) = (calls.clone(), changed.clone());
                Box::pin(async move {
                    calls.lock().unwrap().push(target.app_id.clone());
                    changed.notify_one();
                    if target.app_id == "a" {
                        Err("unavailable".into())
                    } else {
                        Ok(())
                    }
                })
            })
        };
        let notifier = IdentityRefresh::start_with(refresh, settings());
        assert!(notifier.enqueue("a".into(), "node".into()));
        assert!(notifier.enqueue("b".into(), "node".into()));
        until(&changed, || {
            calls.lock().unwrap().iter().filter(|s| *s == "a").count() == 3
        })
        .await;
        let got = calls.lock().unwrap().clone();
        assert_eq!(got, ["a", "b", "a", "a"]);
        drop(notifier);
    }

    #[tokio::test]
    async fn retry_reads_the_live_anchor_instead_of_caching_it_in_the_hint() {
        let anchor = Arc::new(Mutex::new("old".to_owned()));
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let changed = Arc::new(Notify::new());
        let refresh: Refresh = {
            let (anchor, seen, changed) = (anchor.clone(), seen.clone(), changed.clone());
            Arc::new(move |_| {
                let (anchor, seen, changed) = (anchor.clone(), seen.clone(), changed.clone());
                Box::pin(async move {
                    let current = anchor.lock().unwrap().clone();
                    seen.lock().unwrap().push(current.clone());
                    changed.notify_one();
                    if current == "old" {
                        Err("rotating".into())
                    } else {
                        Ok(())
                    }
                })
            })
        };
        let notifier = IdentityRefresh::start_with(refresh, settings());
        notifier.enqueue("app".into(), "node".into());
        until(&changed, || seen.lock().unwrap().len() == 1).await;
        *anchor.lock().unwrap() = "new".into();
        until(&changed, || seen.lock().unwrap().len() == 2).await;
        assert_eq!(*seen.lock().unwrap(), ["old", "new"]);
    }

    #[tokio::test]
    async fn timeout_is_bounded_and_a_full_input_queue_is_reported() {
        let calls = Arc::new(AtomicUsize::new(0));
        let changed = Arc::new(Notify::new());
        let refresh: Refresh = {
            let (calls, changed) = (calls.clone(), changed.clone());
            Arc::new(move |_| {
                let (calls, changed) = (calls.clone(), changed.clone());
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    changed.notify_one();
                    std::future::pending().await
                })
            })
        };
        let notifier = IdentityRefresh::start_with(refresh, settings());
        notifier.enqueue("app".into(), "node".into());
        until(&changed, || calls.load(Ordering::SeqCst) == 1).await;
        for n in 0..CAPACITY {
            assert!(notifier.enqueue(format!("app-{n}"), "node".into()));
        }
        assert!(!notifier.enqueue("overflow".into(), "node".into()));
        // A separate worker proves a stuck external request is cancelled and retried.
        let retry_calls = Arc::new(AtomicUsize::new(0));
        let retry_changed = Arc::new(Notify::new());
        let refresh: Refresh = {
            let (calls, changed) = (retry_calls.clone(), retry_changed.clone());
            Arc::new(move |_| {
                let (calls, changed) = (calls.clone(), changed.clone());
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    changed.notify_one();
                    std::future::pending().await
                })
            })
        };
        let retry = IdentityRefresh::start_with(refresh, settings());
        retry.enqueue("app".into(), "node".into());
        until(&retry_changed, || retry_calls.load(Ordering::SeqCst) == 3).await;
    }
}
