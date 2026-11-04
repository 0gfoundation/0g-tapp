//! Per-app single-flight initialization. A slow KMS request never holds the
//! global map lock or blocks a different application's cached signer.
use std::{collections::HashMap, future::Future, sync::Arc};
use tokio::sync::Mutex;

type Cell = Arc<Mutex<Option<Vec<u8>>>>;

#[derive(Clone, Default)]
pub(crate) struct SignerCache {
    apps: Arc<Mutex<HashMap<String, Cell>>>,
}

impl SignerCache {
    pub(crate) async fn get_or_try_init<E, F, Fut>(
        &self,
        app_id: &str,
        initialize: F,
    ) -> Result<Vec<u8>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<u8>, E>>,
    {
        let cell = {
            let mut apps = self.apps.lock().await;
            apps.entry(app_id.to_string()).or_default().clone()
        };
        let mut cached = cell.lock().await;
        if let Some(secret) = cached.as_ref() {
            return Ok(secret.clone());
        }
        let secret = initialize().await?;
        // Clear only detaches this cell. Never put an in-flight cell back into
        // the map: a request through newer trust anchors owns a different cell.
        *cached = Some(secret.clone());
        Ok(secret)
    }

    pub(crate) async fn clear(&self) {
        self.apps.lock().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::sync::Semaphore;

    async fn cached(cache: &SignerCache, app: &str) -> Vec<u8> {
        cache
            .get_or_try_init::<(), _, _>(app, || async {
                panic!("cached signer must not be fetched again")
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_blocked_app_does_not_block_another_apps_hit_or_miss() {
        let cache = SignerCache::default();
        cache
            .get_or_try_init::<(), _, _>("b", || async { Ok(vec![2]) })
            .await
            .unwrap();
        let entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let first = {
            let (cache, entered, release) = (cache.clone(), entered.clone(), release.clone());
            tokio::spawn(async move {
                cache
                    .get_or_try_init::<(), _, _>("a", || async {
                        entered.add_permits(1);
                        release.acquire().await.unwrap().forget();
                        Ok(vec![1])
                    })
                    .await
                    .unwrap()
            })
        };
        entered.acquire().await.unwrap().forget();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), cached(&cache, "b"))
                .await
                .unwrap(),
            [2]
        );
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                cache.get_or_try_init::<(), _, _>("c", || async { Ok(vec![3]) })
            )
            .await
            .unwrap()
            .unwrap(),
            [3]
        );
        release.add_permits(1);
        assert_eq!(first.await.unwrap(), [1]);
    }

    #[tokio::test]
    async fn concurrent_initializations_of_the_same_app_fetch_only_once() {
        let cache = SignerCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let (cache, calls, entered, release) = (
                cache.clone(),
                calls.clone(),
                entered.clone(),
                release.clone(),
            );
            jobs.spawn(async move {
                cache
                    .get_or_try_init::<(), _, _>("app", || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        entered.add_permits(1);
                        release.acquire().await.unwrap().forget();
                        Ok(vec![7])
                    })
                    .await
                    .unwrap()
            });
        }
        entered.acquire().await.unwrap().forget();
        release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(result) = jobs.join_next().await {
                assert_eq!(result.unwrap(), [7]);
            }
        })
        .await
        .expect("same-app callers share one completed initialization");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn clear_detaches_an_inflight_cell_without_reviving_it_later() {
        let cache = SignerCache::default();
        let entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let old = {
            let (cache, entered, release) = (cache.clone(), entered.clone(), release.clone());
            tokio::spawn(async move {
                cache
                    .get_or_try_init::<(), _, _>("app", || async {
                        entered.add_permits(1);
                        release.acquire().await.unwrap().forget();
                        Ok(vec![1])
                    })
                    .await
                    .unwrap()
            })
        };
        entered.acquire().await.unwrap().forget();
        tokio::time::timeout(Duration::from_secs(1), cache.clear())
            .await
            .unwrap();
        let new = tokio::time::timeout(
            Duration::from_secs(1),
            cache.get_or_try_init::<(), _, _>("app", || async { Ok(vec![2]) }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(new, [2]);
        release.add_permits(1);
        assert_eq!(old.await.unwrap(), [1]);
        assert_eq!(cached(&cache, "app").await, [2]);
    }

    #[tokio::test]
    async fn a_failed_initialization_is_not_cached() {
        let cache = SignerCache::default();
        assert!(cache
            .get_or_try_init("app", || async { Err::<Vec<u8>, _>("unavailable") })
            .await
            .is_err());
        assert_eq!(
            cache
                .get_or_try_init::<(), _, _>("app", || async { Ok(vec![9]) })
                .await
                .unwrap(),
            [9]
        );
    }
}
