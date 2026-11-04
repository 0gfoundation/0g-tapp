use std::future::Future;

/// A measurement preflight must not fetch keys: the app is registered using the
/// resulting measurements, so KMS admission cannot succeed at this point.
/// Take a factory rather than a future so preflight does not even begin setup.
pub(crate) async fn app_tls_after_start<F, Fut, T>(measure_only: bool, derive: F) -> Option<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    if measure_only {
        None
    } else {
        Some(derive().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    #[test]
    fn measure_only_returns_without_starting_or_waiting_for_kms_tls() {
        let calls = Cell::new(0);
        let mut preflight = Box::pin(app_tls_after_start(true, || {
            calls.set(calls.get() + 1);
            // A cold KMS that cannot admit an unregistered app never completes.
            std::future::pending::<Result<(), &'static str>>()
        }));
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);

        assert_eq!(preflight.as_mut().poll(&mut cx), Poll::Ready(None));
        assert_eq!(calls.get(), 0, "preflight started TLS/KMS derivation");
    }

    #[test]
    fn real_start_preserves_the_existing_tls_derivation_and_result() {
        let calls = Cell::new(0);
        let mut start = Box::pin(app_tls_after_start(false, || {
            calls.set(calls.get() + 1);
            std::future::ready(Err::<(), _>("KMS unavailable"))
        }));
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            start.as_mut().poll(&mut cx),
            Poll::Ready(Some(Err("KMS unavailable")))
        );
        assert_eq!(calls.get(), 1);
    }
}
