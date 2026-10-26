//! Platform execution and clocks; protocol and session code stay shared.
use std::future::Future;
#[cfg(target_arch = "wasm32")]
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Instant, SystemTime};
#[cfg(not(target_arch = "wasm32"))]
pub use tokio::time::{sleep, timeout};
#[cfg(target_arch = "wasm32")]
pub use web_time::{Instant, SystemTime};
#[cfg(not(target_arch = "wasm32"))]
pub type Elapsed = tokio::time::error::Elapsed;

#[cfg(target_arch = "wasm32")]
#[derive(Debug, thiserror::Error)]
#[error("operation deadline elapsed")]
pub struct Elapsed;

#[cfg(target_arch = "wasm32")]
pub async fn sleep(duration: Duration) {
    gloo_timers::future::TimeoutFuture::new(duration.as_millis().min(u32::MAX as u128) as u32).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn timeout<F: Future>(duration: Duration, future: F) -> Result<F::Output, Elapsed> {
    use futures_util::future::{Either, select};
    let future = std::pin::pin!(future);
    let timer = std::pin::pin!(sleep(duration));
    match select(future, timer).await {
        Either::Left((output, _)) => Ok(output),
        Either::Right(_) => Err(Elapsed),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn(future: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(future);
}
#[cfg(target_arch = "wasm32")]
pub fn spawn(future: impl Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(future);
}

/// Whether [`sleep`] will be stretched by the browser.
///
/// Hidden tabs and unfocused windows clamp `setTimeout` to about one second.
/// A poll loop that sleeps between reads then lets the meter drop samples.
/// USB transfer completion is not a timer, so the caller can keep reading
/// without sleeping.
#[cfg(not(target_arch = "wasm32"))]
pub fn browser_timers_throttled() -> bool {
    false
}

#[cfg(target_arch = "wasm32")]
pub fn browser_timers_throttled() -> bool {
    web_sys::window()
        .and_then(|window| window.document())
        .is_some_and(|document| document.hidden() || !document.has_focus().unwrap_or(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn deadline_drops_the_pending_operation() {
        use std::{
            future::pending,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
        };
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Guard(dropped.clone());
        let operation = async move {
            let _guard = guard;
            pending::<()>().await;
        };
        assert!(timeout(Duration::from_millis(5), operation).await.is_err());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn completed_operation_preserves_its_result() {
        assert_eq!(timeout(Duration::from_secs(1), async { 42 }).await.unwrap(), 42);
    }
}
