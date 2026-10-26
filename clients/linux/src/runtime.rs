//! Bridge between the tokio runtime (network, crypto) and the GTK main loop.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn rt() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio runtime")
    })
}

/// Runs `work` on the tokio runtime and hands its result to `done` on the
/// GTK main loop.
pub fn run<T: Send + 'static>(work: impl Future<Output = T> + Send + 'static, done: impl FnOnce(T) + 'static) {
    let handle = rt().spawn(work);
    gtk::glib::spawn_future_local(async move {
        if let Ok(value) = handle.await {
            done(value);
        }
    });
}
