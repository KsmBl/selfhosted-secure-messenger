//! ssm-linux: GTK4 desktop client with a classic look (ADR-0009).
//!
//! Environment:
//! - `SSM_PROFILE_DIR`: profile directory (default `$XDG_DATA_HOME/ssm-messenger`)
//! - `SSM_SYSTEM_THEME=1`: use the system GTK theme instead of the classic one

mod pattern_pad;
mod runtime;
mod theme;
mod ui;

use std::path::PathBuf;

use gtk::prelude::*;
use gtk::{gdk, glib};
use tracing_subscriber::EnvFilter;

const APP_ID: &str = "org.selfhosted.SecureMessenger";

fn profile_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SSM_PROFILE_DIR") {
        return dir.into();
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"));
    data.join("ssm-messenger")
}

fn load_theme() {
    if std::env::var_os("SSM_SYSTEM_THEME").is_some() {
        return;
    }
    let provider = gtk::CssProvider::new();
    provider.load_from_string(theme::CLASSIC_CSS);
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(&display, &provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
    }
}

fn main() -> glib::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .init();
    // Keep plaintext out of core dumps (FR-013, best effort).
    #[cfg(target_os = "linux")]
    unsafe_set_not_dumpable();

    let app = gtk::Application::builder().application_id(APP_ID).build();
    app.connect_startup(|_| load_theme());
    app.connect_activate(|app| {
        let window = ui::App::new(app, profile_dir());
        window.start();
        #[cfg(debug_assertions)]
        dev_hooks(&window);
    });
    app.run_with_args::<&str>(&[])
}

/// Debug builds only: `SSM_DEV_PATTERN=0,6,12,...` unlocks automatically,
/// `SSM_SCREENSHOT=file.png` renders the window after a few seconds and quits.
#[cfg(debug_assertions)]
fn dev_hooks(window: &std::rc::Rc<ui::App>) {
    use std::time::Duration;
    if let Ok(dots) = std::env::var("SSM_DEV_PATTERN") {
        let dots: Vec<u8> = dots.split(',').filter_map(|d| d.trim().parse().ok()).collect();
        window.dev_unlock(dots);
        window.dev_open_first_conversation(Duration::from_secs(2));
    }
    if let Ok(path) = std::env::var("SSM_SCREENSHOT") {
        window.screenshot_after(path.into(), Duration::from_secs(5));
    }
}

#[cfg(target_os = "linux")]
fn unsafe_set_not_dumpable() {
    // PR_SET_DUMPABLE = 4
    unsafe extern "C" {
        fn prctl(option: i32, ...) -> i32;
    }
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) only changes this process's dump flag.
    unsafe {
        prctl(4, 0);
    }
}
