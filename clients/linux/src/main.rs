//! ssm-linux: GTK4 desktop client with a classic look (ADR-0009).
//!
//! Environment:
//! - `SSM_DATA_DIR` (or `SSM_PROFILE_DIR`): where accounts are stored
//!   (default `$XDG_DATA_HOME/ssm-messenger`, one `profiles/<id>` per account)
//!
//! Arguments: `--account <username>` opens that account directly.
//! - `SSM_SYSTEM_THEME=1`: no custom styling at all (plain GTK theme)

mod admin;
mod dialogs;
mod pattern_pad;
mod runtime;
mod theme;
mod ui;

use std::path::PathBuf;

use gtk::prelude::*;
use gtk::{gdk, glib};
use tracing_subscriber::EnvFilter;

const APP_ID: &str = "org.selfhosted.SecureMessenger";

thread_local! {
    static WINDOW: std::cell::RefCell<Option<std::rc::Rc<ui::App>>> = const { std::cell::RefCell::new(None) };
}

fn profile_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SSM_DATA_DIR").or_else(|| std::env::var_os("SSM_PROFILE_DIR")) {
        return dir.into();
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"));
    data.join("ssm-messenger")
}

fn account_argument() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--account" {
            return args.next();
        }
        if let Some(name) = arg.strip_prefix("--account=") {
            return Some(name.to_owned());
        }
    }
    None
}

fn load_theme() {
    theme::load(theme::classic_chosen(&profile_dir()));
    // The app icon follows the icon theme; the bundled one (installed into
    // hicolor) is the fallback. Uninstalled builds find it in clients/linux/data.
    gtk::Window::set_default_icon_name(APP_ID);
    if let Some(display) = gdk::Display::default() {
        let icons = gtk::IconTheme::for_display(&display);
        icons.add_search_path(concat!(env!("CARGO_MANIFEST_DIR"), "/data"));
    }
}

fn main() -> glib::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .init();
    // Keep plaintext out of core dumps (FR-013, best effort).
    #[cfg(target_os = "linux")]
    unsafe_set_not_dumpable();

    // Not single-instance: every start is its own process, so several
    // profiles (SSM_PROFILE_DIR) can run side by side.
    let app = gtk::Application::builder().application_id(APP_ID).flags(gtk::gio::ApplicationFlags::NON_UNIQUE).build();
    app.connect_startup(|_| load_theme());
    app.connect_activate(|app| {
        // Widgets only hold weak references to the App, so it is owned here
        // for the lifetime of the process.
        WINDOW.with(|slot| {
            if let Some(existing) = slot.borrow().as_ref() {
                existing.present();
                return;
            }
            let window = ui::App::new(app, profile_dir(), account_argument());
            window.start();
            #[cfg(debug_assertions)]
            dev_hooks(&window);
            slot.replace(Some(window));
        });
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
    if let Ok(setup) = std::env::var("SSM_DEV_SETUP")
        && let Some((server, code)) = setup.split_once('|')
    {
        window.dev_fill_setup(server.to_owned(), code.to_owned());
    }
    if let Ok(dots) = std::env::var("SSM_DEV_ADMIN_PATTERN") {
        let dots: Vec<u8> = dots.split(',').filter_map(|d| d.trim().parse().ok()).collect();
        window.dev_open_admin(dots, Duration::from_secs(3));
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
