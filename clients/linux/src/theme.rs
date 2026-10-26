//! Looks (ADR-0009): the classic Win95/Thunar structure (bevelled buttons,
//! caption bars, sunken fields, tool and status bars) without libadwaita.
//!
//! - [`STRUCTURE_CSS`] is always loaded. It only uses the colours of the
//!   active GTK theme, so the client follows the desktop (dark or light).
//! - [`CLASSIC_CSS`] optionally adds the fixed light Windows 2000 palette.

/// Classic shapes in the colours of the current GTK theme.
pub const STRUCTURE_CSS: &str = r#"
button {
    background-image: none;
    background-color: @theme_bg_color;
    color: @theme_fg_color;
    border-radius: 0;
    border-style: solid;
    border-width: 1px;
    border-color: shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 0.45) shade(@theme_bg_color, 0.45) shade(@theme_bg_color, 1.45);
    box-shadow: inset -1px -1px shade(@theme_bg_color, 0.7), inset 1px 1px shade(@theme_bg_color, 1.2);
    padding: 3px 10px;
    min-height: 0;
    min-width: 0;
}
button:hover { background-color: shade(@theme_bg_color, 1.08); }
button:active, button:checked {
    border-color: shade(@theme_bg_color, 0.45) shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 0.45);
    box-shadow: inset 1px 1px shade(@theme_bg_color, 0.7);
}
button:disabled, button:disabled label, button:disabled image { color: @insensitive_fg_color; }
entry, spinbutton, textview {
    background-color: @theme_base_color;
    color: @theme_text_color;
    border-radius: 0;
    border-style: solid;
    border-width: 1px;
    border-color: shade(@theme_bg_color, 0.45) shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 0.45);
    box-shadow: inset 1px 1px shade(@theme_bg_color, 0.6);
    min-height: 20px;
}
entry > text, spinbutton > text { background: none; border: none; box-shadow: none; min-height: 0; }
scrolledwindow.sunken {
    border-style: solid;
    border-width: 1px;
    border-color: shade(@theme_bg_color, 0.45) shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 0.45);
}
list > row { padding: 2px 4px; border-radius: 0; }
list > row:selected, list > row:selected label { background-color: @theme_selected_bg_color; color: @theme_selected_fg_color; }
menubar { border-bottom: 1px solid @borders; padding: 1px 0; }
menubar > item { padding: 2px 8px; border-radius: 0; }
menubar > item:hover, menubar > item:selected { background-color: @theme_selected_bg_color; color: @theme_selected_fg_color; }
popover > contents { border-radius: 0; padding: 2px; }
popover modelbutton { border-radius: 0; padding: 3px 18px; }
popover modelbutton:hover, popover modelbutton:hover label { background-color: @theme_selected_bg_color; color: @theme_selected_fg_color; }
.toolbar { border-bottom: 1px solid @borders; padding: 3px 4px; }
.toolbar button { padding: 2px 6px; }
.toolbar button image { margin-right: 4px; }
.statusbar { border-top: 1px solid @borders; padding: 2px 3px; }
.statusbar .panel {
    border-style: solid;
    border-width: 1px;
    border-color: shade(@theme_bg_color, 0.6) shade(@theme_bg_color, 1.35) shade(@theme_bg_color, 1.35) shade(@theme_bg_color, 0.6);
    padding: 1px 6px;
}
.caption {
    background-image: linear-gradient(to right, @theme_selected_bg_color, alpha(@theme_selected_bg_color, 0.35));
    color: @theme_selected_fg_color;
    font-weight: bold;
    padding: 3px 6px;
}
.caption label { color: @theme_selected_fg_color; }
.groupbox {
    border-style: solid;
    border-width: 1px;
    border-color: shade(@theme_bg_color, 0.45) shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 0.45);
    padding: 12px;
}
.notice { color: alpha(@theme_fg_color, 0.65); font-style: italic; }
.deleted { color: alpha(@theme_fg_color, 0.5); font-style: italic; }
.time { color: alpha(@theme_fg_color, 0.6); }
.sender { font-weight: bold; }
.error { color: @error_color; }
.unread { font-weight: bold; }
.pattern-dot { min-width: 36px; min-height: 36px; padding: 0; }
.monospace { font-family: monospace; }
notebook > header { border-bottom: 1px solid @borders; box-shadow: none; }
notebook > header > tabs > tab {
    border-style: solid;
    border-width: 1px 1px 0 1px;
    border-color: shade(@theme_bg_color, 1.45) shade(@theme_bg_color, 0.45) shade(@theme_bg_color, 0.45) shade(@theme_bg_color, 1.45);
    border-radius: 0;
    box-shadow: none;
    padding: 3px 12px;
    margin: 2px 1px 0 0;
}
notebook > header > tabs > tab:checked { box-shadow: none; padding-bottom: 5px; margin-top: 0; }
notebook > header > tabs > tab:checked label { font-weight: bold; }
paned > separator { min-width: 4px; background: none; border-left: 1px solid shade(@theme_bg_color, 1.3); border-right: 1px solid shade(@theme_bg_color, 0.6); }
"#;

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use gtk::gdk;

thread_local! {
    static CLASSIC: RefCell<Option<gtk::CssProvider>> = const { RefCell::new(None) };
}

fn add_provider(css: &str) -> Option<gtk::CssProvider> {
    let display = gdk::Display::default()?;
    let provider = gtk::CssProvider::new();
    provider.load_from_string(css);
    gtk::style_context_add_provider_for_display(&display, &provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
    Some(provider)
}

/// Loads the structure CSS and, if chosen, the classic palette.
/// `SSM_SYSTEM_THEME=1` disables all custom styling.
pub fn load(classic: bool) {
    if std::env::var_os("SSM_SYSTEM_THEME").is_some() {
        return;
    }
    add_provider(STRUCTURE_CSS);
    set_classic(classic);
}

pub fn set_classic(classic: bool) {
    CLASSIC.with(|slot| {
        let mut slot = slot.borrow_mut();
        match (classic, slot.take()) {
            (true, None) => *slot = add_provider(CLASSIC_CSS),
            (true, Some(provider)) => *slot = Some(provider),
            (false, Some(provider)) => {
                if let Some(display) = gdk::Display::default() {
                    gtk::style_context_remove_provider_for_display(&display, &provider);
                }
            }
            (false, None) => {}
        }
    });
}

/// The chosen look is stored next to the profiles: `<data>/look`.
fn look_file(data_dir: &Path) -> PathBuf {
    data_dir.join("look")
}

pub fn classic_chosen(data_dir: &Path) -> bool {
    std::fs::read_to_string(look_file(data_dir)).is_ok_and(|s| s.trim() == "classic")
}

pub fn remember_classic(data_dir: &Path, classic: bool) {
    let _ = std::fs::write(look_file(data_dir), if classic { "classic\n" } else { "system\n" });
}

/// Optional fixed light palette (Windows 2000 grey, navy captions).
pub const CLASSIC_CSS: &str = r#"
window, window.background, popover > contents, notebook > stack, notebook > header, menubar {
    background-color: #d4d0c8;
    color: #000000;
    font-family: "Tahoma", "Verdana", "DejaVu Sans", sans-serif;
    font-size: 9pt;
}
label { color: #000000; }
button {
    background-color: #d4d0c8;
    color: #000000;
    border-color: #ffffff #404040 #404040 #ffffff;
    box-shadow: inset -1px -1px #808080, inset 1px 1px #dfdfdf;
}
button:hover { background-color: #dedad2; }
button:active, button:checked { border-color: #404040 #ffffff #ffffff #404040; box-shadow: inset 1px 1px #808080; }
entry, spinbutton, textview, list, listview {
    background-color: #ffffff;
    color: #000000;
    border-color: #808080 #ffffff #ffffff #808080;
}
list > row:selected, list > row:selected label, menubar > item:hover, popover modelbutton:hover, popover modelbutton:hover label {
    background-color: #0a246a;
    color: #ffffff;
}
.caption { background-image: linear-gradient(to right, #0a246a, #a6caf0); color: #ffffff; }
.caption label { color: #ffffff; }
.notice { color: #606060; }
.deleted { color: #808080; }
.time { color: #606060; }
.error { color: #a00000; }
notebook > header > tabs > tab { background-color: #d4d0c8; color: #000000; border-color: #ffffff #404040 #404040 #ffffff; }
"#;
