//! Classic look: Windows 2000 / Thunar style, no libadwaita (ADR-0009).

pub const CLASSIC_CSS: &str = r#"
window, window.background {
    background-color: #d4d0c8;
    color: #000000;
    font-family: "Tahoma", "Verdana", "DejaVu Sans", sans-serif;
    font-size: 9pt;
}
label { color: #000000; }
button {
    background-image: none;
    background-color: #d4d0c8;
    color: #000000;
    border-radius: 0;
    border-style: solid;
    border-width: 1px;
    border-color: #ffffff #404040 #404040 #ffffff;
    box-shadow: inset -1px -1px #808080, inset 1px 1px #dfdfdf;
    padding: 3px 12px;
    min-height: 0;
    min-width: 0;
    outline-color: #000000;
}
button:hover { background-color: #dedad2; }
button:active, button:checked {
    border-color: #404040 #ffffff #ffffff #404040;
    box-shadow: inset 1px 1px #808080;
}
button:disabled, button:disabled label { color: #808080; }
entry, spinbutton, textview {
    background-color: #ffffff;
    color: #000000;
    border-radius: 0;
    border-style: solid;
    border-width: 1px;
    border-color: #808080 #ffffff #ffffff #808080;
    box-shadow: inset 1px 1px #404040;
    min-height: 20px;
}
entry:focus-within { outline: none; }
entry > text, spinbutton > text {
    background: none;
    border: none;
    box-shadow: none;
    min-height: 0;
}
check, radio {
    background-image: none;
    background-color: #ffffff;
    color: #000000;
    border-style: solid;
    border-width: 1px;
    border-color: #808080 #ffffff #ffffff #808080;
    box-shadow: inset 1px 1px #404040;
    -gtk-icon-shadow: none;
}
check { border-radius: 0; }
check:checked, radio:checked { background-color: #ffffff; color: #000000; }
scrolledwindow.sunken {
    border-style: solid;
    border-width: 1px;
    border-color: #808080 #ffffff #ffffff #808080;
    box-shadow: inset 1px 1px #404040;
}
list, listview { background-color: #ffffff; }
list > row { padding: 2px 4px; border-radius: 0; }
list > row:selected, list > row:selected label { background-color: #0a246a; color: #ffffff; }
menubar {
    background-color: #d4d0c8;
    border-bottom: 1px solid #808080;
    box-shadow: 0 1px #ffffff;
    padding: 1px 0;
}
menubar > item { padding: 2px 8px; border-radius: 0; }
menubar > item:hover, menubar > item:selected { background-color: #0a246a; color: #ffffff; }
popover > contents {
    background-color: #d4d0c8;
    border-radius: 0;
    border: 1px solid #404040;
    box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.35);
    padding: 2px;
}
popover modelbutton { border-radius: 0; padding: 3px 18px; }
popover modelbutton:hover, popover modelbutton:hover label { background-color: #0a246a; color: #ffffff; }
popover separator { background-color: #808080; margin: 3px 2px; min-height: 1px; }
.toolbar {
    border-bottom: 1px solid #808080;
    box-shadow: 0 1px #ffffff;
    padding: 3px 4px;
}
.toolbar button { padding: 2px 8px; }
.statusbar { border-top: 1px solid #ffffff; padding: 2px 3px; }
.statusbar .panel {
    border-style: solid;
    border-width: 1px;
    border-color: #808080 #ffffff #ffffff #808080;
    padding: 1px 6px;
}
.caption {
    background-image: linear-gradient(to right, #0a246a, #a6caf0);
    color: #ffffff;
    font-weight: bold;
    padding: 3px 6px;
}
.caption label { color: #ffffff; }
.groupbox {
    border-style: solid;
    border-width: 1px;
    border-color: #808080 #ffffff #ffffff #808080;
    padding: 12px;
}
.notice { color: #606060; font-style: italic; }
.deleted { color: #808080; font-style: italic; }
.time { color: #606060; }
.sender { font-weight: bold; }
.error { color: #a00000; }
.unread { font-weight: bold; }
.pattern-dot { min-width: 36px; min-height: 36px; padding: 0; }
.pattern-dot label { color: #404040; }
paned > separator {
    background-color: #d4d0c8;
    min-width: 4px;
    border-left: 1px solid #ffffff;
    border-right: 1px solid #808080;
}
"#;
