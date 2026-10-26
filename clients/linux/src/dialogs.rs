//! Small modal dialogs shared by the main window and the admin window.

use gtk::glib;
use gtk::prelude::*;

/// Text input; `None` when cancelled or empty.
pub async fn prompt(parent: &impl IsA<gtk::Window>, title: &str, text: &str, initial: &str) -> Option<String> {
    let dialog = gtk::Window::builder().title(title).transient_for(parent).modal(true).resizable(false).build();
    let entry = gtk::Entry::new();
    entry.set_text(initial);
    let ok = gtk::Button::with_label("OK");
    let cancel = gtk::Button::with_label("Cancel");
    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    buttons.set_halign(gtk::Align::End);
    buttons.append(&ok);
    buttons.append(&cancel);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
    content.set_margin_top(12);
    content.set_margin_bottom(12);
    content.set_margin_start(12);
    content.set_margin_end(12);
    content.append(&gtk::Label::builder().label(text).xalign(0.0).wrap(true).build());
    content.append(&entry);
    content.append(&buttons);
    dialog.set_child(Some(&content));

    let (tx, rx) = async_channel::bounded::<Option<String>>(1);
    let (tx_ok, tx_enter, tx_cancel, tx_close) = (tx.clone(), tx.clone(), tx.clone(), tx);
    let entry_ok = entry.clone();
    ok.connect_clicked(move |_| {
        let _ = tx_ok.try_send(Some(entry_ok.text().to_string()));
    });
    entry.connect_activate(move |e| {
        let _ = tx_enter.try_send(Some(e.text().to_string()));
    });
    cancel.connect_clicked(move |_| {
        let _ = tx_cancel.try_send(None);
    });
    dialog.connect_close_request(move |_| {
        let _ = tx_close.try_send(None);
        glib::Propagation::Proceed
    });
    dialog.present();
    let answer = rx.recv().await.ok().flatten();
    dialog.destroy();
    answer.map(|a| a.trim().to_owned()).filter(|a| !a.is_empty())
}

/// Yes/no question; true when `accept` was chosen.
pub async fn confirm(parent: &impl IsA<gtk::Window>, message: &str, detail: &str, accept: &str) -> bool {
    let dialog = gtk::AlertDialog::builder()
        .modal(true)
        .message(message)
        .detail(detail)
        .buttons([accept, "Cancel"])
        .default_button(1)
        .cancel_button(1)
        .build();
    matches!(dialog.choose_future(Some(parent)).await, Ok(0))
}

/// Message box with selectable text and an optional "Copy" button for `copy`.
pub async fn info(parent: &impl IsA<gtk::Window>, title: &str, text: &str, copy: Option<&str>) {
    let dialog = gtk::Window::builder().title(title).transient_for(parent).modal(true).resizable(false).build();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
    content.set_margin_top(12);
    content.set_margin_bottom(12);
    content.set_margin_start(12);
    content.set_margin_end(12);
    content
        .append(&gtk::Label::builder().label(text).xalign(0.0).wrap(true).selectable(true).max_width_chars(70).build());
    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    buttons.set_halign(gtk::Align::End);
    if let Some(copy) = copy {
        let copy_button = gtk::Button::with_label("Copy");
        let value = copy.to_owned();
        copy_button.connect_clicked(move |button| {
            button.clipboard().set_text(&value);
            button.set_label("Copied");
        });
        buttons.append(&copy_button);
    }
    let ok = gtk::Button::with_label("OK");
    buttons.append(&ok);
    content.append(&buttons);
    dialog.set_child(Some(&content));
    let (tx, rx) = async_channel::bounded::<()>(1);
    let tx_close = tx.clone();
    ok.connect_clicked(move |_| {
        let _ = tx.try_send(());
    });
    dialog.connect_close_request(move |_| {
        let _ = tx_close.try_send(());
        glib::Propagation::Proceed
    });
    dialog.present();
    let _ = rx.recv().await;
    dialog.destroy();
}
