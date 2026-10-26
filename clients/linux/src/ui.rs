//! Main window: setup → waiting for approval → unlock → chat.
//!
//! Network and crypto run on the tokio runtime; the decrypted texts of the
//! open conversation exist only in the widgets and are dropped when the
//! conversation is left or the app is locked (FR-013).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gtk::prelude::*;
use gtk::{gio, glib};
use ssm_client::{
    Client, ClientError, ClientResult, DisplayBody, DisplayMessage, EnrollWith, LockedClient, ProfileStore,
    ProfileSummary, Update, Wake, WakeChannel,
};
use ssm_core::{KdfParams, Pattern};
use ssm_proto::api::{ConversationInfo, ConversationKind, DeviceStatus, SystemNotice};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::dialogs;
use crate::pattern_pad::PatternPad;
use crate::runtime::{rt, run};
use crate::theme;

type Shared = Arc<Mutex<Option<Client>>>;

const AUTO_LOCK_AFTER: Duration = Duration::from_secs(5 * 60);
const KDF_TARGET: Duration = Duration::from_secs(3);

fn locked_error() -> ClientError {
    ClientError::Protocol("the app is locked".into())
}

/// Runs `f` with the unlocked client on the tokio runtime.
macro_rules! with_client {
    ($shared:expr, |$c:ident| $body:expr) => {{
        let shared = $shared.clone();
        async move {
            let mut guard = shared.lock().await;
            let $c = guard.as_mut().ok_or_else(locked_error)?;
            $body
        }
    }};
}

fn short_time(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| t.with_timezone(&chrono::Local).format("%d.%m. %H:%M").to_string())
        .unwrap_or_default()
}

/// Own account id and username as known to the client.
fn identity(client: &Client) -> (Option<Uuid>, Option<String>) {
    (client.account_id(), client.username().map(str::to_owned))
}

fn friendly_error(err: &ClientError) -> String {
    match err.problem_kind() {
        Some("enrollment-refused") => "The invitation code or username was not accepted.".into(),
        Some("device-pending") => "This device is still waiting for approval.".into(),
        Some("device-not-active") => "This device was disabled or revoked by an administrator.".into(),
        Some("rate-limited") => "Too many attempts. Please wait a minute.".into(),
        Some("not-found") => "Not found.".into(),
        Some("only-admin-can-invite") => "Only the group admin can invite people.".into(),
        Some("only-admin-can-remove") => "Only the group admin can remove members.".into(),
        _ if err.is_wrong_pattern() => "Wrong pattern.".into(),
        _ => err.to_string(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AfterLock {
    /// Stay on this account; show the unlock pattern.
    Unlock,
    /// Close the account; show the account picker.
    Accounts,
    /// Close the account; register another one.
    Setup,
}

pub struct App {
    app: gtk::Application,
    window: gtk::ApplicationWindow,
    stack: gtk::Stack,
    status: gtk::Label,
    status_user: gtk::Label,
    store: ProfileStore,
    /// Directory and server of the open account (for the admin key).
    account: RefCell<Option<(PathBuf, String)>>,
    admin_window: RefCell<Option<Rc<crate::admin::AdminWindow>>>,
    /// `--account <name>`: open this account directly at startup.
    preselect: RefCell<Option<String>>,
    shared: Shared,
    locked: RefCell<Option<LockedClient>>,
    actions: HashMap<&'static str, gio::SimpleAction>,

    // setup
    setup_stack: gtk::Stack,
    server_entry: gtk::Entry,
    invite_radio: gtk::CheckButton,
    code_entry: gtk::Entry,
    device_entry: gtk::Entry,
    setup_pad: Rc<PatternPad>,
    setup_info: gtk::Label,
    first_pattern: RefCell<Option<Pattern>>,

    // accounts
    account_list: gtk::ListBox,
    accounts: RefCell<Vec<ProfileSummary>>,
    accounts_info: gtk::Label,
    setup_cancel: gtk::Button,

    // pending
    pending_info: gtk::Label,

    // unlock
    unlock_pad: Rc<PatternPad>,
    unlock_title: gtk::Label,
    unlock_info: gtk::Label,
    unlock_button: gtk::Button,

    // chat
    conv_list: gtk::ListBox,
    conversations: RefCell<Vec<ConversationInfo>>,
    unread: RefCell<HashSet<Uuid>>,
    current: RefCell<Option<ConversationInfo>>,
    caption: gtk::Label,
    msg_list: gtk::ListBox,
    msg_ids: RefCell<Vec<Option<Uuid>>>,
    next_before: Cell<Option<i64>>,
    compose: gtk::Entry,
    send_button: gtk::Button,

    /// Own account id and username, cached so the UI never waits for the
    /// client mutex while a network operation runs.
    me: Cell<Option<Uuid>>,
    my_name: RefCell<Option<String>>,
    realtime: RefCell<Option<tokio::task::JoinHandle<()>>>,
    syncing: Cell<bool>,
    sync_again: Cell<bool>,
    last_activity: Cell<Instant>,
}

fn labeled(grid: &gtk::Grid, row: i32, text: &str, widget: &impl IsA<gtk::Widget>) {
    let label = gtk::Label::builder().label(text).xalign(0.0).build();
    grid.attach(&label, 0, row, 1, 1);
    grid.attach(widget, 1, row, 1, 1);
}

/// Toolbar button with an icon from the icon theme and a text label.
fn icon_button(label: &str, icon_names: &[&str]) -> gtk::Button {
    let icon = gio::ThemedIcon::from_names(icon_names);
    let content = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    content.append(&gtk::Image::from_gicon(&icon));
    content.append(&gtk::Label::new(Some(label)));
    let button = gtk::Button::new();
    button.set_child(Some(&content));
    button.set_tooltip_text(Some(label));
    button
}

fn caption(text: &str) -> gtk::Label {
    let label = gtk::Label::builder().label(text).xalign(0.0).build();
    label.add_css_class("caption");
    label
}

fn centered_panel(title: &str, content: &impl IsA<gtk::Widget>) -> gtk::Box {
    let outer = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .width_request(420)
        .build();
    let body = gtk::Box::new(gtk::Orientation::Vertical, 8);
    body.add_css_class("groupbox");
    body.append(content);
    outer.append(&caption(title));
    outer.append(&body);
    outer
}

impl App {
    pub fn new(app: &gtk::Application, base_dir: PathBuf, preselect: Option<String>) -> Rc<Self> {
        let store = ProfileStore::open(&base_dir)
            .unwrap_or_else(|e| panic!("cannot use the profile directory {}: {e}", base_dir.display()));
        let window = gtk::ApplicationWindow::builder()
            .application(app)
            .title("Secure Messenger")
            .default_width(960)
            .default_height(640)
            .show_menubar(true)
            .build();

        let (status, status_user) = (gtk::Label::new(None), gtk::Label::new(None));
        status.set_xalign(0.0);
        status.set_hexpand(true);
        status.add_css_class("panel");
        status_user.add_css_class("panel");
        status_user.set_visible(false);

        // ---- setup ----
        let server_entry =
            gtk::Entry::builder().placeholder_text("https://messenger.example.org").hexpand(true).build();
        let invite_radio = gtk::CheckButton::with_label("I have an invitation code");
        let username_radio = gtk::CheckButton::with_label("Add this device to my existing account");
        username_radio.set_group(Some(&invite_radio));
        invite_radio.set_active(true);
        let code_entry = gtk::Entry::builder().placeholder_text("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX").build();
        let device_entry = gtk::Entry::new();
        device_entry.set_text(
            std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_owned()).as_deref().unwrap_or("Linux PC"),
        );
        let setup_info = gtk::Label::builder().wrap(true).xalign(0.0).build();
        let setup_pad = PatternPad::new();
        let setup_stack = gtk::Stack::new();

        // ---- pending ----
        let pending_info = gtk::Label::builder().wrap(true).xalign(0.0).selectable(true).build();

        // ---- unlock ----
        let unlock_pad = PatternPad::new();
        let unlock_info = gtk::Label::builder().wrap(true).build();
        let unlock_button = gtk::Button::with_label("Unlock");

        // ---- chat ----
        let conv_list = gtk::ListBox::new();
        let msg_list = gtk::ListBox::new();
        msg_list.set_selection_mode(gtk::SelectionMode::Single);
        let compose = gtk::Entry::builder().hexpand(true).placeholder_text("Write a message…").build();
        let send_button = gtk::Button::with_label("Send");
        let caption_label = gtk::Label::builder().label("No conversation selected").xalign(0.0).build();
        caption_label.add_css_class("caption");

        let stack = gtk::Stack::new();
        let actions = HashMap::new();
        let this = Rc::new(Self {
            app: app.clone(),
            window,
            stack,
            status,
            status_user,
            store,
            account: RefCell::new(None),
            admin_window: RefCell::new(None),
            preselect: RefCell::new(preselect),
            account_list: gtk::ListBox::new(),
            accounts: RefCell::default(),
            accounts_info: gtk::Label::builder().wrap(true).xalign(0.0).build(),
            setup_cancel: gtk::Button::with_label("Cancel"),
            shared: Arc::new(Mutex::new(None)),
            locked: RefCell::new(None),
            actions,
            setup_stack,
            server_entry,
            invite_radio,
            code_entry,
            device_entry,
            setup_pad,
            setup_info,
            first_pattern: RefCell::new(None),
            pending_info,
            unlock_pad,
            unlock_title: gtk::Label::builder().xalign(0.0).build(),
            unlock_info,
            unlock_button,
            conv_list,
            conversations: RefCell::default(),
            unread: RefCell::default(),
            current: RefCell::new(None),
            caption: caption_label,
            msg_list,
            msg_ids: RefCell::default(),
            next_before: Cell::new(None),
            compose,
            send_button,
            me: Cell::new(None),
            my_name: RefCell::new(None),
            realtime: RefCell::new(None),
            syncing: Cell::new(false),
            sync_again: Cell::new(false),
            last_activity: Cell::new(Instant::now()),
        });
        let this = Self::with_actions(this);
        this.build_layout(&username_radio);
        this.connect_signals();
        this.start_auto_lock();
        this
    }

    // ------------------------------------------------------------------ menu

    fn with_actions(this: Rc<Self>) -> Rc<Self> {
        let mut this = Rc::try_unwrap(this).ok().expect("no other references yet");
        let names = [
            "admin-setup",
            "switch-account",
            "add-account",
            "new-window",
            "new-chat",
            "new-group",
            "lock",
            "quit",
            "add-member",
            "leave",
            "retention",
            "delete-message",
            "refresh",
            "admin",
            "about",
        ];
        for name in names {
            let action = gio::SimpleAction::new(name, None);
            this.app.add_action(&action);
            this.actions.insert(name, action);
        }
        this.app.set_accels_for_action("app.lock", &["<Control>l"]);
        this.app.set_accels_for_action("app.quit", &["<Control>q"]);
        this.app.set_accels_for_action("app.new-chat", &["<Control>n"]);
        this.app.set_accels_for_action("app.refresh", &["F5"]);
        this.app.set_accels_for_action("app.delete-message", &["Delete"]);

        let menubar = gio::Menu::new();
        let file = gio::Menu::new();
        let file_main = gio::Menu::new();
        file_main.append(Some("_New Chat…"), Some("app.new-chat"));
        file_main.append(Some("New _Group…"), Some("app.new-group"));
        file.append_section(None, &file_main);
        let file_accounts = gio::Menu::new();
        file_accounts.append(Some("_Switch Account…"), Some("app.switch-account"));
        file_accounts.append(Some("A_dd Account…"), Some("app.add-account"));
        file_accounts.append(Some("New _Window"), Some("app.new-window"));
        file.append_section(None, &file_accounts);
        let file_end = gio::Menu::new();
        file_end.append(Some("_Lock"), Some("app.lock"));
        file_end.append(Some("_Quit"), Some("app.quit"));
        file.append_section(None, &file_end);
        menubar.append_submenu(Some("_File"), &file);

        let conversation = gio::Menu::new();
        let conv_main = gio::Menu::new();
        conv_main.append(Some("_Add Member…"), Some("app.add-member"));
        conv_main.append(Some("_Leave Group"), Some("app.leave"));
        conv_main.append(Some("_Retention Period…"), Some("app.retention"));
        conversation.append_section(None, &conv_main);
        let conv_delete = gio::Menu::new();
        conv_delete.append(Some("_Delete Message for Everyone"), Some("app.delete-message"));
        conversation.append_section(None, &conv_delete);
        menubar.append_submenu(Some("_Conversation"), &conversation);

        let view = gio::Menu::new();
        view.append(Some("_Refresh"), Some("app.refresh"));
        view.append(Some("_Classic Light Look"), Some("app.classic-look"));
        menubar.append_submenu(Some("_View"), &view);

        let admin = gio::Menu::new();
        admin.append(Some("_Set Up Admin Key…"), Some("app.admin-setup"));
        admin.append(Some("_Administration…"), Some("app.admin"));
        menubar.append_submenu(Some("_Admin"), &admin);

        let help = gio::Menu::new();
        help.append(Some("_About"), Some("app.about"));
        menubar.append_submenu(Some("_Help"), &help);
        this.app.set_menubar(Some(&menubar));
        Rc::new(this)
    }

    fn on_action(self: &Rc<Self>, name: &str, f: impl Fn(&Rc<Self>) + 'static) {
        let this = Rc::downgrade(self);
        self.actions[name].connect_activate(move |_, _| {
            if let Some(this) = this.upgrade() {
                f(&this);
            }
        });
    }

    fn set_chat_actions(&self, unlocked: bool) {
        let conv = self.current.borrow();
        let group = conv.as_ref().is_some_and(|c| c.kind == ConversationKind::Group);
        let admin = group && conv.as_ref().is_some_and(|c| self.is_admin(c));
        let selected = conv.is_some();
        for (name, enabled) in [
            ("new-chat", unlocked),
            ("new-group", unlocked),
            ("lock", unlocked),
            ("refresh", unlocked),
            ("add-member", unlocked && admin),
            ("leave", unlocked && group),
            ("retention", unlocked && selected),
            ("delete-message", unlocked && selected),
            ("admin", unlocked && self.has_admin_key()),
            ("admin-setup", unlocked && self.account.borrow().is_some() && !self.has_admin_key()),
        ] {
            self.actions[name].set_enabled(enabled);
        }
    }

    fn has_admin_key(&self) -> bool {
        self.account.borrow().as_ref().is_some_and(|(dir, _)| ssm_client::AdminKey::exists(dir))
    }

    fn open_admin(self: &Rc<Self>) {
        if let Some(window) = self.admin_window.borrow().as_ref()
            && window.window.is_visible()
        {
            window.window.present();
            return;
        }
        let Some((dir, server)) = self.account.borrow().clone() else { return };
        let window = crate::admin::AdminWindow::open(&self.window, dir, server);
        self.admin_window.replace(Some(window));
    }

    fn close_admin(&self) {
        if let Some(window) = self.admin_window.borrow_mut().take() {
            window.close();
        }
    }

    fn is_admin(&self, conv: &ConversationInfo) -> bool {
        let me = self.me.get();
        conv.members.iter().any(|m| Some(m.account_id) == me && m.status == "active" && m.role == "admin")
    }

    // ---------------------------------------------------------------- layout

    fn build_layout(self: &Rc<Self>, username_radio: &gtk::CheckButton) {
        // Setup: step 1 form, step 2/3 pattern.
        let form = gtk::Grid::builder().row_spacing(6).column_spacing(8).build();
        labeled(&form, 0, "Server address:", &self.server_entry);
        form.attach(&self.invite_radio, 0, 1, 2, 1);
        form.attach(username_radio, 0, 2, 2, 1);
        labeled(&form, 3, "Code / username:", &self.code_entry);
        labeled(&form, 4, "Name of this device:", &self.device_entry);
        let next = gtk::Button::with_label("Next >");
        let form_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        form_buttons.set_halign(gtk::Align::End);
        form_buttons.append(&self.setup_cancel);
        form_buttons.append(&next);
        form.attach(&form_buttons, 1, 5, 1, 1);
        let form_page = gtk::Box::new(gtk::Orientation::Vertical, 8);
        form_page.append(&gtk::Label::builder().label("Register this device with your messenger server. An administrator has to approve it before you can chat.").wrap(true).xalign(0.0).build());
        form_page.append(&form);
        self.setup_stack.add_named(&form_page, Some("form"));

        let pattern_page = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let pattern_title = gtk::Label::builder().wrap(true).xalign(0.0).build();
        let pattern_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        pattern_buttons.set_halign(gtk::Align::End);
        let back = gtk::Button::with_label("< Back");
        let confirm = gtk::Button::with_label("Next >");
        pattern_buttons.append(&back);
        pattern_buttons.append(&confirm);
        pattern_page.append(&pattern_title);
        pattern_page.append(&self.setup_pad.widget);
        pattern_page.append(&pattern_buttons);
        self.setup_stack.add_named(&pattern_page, Some("pattern"));

        self.setup_stack.set_vhomogeneous(false);
        self.setup_stack.set_interpolate_size(true);
        let setup_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        setup_box.append(&self.setup_stack);
        setup_box.append(&self.setup_info);
        self.stack.add_named(&centered_panel("Device Setup", &setup_box), Some("setup"));

        // Accounts on this computer.
        let accounts_scroll = gtk::ScrolledWindow::builder()
            .child(&self.account_list)
            .min_content_height(160)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build();
        accounts_scroll.add_css_class("sunken");
        let open = gtk::Button::with_label("Open");
        let add = gtk::Button::with_label("Add Account…");
        let remove = gtk::Button::with_label("Remove from this Computer…");
        let account_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        account_buttons.set_halign(gtk::Align::End);
        account_buttons.append(&remove);
        account_buttons.append(&add);
        account_buttons.append(&open);
        let accounts_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        accounts_box.append(
            &gtk::Label::builder()
                .label(
                    "Choose the account to use in this window. Each account has its own unlock pattern. \
                     File → New Window opens another account at the same time.",
                )
                .wrap(true)
                .xalign(0.0)
                .build(),
        );
        accounts_box.append(&accounts_scroll);
        accounts_box.append(&account_buttons);
        accounts_box.append(&self.accounts_info);
        self.stack.add_named(&centered_panel("Accounts on this Computer", &accounts_box), Some("accounts"));

        // Pending.
        let pending_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let check = gtk::Button::with_label("Check Now");
        check.set_halign(gtk::Align::End);
        pending_box.append(&self.pending_info);
        pending_box.append(&check);
        self.stack.add_named(&centered_panel("Waiting for Approval", &pending_box), Some("pending"));

        // Unlock.
        let unlock_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        unlock_box.append(&self.unlock_title);
        unlock_box.append(&gtk::Label::new(Some("Enter your unlock pattern.")));
        unlock_box.append(&self.unlock_pad.widget);
        let switch = gtk::Button::with_label("Switch Account");
        switch.set_action_name(Some("app.switch-account"));
        let unlock_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        unlock_buttons.set_halign(gtk::Align::End);
        unlock_buttons.append(&switch);
        unlock_buttons.append(&self.unlock_button);
        unlock_box.append(&unlock_buttons);
        unlock_box.append(&self.unlock_info);
        self.stack.add_named(&centered_panel("Secure Messenger is Locked", &unlock_box), Some("unlock"));

        // Chat: toolbar, paned lists, compose row.
        let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 2);
        toolbar.add_css_class("toolbar");
        // Icons from the desktop's icon theme: coloured names first, then
        // the symbolic variants (Adwaita) as fallback.
        for (label, action, icons) in [
            ("New Chat", "app.new-chat", &["mail-message-new", "mail-message-new-symbolic"][..]),
            ("New Group", "app.new-group", &["system-users", "system-users-symbolic", "contact-new-symbolic"][..]),
            ("Delete", "app.delete-message", &["edit-delete", "edit-delete-symbolic"][..]),
            ("Refresh", "app.refresh", &["view-refresh", "view-refresh-symbolic"][..]),
            ("Lock", "app.lock", &["system-lock-screen", "system-lock-screen-symbolic"][..]),
        ] {
            let button = icon_button(label, icons);
            button.set_action_name(Some(action));
            toolbar.append(&button);
        }

        let conv_scroll =
            gtk::ScrolledWindow::builder().child(&self.conv_list).hscrollbar_policy(gtk::PolicyType::Never).build();
        conv_scroll.add_css_class("sunken");
        let left = gtk::Box::new(gtk::Orientation::Vertical, 0);
        left.append(&caption("Conversations"));
        conv_scroll.set_vexpand(true);
        left.append(&conv_scroll);

        let msg_scroll = gtk::ScrolledWindow::builder().child(&self.msg_list).vexpand(true).build();
        msg_scroll.add_css_class("sunken");
        let compose_row = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        compose_row.set_margin_top(4);
        compose_row.append(&self.compose);
        compose_row.append(&self.send_button);
        let right = gtk::Box::new(gtk::Orientation::Vertical, 0);
        right.append(&self.caption);
        right.append(&msg_scroll);
        right.append(&compose_row);

        let paned = gtk::Paned::builder().orientation(gtk::Orientation::Horizontal).position(260).vexpand(true).build();
        paned.set_start_child(Some(&left));
        paned.set_end_child(Some(&right));
        paned.set_margin_start(4);
        paned.set_margin_end(4);
        paned.set_margin_top(4);
        paned.set_margin_bottom(4);
        let chat = gtk::Box::new(gtk::Orientation::Vertical, 0);
        chat.append(&toolbar);
        chat.append(&paned);
        self.stack.add_named(&chat, Some("chat"));

        let statusbar = gtk::Box::new(gtk::Orientation::Horizontal, 2);
        statusbar.add_css_class("statusbar");
        statusbar.append(&self.status);
        statusbar.append(&self.status_user);

        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        self.stack.set_vexpand(true);
        root.append(&self.stack);
        root.append(&statusbar);
        self.window.set_child(Some(&root));

        // Setup navigation.
        {
            let this = Rc::downgrade(self);
            let title = pattern_title.clone();
            next.connect_clicked(move |_| {
                let Some(this) = this.upgrade() else { return };
                if this.server_entry.text().trim().is_empty() || this.code_entry.text().trim().is_empty() {
                    this.setup_info.set_text("Please fill in the server address and the code or username.");
                    return;
                }
                this.setup_info.set_text("");
                this.first_pattern.replace(None);
                title.set_text(
                    "Choose an unlock pattern. It protects the keys on this device and is never sent to the server.",
                );
                this.setup_stack.set_visible_child_name("pattern");
            });
        }
        for entry in [&self.server_entry, &self.code_entry, &self.device_entry] {
            let next = next.clone();
            entry.connect_activate(move |_| next.emit_clicked());
        }
        {
            let this = Rc::downgrade(self);
            back.connect_clicked(move |_| {
                if let Some(this) = this.upgrade() {
                    this.setup_pad.clear();
                    this.first_pattern.replace(None);
                    this.setup_stack.set_visible_child_name("form");
                }
            });
        }
        {
            let this = Rc::downgrade(self);
            confirm.connect_clicked(move |button| {
                let Some(this) = this.upgrade() else { return };
                match this.setup_pad.take() {
                    Err(err) => this.setup_info.set_text(&format!("{err}.")),
                    Ok(pattern) => {
                        let first = this.first_pattern.borrow_mut().take();
                        match first {
                            None => {
                                this.first_pattern.replace(Some(pattern));
                                this.setup_info.set_text("");
                                pattern_title.set_text("Repeat the pattern to confirm it.");
                            }
                            Some(first) if first.encode() == pattern.encode() => {
                                button.set_sensitive(false);
                                this.enroll(pattern, button.clone());
                            }
                            Some(_) => {
                                this.setup_info.set_text("The patterns did not match. Please choose a pattern again.");
                                pattern_title.set_text("Choose an unlock pattern.");
                            }
                        }
                    }
                }
            });
        }
        {
            let this = Rc::downgrade(self);
            check.connect_clicked(move |_| {
                if let Some(this) = this.upgrade() {
                    this.check_approval();
                }
            });
        }
        {
            let this = Rc::downgrade(self);
            open.connect_clicked(move |_| {
                if let Some(this) = this.upgrade() {
                    this.open_selected_account();
                }
            });
            let this = Rc::downgrade(self);
            self.account_list.connect_row_activated(move |_, _| {
                if let Some(this) = this.upgrade() {
                    this.open_selected_account();
                }
            });
            add.set_action_name(Some("app.add-account"));
            let this = Rc::downgrade(self);
            remove.connect_clicked(move |_| {
                if let Some(this) = this.upgrade() {
                    this.remove_selected_account();
                }
            });
            let this = Rc::downgrade(self);
            self.setup_cancel.connect_clicked(move |_| {
                if let Some(this) = this.upgrade() {
                    this.setup_pad.clear();
                    this.show_accounts(false);
                }
            });
        }
    }

    fn connect_signals(self: &Rc<Self>) {
        // Stateful toggle: classic light palette instead of the desktop colours.
        let classic = theme::classic_chosen(self.store.base());
        let action = gio::SimpleAction::new_stateful("classic-look", None, &classic.to_variant());
        let base = self.store.base().to_owned();
        action.connect_activate(move |action, _| {
            let on = !action.state().and_then(|s| s.get::<bool>()).unwrap_or(false);
            action.set_state(&on.to_variant());
            theme::set_classic(on);
            theme::remember_classic(&base, on);
        });
        self.app.add_action(&action);
        self.on_action("quit", |this| this.app.quit());
        self.on_action("lock", |this| this.lock(AfterLock::Unlock));
        self.on_action("switch-account", |this| this.lock(AfterLock::Accounts));
        self.on_action("admin", |this| this.open_admin());
        self.on_action("admin-setup", |this| {
            let Some((dir, _)) = this.account.borrow().clone() else { return };
            let weak = Rc::downgrade(this);
            crate::admin::setup_key(&this.window, dir, move || {
                if let Some(this) = weak.upgrade() {
                    this.set_chat_actions(true);
                }
            });
        });
        self.on_action("add-account", |this| this.lock(AfterLock::Setup));
        self.on_action("new-window", |this| match std::env::current_exe() {
            Ok(exe) => {
                if let Err(err) = std::process::Command::new(exe).spawn() {
                    this.set_status(&format!("Could not open a new window: {err}"));
                }
            }
            Err(err) => this.set_status(&format!("Could not open a new window: {err}")),
        });
        self.on_action("refresh", |this| {
            this.sync_now();
            this.reload_current();
        });
        self.on_action("about", |this| {
            gtk::AboutDialog::builder()
                .transient_for(&this.window)
                .modal(true)
                .program_name("Secure Messenger")
                .version(env!("CARGO_PKG_VERSION"))
                .comments(
                    "Self-hosted, end-to-end encrypted messenger.\nThere is only one way to delete: for everyone.",
                )
                .build()
                .present();
        });
        self.on_action("new-chat", |this| this.new_chat(ConversationKind::Direct));
        self.on_action("new-group", |this| this.new_chat(ConversationKind::Group));
        self.on_action("add-member", |this| this.add_member());
        self.on_action("leave", |this| this.leave_group());
        self.on_action("retention", |this| this.change_retention());
        self.on_action("delete-message", |this| this.delete_selected());

        let this = Rc::downgrade(self);
        self.unlock_button.connect_clicked(move |_| {
            if let Some(this) = this.upgrade() {
                this.unlock();
            }
        });
        let this = Rc::downgrade(self);
        self.conv_list.connect_row_selected(move |_, row| {
            let (Some(this), Some(row)) = (this.upgrade(), row) else { return };
            let conv = this.conversations.borrow().get(row.index() as usize).cloned();
            if let Some(conv) = conv {
                this.open_conversation(conv);
            }
        });
        let this = Rc::downgrade(self);
        self.send_button.connect_clicked(move |_| {
            if let Some(this) = this.upgrade() {
                this.send();
            }
        });
        let this = Rc::downgrade(self);
        self.compose.connect_activate(move |_| {
            if let Some(this) = this.upgrade() {
                this.send();
            }
        });

        // Any input counts as activity for the auto-lock.
        let keys = gtk::EventControllerKey::new();
        let this = Rc::downgrade(self);
        keys.connect_key_pressed(move |_, _, _, _| {
            if let Some(this) = this.upgrade() {
                this.last_activity.set(Instant::now());
            }
            glib::Propagation::Proceed
        });
        self.window.add_controller(keys);
        let motion = gtk::EventControllerMotion::new();
        let this = Rc::downgrade(self);
        motion.connect_motion(move |_, _, _| {
            if let Some(this) = this.upgrade() {
                this.last_activity.set(Instant::now());
            }
        });
        self.window.add_controller(motion);
    }

    fn start_auto_lock(self: &Rc<Self>) {
        let this = Rc::downgrade(self);
        glib::timeout_add_seconds_local(15, move || {
            let Some(this) = this.upgrade() else { return glib::ControlFlow::Break };
            let unlocked = matches!(this.stack.visible_child_name().as_deref(), Some("chat" | "pending"));
            if unlocked && this.last_activity.get().elapsed() > AUTO_LOCK_AFTER {
                this.lock(AfterLock::Unlock);
            }
            glib::ControlFlow::Continue
        });
    }

    fn set_status(&self, text: &str) {
        self.status.set_text(text);
    }

    // ----------------------------------------------------------------- start

    pub fn present(&self) {
        self.window.present();
    }

    pub fn start(self: &Rc<Self>) {
        self.set_chat_actions(false);
        self.window.present();
        self.show_accounts(true);
    }

    /// Account picker. With `auto`, opens the account directly when there is
    /// only one free account or `--account` named one; with none, shows setup.
    fn show_accounts(self: &Rc<Self>, auto: bool) {
        self.window.set_title(Some("Secure Messenger"));
        self.status_user.set_visible(false);
        self.set_chat_actions(false);
        let accounts = match self.store.list() {
            Ok(list) => list,
            Err(err) => {
                self.accounts_info.set_text(&friendly_error(&err));
                Vec::new()
            }
        };
        if accounts.is_empty() {
            self.show_setup(false);
            return;
        }
        if auto {
            let wanted = self.preselect.borrow_mut().take();
            let pick = match &wanted {
                Some(name) => accounts.iter().find(|a| a.data.username.as_deref() == Some(name.as_str())),
                None if accounts.len() == 1 && !accounts[0].in_use => accounts.first(),
                None => None,
            };
            if let Some(account) = pick {
                let dir = account.dir.clone();
                self.accounts.replace(accounts);
                self.open_account(dir);
                return;
            }
            if let Some(name) = wanted {
                self.accounts_info.set_text(&format!("There is no account '{name}' on this computer."));
            }
        }
        while let Some(row) = self.account_list.row_at_index(0) {
            self.account_list.remove(&row);
        }
        for account in &accounts {
            let mut text = account.label();
            if account.in_use {
                text.push_str("   [open in another window]");
            }
            self.account_list.append(&gtk::Label::builder().label(&text).xalign(0.0).build());
        }
        if let Some(row) = self.account_list.row_at_index(0) {
            self.account_list.select_row(Some(&row));
        }
        self.accounts.replace(accounts);
        self.stack.set_visible_child_name("accounts");
        self.set_status("Choose an account");
    }

    fn selected_account(&self) -> Option<ProfileSummary> {
        let row = self.account_list.selected_row()?;
        self.accounts.borrow().get(row.index() as usize).cloned()
    }

    fn open_selected_account(self: &Rc<Self>) {
        if let Some(account) = self.selected_account() {
            self.open_account(account.dir);
        }
    }

    fn open_account(self: &Rc<Self>, dir: PathBuf) {
        match LockedClient::open(&dir) {
            Ok(locked) => {
                let name = locked.data().username.clone().unwrap_or_else(|| "(not approved yet)".into());
                self.window.set_title(Some(&format!("Secure Messenger — {name}")));
                self.unlock_title.set_text(&format!("Account: {name}  ({})", locked.data().server_url));
                self.status_user.set_text(&name);
                self.status_user.set_visible(true);
                self.account.replace(Some((locked.dir().to_owned(), locked.data().server_url.clone())));
                self.locked.replace(Some(locked));
                self.show_unlock("");
            }
            Err(err) => {
                self.show_accounts(false);
                self.accounts_info.set_text(&friendly_error(&err));
            }
        }
    }

    fn show_setup(self: &Rc<Self>, cancellable: bool) {
        self.setup_cancel.set_visible(cancellable);
        self.setup_stack.set_visible_child_name("form");
        self.code_entry.set_text("");
        self.setup_info.set_text("");
        self.window.set_title(Some("Secure Messenger"));
        self.stack.set_visible_child_name("setup");
        self.set_status("Not registered");
    }

    /// Signs the device out on the server and deletes its keys here.
    fn remove_selected_account(self: &Rc<Self>) {
        let Some(account) = self.selected_account() else { return };
        let name = account.data.username.clone().unwrap_or_else(|| "this account".into());
        let this = self.clone();
        glib::spawn_future_local(async move {
            let detail = "This device is signed out on the server and its keys are deleted from this computer. \
                          To use the account here again, the device has to be registered and approved again.";
            if !this.confirm(&format!("Remove {name} from this computer?"), detail, "Remove").await {
                return;
            }
            let locked = match LockedClient::open(&account.dir) {
                Ok(locked) => locked,
                Err(err) => {
                    this.accounts_info.set_text(&friendly_error(&err));
                    return;
                }
            };
            let (tx, rx) = async_channel::bounded(1);
            run(
                async move {
                    let result = locked.unregister().await;
                    drop(locked);
                    result
                },
                move |result| {
                    let _ = tx.try_send(result);
                },
            );
            let Ok(result) = rx.recv().await else { return };
            if let Err(err) = result {
                let detail = format!(
                    "{}\n\nRemove it from this computer anyway? The device then stays registered on the \
                     server until an administrator revokes it.",
                    friendly_error(&err)
                );
                if !this.confirm("The server could not be reached", &detail, "Remove Anyway").await {
                    return;
                }
            }
            match this.store.remove(&account.dir) {
                Ok(()) => {
                    this.show_accounts(false);
                    this.accounts_info.set_text(&format!("{name} was removed from this computer."));
                }
                Err(err) => this.accounts_info.set_text(&friendly_error(&err)),
            }
        });
    }

    fn show_unlock(&self, message: &str) {
        self.unlock_pad.clear();
        self.unlock_info.set_text(message);
        self.unlock_button.set_sensitive(true);
        self.stack.set_visible_child_name("unlock");
        self.set_status("Locked");
        self.set_chat_actions(false);
    }

    // ----------------------------------------------------------------- setup

    fn enroll(self: &Rc<Self>, pattern: Pattern, button: gtk::Button) {
        let server = self.server_entry.text().trim().to_owned();
        let code = self.code_entry.text().trim().to_owned();
        let device = self.device_entry.text().trim().to_owned();
        let with = if self.invite_radio.is_active() { EnrollWith::Invite(code) } else { EnrollWith::Username(code) };
        let dir = match self.store.new_profile_dir() {
            Ok(dir) => dir,
            Err(err) => {
                self.setup_info.set_text(&friendly_error(&err));
                button.set_sensitive(true);
                return;
            }
        };
        let cleanup = dir.clone();
        self.setup_info.set_text("Measuring this computer for the key derivation and registering… (a few seconds)");
        self.set_status("Registering…");
        let this = self.clone();
        run(
            async move {
                let params = tokio::task::spawn_blocking(move || KdfParams::calibrate(KDF_TARGET))
                    .await
                    .map_err(|e| ClientError::Protocol(e.to_string()))??;
                Client::enroll(dir, &server, with, &device, &pattern, params, None).await
            },
            move |result: ClientResult<Client>| {
                button.set_sensitive(true);
                match result {
                    Ok(client) => {
                        this.account.replace(Some((client.dir().to_owned(), client.data().server_url.clone())));
                        let fingerprint = client.fingerprint();
                        this.pending_info.set_text(&format!(
                            "This device is registered and waits for an administrator to approve it.\n\n\
                             Device fingerprint (tell your administrator):\n{fingerprint}"
                        ));
                        rt().block_on(async { this.shared.lock().await.replace(client) });
                        this.stack.set_visible_child_name("pending");
                        this.set_status("Waiting for approval");
                        this.start_approval_polling();
                    }
                    Err(err) => {
                        let _ = this.store.remove(&cleanup);
                        this.setup_info.set_text(&friendly_error(&err));
                        this.setup_stack.set_visible_child_name("form");
                        this.set_status("Not registered");
                    }
                }
            },
        );
    }

    fn start_approval_polling(self: &Rc<Self>) {
        let this = Rc::downgrade(self);
        glib::timeout_add_seconds_local(10, move || {
            let Some(this) = this.upgrade() else { return glib::ControlFlow::Break };
            if this.stack.visible_child_name().as_deref() != Some("pending") {
                return glib::ControlFlow::Break;
            }
            this.check_approval();
            glib::ControlFlow::Continue
        });
    }

    fn check_approval(self: &Rc<Self>) {
        let this = self.clone();
        run(
            with_client!(self.shared, |c| c.device_status().await.map(|s| (s, identity(c)))),
            move |result| match result {
                Ok((DeviceStatus::Active, me)) => {
                    this.remember(me);
                    this.enter_chat()
                }
                Ok((DeviceStatus::Pending, _)) => this.set_status("Still waiting for approval"),
                Ok((other, _)) => {
                    this.pending_info.set_text(&format!("This device was {} by an administrator.", other.as_str()))
                }
                Err(err) => this.set_status(&friendly_error(&err)),
            },
        );
    }

    // ---------------------------------------------------------------- unlock

    fn unlock(self: &Rc<Self>) {
        let Some(locked) = self.locked.borrow_mut().take() else { return };
        let delay = locked.unlock_delay();
        if !delay.is_zero() {
            self.locked.replace(Some(locked));
            self.unlock_pad.clear();
            self.unlock_info.set_text(&format!("Too many wrong patterns. Please wait {} seconds.", delay.as_secs()));
            return;
        }
        let pattern = match self.unlock_pad.take() {
            Ok(pattern) => pattern,
            Err(err) => {
                self.locked.replace(Some(locked));
                self.unlock_info.set_text(&format!("{err}."));
                return;
            }
        };
        self.unlock_button.set_sensitive(false);
        self.unlock_info.set_text("Unlocking…");
        let this = self.clone();
        run(
            async move { tokio::task::spawn_blocking(move || locked.unlock(&pattern, None)).await.expect("unlock task") },
            move |result| {
                this.unlock_button.set_sensitive(true);
                match result {
                    Ok(client) => {
                        rt().block_on(async { this.shared.lock().await.replace(client) });
                        this.last_activity.set(Instant::now());
                        this.after_unlock();
                    }
                    Err(failed) => {
                        let wait = failed.locked.unlock_delay();
                        let mut text = friendly_error(&failed.error);
                        if !wait.is_zero() {
                            text.push_str(&format!(" Next attempt in {} seconds.", wait.as_secs()));
                        }
                        this.unlock_info.set_text(&text);
                        this.locked.replace(Some(*failed.locked));
                    }
                }
            },
        );
    }

    fn after_unlock(self: &Rc<Self>) {
        let this = self.clone();
        run(
            with_client!(self.shared, |c| {
                let status = c.device_status().await;
                Ok::<_, ClientError>((status, c.fingerprint(), identity(c)))
            }),
            move |result| match result {
                Ok((status, fingerprint, me)) => {
                    this.remember(me);
                    this.after_status(status, fingerprint);
                }
                Err(err) => this.set_status(&friendly_error(&err)),
            },
        );
    }

    fn remember(&self, (id, name): (Option<Uuid>, Option<String>)) {
        self.me.set(id);
        self.my_name.replace(name);
    }

    fn after_status(self: &Rc<Self>, status: ClientResult<DeviceStatus>, fingerprint: String) {
        match status {
            Ok(DeviceStatus::Active) => self.enter_chat(),
            Ok(DeviceStatus::Pending) => {
                self.pending_info.set_text(&format!(
                    "This device waits for an administrator to approve it.\n\nDevice fingerprint:\n{fingerprint}"
                ));
                self.stack.set_visible_child_name("pending");
                self.start_approval_polling();
            }
            Ok(other) => {
                self.lock(AfterLock::Unlock);
                self.unlock_info.set_text(&format!("This device was {} by an administrator.", other.as_str()));
            }
            Err(err) => {
                // Offline or server error: stay unlocked, retry via Refresh.
                self.enter_chat();
                self.set_status(&friendly_error(&err));
            }
        }
    }

    /// Drops all keys and plaintext from memory, then shows `after`.
    fn lock(self: &Rc<Self>, after: AfterLock) {
        // The admin key leaves memory together with the chat keys.
        self.close_admin();
        if after != AfterLock::Unlock {
            self.account.replace(None);
        }
        if let Some(task) = self.realtime.borrow_mut().take() {
            task.abort();
        }
        self.clear_messages();
        self.current.replace(None);
        self.conversations.borrow_mut().clear();
        while let Some(row) = self.conv_list.row_at_index(0) {
            self.conv_list.remove(&row);
        }
        self.caption.set_text("No conversation selected");
        self.compose.set_text("");
        self.me.set(None);
        self.show_unlock("");
        self.unlock_button.set_sensitive(false);
        if after != AfterLock::Unlock {
            self.stack.set_visible_child_name("accounts");
        }
        // Waits for a running operation to finish before the keys are dropped.
        let this = self.clone();
        run(
            {
                let shared = self.shared.clone();
                async move { shared.lock().await.take().map(Client::lock) }
            },
            move |locked| {
                if let Some(locked) = locked {
                    this.locked.replace(Some(locked));
                }
                this.unlock_button.set_sensitive(true);
                if after != AfterLock::Unlock {
                    // Closing the account releases its lock for other windows.
                    this.locked.replace(None);
                    match after {
                        AfterLock::Setup => this.show_setup(true),
                        _ => this.show_accounts(false),
                    }
                }
            },
        );
    }

    // ------------------------------------------------------------------ chat

    fn enter_chat(self: &Rc<Self>) {
        let user = self.my_name.borrow().clone();
        self.status_user.set_text(user.as_deref().unwrap_or(""));
        self.status_user.set_visible(user.is_some());
        self.stack.set_visible_child_name("chat");
        self.set_chat_actions(true);
        self.set_status("Connected");
        self.start_realtime();
        self.sync_now();
        self.reload_conversations(None);
    }

    fn start_realtime(self: &Rc<Self>) {
        if let Some(task) = self.realtime.borrow_mut().take() {
            task.abort();
        }
        let (tx, rx) = async_channel::unbounded::<bool>();
        let shared = self.shared.clone();
        let task = rt().spawn(async move {
            loop {
                let credentials = {
                    let guard = shared.lock().await;
                    match guard.as_ref() {
                        Some(client) => client.realtime_credentials().await,
                        None => return,
                    }
                };
                match credentials {
                    Ok((url, token)) => match WakeChannel::connect(&url, &token).await {
                        Ok(mut channel) => {
                            let _ = tx.send(true).await;
                            loop {
                                match channel.next().await {
                                    Wake::Sync(_) => {
                                        if tx.send(true).await.is_err() {
                                            return;
                                        }
                                    }
                                    Wake::Closed(code) => {
                                        tracing::info!(?code, "wake channel closed");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(err) => tracing::warn!(error = %err, "wake channel connect failed"),
                    },
                    Err(err) => tracing::warn!(error = %err, "no session for wake channel"),
                }
                let _ = tx.send(false).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        self.realtime.replace(Some(task));
        let this = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            while let Ok(connected) = rx.recv().await {
                let Some(this) = this.upgrade() else { return };
                if connected {
                    this.sync_now();
                } else {
                    this.set_status("Offline – reconnecting…");
                }
            }
        });
    }

    fn sync_now(self: &Rc<Self>) {
        if self.syncing.replace(true) {
            self.sync_again.set(true);
            return;
        }
        let this = self.clone();
        run(with_client!(self.shared, |c| c.sync().await), move |result| {
            this.syncing.set(false);
            match result {
                Ok(updates) => {
                    this.set_status("Connected");
                    this.apply_updates(updates);
                }
                Err(err) if err.problem_kind() == Some("device-not-active") => {
                    this.lock(AfterLock::Unlock);
                    this.unlock_info.set_text(&friendly_error(&err));
                }
                Err(err) => this.set_status(&friendly_error(&err)),
            }
            if this.sync_again.replace(false) {
                this.sync_now();
            }
        });
    }

    fn apply_updates(self: &Rc<Self>, updates: Vec<Update>) {
        let current = self.current.borrow().as_ref().map(|c| c.conversation_id);
        let mut reload_current = false;
        let mut reload_list = false;
        let mut notify = false;
        for update in updates {
            match update {
                Update::NewMessage { conversation_id, .. } => {
                    if Some(conversation_id) == current {
                        reload_current = true;
                    } else {
                        self.unread.borrow_mut().insert(conversation_id);
                        reload_list = true;
                    }
                    notify = true;
                }
                Update::MessageDeleted { conversation_id, .. } if Some(conversation_id) == current => {
                    reload_current = true
                }
                Update::ConversationUpdated { conversation_id } => {
                    reload_list = true;
                    if Some(conversation_id) == current {
                        reload_current = true;
                    }
                }
                Update::MessageDeleted { .. } | Update::KeyReceived { .. } => {}
            }
        }
        if reload_list {
            self.reload_conversations(current);
        }
        if reload_current {
            self.reload_current();
        }
        if notify && !self.window.is_active() {
            self.notify();
        }
    }

    /// Desktop notification with at most the sender's initial (FR-015).
    fn notify(self: &Rc<Self>) {
        let this = self.clone();
        run(with_client!(self.shared, |c| c.notification_hint().await), move |result| {
            if let Ok(hint) = result {
                let notification = gio::Notification::new("New message");
                let body = hint.sender_initial.map(|i| format!("From {i}…")).unwrap_or_default();
                notification.set_body(Some(&body));
                this.app.send_notification(Some("new-message"), &notification);
            }
        });
    }

    fn conversation_title(&self, conv: &ConversationInfo) -> String {
        let me = self.me.get();
        let others: Vec<&str> = conv
            .members
            .iter()
            .filter(|m| m.status == "active" && Some(m.account_id) != me)
            .map(|m| m.username.as_str())
            .collect();
        match conv.kind {
            ConversationKind::Direct => others.first().copied().unwrap_or("(nobody)").to_owned(),
            ConversationKind::Group if others.is_empty() => "Group (only you)".to_owned(),
            ConversationKind::Group => format!("Group: {}", others.join(", ")),
        }
    }

    fn reload_conversations(self: &Rc<Self>, select: Option<Uuid>) {
        let this = self.clone();
        run(with_client!(self.shared, |c| c.conversations().await), move |result| match result {
            Ok(list) => {
                // Suppress selection signals while rebuilding.
                this.conversations.replace(Vec::new());
                while let Some(row) = this.conv_list.row_at_index(0) {
                    this.conv_list.remove(&row);
                }
                for conv in &list {
                    let unread = this.unread.borrow().contains(&conv.conversation_id);
                    let text = format!("{}{}", if unread { "• " } else { "" }, this.conversation_title(conv));
                    let label = gtk::Label::builder().label(&text).xalign(0.0).build();
                    if unread {
                        label.add_css_class("unread");
                    }
                    this.conv_list.append(&label);
                }
                let position = select.and_then(|id| list.iter().position(|c| c.conversation_id == id));
                let still_member = position.is_some();
                this.conversations.replace(list);
                match position {
                    Some(index) => {
                        if let Some(row) = this.conv_list.row_at_index(index as i32) {
                            this.conv_list.select_row(Some(&row));
                        }
                    }
                    None if select.is_some() && !still_member => {
                        this.clear_messages();
                        this.current.replace(None);
                        this.caption.set_text("No conversation selected");
                        this.set_chat_actions(true);
                    }
                    None => {}
                }
            }
            Err(err) => this.set_status(&friendly_error(&err)),
        });
    }

    /// Drops the decrypted messages of the open conversation (FR-013).
    fn clear_messages(&self) {
        while let Some(row) = self.msg_list.row_at_index(0) {
            self.msg_list.remove(&row);
        }
        self.msg_ids.borrow_mut().clear();
        self.next_before.set(None);
    }

    fn open_conversation(self: &Rc<Self>, conv: ConversationInfo) {
        let same = self.current.borrow().as_ref().is_some_and(|c| c.conversation_id == conv.conversation_id);
        self.unread.borrow_mut().remove(&conv.conversation_id);
        self.caption.set_text(&format!(
            "{}   —   messages are deleted after {} days",
            self.conversation_title(&conv),
            conv.retention_days
        ));
        self.current.replace(Some(conv));
        self.set_chat_actions(true);
        if !same {
            self.clear_messages();
            self.reload_current();
        }
    }

    fn reload_current(self: &Rc<Self>) {
        let Some(conv) = self.current.borrow().as_ref().map(|c| c.conversation_id) else { return };
        let this = self.clone();
        run(with_client!(self.shared, |c| c.messages(conv, None).await), move |result| {
            if this.current.borrow().as_ref().map(|c| c.conversation_id) != Some(conv) {
                return;
            }
            match result {
                Ok((messages, next)) => {
                    this.clear_messages();
                    this.next_before.set(next);
                    this.append_page(messages);
                    if let Some(last) = this.msg_list.last_child() {
                        last.grab_focus();
                    }
                    this.compose.grab_focus();
                }
                Err(err) => this.set_status(&friendly_error(&err)),
            }
        });
    }

    fn load_older(self: &Rc<Self>) {
        let (Some(conv), Some(before)) =
            (self.current.borrow().as_ref().map(|c| c.conversation_id), self.next_before.get())
        else {
            return;
        };
        let this = self.clone();
        run(with_client!(self.shared, |c| c.messages(conv, Some(before)).await), move |result| match result {
            Ok((messages, next)) => {
                // Remove the old "load older" row, then prepend the page.
                if this.msg_ids.borrow().first() == Some(&None) {
                    if let Some(row) = this.msg_list.row_at_index(0) {
                        this.msg_list.remove(&row);
                    }
                    this.msg_ids.borrow_mut().remove(0);
                }
                this.next_before.set(next);
                this.prepend_page(messages);
            }
            Err(err) => this.set_status(&friendly_error(&err)),
        });
    }

    fn username(&self, account: Option<Uuid>) -> String {
        let conv = self.current.borrow();
        account
            .and_then(|id| conv.as_ref()?.members.iter().find(|m| m.account_id == id).map(|m| m.username.clone()))
            .unwrap_or_else(|| "someone".into())
    }

    fn message_row(&self, message: &DisplayMessage) -> gtk::Widget {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let time = gtk::Label::new(Some(&short_time(&message.created_at)));
        time.add_css_class("time");
        time.set_valign(gtk::Align::Start);
        row.append(&time);
        let body = gtk::Label::builder().xalign(0.0).wrap(true).hexpand(true).build();
        match &message.body {
            DisplayBody::Text(text) => {
                let sender = gtk::Label::new(Some(&format!("{}:", self.username(message.sender_account_id))));
                sender.add_css_class("sender");
                sender.set_valign(gtk::Align::Start);
                row.append(&sender);
                body.set_text(text);
            }
            DisplayBody::Unavailable => {
                body.set_text(&format!(
                    "{}: (this device has no key for this message)",
                    self.username(message.sender_account_id)
                ));
                body.add_css_class("deleted");
            }
            DisplayBody::Undecryptable(reason) => {
                body.set_text(&format!("(cannot decrypt: {reason})"));
                body.add_css_class("error");
            }
            DisplayBody::Deleted { by } => {
                let who = by.map(|id| self.username(Some(id))).unwrap_or_else(|| "an administrator".into());
                body.set_text(&format!("Message deleted for everyone by {who}"));
                body.add_css_class("deleted");
            }
            DisplayBody::Notice(notice) => {
                body.set_text(&self.notice_text(notice));
                body.add_css_class("notice");
            }
        }
        row.append(&body);
        row.upcast()
    }

    fn notice_text(&self, notice: &SystemNotice) -> String {
        let name = |id: &Uuid| self.username(Some(*id));
        match notice {
            SystemNotice::ConversationCreated { by } => format!("{} started the conversation", name(by)),
            SystemNotice::MemberAdded { account_id, by } => format!("{} added {}", name(by), name(account_id)),
            SystemNotice::MemberLeft { account_id } => format!("{} left", name(account_id)),
            SystemNotice::MemberRemoved { account_id, by } => format!("{} removed {}", name(by), name(account_id)),
            SystemNotice::RetentionChanged { from_days, to_days, by } => {
                format!("{} changed the retention period from {from_days} to {to_days} days", name(by))
            }
            SystemNotice::AdminChanged { account_id } => format!("{} is now the group admin", name(account_id)),
            SystemNotice::AccountDeleted { username } => {
                format!("The account of {username} was deleted; their messages were removed for everyone")
            }
        }
    }

    fn load_older_row(self: &Rc<Self>) -> gtk::Widget {
        let button = gtk::Button::with_label("Load older messages");
        button.set_halign(gtk::Align::Center);
        let this = Rc::downgrade(self);
        button.connect_clicked(move |_| {
            if let Some(this) = this.upgrade() {
                this.load_older();
            }
        });
        button.upcast()
    }

    /// `messages` is newest first; rows are shown oldest at the top.
    fn append_page(self: &Rc<Self>, messages: Vec<DisplayMessage>) {
        if self.next_before.get().is_some() {
            self.msg_list.append(&self.load_older_row());
            self.msg_ids.borrow_mut().push(None);
        }
        for message in messages.iter().rev() {
            self.msg_list.append(&self.message_row(message));
            self.msg_ids.borrow_mut().push(Some(message.message_id));
        }
    }

    fn prepend_page(self: &Rc<Self>, messages: Vec<DisplayMessage>) {
        for message in &messages {
            self.msg_list.prepend(&self.message_row(message));
            self.msg_ids.borrow_mut().insert(0, Some(message.message_id));
        }
        if self.next_before.get().is_some() {
            self.msg_list.prepend(&self.load_older_row());
            self.msg_ids.borrow_mut().insert(0, None);
        }
    }

    fn send(self: &Rc<Self>) {
        let text = self.compose.text().trim().to_owned();
        let Some(conv) = self.current.borrow().as_ref().map(|c| c.conversation_id) else { return };
        if text.is_empty() {
            return;
        }
        self.compose.set_text("");
        self.send_button.set_sensitive(false);
        self.set_status("Sending…");
        let this = self.clone();
        run(with_client!(self.shared, |c| c.send_text(conv, &text).await), move |result| {
            this.send_button.set_sensitive(true);
            match result {
                Ok(_) => {
                    this.set_status("Connected");
                    this.reload_current();
                }
                Err(err) => this.set_status(&format!("Not sent: {}", friendly_error(&err))),
            }
        });
    }

    // --------------------------------------------------------------- dialogs

    /// Small modal input dialog; `None` when cancelled.
    async fn prompt(self: &Rc<Self>, title: &str, text: &str, initial: &str) -> Option<String> {
        dialogs::prompt(&self.window, title, text, initial).await
    }

    async fn confirm(self: &Rc<Self>, message: &str, detail: &str, accept: &str) -> bool {
        dialogs::confirm(&self.window, message, detail, accept).await
    }

    fn new_chat(self: &Rc<Self>, kind: ConversationKind) {
        let this = self.clone();
        glib::spawn_future_local(async move {
            let (title, text) = match kind {
                ConversationKind::Direct => ("New Chat", "Username of the person to chat with:"),
                ConversationKind::Group => ("New Group", "Usernames of the members, separated by commas:"),
            };
            let Some(answer) = this.prompt(title, text, "").await else { return };
            let names: Vec<String> =
                answer.split(',').map(|n| n.trim().to_lowercase()).filter(|n| !n.is_empty()).collect();
            let this2 = this.clone();
            run(
                with_client!(this.shared, |c| {
                    let mut members = Vec::new();
                    for name in &names {
                        members.push(c.lookup(name).await?.account_id);
                    }
                    c.create_conversation(kind, members, None).await
                }),
                move |result| match result {
                    Ok(conv) => this2.reload_conversations(Some(conv.conversation_id)),
                    Err(err) => {
                        this2.set_status(&format!("Could not create the conversation: {}", friendly_error(&err)))
                    }
                },
            );
        });
    }

    fn add_member(self: &Rc<Self>) {
        let Some(conv) = self.current.borrow().as_ref().map(|c| c.conversation_id) else { return };
        let this = self.clone();
        glib::spawn_future_local(async move {
            let Some(name) = this.prompt("Add Member", "Username of the new member:", "").await else { return };
            let this2 = this.clone();
            run(
                with_client!(this.shared, |c| {
                    let account = c.lookup(&name.to_lowercase()).await?.account_id;
                    c.add_member(conv, account).await
                }),
                move |result| match result {
                    Ok(_) => this2.reload_conversations(Some(conv)),
                    Err(err) => this2.set_status(&friendly_error(&err)),
                },
            );
        });
    }

    fn leave_group(self: &Rc<Self>) {
        let Some(conv) = self.current.borrow().as_ref().map(|c| c.conversation_id) else { return };
        let this = self.clone();
        glib::spawn_future_local(async move {
            if !this.confirm("Leave this group?", "You will no longer see its messages.", "Leave").await {
                return;
            }
            let this2 = this.clone();
            run(
                with_client!(this.shared, |c| {
                    let me = c.account_id().ok_or_else(|| ClientError::Protocol("unknown account".into()))?;
                    c.remove_member(conv, me).await
                }),
                move |result| match result {
                    Ok(_) => this2.reload_conversations(Some(conv)),
                    Err(err) => this2.set_status(&friendly_error(&err)),
                },
            );
        });
    }

    fn change_retention(self: &Rc<Self>) {
        let Some((conv, days)) = self.current.borrow().as_ref().map(|c| (c.conversation_id, c.retention_days)) else {
            return;
        };
        let this = self.clone();
        glib::spawn_future_local(async move {
            let text =
                "Messages are deleted automatically after this many days (1–365).\nAll members will see the change.";
            let Some(answer) = this.prompt("Retention Period", text, &days.to_string()).await else { return };
            let Ok(days) = answer.parse::<u16>() else {
                this.set_status("Please enter a number of days between 1 and 365.");
                return;
            };
            let this2 = this.clone();
            run(with_client!(this.shared, |c| c.set_retention(conv, days).await), move |result| match result {
                Ok(_) => this2.reload_conversations(Some(conv)),
                Err(err) => this2.set_status(&friendly_error(&err)),
            });
        });
    }

    /// The only delete there is: for everyone (FR-007).
    fn delete_selected(self: &Rc<Self>) {
        let Some(row) = self.msg_list.selected_row() else {
            self.set_status("Select a message first.");
            return;
        };
        let Some(Some(message_id)) = self.msg_ids.borrow().get(row.index() as usize).copied() else { return };
        let this = self.clone();
        glib::spawn_future_local(async move {
            let detail = "The message is removed for all participants of this conversation. \
                          Copies someone exported or photographed cannot be recalled.";
            if !this.confirm("Delete this message for everyone?", detail, "Delete for Everyone").await {
                return;
            }
            let this2 = this.clone();
            run(with_client!(this.shared, |c| c.delete_for_all(message_id).await), move |result| match result {
                Ok(_) => this2.reload_current(),
                Err(err) => this2.set_status(&friendly_error(&err)),
            });
        });
    }

    // -------------------------------------------------------------- dev aids

    /// Debug builds only: renders the window to a PNG (used with the
    /// off-screen Broadway backend to check the layout) and quits.
    #[cfg(debug_assertions)]
    pub fn screenshot_after(self: &Rc<Self>, path: PathBuf, delay: Duration) {
        // Weak on purpose: a hook must not keep the App alive by itself.
        let this = Rc::downgrade(self);
        glib::timeout_add_local_once(delay, move || {
            let Some(this) = this.upgrade() else {
                eprintln!("screenshot skipped: App was dropped");
                return;
            };
            // The admin window, if open, is the interesting one.
            let target: gtk::Window = match this.admin_window.borrow().as_ref() {
                Some(admin) if admin.window.is_visible() => admin.window.clone(),
                _ => this.window.clone().upcast(),
            };
            let paintable = gtk::WidgetPaintable::new(Some(&target));
            let (width, height) = (target.width(), target.height());
            let snapshot = gtk::Snapshot::new();
            paintable.snapshot(&snapshot, f64::from(width), f64::from(height));
            if let (Some(node), Some(renderer)) = (snapshot.to_node(), target.renderer()) {
                let texture = renderer.render_texture(node, None);
                if let Err(err) = texture.save_to_png(&path) {
                    eprintln!("screenshot failed: {err}");
                }
            }
            this.app.quit();
        });
    }

    /// Debug builds only: fill the setup form and press Enter, like a user.
    #[cfg(debug_assertions)]
    pub fn dev_fill_setup(self: &Rc<Self>, server: String, code: String) {
        let this = Rc::downgrade(self);
        glib::timeout_add_local_once(Duration::from_secs(1), move || {
            if let Some(this) = this.upgrade() {
                this.server_entry.set_text(&server);
                this.code_entry.set_text(&code);
                this.code_entry.emit_activate();
            }
        });
    }

    /// Debug builds only: open the administration and unlock the admin key.
    #[cfg(debug_assertions)]
    pub fn dev_open_admin(self: &Rc<Self>, dots: Vec<u8>, delay: Duration) {
        let this = Rc::downgrade(self);
        glib::timeout_add_local_once(delay, move || {
            let Some(this) = this.upgrade() else { return };
            this.open_admin();
            if let Some(window) = this.admin_window.borrow().as_ref() {
                let page = std::env::var("SSM_DEV_ADMIN_TAB").ok().and_then(|t| t.parse().ok()).unwrap_or(0);
                window.dev_unlock(&dots, page);
            }
        });
    }

    /// Debug builds only: unlock with a pattern from the environment.
    #[cfg(debug_assertions)]
    pub fn dev_unlock(self: &Rc<Self>, dots: Vec<u8>) {
        if let Ok(pattern) = Pattern::new(dots) {
            let Some(locked) = self.locked.borrow_mut().take() else { return };
            match locked.unlock(&pattern, None) {
                Ok(client) => {
                    rt().block_on(async { self.shared.lock().await.replace(client) });
                    self.after_unlock();
                }
                Err(failed) => {
                    self.locked.replace(Some(*failed.locked));
                }
            }
        }
    }

    #[cfg(debug_assertions)]
    pub fn dev_open_first_conversation(self: &Rc<Self>, delay: Duration) {
        let this = self.clone();
        glib::timeout_add_local_once(delay, move || {
            if let Some(row) = this.conv_list.row_at_index(0) {
                this.conv_list.select_row(Some(&row));
            }
        });
    }
}
