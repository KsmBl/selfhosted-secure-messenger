//! Admin area (ADR-0006): setting up the admin key and the administration
//! window. The admin key has its own pattern; the window only exists while it
//! is unlocked, and every destructive action is signed afresh.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use gtk::glib;
use gtk::prelude::*;
use ssm_client::{AdminClient, AdminKey, ClientError, ClientResult};
use ssm_core::{KdfParams, Pattern};
use ssm_proto::api::{AccountInfo, AdminDeviceInfo, AdminJob, AdminOverview, AuditEvent, DeviceAction, DeviceStatus};

use crate::dialogs;
use crate::pattern_pad::PatternPad;
use crate::runtime::run;

const KDF_TARGET: Duration = Duration::from_secs(3);
const REFRESH_EVERY: u32 = 10;

fn error_text(err: &ClientError) -> String {
    match err.problem_kind() {
        Some("not-found") => "Not found.".into(),
        Some("not-on-self") | Some("operation-refused") | Some("invalid-transition") => match err {
            ClientError::Api { detail: Some(detail), .. } => detail.clone(),
            other => other.to_string(),
        },
        Some("unauthorized") | Some("invalid-signature") => {
            "The server did not accept the admin key (revoked, or the admin role was removed).".into()
        }
        _ if err.is_wrong_pattern() => "Wrong admin pattern.".into(),
        _ => err.to_string(),
    }
}

fn short_time(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

fn padded(child: &impl IsA<gtk::Widget>) -> gtk::Box {
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 8);
    outer.set_margin_top(10);
    outer.set_margin_bottom(10);
    outer.set_margin_start(10);
    outer.set_margin_end(10);
    outer.append(child);
    outer
}

/// A row of fixed-width columns (classic list view look).
fn columns(cells: &[(&str, i32)], bold: bool) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    for (text, width) in cells {
        let label = gtk::Label::builder()
            .label(*text)
            .xalign(0.0)
            .width_chars(*width)
            .max_width_chars(*width)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .build();
        if bold {
            label.add_css_class("sender");
        }
        row.append(&label);
    }
    row
}

// ---------------------------------------------------------------- key setup

/// Asks for a new admin pattern (twice), creates the key and shows the
/// public key to register in the TUI. Calls `done` when a key was created.
pub fn setup_key(parent: &gtk::ApplicationWindow, dir: PathBuf, done: impl Fn() + 'static) {
    let window =
        gtk::Window::builder().title("Set Up Admin Key").transient_for(parent).modal(true).resizable(false).build();
    let pad = PatternPad::new();
    let title = gtk::Label::builder()
        .label(
            "Choose an admin pattern. It protects your admin key and should differ from your chat pattern. \
             You enter it each time you open the administration.",
        )
        .wrap(true)
        .max_width_chars(60)
        .xalign(0.0)
        .build();
    let info = gtk::Label::builder().wrap(true).xalign(0.0).max_width_chars(60).build();
    let next = gtk::Button::with_label("Next >");
    let cancel = gtk::Button::with_label("Cancel");
    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    buttons.set_halign(gtk::Align::End);
    buttons.append(&cancel);
    buttons.append(&next);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
    content.append(&title);
    content.append(&pad.widget);
    content.append(&buttons);
    content.append(&info);
    window.set_child(Some(&padded(&content)));

    let first: Rc<RefCell<Option<Pattern>>> = Rc::default();
    let done = Rc::new(done);
    {
        let window = window.clone();
        cancel.connect_clicked(move |_| window.destroy());
    }
    let parent = parent.clone();
    let window_ref = window.clone();
    next.connect_clicked(move |button| {
        let pattern = match pad.take() {
            Ok(pattern) => pattern,
            Err(err) => {
                info.set_text(&format!("{err}."));
                return;
            }
        };
        let earlier = first.borrow_mut().take();
        match earlier {
            None => {
                first.replace(Some(pattern));
                title.set_text("Repeat the admin pattern to confirm it.");
                info.set_text("");
            }
            Some(earlier) if earlier.encode() != pattern.encode() => {
                title.set_text("The patterns did not match. Choose an admin pattern.");
            }
            Some(_) => {
                button.set_sensitive(false);
                info.set_text("Creating the admin key… (a few seconds)");
                let dir = dir.clone();
                let (window, parent, info, button, done) =
                    (window_ref.clone(), parent.clone(), info.clone(), button.clone(), done.clone());
                run(
                    async move {
                        tokio::task::spawn_blocking(move || -> ClientResult<String> {
                            let params = KdfParams::calibrate(KDF_TARGET)?;
                            Ok(AdminKey::create(&dir, &pattern, params, None)?.public_key())
                        })
                        .await
                        .map_err(|e| ClientError::Protocol(e.to_string()))?
                    },
                    move |result: ClientResult<String>| match result {
                        Ok(public_key) => {
                            window.destroy();
                            done();
                            glib::spawn_future_local(async move {
                                let text = format!(
                                    "Your admin key was created.\n\nPublic key:\n{public_key}\n\n\
                                     Give it to whoever runs the server. They register it with:\n  \
                                     sudo ssm-tui  →  3 (Accounts)  →  select your account  →  k  →  paste\n\n\
                                     Then open Admin → Administration… here."
                                );
                                dialogs::info(&parent, "Admin Key Created", &text, Some(&public_key)).await;
                            });
                        }
                        Err(err) => {
                            button.set_sensitive(true);
                            info.set_text(&error_text(&err));
                        }
                    },
                );
            }
        }
    });
    window.present();
}

// ----------------------------------------------------------- admin window

pub struct AdminWindow {
    pub window: gtk::Window,
    dir: PathBuf,
    server: String,
    stack: gtk::Stack,
    notebook: gtk::Notebook,
    pad: Rc<PatternPad>,
    unlock_info: gtk::Label,
    unlock_button: gtk::Button,
    client: RefCell<Option<Arc<AdminClient>>>,
    status: gtk::Label,
    overview: gtk::Label,
    device_filter: gtk::DropDown,
    device_list: gtk::ListBox,
    devices: RefCell<Vec<AdminDeviceInfo>>,
    account_list: gtk::ListBox,
    accounts: RefCell<Vec<AccountInfo>>,
    job_list: gtk::ListBox,
    audit_list: gtk::ListBox,
}

fn list_page(header: &gtk::Box, list: &gtk::ListBox, toolbar: Option<&gtk::Box>) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 4);
    // Rows have 4px padding (theme); align the header with them.
    header.set_margin_start(4);
    if let Some(toolbar) = toolbar {
        toolbar.add_css_class("toolbar");
        page.append(toolbar);
    }
    let scroll = gtk::ScrolledWindow::builder().child(list).vexpand(true).build();
    scroll.add_css_class("sunken");
    page.append(header);
    page.append(&scroll);
    page
}

fn clear(list: &gtk::ListBox) {
    while let Some(row) = list.row_at_index(0) {
        list.remove(&row);
    }
}

impl AdminWindow {
    pub fn open(parent: &gtk::ApplicationWindow, dir: PathBuf, server: String) -> Rc<Self> {
        let window = gtk::Window::builder()
            .title("Administration")
            .transient_for(parent)
            .default_width(940)
            .default_height(600)
            .build();
        let this = Rc::new(Self {
            window,
            dir,
            server,
            stack: gtk::Stack::new(),
            notebook: gtk::Notebook::new(),
            pad: PatternPad::new(),
            unlock_info: gtk::Label::builder().wrap(true).build(),
            unlock_button: gtk::Button::with_label("Unlock"),
            client: RefCell::new(None),
            status: gtk::Label::builder().xalign(0.0).hexpand(true).build(),
            overview: gtk::Label::builder().xalign(0.0).yalign(0.0).selectable(true).css_classes(["monospace"]).build(),
            device_filter: gtk::DropDown::from_strings(&["All devices", "Waiting for approval", "Active", "Disabled"]),
            device_list: gtk::ListBox::new(),
            devices: RefCell::default(),
            account_list: gtk::ListBox::new(),
            accounts: RefCell::default(),
            job_list: gtk::ListBox::new(),
            audit_list: gtk::ListBox::new(),
        });
        this.build();
        this.window.present();
        this
    }

    fn build(self: &Rc<Self>) {
        // Unlock page.
        let unlock = gtk::Box::new(gtk::Orientation::Vertical, 8);
        unlock.set_halign(gtk::Align::Center);
        unlock.set_valign(gtk::Align::Center);
        unlock.append(&gtk::Label::new(Some("Enter your admin pattern.")));
        unlock.append(&self.pad.widget);
        self.unlock_button.set_halign(gtk::Align::End);
        unlock.append(&self.unlock_button);
        unlock.append(&self.unlock_info);
        self.stack.add_named(&unlock, Some("unlock"));

        // Main page: notebook with five tabs.
        let notebook = &self.notebook;
        notebook.append_page(&padded(&self.overview), Some(&gtk::Label::new(Some("Overview"))));

        let device_bar = gtk::Box::new(gtk::Orientation::Horizontal, 2);
        device_bar.append(&self.device_filter);
        for (label, action) in [
            ("Approve", DeviceAction::Approve),
            ("Reject", DeviceAction::Reject),
            ("Disable", DeviceAction::Disable),
            ("Enable", DeviceAction::Enable),
            ("Revoke", DeviceAction::Revoke),
        ] {
            let button = gtk::Button::with_label(label);
            let this = Rc::downgrade(self);
            button.connect_clicked(move |_| {
                if let Some(this) = this.upgrade() {
                    this.device_action(action);
                }
            });
            device_bar.append(&button);
        }
        let device_header =
            columns(&[("User", 14), ("Device", 20), ("Status", 9), ("Registered", 16), ("Fingerprint", 30)], true);
        notebook.append_page(
            &list_page(&device_header, &self.device_list, Some(&device_bar)),
            Some(&gtk::Label::new(Some("Devices"))),
        );

        let account_bar = gtk::Box::new(gtk::Orientation::Horizontal, 2);
        type AccountOp = fn(&Rc<AdminWindow>);
        let ops: [(&str, AccountOp); 7] = [
            ("New Account…", |w| w.new_account()),
            ("New Invite", |w| w.new_invite()),
            ("Admin On/Off", |w| w.toggle_admin()),
            ("Admin Key…", |w| w.register_key()),
            ("Lock/Unlock", |w| w.toggle_lock()),
            ("Delete Messages…", |w| w.delete_content()),
            ("Delete Account…", |w| w.delete_account()),
        ];
        for (label, op) in ops {
            let button = gtk::Button::with_label(label);
            let this = Rc::downgrade(self);
            button.connect_clicked(move |_| {
                if let Some(this) = this.upgrade() {
                    op(&this);
                }
            });
            account_bar.append(&button);
        }
        let account_header = columns(
            &[("User", 16), ("Role", 6), ("Status", 9), ("Devices", 7), ("Messages", 9), ("Created", 16)],
            true,
        );
        notebook.append_page(
            &list_page(&account_header, &self.account_list, Some(&account_bar)),
            Some(&gtk::Label::new(Some("Accounts"))),
        );

        let job_header = columns(&[("Scope", 28), ("Status", 20), ("Msgs", 5), ("Started", 16)], true);
        notebook
            .append_page(&list_page(&job_header, &self.job_list, None), Some(&gtk::Label::new(Some("Delete Jobs"))));
        let audit_header = columns(&[("Time", 16), ("Action", 26), ("Target", 28), ("Result", 30)], true);
        notebook
            .append_page(&list_page(&audit_header, &self.audit_list, None), Some(&gtk::Label::new(Some("Audit Log"))));

        let refresh = gtk::Button::with_label("Refresh");
        let bottom = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        bottom.add_css_class("statusbar");
        self.status.add_css_class("panel");
        bottom.append(&self.status);
        bottom.append(&refresh);
        let main = gtk::Box::new(gtk::Orientation::Vertical, 0);
        notebook.set_vexpand(true);
        main.append(&padded(notebook));
        main.append(&bottom);
        self.stack.add_named(&main, Some("main"));
        self.window.set_child(Some(&self.stack));

        let this = Rc::downgrade(self);
        self.unlock_button.connect_clicked(move |_| {
            if let Some(this) = this.upgrade() {
                this.unlock();
            }
        });
        let this = Rc::downgrade(self);
        refresh.connect_clicked(move |_| {
            if let Some(this) = this.upgrade() {
                this.refresh();
            }
        });
        let this = Rc::downgrade(self);
        self.device_filter.connect_selected_notify(move |_| {
            if let Some(this) = this.upgrade() {
                this.refresh();
            }
        });
        // Closing the window drops the admin client and with it the key.
        let this = Rc::downgrade(self);
        self.window.connect_close_request(move |_| {
            if let Some(this) = this.upgrade() {
                this.client.replace(None);
            }
            glib::Propagation::Proceed
        });
        let this = Rc::downgrade(self);
        glib::timeout_add_seconds_local(REFRESH_EVERY, move || {
            let Some(this) = this.upgrade() else { return glib::ControlFlow::Break };
            if !this.window.is_visible() {
                return glib::ControlFlow::Break;
            }
            if this.client.borrow().is_some() {
                this.refresh();
            }
            glib::ControlFlow::Continue
        });
    }

    /// Debug builds only: unlock with a pattern and show tab `page`.
    #[cfg(debug_assertions)]
    pub fn dev_unlock(self: &Rc<Self>, dots: &[u8], page: u32) {
        self.pad.set(dots);
        self.unlock();
        self.notebook.set_current_page(Some(page));
    }

    pub fn close(&self) {
        self.client.replace(None);
        self.window.destroy();
    }

    fn unlock(self: &Rc<Self>) {
        let pattern = match self.pad.take() {
            Ok(pattern) => pattern,
            Err(err) => {
                self.unlock_info.set_text(&format!("{err}."));
                return;
            }
        };
        self.unlock_button.set_sensitive(false);
        self.unlock_info.set_text("Unlocking the admin key and signing in…");
        let (dir, server) = (self.dir.clone(), self.server.clone());
        let this = self.clone();
        run(
            async move {
                let key = match tokio::task::spawn_blocking(move || AdminKey::open(&dir, &pattern, None)).await {
                    Ok(Ok(key)) => key,
                    Ok(Err(err)) => return Err((err, None)),
                    Err(err) => return Err((ClientError::Protocol(err.to_string()), None)),
                };
                // Kept for the "not registered yet" message.
                let public_key = key.public_key();
                AdminClient::connect(&server, key).await.map_err(|e| (e, Some(public_key)))
            },
            move |result: Result<AdminClient, (ClientError, Option<String>)>| {
                this.unlock_button.set_sensitive(true);
                match result {
                    Ok(client) => {
                        this.client.replace(Some(Arc::new(client)));
                        this.stack.set_visible_child_name("main");
                        this.refresh();
                    }
                    Err((err, Some(public_key))) if err.problem_kind() == Some("not-found") => {
                        this.unlock_info.set_text("");
                        let parent = this.window.clone();
                        glib::spawn_future_local(async move {
                            let text = format!(
                                "Your admin key is not registered on the server yet.\n\nPublic key:\n{public_key}\n\n\
                                 Register it with:  sudo ssm-tui  →  3 (Accounts)  →  select your account  →  k"
                            );
                            dialogs::info(&parent, "Admin Key Not Registered", &text, Some(&public_key)).await;
                        });
                    }
                    Err((err, _)) => this.unlock_info.set_text(&error_text(&err)),
                }
            },
        );
    }

    fn client(&self) -> Option<Arc<AdminClient>> {
        self.client.borrow().clone()
    }

    fn refresh(self: &Rc<Self>) {
        let Some(client) = self.client() else { return };
        let filter = match self.device_filter.selected() {
            1 => Some(DeviceStatus::Pending),
            2 => Some(DeviceStatus::Active),
            3 => Some(DeviceStatus::Disabled),
            _ => None,
        };
        let this = self.clone();
        run(
            async move {
                Ok::<_, ClientError>((
                    client.overview().await?,
                    client.devices(filter).await?,
                    client.accounts().await?,
                    client.jobs().await?,
                    client.audit().await?,
                ))
            },
            move |result| match result {
                Ok((overview, devices, accounts, jobs, audit)) => {
                    this.show_overview(&overview);
                    this.show_devices(devices);
                    this.show_accounts(accounts);
                    this.show_jobs(&jobs);
                    this.show_audit(&audit);
                    this.status.set_text(&format!("Connected to {}", this.server));
                }
                Err(err) => this.status.set_text(&error_text(&err)),
            },
        );
    }

    fn show_overview(&self, o: &AdminOverview) {
        let audit = match o.audit_broken_at {
            None => "intact".to_owned(),
            Some(id) => format!("BROKEN at entry {id} – the log was modified!"),
        };
        self.overview.set_text(&format!(
            "Accounts:                       {} ({} admin)\n\
             Devices waiting for approval:   {}\n\
             Active devices:                 {}\n\
             Disabled devices:               {}\n\n\
             Conversations:                  {}\n\
             Stored messages (encrypted):    {}\n\
             Delete jobs running:            {}\n\n\
             Audit log entries:              {}\n\
             Audit log integrity:            {audit}\n\n\
             Admins cannot read messages: the server only stores encrypted content.",
            o.accounts,
            o.admins,
            o.devices_pending,
            o.devices_active,
            o.devices_disabled,
            o.conversations,
            o.messages,
            o.jobs_running,
            o.audit_entries,
        ));
    }

    fn show_devices(&self, devices: Vec<AdminDeviceInfo>) {
        let selected = self.device_list.selected_row().map(|r| r.index());
        clear(&self.device_list);
        for d in &devices {
            self.device_list.append(&columns(
                &[
                    (&d.username, 14),
                    (&d.display_name, 20),
                    (d.status.as_str(), 9),
                    (&short_time(&d.created_at), 16),
                    (&ssm_proto::B64::encode(&d.olm_fingerprint_key.0), 30),
                ],
                false,
            ));
        }
        self.devices.replace(devices);
        if let Some(row) = selected.and_then(|i| self.device_list.row_at_index(i)) {
            self.device_list.select_row(Some(&row));
        }
    }

    fn show_accounts(&self, accounts: Vec<AccountInfo>) {
        let selected = self.account_list.selected_row().map(|r| r.index());
        clear(&self.account_list);
        for a in &accounts {
            self.account_list.append(&columns(
                &[
                    (&a.username, 16),
                    (&a.role, 6),
                    (&a.status, 9),
                    (&a.active_devices.to_string(), 7),
                    (&a.messages.to_string(), 9),
                    (&short_time(&a.created_at), 16),
                ],
                false,
            ));
        }
        self.accounts.replace(accounts);
        if let Some(row) = selected.and_then(|i| self.account_list.row_at_index(i)) {
            self.account_list.select_row(Some(&row));
        }
    }

    fn show_jobs(&self, jobs: &[AdminJob]) {
        clear(&self.job_list);
        for j in jobs {
            self.job_list.append(&columns(
                &[
                    (&j.scope, 28),
                    (j.status.as_str(), 20),
                    (&j.affected_messages.to_string(), 5),
                    (&short_time(&j.created_at), 16),
                ],
                false,
            ));
        }
    }

    fn show_audit(&self, audit: &[AuditEvent]) {
        clear(&self.audit_list);
        for e in audit {
            self.audit_list.append(&columns(
                &[(&short_time(&e.created_at), 16), (&e.action, 26), (&e.target_label, 28), (&e.result, 30)],
                false,
            ));
        }
    }

    fn selected_device(&self) -> Option<AdminDeviceInfo> {
        let row = self.device_list.selected_row()?;
        self.devices.borrow().get(row.index() as usize).cloned()
    }

    fn selected_account(&self) -> Option<AccountInfo> {
        let row = self.account_list.selected_row()?;
        self.accounts.borrow().get(row.index() as usize).cloned()
    }

    /// Runs an admin operation, shows its message (in a box if it has
    /// several lines) and refreshes.
    fn perform<F, Fut>(self: &Rc<Self>, op: F)
    where
        F: FnOnce(Arc<AdminClient>) -> Fut,
        Fut: std::future::Future<Output = ClientResult<String>> + Send + 'static,
    {
        let Some(client) = self.client() else { return };
        self.status.set_text("Working…");
        let this = self.clone();
        run(op(client), move |result| {
            match result {
                Ok(message) if message.contains('\n') => {
                    this.status.set_text("Done.");
                    let parent = this.window.clone();
                    let copy = message.lines().find_map(|l| l.strip_prefix("Invite code: ")).map(str::to_owned);
                    glib::spawn_future_local(async move {
                        dialogs::info(&parent, "Done", &message, copy.as_deref()).await;
                    });
                }
                Ok(message) => this.status.set_text(&message),
                Err(err) => this.status.set_text(&error_text(&err)),
            }
            this.refresh();
        });
    }

    fn device_action(self: &Rc<Self>, action: DeviceAction) {
        let Some(device) = self.selected_device() else {
            self.status.set_text("Select a device first.");
            return;
        };
        let this = self.clone();
        glib::spawn_future_local(async move {
            if matches!(action, DeviceAction::Revoke | DeviceAction::Reject) {
                let question = format!(
                    "{} the device '{}' of {}?",
                    capitalize(action.as_str()),
                    device.display_name,
                    device.username
                );
                let detail =
                    "The device is deleted completely and has to register again. Messages it sent stay readable.";
                if !dialogs::confirm(&this.window, &question, detail, capitalize(action.as_str()).as_str()).await {
                    return;
                }
            }
            this.perform(move |client| async move {
                let info = client.device_action(device.device_id, action).await?;
                Ok(format!("Device '{}' of {}: {}.", info.display_name, info.username, info.status.as_str()))
            });
        });
    }

    fn new_account(self: &Rc<Self>) {
        let this = self.clone();
        glib::spawn_future_local(async move {
            let Some(name) = dialogs::prompt(&this.window, "New Account", "Username (a-z, 0-9, _ . -):", "").await
            else {
                return;
            };
            this.perform(move |client| async move {
                let invite = client.create_account(&name.to_lowercase()).await?;
                Ok(format!(
                    "Account '{name}' created.\n\nInvite code: {}\nValid until: {}",
                    invite.invite_code,
                    short_time(&invite.expires_at)
                ))
            });
        });
    }

    fn new_invite(self: &Rc<Self>) {
        let Some(account) = self.selected_account() else { return };
        self.perform(move |client| async move {
            let invite = client.new_invite(account.account_id).await?;
            Ok(format!(
                "New invite for '{}' (older unused codes are invalid now).\n\nInvite code: {}\nValid until: {}",
                account.username,
                invite.invite_code,
                short_time(&invite.expires_at)
            ))
        });
    }

    fn toggle_admin(self: &Rc<Self>) {
        let Some(account) = self.selected_account() else { return };
        let grant = account.role != "admin";
        let this = self.clone();
        glib::spawn_future_local(async move {
            let question = if grant {
                format!("Make {} a server admin?", account.username)
            } else {
                format!("Remove the admin role from {}?", account.username)
            };
            if !dialogs::confirm(&this.window, &question, "This is written to the audit log.", "Yes").await {
                return;
            }
            this.perform(move |client| async move { client.set_admin_role(account.account_id, grant).await });
        });
    }

    fn register_key(self: &Rc<Self>) {
        let Some(account) = self.selected_account() else { return };
        let this = self.clone();
        glib::spawn_future_local(async move {
            let text =
                format!("Public admin key for {} (they create it under Admin → Set Up Admin Key…):", account.username);
            let Some(key) = dialogs::prompt(&this.window, "Register Admin Key", &text, "").await else { return };
            this.perform(move |client| async move { client.add_admin_key(account.account_id, &key).await });
        });
    }

    fn toggle_lock(self: &Rc<Self>) {
        let Some(account) = self.selected_account() else { return };
        let lock = account.status == "active";
        let this = self.clone();
        glib::spawn_future_local(async move {
            let (question, detail) = if lock {
                (
                    format!("Lock the account {}?", account.username),
                    "All its devices are signed out until you unlock it.",
                )
            } else {
                (format!("Unlock the account {}?", account.username), "Its devices can sign in again.")
            };
            if !dialogs::confirm(&this.window, &question, detail, if lock { "Lock" } else { "Unlock" }).await {
                return;
            }
            this.perform(move |client| async move { client.set_account_locked(account.account_id, lock).await });
        });
    }

    /// Asks to type the username, so nothing is deleted by a slip.
    async fn typed_confirmation(self: &Rc<Self>, title: &str, text: &str, username: &str) -> bool {
        let text = format!("{text}\n\nThis cannot be undone. Type the username to confirm:");
        match dialogs::prompt(&self.window, title, &text, "").await {
            Some(typed) if typed == username => true,
            Some(_) => {
                self.status.set_text("Name did not match – nothing was deleted.");
                false
            }
            None => false,
        }
    }

    fn delete_content(self: &Rc<Self>) {
        let Some(account) = self.selected_account() else { return };
        let this = self.clone();
        glib::spawn_future_local(async move {
            let text = format!(
                "Delete all {} messages sent by {} for everyone, in all conversations. Messages of other people stay.",
                account.messages, account.username
            );
            if !this.typed_confirmation("Delete All Messages", &text, &account.username).await {
                return;
            }
            this.perform(move |client| async move {
                client.delete_all_content(account.account_id).await?;
                Ok("Deletion started; progress is shown under Delete Jobs.".into())
            });
        });
    }

    fn delete_account(self: &Rc<Self>) {
        let Some(account) = self.selected_account() else { return };
        let this = self.clone();
        glib::spawn_future_local(async move {
            let text = format!(
                "Delete the account {} completely: its {} messages are deleted for everyone, it leaves all \
                 conversations, its devices and keys are deleted and the username becomes free again.",
                account.username, account.messages
            );
            if !this.typed_confirmation("Delete Account", &text, &account.username).await {
                return;
            }
            this.perform(move |client| async move { client.delete_account(account.account_id).await });
        });
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}
