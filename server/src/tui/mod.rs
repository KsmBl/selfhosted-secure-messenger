//! `ssm-server tui`: terminal management for the server host.
//!
//! Tabs: Overview, Devices, Accounts, Delete Jobs, Audit. Changes go straight
//! to the database (audited) and are forwarded to the running server, so
//! revoked devices are disconnected and members are woken up immediately.

pub mod data;

use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap};
use ssm_proto::api::{DeviceAction, DeviceStatus};
use uuid::Uuid;

use self::data::{AccountRow, AuditRow, DataResult, DeviceRow, JobRow, Stats};
use crate::AppState;

const REFRESH_EVERY: Duration = Duration::from_secs(3);
const TABS: [&str; 5] = ["1 Overview", "2 Devices", "3 Accounts", "4 Delete Jobs", "5 Audit"];
// Revoked and rejected devices are deleted, so they never show up.
const DEVICE_FILTERS: [Option<DeviceStatus>; 4] =
    [None, Some(DeviceStatus::Pending), Some(DeviceStatus::Active), Some(DeviceStatus::Disabled)];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Devices,
    Accounts,
    Jobs,
    Audit,
}

impl Tab {
    const ALL: [Tab; 5] = [Tab::Overview, Tab::Devices, Tab::Accounts, Tab::Jobs, Tab::Audit];

    fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

enum Pending {
    Device(Uuid, DeviceAction),
    AccountStatus(Uuid, bool),
    Admin(Uuid, bool),
    Invite(Uuid, String),
}

enum Mode {
    Normal,
    /// y/n question.
    Confirm {
        question: String,
        action: Pending,
    },
    /// Text input; `purpose` decides what happens on Enter.
    Input {
        prompt: String,
        buffer: String,
        purpose: InputPurpose,
    },
    /// Message box, closed with any key.
    Info {
        title: String,
        text: String,
    },
}

enum InputPurpose {
    NewAccount,
    /// The admin has to type the username to confirm the mass deletion.
    ConfirmMassDelete {
        account_id: Uuid,
        username: String,
    },
    /// Same for deleting the whole account.
    ConfirmDeleteAccount {
        account_id: Uuid,
        username: String,
    },
}

struct Tui {
    state: AppState,
    tab: Tab,
    mode: Mode,
    message: (String, bool),
    stats: Stats,
    audit_check: Option<DataResult<String>>,
    devices: Vec<DeviceRow>,
    device_filter: usize,
    accounts: Vec<AccountRow>,
    jobs: Vec<JobRow>,
    audit: Vec<AuditRow>,
    selection: [TableState; 5],
    last_refresh: Instant,
    quit: bool,
}

pub async fn run(state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    let mut tui = Tui::new(state);
    tui.refresh().await;
    tui.audit_check = Some(data::verify_audit(&tui.state).await);

    let mut terminal = ratatui::init();
    let result = tui.event_loop(&mut terminal).await;
    ratatui::restore();
    result
}

/// Renders one tab (0-4) into plain text, for tests and documentation.
pub async fn snapshot(state: AppState, tab: usize, width: u16, height: u16) -> String {
    let mut tui = Tui::new(state);
    tui.refresh().await;
    tui.audit_check = Some(data::verify_audit(&tui.state).await);
    tui.tab = Tab::ALL[tab.min(4)];
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).expect("test backend");
    terminal.draw(|frame| tui.draw(frame)).expect("draw");
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>().trim_end().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

impl Tui {
    fn new(state: AppState) -> Self {
        Self {
            state,
            tab: Tab::Overview,
            mode: Mode::Normal,
            message: ("Press ? for help.".into(), false),
            stats: Stats::default(),
            audit_check: None,
            devices: Vec::new(),
            device_filter: 0,
            accounts: Vec::new(),
            jobs: Vec::new(),
            audit: Vec::new(),
            selection: Default::default(),
            last_refresh: Instant::now(),
            quit: false,
        }
    }

    async fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> Result<(), Box<dyn std::error::Error>> {
        while !self.quit {
            terminal.draw(|frame| self.draw(frame))?;
            if event::poll(Duration::from_millis(250))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.on_key(key).await;
            }
            if self.last_refresh.elapsed() >= REFRESH_EVERY && matches!(self.mode, Mode::Normal) {
                self.refresh().await;
            }
        }
        Ok(())
    }

    fn say(&mut self, result: DataResult<String>) {
        self.message = match result {
            Ok(text) => (text, false),
            Err(text) => (text, true),
        };
    }

    async fn refresh(&mut self) {
        let state = &self.state;
        let loaded = async {
            Ok::<_, String>((
                data::stats(state).await?,
                data::devices(state, DEVICE_FILTERS[self.device_filter]).await?,
                data::accounts(state).await?,
                data::jobs(state).await?,
                data::audit(state).await?,
            ))
        }
        .await;
        match loaded {
            Ok((stats, devices, accounts, jobs, audit)) => {
                self.stats = stats;
                self.devices = devices;
                self.accounts = accounts;
                self.jobs = jobs;
                self.audit = audit;
            }
            Err(err) => self.message = (err, true),
        }
        let lengths = [0, self.devices.len(), self.accounts.len(), self.jobs.len(), self.audit.len()];
        for (state, len) in self.selection.iter_mut().zip(lengths) {
            match (state.selected(), len) {
                (_, 0) => state.select(None),
                (None, _) => state.select(Some(0)),
                (Some(i), len) if i >= len => state.select(Some(len - 1)),
                _ => {}
            }
        }
        self.last_refresh = Instant::now();
    }

    fn selected(&self) -> Option<usize> {
        self.selection[self.tab.index()].selected()
    }

    // ------------------------------------------------------------- input

    async fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Normal => self.on_normal_key(key).await,
            Mode::Info { .. } => {}
            Mode::Confirm { question, action } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('j') => {
                    let result = self.execute(action).await;
                    self.after_action(result).await;
                }
                KeyCode::Char('n') | KeyCode::Esc => self.message = ("Cancelled.".into(), false),
                _ => self.mode = Mode::Confirm { question, action },
            },
            Mode::Input { prompt, mut buffer, purpose } => match key.code {
                KeyCode::Esc => self.message = ("Cancelled.".into(), false),
                KeyCode::Enter => self.submit_input(buffer.trim().to_owned(), purpose).await,
                KeyCode::Backspace => {
                    buffer.pop();
                    self.mode = Mode::Input { prompt, buffer, purpose };
                }
                KeyCode::Char(c) if buffer.len() < 64 => {
                    buffer.push(c);
                    self.mode = Mode::Input { prompt, buffer, purpose };
                }
                _ => self.mode = Mode::Input { prompt, buffer, purpose },
            },
        }
    }

    async fn after_action(&mut self, result: DataResult<String>) {
        // Results with several lines (invite codes) go into a message box.
        match result {
            Ok(text) if text.contains('\n') => self.mode = Mode::Info { title: "Done".into(), text },
            other => self.say(other),
        }
        self.refresh().await;
    }

    async fn submit_input(&mut self, value: String, purpose: InputPurpose) {
        match purpose {
            InputPurpose::NewAccount => {
                let result = data::create_account(&self.state, &value.to_lowercase()).await;
                self.after_action(result).await;
            }
            InputPurpose::ConfirmMassDelete { account_id, username } => {
                if value != username {
                    self.message = ("Name did not match – nothing was deleted.".into(), true);
                    return;
                }
                let result = data::start_mass_delete(&self.state, account_id).await;
                self.after_action(result).await;
                self.tab = Tab::Jobs;
            }
            InputPurpose::ConfirmDeleteAccount { account_id, username } => {
                if value != username {
                    self.message = ("Name did not match – nothing was deleted.".into(), true);
                    return;
                }
                let result = data::delete_account(&self.state, account_id).await;
                self.after_action(result).await;
            }
        }
    }

    async fn execute(&mut self, action: Pending) -> DataResult<String> {
        match action {
            Pending::Device(id, action) => data::device_action(&self.state, id, action).await,
            Pending::AccountStatus(id, disable) => data::set_account_status(&self.state, id, disable).await,
            Pending::Admin(id, admin) => data::set_admin(&self.state, id, admin).await,
            Pending::Invite(id, username) => data::new_invite(&self.state, id, &username).await,
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let len = match self.tab {
            Tab::Overview => 0,
            Tab::Devices => self.devices.len(),
            Tab::Accounts => self.accounts.len(),
            Tab::Jobs => self.jobs.len(),
            Tab::Audit => self.audit.len(),
        };
        if len == 0 {
            return;
        }
        let state = &mut self.selection[self.tab.index()];
        let current = state.selected().unwrap_or(0) as isize;
        state.select(Some((current + delta).clamp(0, len as isize - 1) as usize));
    }

    async fn on_normal_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') | KeyCode::F(1) => {
                self.mode = Mode::Info { title: "Keys".into(), text: HELP.into() };
            }
            KeyCode::Tab | KeyCode::Right => self.tab = Tab::ALL[(self.tab.index() + 1) % 5],
            KeyCode::BackTab | KeyCode::Left => self.tab = Tab::ALL[(self.tab.index() + 4) % 5],
            KeyCode::Char(c @ '1'..='5') => self.tab = Tab::ALL[c as usize - '1' as usize],
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(15),
            KeyCode::PageUp => self.move_selection(-15),
            KeyCode::Char('R') | KeyCode::F(5) => {
                self.refresh().await;
                self.message = ("Refreshed.".into(), false);
            }
            _ => match self.tab {
                Tab::Devices => self.on_device_key(key.code),
                Tab::Accounts => self.on_account_key(key.code),
                Tab::Audit if key.code == KeyCode::Char('v') => {
                    let check = data::verify_audit(&self.state).await;
                    self.say(check.clone());
                    self.audit_check = Some(check);
                }
                _ => {}
            },
        }
    }

    fn on_device_key(&mut self, code: KeyCode) {
        if code == KeyCode::Char('f') {
            self.device_filter = (self.device_filter + 1) % DEVICE_FILTERS.len();
            self.last_refresh = Instant::now() - REFRESH_EVERY;
            self.selection[Tab::Devices.index()].select(Some(0));
            return;
        }
        let action = match code {
            KeyCode::Char('a') => DeviceAction::Approve,
            KeyCode::Char('r') => DeviceAction::Reject,
            KeyCode::Char('d') => DeviceAction::Disable,
            KeyCode::Char('e') => DeviceAction::Enable,
            KeyCode::Char('x') | KeyCode::Delete => DeviceAction::Revoke,
            _ => return,
        };
        let Some(device) = self.selected().and_then(|i| self.devices.get(i)) else { return };
        let mut question = format!(
            "{} device '{}' of {}?\nFingerprint: {}",
            capitalize(action.as_str()),
            device.name,
            device.username,
            device.fingerprint
        );
        if matches!(action, DeviceAction::Revoke | DeviceAction::Reject) {
            question.push_str("\n\nThe device is deleted completely and has to register again.");
        }
        self.mode = Mode::Confirm { question, action: Pending::Device(device.id, action) };
    }

    fn on_account_key(&mut self, code: KeyCode) {
        if code == KeyCode::Char('n') {
            self.mode = Mode::Input {
                prompt: "Username for the new account (a-z, 0-9, _ . -):".into(),
                buffer: String::new(),
                purpose: InputPurpose::NewAccount,
            };
            return;
        }
        let Some(account) = self.selected().and_then(|i| self.accounts.get(i)).cloned() else { return };
        match code {
            KeyCode::Char('i') => {
                self.mode = Mode::Confirm {
                    question: format!("Create a new invite code for '{}'?", account.username),
                    action: Pending::Invite(account.id, account.username),
                };
            }
            KeyCode::Char('d') | KeyCode::Char('e') => {
                let disable = code == KeyCode::Char('d');
                let question = if disable {
                    format!("Disable account '{}'? All its devices are signed out.", account.username)
                } else {
                    format!("Enable account '{}' again?", account.username)
                };
                self.mode = Mode::Confirm { question, action: Pending::AccountStatus(account.id, disable) };
            }
            KeyCode::Char('a') => {
                let admin = account.role != "admin";
                let question = if admin {
                    format!("Make '{}' a server admin?", account.username)
                } else {
                    format!("Remove the admin role from '{}'? Its admin keys are revoked.", account.username)
                };
                self.mode = Mode::Confirm { question, action: Pending::Admin(account.id, admin) };
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                self.mode = Mode::Input {
                    prompt: format!(
                        "Delete the account '{}' completely:\n\
                         - all {} of its messages are deleted for everyone\n\
                         - it leaves all groups, its devices and keys are deleted\n\
                         - the username becomes free again\n\
                         This cannot be undone.\n\n\
                         Type the username to confirm:",
                        account.username, account.messages
                    ),
                    buffer: String::new(),
                    purpose: InputPurpose::ConfirmDeleteAccount { account_id: account.id, username: account.username },
                };
            }
            KeyCode::Char('m') => {
                self.mode = Mode::Input {
                    prompt: format!(
                        "Delete ALL {} messages sent by '{}' for everyone, in all conversations.\n\
                         Messages of other people stay. This cannot be undone.\n\n\
                         Type the username to confirm:",
                        account.messages, account.username
                    ),
                    buffer: String::new(),
                    purpose: InputPurpose::ConfirmMassDelete { account_id: account.id, username: account.username },
                };
            }
            _ => {}
        }
    }

    // ----------------------------------------------------------- drawing

    fn draw(&mut self, frame: &mut Frame) {
        let [header, tabs, body, footer] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Min(5), Constraint::Length(2)])
                .areas(frame.area());

        let pending = self.stats.devices_pending;
        let mut title = vec![Span::from(" Secure Messenger Server ").bold().reversed()];
        if pending > 0 {
            title.push(Span::from(format!("  {pending} device(s) waiting for approval ")).yellow().bold());
        }
        frame.render_widget(Line::from(title), header);
        frame.render_widget(
            Tabs::new(TABS).select(self.tab.index()).highlight_style(Style::new().bold().reversed()).divider("│"),
            tabs,
        );

        match self.tab {
            Tab::Overview => self.draw_overview(frame, body),
            Tab::Devices => self.draw_devices(frame, body),
            Tab::Accounts => self.draw_accounts(frame, body),
            Tab::Jobs => self.draw_jobs(frame, body),
            Tab::Audit => self.draw_audit(frame, body),
        }

        let [message, keys] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(footer);
        let style = if self.message.1 { Style::new().red().bold() } else { Style::new().green() };
        frame.render_widget(Line::styled(format!(" {}", self.message.0), style), message);
        frame.render_widget(Line::from(format!(" {}", self.key_hint())).dark_gray(), keys);

        match &self.mode {
            Mode::Normal => {}
            Mode::Info { title, text } => popup(frame, title, text, "any key: close"),
            Mode::Confirm { question, .. } => popup(frame, "Confirm", question, "y: yes   n/Esc: no"),
            Mode::Input { prompt, buffer, .. } => {
                popup(frame, "Input", &format!("{prompt}\n\n> {buffer}█"), "Enter: OK   Esc: cancel")
            }
        }
    }

    fn key_hint(&self) -> &'static str {
        match self.tab {
            // Must fit into 80 columns.
            Tab::Overview => "Tab/1-5 switch  R refresh  ? help  q quit",
            Tab::Devices => "a approve r reject d disable e enable x/Del revoke f filter ? help q quit",
            Tab::Accounts => "n new i invite a admin d/e disable/enable m del msgs x/Del DELETE ? q",
            Tab::Jobs => "↑↓ select  R refresh  ? help  q quit",
            Tab::Audit => "v verify hash chain  ↑↓ select  ? help  q quit",
        }
    }

    fn draw_overview(&self, frame: &mut Frame, area: Rect) {
        let s = &self.stats;
        let audit = match &self.audit_check {
            Some(Ok(text)) => Span::from(text.clone()).green(),
            Some(Err(text)) => Span::from(text.clone()).red().bold(),
            None => Span::from("not checked"),
        };
        let line = |label: &str, value: String| {
            Line::from(vec![Span::from(format!("  {label:<31}")), Span::from(value).bold()])
        };
        let mut lines = vec![
            Line::from(""),
            line("Accounts", format!("{} ({} admin)", s.accounts, s.admins)),
            line("Devices waiting for approval", s.devices_pending.to_string()),
            line("Active devices", s.devices_active.to_string()),
            line("Disabled devices", s.devices_disabled.to_string()),
            Line::from(""),
            line("Conversations", s.conversations.to_string()),
            line("Stored messages (encrypted)", s.messages.to_string()),
            line("Delete jobs running", s.jobs_running.to_string()),
            line("Waiting for backup rotation", s.jobs_backup_pending.to_string()),
            Line::from(""),
            line("Audit log entries", s.audit_entries.to_string()),
            Line::from(vec![Span::from(format!("  {:<31}", "Audit log integrity")), audit]),
            Line::from(""),
            Line::from("  The server never sees message content; admins cannot read messages.").dark_gray(),
        ];
        if s.devices_pending > 0 {
            lines.insert(0, Line::from("  → Switch to Devices (2) to approve waiting devices.").yellow());
        }
        frame.render_widget(Paragraph::new(lines).block(boxed("Overview")), area);
    }

    fn draw_devices(&mut self, frame: &mut Frame, area: Rect) {
        let filter = DEVICE_FILTERS[self.device_filter].map(DeviceStatus::as_str).unwrap_or("all");
        let rows = self.devices.iter().map(|d| {
            let status = Cell::from(d.status.as_str()).style(status_style(d.status.as_str()));
            Row::new(vec![
                Cell::from(d.username.clone()),
                Cell::from(d.name.clone()),
                status,
                Cell::from(d.created.clone()),
                Cell::from(d.fingerprint.clone()),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Length(22),
                Constraint::Length(10),
                Constraint::Length(17),
                Constraint::Min(20),
            ],
        )
        .header(header(["User", "Device", "Status", "Registered", "Fingerprint"]))
        .block(boxed(&format!("Devices (filter: {filter})")))
        .row_highlight_style(highlight())
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, area, &mut self.selection[Tab::Devices.index()]);
    }

    fn draw_accounts(&mut self, frame: &mut Frame, area: Rect) {
        let rows = self.accounts.iter().map(|a| {
            Row::new(vec![
                Cell::from(a.username.clone()),
                Cell::from(a.role.clone()),
                Cell::from(a.status.clone()).style(status_style(&a.status)),
                Cell::from(a.active_devices.to_string()),
                Cell::from(a.messages.to_string()),
                Cell::from(a.created.clone()),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(20),
                Constraint::Length(7),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Min(17),
            ],
        )
        .header(header(["User", "Role", "Status", "Devices", "Messages", "Created"]))
        .block(boxed("Accounts"))
        .row_highlight_style(highlight())
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, area, &mut self.selection[Tab::Accounts.index()]);
    }

    fn draw_jobs(&mut self, frame: &mut Frame, area: Rect) {
        let rows = self.jobs.iter().map(|j| {
            let id = j.id.to_string();
            Row::new(vec![
                Cell::from(id[..8].to_owned()),
                Cell::from(j.scope.clone()),
                Cell::from(j.status.clone()).style(status_style(&j.status)),
                Cell::from(j.affected.to_string()),
                Cell::from(j.created.clone()),
                Cell::from(j.backup_due.clone()),
                Cell::from(j.error.clone()).red(),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Length(30),
                Constraint::Length(21),
                Constraint::Length(8),
                Constraint::Length(17),
                Constraint::Length(17),
                Constraint::Min(10),
            ],
        )
        .header(header(["Job", "Scope", "Status", "Msgs", "Started", "Backups clean", "Error"]))
        .block(boxed("Delete Jobs"))
        .row_highlight_style(highlight());
        frame.render_stateful_widget(table, area, &mut self.selection[Tab::Jobs.index()]);
    }

    fn draw_audit(&mut self, frame: &mut Frame, area: Rect) {
        let rows = self.audit.iter().map(|a| {
            let result = Cell::from(a.result.clone());
            let result = if a.result.starts_with("ok") || a.result.starts_with("started") {
                result
            } else {
                result.style(Style::new().fg(Color::Red))
            };
            Row::new(vec![
                Cell::from(a.id.to_string()),
                Cell::from(a.time.clone()),
                Cell::from(a.action.clone()),
                Cell::from(a.target.clone()),
                result,
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(17),
                Constraint::Length(36),
                Constraint::Length(46),
                Constraint::Min(10),
            ],
        )
        .header(header(["#", "Time", "Action", "Target", "Result"]))
        .block(boxed("Audit Log (newest first)"))
        .row_highlight_style(highlight());
        frame.render_stateful_widget(table, area, &mut self.selection[Tab::Audit.index()]);
    }
}

const HELP: &str = "\
Tab / ← → / 1-5   switch tabs
↑ ↓ / j k         move the selection
R / F5            refresh (also automatic every 3 s)
q / Ctrl-C        quit

Devices:   a approve   r reject   d disable   e enable   x revoke   f cycle filter
           (rejected and revoked devices are deleted completely)
Accounts:  n new account (shows the invite code)   i new invite code
           a make admin / remove admin role   d disable   e enable
           m delete all messages of the person for everyone
           x delete the account completely (messages, devices, memberships)
Audit:     v verify the hash chain

All actions are written to the audit log with the origin '(tui)'.";

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

fn boxed(title: &str) -> Block<'static> {
    Block::default().borders(Borders::ALL).border_type(BorderType::Plain).title(format!(" {title} "))
}

fn header<const N: usize>(titles: [&'static str; N]) -> Row<'static> {
    Row::new(titles).style(Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
}

fn highlight() -> Style {
    Style::new().add_modifier(Modifier::REVERSED)
}

fn status_style(status: &str) -> Style {
    match status {
        "pending" | "in_progress" | "requested" => Style::new().fg(Color::Yellow).bold(),
        "active" | "backup_purge_done" => Style::new().fg(Color::Green),
        "backup_purge_pending" => Style::new().fg(Color::Cyan),
        "disabled" => Style::new().fg(Color::Magenta),
        "revoked" | "rejected" | "failed" => Style::new().fg(Color::Red),
        _ => Style::new(),
    }
}

fn popup(frame: &mut Frame, title: &str, text: &str, keys: &str) {
    let width = text.lines().map(|l| l.chars().count()).max().unwrap_or(20).clamp(30, 90) as u16 + 4;
    let height = text.lines().count() as u16 + 4;
    let [area] = Layout::horizontal([Constraint::Length(width)]).flex(Flex::Center).areas(frame.area());
    let [area] = Layout::vertical([Constraint::Length(height)]).flex(Flex::Center).areas(area);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .title(format!(" {title} "))
        .title_bottom(Line::from(format!(" {keys} ")).right_aligned());
    frame.render_widget(Paragraph::new(Text::from(text.to_owned())).wrap(Wrap { trim: false }).block(block), area);
}
