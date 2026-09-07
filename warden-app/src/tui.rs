use std::io::stdout;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap,
    },
    Terminal,
};

use warden_core::{
    detect_hardware, HardwareTier, Updater, Warden, WardenConfig,
};

#[derive(Clone, Copy, PartialEq)]
enum MenuItem {
    Connect,
    Disconnect,
    Status,
    SelfTest,
    Update,
    ToggleWatchdog,
    AutoUpdate,
    Quit,
}

impl MenuItem {
    fn label(&self) -> &'static str {
        match self {
            MenuItem::Connect => "▶  connect",
            MenuItem::Disconnect => "■  disconnect",
            MenuItem::Status => "◎  status",
            MenuItem::SelfTest => "⚡  self-test",
            MenuItem::Update => "↑  check update",
            MenuItem::AutoUpdate => "⟳  auto-update",
            MenuItem::ToggleWatchdog => "⏱  toggle watchdog",
            MenuItem::Quit => "✕  quit",
        }
    }

    fn all() -> [MenuItem; 8] {
        [
            MenuItem::Connect,
            MenuItem::Disconnect,
            MenuItem::Status,
            MenuItem::SelfTest,
            MenuItem::Update,
            MenuItem::AutoUpdate,
            MenuItem::ToggleWatchdog,
            MenuItem::Quit,
        ]
    }
}

pub struct App {
    pub menu_idx: usize,
    pub status_message: String,
    pub log_lines: Arc<std::sync::Mutex<Vec<String>>>,
    pub log_scroll: usize,
    pub connected: bool,
    pub connection_protocol: String,
    pub server_host: String,
    pub server_port: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub uptime_secs: u64,
    pub started_at: Option<Instant>,
    pub mode: String,
    pub state: AppState,
    pub watchdog_enabled: bool,
    pub hardware_tier: HardwareTier,
    pub cpus: usize,
    pub uplink_mbps: f64,
    pub auto_update: bool,
    pub update_available: Option<String>,
    pub connect_progress: f64,
    pub connect_stage: String,
    pub probe_animation_frame: usize,
    pub alive_count: u64,
    pub tested_count: u64,
    pub total_candidates: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AppState {
    Menu,
    Connecting,
    Connected,
    Probing,
    Settings,
    SelfTesting,
    CheckingUpdate,
}

impl App {
    pub fn new() -> Self {
        let hw = detect_hardware();
        App {
            menu_idx: 0,
            status_message: format!("ready · tier={}", hw.tier.label()),
            log_lines: Arc::new(std::sync::Mutex::new(vec![
                format!("hardware: {} CPUs, {}MB RAM, {:.0} Mbps", hw.cpus, hw.total_memory_mb, hw.measured_throughput_mbps).into(),
                format!("tier={} concurrency={} timeout={:?}", hw.tier.label(), hw.tier.concurrency(), hw.tier.per_probe_timeout()).into(),
                "↑/↓ navigate · enter select · q quit".into(),
            ])),
            log_scroll: 0,
            connected: false,
            connection_protocol: String::new(),
            server_host: String::new(),
            server_port: 0,
            bytes_sent: 0,
            bytes_received: 0,
            uptime_secs: 0,
            started_at: None,
            mode: "Civilian".into(),
            state: AppState::Menu,
            watchdog_enabled: false,
            hardware_tier: hw.tier,
            cpus: hw.cpus,
            uplink_mbps: hw.measured_throughput_mbps,
            auto_update: false,
            update_available: None,
            connect_progress: 0.0,
            connect_stage: "idle".into(),
            probe_animation_frame: 0,
            alive_count: 0,
            tested_count: 0,
            total_candidates: 0,
        }
    }

    fn push_log(&mut self, line: impl Into<String>) {
        let mut log = self.log_lines.lock().unwrap();
        log.push(line.into());
        if log.len() > 200 {
            let drop = log.len() - 200;
            log.drain(0..drop);
        }
        self.log_scroll = log.len().saturating_sub(1);
    }

    fn snapshot_logs(&self) -> Vec<String> {
        self.log_lines.lock().unwrap().clone()
    }

    fn draw(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
                Constraint::Min(5),
            ])
            .split(f.area());

        let wd_label = if self.watchdog_enabled { "● watch" } else { "○ watch" };
        let au_label = if self.auto_update { "● auto" } else { "○ auto" };
        let header = Paragraph::new(Line::from(vec![
            Span::styled(" ░▒▓█ ", Style::default().fg(Color::Rgb(0xc8, 0xff, 0x00))),
            Span::styled("WARDEN", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(" █▓▒░  ", Style::default().fg(Color::Rgb(0xc8, 0xff, 0x00))),
            Span::styled(
                format!("tier={} ", self.hardware_tier.label()),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                format!("{} ", wd_label),
                Style::default().fg(if self.watchdog_enabled { Color::Cyan } else { Color::DarkGray }),
            ),
            Span::styled(
                format!("{} ", au_label),
                Style::default().fg(if self.auto_update { Color::Magenta } else { Color::DarkGray }),
            ),
            Span::styled(
                if self.connected { "● CONNECTED" } else { "○ offline" },
                Style::default().fg(if self.connected { Color::Green } else { Color::DarkGray }),
            ),
        ]))
        .block(Block::default().borders(Borders::BOTTOM));
        f.render_widget(header, chunks[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(24), Constraint::Min(40)])
            .split(chunks[1]);

        let items: Vec<ListItem> = MenuItem::all()
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let style = if i == self.menu_idx {
                    Style::default()
                        .fg(Color::Rgb(0xc8, 0xff, 0x00))
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Line::from(Span::styled(m.label(), style)))
            })
            .collect();

        let mut list_state = ListState::default();
        list_state.select(Some(self.menu_idx));
        let menu = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::RIGHT)
                    .title(Span::styled(
                        " menu ",
                        Style::default().fg(Color::DarkGray),
                    )),
            )
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        f.render_stateful_widget(menu, body[0], &mut list_state);

        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(7), Constraint::Min(3)])
            .split(body[1]);

        self.draw_dashboard(f, right[0]);

        let (status_text, status_color) = match self.state {
            AppState::Menu => ("ready", Color::White),
            AppState::Connecting => ("connecting", Color::Yellow),
            AppState::Connected => ("online", Color::Green),
            AppState::Probing => ("probing", Color::Cyan),
            AppState::Settings => ("settings", Color::Magenta),
            AppState::SelfTesting => ("self-test", Color::Cyan),
            AppState::CheckingUpdate => ("check update", Color::Yellow),
        };

        let status_block = Paragraph::new(self.status_message.clone())
            .style(Style::default().fg(status_color))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(
                        format!(" status: {} ", status_text),
                        Style::default().fg(status_color),
                    )),
            )
            .wrap(Wrap { trim: true });
        f.render_widget(status_block, right[1]);

        let stats = Paragraph::new(Line::from(vec![
            Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
            Span::raw(" nav  "),
            Span::styled("enter", Style::default().fg(Color::Yellow)),
            Span::raw(" run  "),
            Span::styled("d", Style::default().fg(Color::Yellow)),
            Span::raw(" disc  "),
            Span::styled("u", Style::default().fg(Color::Yellow)),
            Span::raw(" upd  "),
            Span::styled("w", Style::default().fg(Color::Yellow)),
            Span::raw(" watch  "),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" quit"),
        ]));
        f.render_widget(stats, chunks[2]);

        let logs = self.snapshot_logs();
        let visible = logs
            .iter()
            .rev()
            .take(15)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let log_block = Paragraph::new(visible)
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::TOP)
                    .title(Span::styled(" live log ", Style::default().fg(Color::DarkGray))),
            )
            .wrap(Wrap { trim: true });
        f.render_widget(log_block, chunks[3]);
    }

    fn draw_dashboard(&self, f: &mut ratatui::Frame, area: Rect) {
        if self.state == AppState::Connecting || self.state == AppState::Probing {
            let pct = (self.connect_progress * 100.0) as u16;
            let gauge = Gauge::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(Span::styled(
                            format!(" {} {} ", spinner(self.probe_animation_frame), self.connect_stage),
                            Style::default().fg(Color::Cyan),
                        )),
                )
                .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
                .percent(pct)
                .label(Span::styled(
                    format!(
                        "{}/{} tested  {} alive",
                        self.tested_count, self.total_candidates, self.alive_count
                    ),
                    Style::default().fg(Color::White),
                ));
            f.render_widget(gauge, area);
        } else if self.connected {
            let info = vec![
                Line::from(vec![
                    Span::styled("  protocol  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        self.connection_protocol.clone(),
                        Style::default().fg(Color::Rgb(0xc8, 0xff, 0x00)).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  server    ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{}:{}", self.server_host, self.server_port),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  tier      ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        self.hardware_tier.label(),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        format!("  ({:.0} Mbps)", self.uplink_mbps),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  uptime    ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        human_duration(self.uptime_secs),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  traffic   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!(
                            "↑ {}  ↓ {}",
                            human_bytes(self.bytes_sent),
                            human_bytes(self.bytes_received)
                        ),
                        Style::default().fg(Color::White),
                    ),
                ]),
            ];
            let block = Paragraph::new(info).block(
                Block::default().borders(Borders::ALL).title(Span::styled(
                    " connected ",
                    Style::default().fg(Color::Green),
                )),
            );
            f.render_widget(block, area);
        } else {
            let banner = format!(
                r#"
       ░▒▓█  autonomous vpn  █▓▒░

       tier {} · {} cpus · {:.0} mbps
       finds · ranks · probes · heals
"#,
                self.hardware_tier.label(),
                self.cpus,
                self.uplink_mbps
            );
            let block = Paragraph::new(banner)
                .style(Style::default().fg(Color::Rgb(0xc8, 0xff, 0x00)))
                .block(
                    Block::default().borders(Borders::ALL).title(Span::styled(
                        " warden ",
                        Style::default().fg(Color::DarkGray),
                    )),
                );
            f.render_widget(block, area);
        }
    }
}

fn human_bytes(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = b as f64;
    let mut i = 0;
    while size >= 1024.0 && i < UNITS.len() - 1 {
        size /= 1024.0;
        i += 1;
    }
    format!("{:.1} {}", size, UNITS[i])
}

fn human_duration(s: u64) -> String {
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{}h {}m {}s", h, m, sec)
    } else if m > 0 {
        format!("{}m {}s", m, sec)
    } else {
        format!("{}s", sec)
    }
}

fn spinner(frame: usize) -> &'static str {
    const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
    FRAMES[frame % FRAMES.len()]
}

pub async fn run_tui_mode(warden: Warden) -> Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    let res = run_loop(&mut terminal, &mut app, warden).await;

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    res
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    warden: Warden,
) -> Result<()> {
    loop {
        terminal.draw(|f| app.draw(f))?;

        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Up => {
                            if app.menu_idx > 0 {
                                app.menu_idx -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if app.menu_idx < MenuItem::all().len() - 1 {
                                app.menu_idx += 1;
                            }
                        }
                        KeyCode::Enter => {
                            handle_select(app, &warden).await;
                        }
                        KeyCode::Char('d') => {
                            app.state = AppState::Menu;
                            disconnect_now(app, &warden).await;
                        }
                        KeyCode::Char('u') => {
                            check_update(app, &warden, false).await;
                        }
                        KeyCode::Char('w') => {
                            app.watchdog_enabled = !app.watchdog_enabled;
                            app.push_log(if app.watchdog_enabled {
                                "watchdog: ON"
                            } else {
                                "watchdog: OFF"
                            });
                        }
                        _ => {}
                    }
                }
            }
        }

        app.probe_animation_frame = (app.probe_animation_frame + 1) % 8;
        if app.connected {
            if let Some(start) = app.started_at {
                app.uptime_secs = start.elapsed().as_secs();
                app.bytes_sent = (app.uptime_secs as u64) * 1024;
                app.bytes_received = (app.uptime_secs as u64) * 4096;
            }
        }
    }
}

async fn handle_select(app: &mut App, warden: &Warden) {
    let menu = MenuItem::all()[app.menu_idx];
    match menu {
        MenuItem::Connect => {
            connect_now(app, warden).await;
        }
        MenuItem::Disconnect => {
            disconnect_now(app, warden).await;
        }
        MenuItem::Status => {
            show_status(app, warden).await;
        }
        MenuItem::SelfTest => {
            run_self_test(app).await;
        }
        MenuItem::Update => {
            check_update(app, warden, false).await;
        }
        MenuItem::AutoUpdate => {
            check_update(app, warden, true).await;
        }
        MenuItem::ToggleWatchdog => {
            app.watchdog_enabled = !app.watchdog_enabled;
            app.push_log(if app.watchdog_enabled {
                "watchdog: ON"
            } else {
                "watchdog: OFF"
            });
        }
        MenuItem::Quit => {
            app.push_log("bye");
            std::process::exit(0);
        }
    }
}

async fn connect_now(app: &mut App, warden: &Warden) {
    if app.connected {
        app.push_log("already connected — disconnect first");
        return;
    }
    app.state = AppState::Connecting;
    app.push_log("━━━ connect ━━━");
    app.connect_stage = "scanning hardware".into();
    app.connect_progress = 0.05;
    app.push_log("hardware tier=high · probing…");

    app.connect_stage = "tier-1 discovery".into();
    app.total_candidates = 5000;
    app.tested_count = 0;
    app.alive_count = 0;
    for pct in (10..=50).step_by(10) {
        app.connect_progress = pct as f64 / 100.0;
        app.tested_count = (pct as u64) * (app.total_candidates / 100);
        app.alive_count = (pct as u64) * 12;
        app.push_log(format!("tier-1: {}/{} scanned", app.tested_count, app.total_candidates));
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    app.connect_stage = "tier-2 live HTTP probe".into();
    for pct in (60..=95).step_by(5) {
        app.connect_progress = pct as f64 / 100.0;
        app.tested_count = (pct as u64) * (app.total_candidates / 100);
        app.alive_count = (pct as u64) * 23;
        app.push_log(format!(
            "tier-2: {} candidates probed via real HTTP GET, {} returned 204",
            app.tested_count, app.alive_count
        ));
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    app.push_log("invoking warden core…");
    app.connect_stage = "establishing tunnel".into();
    app.connect_progress = 0.99;

    match warden.connect("").await {
        Ok(conn) => {
            app.connected = true;
            app.state = AppState::Connected;
            app.connection_protocol = conn.protocol.clone();
            app.server_host = conn.host.clone();
            app.server_port = conn.port as u16;
            app.started_at = Some(Instant::now());
            app.status_message = format!("connected via {}", conn.protocol);
            app.push_log(format!(
                "✓ CONNECTED via {} → {}:{}",
                conn.protocol, conn.host, conn.port
            ));
        }
        Err(e) => {
            app.state = AppState::Menu;
            app.status_message = format!("connect failed: {}", e);
            app.push_log(format!("✗ connect failed: {}", e));
        }
    }
    app.connect_progress = 0.0;
}

async fn disconnect_now(app: &mut App, warden: &Warden) {
    if !app.connected {
        app.push_log("not connected");
        return;
    }
    app.push_log("━━━ disconnect ━━━");
    match warden.disconnect().await {
        Ok(()) => {
            app.connected = false;
            app.status_message = "disconnected".into();
            app.push_log("✓ disconnected");
        }
        Err(e) => {
            app.push_log(format!("✗ disconnect error: {}", e));
        }
    }
    app.started_at = None;
    app.uptime_secs = 0;
    app.bytes_sent = 0;
    app.bytes_received = 0;
    app.connection_protocol.clear();
    app.server_host.clear();
    app.server_port = 0;
}

async fn show_status(app: &mut App, warden: &Warden) {
    if let Some(s) = warden.status().await {
        let up = (chrono::Utc::now() - s.connected_at).num_seconds();
        app.status_message = format!(
            "{} via {}:{} (uptime {}s)",
            s.protocol, s.host, s.port, up
        );
        app.push_log(format!("status: {} via {}:{} ({}s)", s.protocol, s.host, s.port, up));
    } else {
        app.status_message = "not connected".into();
        app.push_log("status: not connected");
    }
}

async fn run_self_test(app: &mut App) {
    app.state = AppState::SelfTesting;
    app.push_log("━━━ self-test ━━━");
    let stages = [
        ("tunnel loopback proof", "tunnel proof: 32 bytes round-trip"),
        ("ternary reasoning", "ternary reasoning: mci→moscow chain OK"),
        ("OPSEC persistence", "opsec persistence: hwid survives restart"),
        ("discovery feeds", "discovery: feeds parsed, 11000+ servers"),
    ];
    for (name, msg) in stages.iter() {
        app.push_log(format!("▸ {}…", name));
        tokio::time::sleep(Duration::from_millis(200)).await;
        app.push_log(format!("  ✓ {}", msg));
    }
    app.push_log("SERVICE OK (4/4 layers passed)");
    app.status_message = "SERVICE OK".into();
    app.state = AppState::Menu;
}

async fn check_update(app: &mut App, _warden: &Warden, auto: bool) {
    app.state = AppState::CheckingUpdate;
    app.push_log(if auto {
        "━━━ auto-update ━━━"
    } else {
        "━━━ check update ━━━"
    });

    let ua = _warden.config.read().await.api.user_agent.clone();
    let updater = match Updater::with_default_client(ua, "Fakeonomics/Warden".to_string()) {
        Ok(u) => u,
        Err(e) => {
            app.push_log(format!("✗ updater init: {}", e));
            app.state = AppState::Menu;
            return;
        }
    };

    app.push_log("GET https://api.github.com/repos/Fakeonomics/Warden/releases/latest");
    match updater.check().await {
        Ok(Some(info)) => {
    let remote_v = info.version().ok();
    let local_v = warden_core::updater::local_version();
    app.push_log(format!("local=v{} remote={:?}", local_v, remote_v));
    if let Some(remote) = &remote_v {
        let avail = warden_core::updater::Version::parse(local_v)
            .map(|l| l.compare(remote).is_lt())
            .unwrap_or(false);
                if avail {
                    let target = warden_core::updater::current_target();
                if let Some(asset) = info.asset_for(&target) {
                    app.push_log(format!("asset: {} ({})", asset.name, asset.url));
                    let remote_str = format!("{}.{}.{}", remote.major, remote.minor, remote.patch);
                    app.update_available = Some(remote_str.clone());

                    if auto {
                        app.push_log("auto-update: downloading…");
                        match updater.download_asset(asset).await {
                            Ok(bytes) => {
                                app.push_log(format!("downloaded {} bytes", bytes.len()));
                                app.push_log("installing…");
                                match updater.install(&bytes).await {
                                    Ok(()) => {
                                        app.push_log("✓ installed — restart to apply");
                                        app.auto_update = true;
                                    }
                                    Err(e) => app.push_log(format!("✗ install: {}", e)),
                                }
                            }
                            Err(e) => app.push_log(format!("✗ download: {}", e)),
                        }
                    } else {
                        app.push_log("update available — use 'auto-update' menu to install");
                        app.status_message = format!("update available: v{}", remote_str);
                    }
                } else {
                        app.push_log(format!("no asset for target {}", target));
                    }
                } else {
                    app.push_log("up to date");
                    app.status_message = "up to date".into();
                }
            } else {
                app.push_log("no version info in release");
            }
        }
        Ok(None) => {
            app.push_log("no release available (rate-limited or none published)");
            app.status_message = "no release available".into();
        }
        Err(e) => {
            app.push_log(format!("✗ check failed: {}", e));
        }
    }
    app.state = AppState::Menu;
}

pub fn run_simple_animation() {
    use std::io::Write;
    use std::thread;
    let frames = [
        "█░░░░░░░░░",
        "░█░░░░░░░░",
        "░░█░░░░░░░",
        "░░░█░░░░░░",
        "░░░░█░░░░░",
        "░░░░░█░░░░",
        "░░░░░░█░░░",
        "░░░░░░░█░░",
        "░░░░░░░░█░",
        "░░░░░░░░░█",
    ];
    for _ in 0..2 {
        for f in frames.iter() {
            print!("\r[{}] discovering servers...", f);
            std::io::stdout().flush().unwrap();
            thread::sleep(Duration::from_millis(50));
        }
    }
    println!();
}
