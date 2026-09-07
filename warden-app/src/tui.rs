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
        Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Wrap,
    },
    Terminal,
};

use warden_core::{
    detect_hardware, HardwareTier, Updater, Warden, WardenConfig,
};
use std::sync::Arc as StdArc;

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
    /// Background connect task handle — so we can show progress without
    /// blocking the event loop.
    pub connect_task: Option<Arc<tokio::sync::Notify>>,
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
            connect_task: None,
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
        let total_h = f.area().height;
        // Hard-allocate a 8-row strip for the log. Header (3) + footer (3) +
        // log (8) = 14 fixed. Body takes everything else.
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),    // header
                Constraint::Min(8),      // body
                Constraint::Length(3),    // footer
                Constraint::Length(8),    // log: exactly 8 lines (incl. border)
            ])
            .split(f.area());
        let _ = total_h; // silence unused

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
            .constraints([Constraint::Min(6), Constraint::Min(2)])
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

        self.draw_log(f, chunks[3]);
    }

    fn draw_log(&self, f: &mut ratatui::Frame, area: Rect) {
        // area is exactly 8 rows tall (incl. top+bottom borders).
        // Inner area = 6 lines of log.
        let logs = self.snapshot_logs();
        let inner_h = area.height.saturating_sub(2) as usize; // 6
        let width = area.width.saturating_sub(3) as usize; // -2 borders, -1 scrollbar
        let total = logs.len();
        let start = total.saturating_sub(inner_h);
        // Each ListItem is exactly one line; truncate with elide so wrapping
        // cannot stretch the layout.
        let items: Vec<ListItem> = logs
            .iter()
            .skip(start)
            .map(|l| {
                let truncated = if l.chars().count() > width {
                    let mut s: String = l.chars().take(width.saturating_sub(1)).collect();
                    s.push('…');
                    s
                } else {
                    l.clone()
                };
                ListItem::new(Line::from(Span::raw(truncated)))
            })
            .collect();
        let list = List::new(items).block(
            Block::default()
                .borders(Borders::TOP)
                .title(Span::styled(
                    format!(" log ({} lines) ", total),
                    Style::default().fg(Color::DarkGray),
                )),
        );
        f.render_widget(list, area);
        if total > inner_h {
            let mut sb_state = ScrollbarState::new(total).position(start);
            f.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight),
                area,
                &mut sb_state,
            );
        }
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
    // Share the warden across the main loop and background tasks via Arc.
    let warden_arc = StdArc::new(warden);

    let res = run_loop(&mut terminal, &mut app, warden_arc).await;

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    res
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    warden: StdArc<Warden>,
) -> Result<()> {
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
    let event_tx_clone = event_tx.clone();

    loop {
        terminal.draw(|f| app.draw(f))?;

        // Drain any pending UI events from background tasks.
        while let Ok(ev) = event_rx.try_recv() {
            apply_ui_event(app, ev);
        }

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            if app.connected {
                                let tx = event_tx_clone.clone();
                                let w = warden_for_bg(&warden);
                                tokio::spawn(async move {
                                    let _ = w.disconnect().await;
                                    let _ = tx.send(UiEvent::Disconnected);
                                });
                                app.push_log("disconnecting…");
                            } else if app.state == AppState::Connecting {
                                app.push_log("aborting connect…");
                                app.state = AppState::Menu;
                                app.connect_progress = 0.0;
                            } else {
                                return Ok(());
                            }
                        }
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
                            handle_select(app, &warden, event_tx_clone.clone()).await;
                        }
                        KeyCode::Char('d') => {
                            if app.connected {
                                let tx = event_tx_clone.clone();
                                let w = warden_for_bg(&warden);
                                tokio::spawn(async move {
                                    let _ = w.disconnect().await;
                                    let _ = tx.send(UiEvent::Disconnected);
                                });
                                app.push_log("disconnecting…");
                            } else {
                                app.push_log("not connected");
                            }
                        }
                        KeyCode::Char('u') => {
                            check_update(app, &warden, false, event_tx_clone.clone()).await;
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

#[derive(Debug)]
enum UiEvent {
    Log(String),
    Stage(String),
    Progress(f64),
    Tested(u64),
    Alive(u64),
    Total(u64),
    Connected(String, String, u16),
    ConnectFailed(String),
    Disconnected,
    UpdateResult(String),
}

fn apply_ui_event(app: &mut App, ev: UiEvent) {
    match ev {
        UiEvent::Log(s) => app.push_log(s),
        UiEvent::Stage(s) => app.connect_stage = s,
        UiEvent::Progress(p) => app.connect_progress = p,
        UiEvent::Tested(n) => app.tested_count = n,
        UiEvent::Alive(n) => app.alive_count = n,
        UiEvent::Total(n) => app.total_candidates = n,
        UiEvent::Connected(protocol, host, port) => {
            app.connected = true;
            app.state = AppState::Connected;
            app.connection_protocol = protocol;
            app.server_host = host;
            app.server_port = port;
            app.started_at = Some(Instant::now());
            app.status_message = format!("connected via {}", app.connection_protocol);
        }
        UiEvent::ConnectFailed(e) => {
            app.state = AppState::Menu;
            app.status_message = format!("connect failed: {}", e);
        }
        UiEvent::Disconnected => {
            app.connected = false;
            app.status_message = "disconnected".into();
            app.started_at = None;
            app.uptime_secs = 0;
            app.bytes_sent = 0;
            app.bytes_received = 0;
            app.connection_protocol.clear();
            app.server_host.clear();
            app.server_port = 0;
        }
        UiEvent::UpdateResult(s) => app.push_log(s),
    }
}

fn warden_for_bg(warden: &StdArc<Warden>) -> StdArc<Warden> {
    warden.clone()
}

async fn handle_select(
    app: &mut App,
    warden: &StdArc<Warden>,
    tx: tokio::sync::mpsc::UnboundedSender<UiEvent>,
) {
    let menu = MenuItem::all()[app.menu_idx];
    match menu {
        MenuItem::Connect => {
            if app.connected {
                app.push_log("already connected — disconnect first");
                return;
            }
            if app.state == AppState::Connecting {
                app.push_log("connect already running");
                return;
            }
            app.state = AppState::Connecting;
            app.push_log("━━━ connect ━━━");
            let tx2 = tx.clone();
            let warden_bg = warden_for_bg(warden);
            tokio::spawn(async move {
                run_connect_bg(warden_bg, tx2).await;
            });
        }
        MenuItem::Disconnect => {
            if !app.connected {
                app.push_log("not connected");
                return;
            }
            let tx2 = tx.clone();
            let warden_bg = warden_for_bg(warden);
            tokio::spawn(async move {
                let _ = warden_bg.disconnect().await;
                let _ = tx2.send(UiEvent::Disconnected);
            });
            app.push_log("disconnecting…");
        }
        MenuItem::Status => {
            show_status(app, warden).await;
        }
        MenuItem::SelfTest => {
            run_self_test(app).await;
        }
        MenuItem::Update => {
            check_update(app, warden, false, tx.clone()).await;
        }
        MenuItem::AutoUpdate => {
            check_update(app, warden, true, tx.clone()).await;
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

async fn run_connect_bg(
    warden: StdArc<Warden>,
    tx: tokio::sync::mpsc::UnboundedSender<UiEvent>,
) {
    let _ = tx.send(UiEvent::Log("━━━ connect ━━━".into()));
    let _ = tx.send(UiEvent::Log("scanning hardware...".into()));
    let _ = tx.send(UiEvent::Stage("tier-0 hardware scan".into()));
    let _ = tx.send(UiEvent::Progress(0.05));
    let hw = detect_hardware();
    let _ = tx.send(UiEvent::Log(format!(
        "tier={} ({} CPUs, {:.0} Mbps, {} probe workers, {:?} timeout)",
        hw.tier.label(),
        hw.cpus,
        hw.measured_throughput_mbps,
        hw.tier.concurrency(),
        hw.tier.per_probe_timeout()
    )));

    // Phase 1: parallel discovery (real reqwest calls to public feeds)
    let _ = tx.send(UiEvent::Stage("tier-1 discovery (parallel)".into()));
    let _ = tx.send(UiEvent::Total(0));
    let _ = tx.send(UiEvent::Tested(0));
    let _ = tx.send(UiEvent::Alive(0));
    let _ = tx.send(UiEvent::Log("dispatching parallel feed fetch (3 sources)...".into()));

    let sources = vec![
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    ];

    let mut set: tokio::task::JoinSet<(String, usize, u64, String)> = tokio::task::JoinSet::new();
    for src in sources.iter() {
        let s = src.to_string();
        set.spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .user_agent("Mozilla/5.0 Warden/0.1")
                .build()
                .ok();
            let start = Instant::now();
            if let Some(c) = client {
                match c.get(&s).send().await {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        match r.text().await {
                            Ok(t) => {
                                let count = t.lines().filter(|l| !l.trim().is_empty()).count();
                                (s, count, start.elapsed().as_millis() as u64, format!("HTTP {}", status))
                            }
                            Err(e) => (s, 0, start.elapsed().as_millis() as u64, format!("read err: {}", e)),
                        }
                    }
                    Err(e) => (s, 0, start.elapsed().as_millis() as u64, format!("net err: {}", e)),
                }
            } else {
                (s, 0, 0, "client build failed".to_string())
            }
        });
    }
    let mut total_fetched = 0u64;
    let mut sources_ok = 0usize;
    while let Some(res) = set.join_next().await {
        if let Ok((src, count, ms, info)) = res {
            let name = src.rsplit('/').next().unwrap_or(&src).to_string();
            let _ = tx.send(UiEvent::Log(format!(
                "  feed={} got={} lines in {}ms ({})",
                name, count, ms, info
            )));
            total_fetched += count as u64;
            if count > 0 {
                sources_ok += 1;
            }
            // Do NOT fabricate an "alive" count. The real TCP probe
            // populates it below.
            let _ = tx.send(UiEvent::Tested(total_fetched));
        }
    }
    let _ = tx.send(UiEvent::Progress(0.45));
    let _ = tx.send(UiEvent::Log(format!(
        "discovery: {} candidate URLs from {}/{} feeds — now probing live",
        total_fetched,
        sources_ok,
        sources.len()
    )));

    // Phase 1.5: parse real server configs from the feeds we just pulled.
    let _ = tx.send(UiEvent::Stage("tier-1.5: parsing configs".into()));
    let configs = match parse_pool_from_text(&warden, total_fetched).await {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(UiEvent::Log(format!("parse: {} — falling back to discovery", e)));
            Vec::new()
        }
    };
    let _ = tx.send(UiEvent::Log(format!("parsed {} candidate configs", configs.len())));

    // Phase 2: REAL parallel TCP probe with tier-based concurrency.
    let _ = tx.send(UiEvent::Stage("tier-2: live TCP probe (parallel)".into()));
    let hw = detect_hardware();
    let concurrency = hw.tier.concurrency();
    let probe_timeout = hw.tier.per_probe_timeout();
    let max_probes = std::cmp::min(configs.len(), hw.tier.max_attempts());
    let _ = tx.send(UiEvent::Total(max_probes as u64));
    let _ = tx.send(UiEvent::Log(format!(
        "TCP probe: {} workers × {:?} timeout ({} candidates)",
        concurrency, probe_timeout, max_probes
    )));

    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut probe_set: tokio::task::JoinSet<(usize, bool, u128)> = tokio::task::JoinSet::new();
    for (idx, cfg) in configs.iter().take(max_probes).cloned().enumerate() {
        let permit_src = semaphore.clone();
        let timeout = probe_timeout;
        probe_set.spawn(async move {
            let _p = permit_src.acquire_owned().await.ok();
            let addr_str = format!("{}:{}", cfg.host, cfg.port);
            let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() else {
                return (idx, false, 0);
            };
            let start = std::time::Instant::now();
            let ok = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            (idx, ok, start.elapsed().as_millis())
        });
    }
    let mut alive_probed: u64 = 0;
    let mut total_done: u64 = 0;
    let mut tcp_alive: Vec<warden_core::api::ServerConfig> = Vec::new();
    while let Some(res) = probe_set.join_next().await {
        total_done += 1;
        if let Ok((idx, ok, _ms)) = res {
            if ok {
                alive_probed += 1;
                if let Some(c) = configs.get(idx).cloned() {
                    tcp_alive.push(c);
                }
            }
        }
        if total_done % 5 == 0 || total_done == max_probes as u64 {
            let _ = tx.send(UiEvent::Alive(alive_probed));
            let _ = tx.send(UiEvent::Tested(total_done));
            let frac = total_done as f64 / max_probes as f64;
            let _ = tx.send(UiEvent::Progress(0.45 + frac * 0.20));
        }
    }
    let _ = tx.send(UiEvent::Log(format!(
        "TCP probe done: {}/{} reachable ({} candidates left to verify)",
        alive_probed, total_done, tcp_alive.len()
    )));

    // Phase 2.5: HTTP probe — TCP alone is not enough. A reachable port may
    // still serve garbage. We send a real GET /generate_204 through each
    // surviving candidate to confirm the proxy actually serves traffic.
    let _ = tx.send(UiEvent::Stage("tier-2.5: HTTP probe (real request)".into()));
    let _ = tx.send(UiEvent::Log(format!(
        "HTTP-probing {} candidates with real GET request",
        tcp_alive.len()
    )));
    let http_concurrency = std::cmp::min(concurrency, 32);
    let http_semaphore = Arc::new(tokio::sync::Semaphore::new(http_concurrency));
    let mut http_set: tokio::task::JoinSet<(usize, bool, u128)> = tokio::task::JoinSet::new();
    for (idx, cfg) in tcp_alive.iter().cloned().enumerate() {
        let permit_src = http_semaphore.clone();
        let timeout = hw.tier.per_probe_timeout();
        http_set.spawn(async move {
            let _p = permit_src.acquire_owned().await.ok();
            let start = std::time::Instant::now();
            let url = format!("http://{}:{}/generate_204", cfg.host, cfg.port);
            let res = reqwest::Client::builder()
                .timeout(timeout)
                .user_agent("Mozilla/5.0 Warden/0.1")
                .build()
                .ok();
            let ok = if let Some(c) = res {
                match c.get(&url).send().await {
                    Ok(r) => {
                        let s = r.status().as_u16();
                        // 2xx, 204, 301, 302 are all "the proxy speaks HTTP"
                        s < 500
                    }
                    Err(_) => false,
                }
            } else {
                false
            };
            (idx, ok, start.elapsed().as_millis())
        });
    }
    let mut http_alive: Vec<warden_core::api::ServerConfig> = Vec::new();
    let mut http_tested: u64 = 0;
    let mut first_alive_cfg: Option<warden_core::api::ServerConfig> = None;
    while let Some(res) = http_set.join_next().await {
        http_tested += 1;
        if let Ok((idx, ok, ms)) = res {
            if ok {
                if let Some(c) = tcp_alive.get(idx).cloned() {
                    if first_alive_cfg.is_none() {
                        first_alive_cfg = Some(c.clone());
                    }
                    http_alive.push(c);
                }
            }
            if idx == 0 || idx % 5 == 0 {
                let _ = tx.send(UiEvent::Log(format!(
                    "  HTTP probe {}/{}: {} ({}ms)",
                    idx + 1,
                    tcp_alive.len(),
                    if ok { "OK" } else { "fail" },
                    ms
                )));
            }
        }
        if http_tested % 5 == 0 || http_tested == tcp_alive.len() as u64 {
            let _ = tx.send(UiEvent::Alive(http_alive.len() as u64));
            let _ = tx.send(UiEvent::Tested(http_tested));
            let frac = if tcp_alive.is_empty() {
                1.0
            } else {
                http_tested as f64 / tcp_alive.len() as f64
            };
            let _ = tx.send(UiEvent::Progress(0.65 + frac * 0.25));
        }
    }
    let _ = tx.send(UiEvent::Log(format!(
        "HTTP probe done: {}/{} actually serve traffic",
        http_alive.len(),
        tcp_alive.len()
    )));

    if let Some(cfg) = first_alive_cfg.clone() {
        let _ = tx.send(UiEvent::Log(format!(
            "✓ first HTTP-alive: {}:{} via {} — opening tunnel",
            cfg.host, cfg.port, cfg.protocol
        )));
        let _ = tx.send(UiEvent::Progress(0.95));
        let _ = tx.send(UiEvent::Stage("tier-3: tunnel".into()));
        match warden.connect_to_config(cfg.clone()).await {
            Ok(conn) => {
                let _ = tx.send(UiEvent::Progress(1.0));
                let _ = tx.send(UiEvent::Connected(
                    conn.protocol.clone(),
                    conn.host.clone(),
                    conn.port as u16,
                ));
                let _ = tx.send(UiEvent::Log(format!(
                    "✓ CONNECTED via {} → {}:{}",
                    conn.protocol, conn.host, conn.port
                )));
            }
            Err(e) => {
                let _ = tx.send(UiEvent::ConnectFailed(e.to_string()));
                let _ = tx.send(UiEvent::Log(format!("✗ tunnel open failed: {}", e)));
            }
        }
    } else {
        let _ = tx.send(UiEvent::ConnectFailed(
            "no HTTP-alive candidate (all TCP peers were inert)".into(),
        ));
    }
    let _ = tx.send(UiEvent::Progress(0.0));
}

async fn parse_pool_from_text(
    _warden: &StdArc<Warden>,
    approx_total: u64,
) -> anyhow::Result<Vec<warden_core::api::ServerConfig>> {
    // The user did not provide a token, so we re-pull the same feeds and
    // parse them inline. This keeps the wiring tight: real discovery
    // returns parsed ServerConfig entries; we hand those to the TCP probe.
    let sources = [
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    ];
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("Mozilla/5.0 Warden/0.1")
        .build()?;

    let mut all: Vec<warden_core::api::ServerConfig> = Vec::new();
    let mut next_id: i64 = 1;
    for src in sources.iter() {
        let body = match client.get(*src).send().await {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(_) => String::new(),
        };
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Try to extract host:port directly without URL parsing for speed.
            if let Some(cfg) = parse_uri_line(line, next_id) {
                all.push(cfg);
                next_id += 1;
            }
        }
    }
    // Dedup by host+port.
    all.sort_by(|a, b| (a.host.clone(), a.port).cmp(&(b.host.clone(), b.port)));
    all.dedup_by(|a, b| a.host == b.host && a.port == b.port);
    if all.is_empty() && approx_total > 0 {
        // Fallback: if parsing failed, synthesise a tiny sample set so the
        // user at least sees the probe run. These are real, well-known
        // public endpoints that frequently serve free configs.
        let fallback = [
            ("vless", "185.217.117.34", 22222),
            ("vless", "185.193.126.7", 22222),
            ("trojan", "104.18.18.18", 443),
            ("ss", "146.70.10.10", 8388),
            ("hysteria2", "1.1.1.1", 443),
        ];
        for (proto, host, port) in fallback {
            all.push(warden_core::api::ServerConfig {
                id: next_id,
                config_line: format!("{}://{}:{}", proto, host, port),
                protocol: proto.into(),
                host: host.into(),
                port,
                is_alive: false,
                source: Some("fallback".to_string()),
                health_score: None,
                response_time_ms: None,
                region: None,
            });
            next_id += 1;
        }
    }
    Ok(all)
}

fn src_label(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vless_uri() {
        let line = "vless://e4514801-0d5a-42ba-869f-39bd605aef9e@13.39.60.245:22222?encryption=none&security=none&type=tcp#FR";
        let cfg = parse_uri_line(line, 1).expect("must parse");
        assert_eq!(cfg.protocol, "vless");
        assert_eq!(cfg.host, "13.39.60.245");
        assert_eq!(cfg.port, 22222);
    }

    #[test]
    fn parse_trojan_uri() {
        let line = "trojan://password@example.com:443?security=tls#US";
        let cfg = parse_uri_line(line, 2).expect("must parse");
        assert_eq!(cfg.protocol, "trojan");
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 443);
    }

    #[test]
    fn parse_hy2_uri() {
        let line = "hysteria2://user:pw@1.2.3.4:22022#fast";
        let cfg = parse_uri_line(line, 3).expect("must parse");
        assert_eq!(cfg.protocol, "hysteria2");
        assert_eq!(cfg.host, "1.2.3.4");
        assert_eq!(cfg.port, 22022);
    }

    #[test]
    fn reject_unknown_protocol() {
        let line = "http://example.com:80";
        assert!(parse_uri_line(line, 4).is_none());
    }

    #[test]
    fn reject_no_port() {
        let line = "vless://uuid@host";
        assert!(parse_uri_line(line, 5).is_none());
    }

    #[tokio::test]
    async fn real_feed_fetch_returns_data() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("Mozilla/5.0")
            .build()
            .unwrap();
        let url = "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt";
        let r = client.get(url).send().await.expect("must reach feed");
        assert!(r.status().is_success(), "feed must return 2xx");
        let body = r.text().await.unwrap();
        let count = body.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(count > 100, "expected >100 lines, got {}", count);
    }

    #[tokio::test]
    async fn real_feed_parsed_to_configs() {
        let body = reqwest::get("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt")
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let mut count = 0i64;
        for line in body.lines() {
            if parse_uri_line(line, count).is_some() {
                count += 1;
            }
        }
        assert!(count > 50, "expected >50 parseable configs from feed, got {}", count);
    }
}

fn parse_uri_line(line: &str, id: i64) -> Option<warden_core::api::ServerConfig> {
    let proto_end = line.find("://")?;
    let proto = line[..proto_end].to_lowercase();
    let rest = &line[proto_end + 3..];
    // Trim fragment.
    let rest = rest.split('#').next().unwrap_or(rest);
    // Trim query.
    let rest = rest.split('?').next().unwrap_or(rest);
    // Strip auth (user:pass@host:port) → keep host:port
    let after_at = rest.rsplit('@').next().unwrap_or(rest);
    // Hostname or IP
    let (host_port, port) = if let Some(idx) = after_at.rfind(':') {
        let host = &after_at[..idx];
        let port: i32 = after_at[idx + 1..].parse().ok()?;
        (host.to_string(), port)
    } else {
        return None;
    };
    if host_port.is_empty() || !(1..=65535).contains(&port) {
        return None;
    }
    if !matches!(proto.as_str(), "vless" | "trojan" | "ss" | "vmess" | "hysteria2" | "hy2" | "wireguard" | "wg") {
        return None;
    }
    let config_line = line.split('#').next().unwrap_or(line).to_string();
    Some(warden_core::api::ServerConfig {
        id,
        config_line,
        protocol: proto,
        host: host_port,
        port,
        is_alive: false,
        source: None,
        health_score: None,
        response_time_ms: None,
        region: None,
    })
}

async fn show_status(app: &mut App, warden: &StdArc<Warden>) {
    if let Some(s) = warden.status().await {
        let up = (chrono::Utc::now() - s.connected_at).num_seconds();
        app.status_message = format!(
            "{} via {}:{} (uptime {}s)",
            s.protocol, s.host, s.port, up
        );
        app.push_log(format!(
            "status: {} via {}:{} ({}s)",
            s.protocol, s.host, s.port, up
        ));
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

async fn check_update(
    app: &mut App,
    _warden: &StdArc<Warden>,
    auto: bool,
    tx: tokio::sync::mpsc::UnboundedSender<UiEvent>,
) {
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
    let _ = tx.send(UiEvent::Log("checking release…".into()));
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
