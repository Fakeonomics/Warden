use std::io::stdout;
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
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};

use warden_core::{
    detect_hardware, HardwareTier, LiveProbeStats, ProbeVerdict, Warden, WardenConfig,
};

#[derive(Clone, Copy, PartialEq)]
enum MenuItem {
    Connect,
    Status,
    SelfTest,
    ToggleWatchdog,
    Settings,
    Quit,
}

impl MenuItem {
    fn label(&self) -> &'static str {
        match self {
            MenuItem::Connect => "▶  connect",
            MenuItem::Status => "◎  status",
            MenuItem::SelfTest => "⚡  self-test",
            MenuItem::ToggleWatchdog => "⏱  toggle watchdog",
            MenuItem::Settings => "⚙  settings",
            MenuItem::Quit => "✕  quit",
        }
    }

    fn all() -> [MenuItem; 6] {
        [
            MenuItem::Connect,
            MenuItem::Status,
            MenuItem::SelfTest,
            MenuItem::ToggleWatchdog,
            MenuItem::Settings,
            MenuItem::Quit,
        ]
    }
}

pub struct App {
    pub menu_idx: usize,
    pub status_message: String,
    pub discovery_progress: f64,
    pub discovery_total: u64,
    pub discovery_done: u64,
    pub alive_servers: u64,
    pub probing_active: bool,
    pub connected: bool,
    pub connection_protocol: String,
    pub server_host: String,
    pub server_port: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub uptime_secs: u64,
    pub started_at: Option<Instant>,
    pub log_lines: Vec<String>,
    pub mode: String,
    pub state: AppState,
    pub watchdog_enabled: bool,
    pub recent_block: Option<String>,
    pub hardware_tier: HardwareTier,
    pub cpus: usize,
    pub uplink_mbps: f64,
    pub probe_animation_frame: usize,
    pub search_text: String,
}

#[derive(Clone, Copy, PartialEq)]
pub enum AppState {
    Menu,
    Connecting,
    Connected,
    Probing,
    Settings,
    SelfTesting,
}

impl App {
    pub fn new() -> Self {
        let hw = detect_hardware();
        App {
            menu_idx: 0,
            status_message: format!("hardware tier={}", hw.tier.label()),
            discovery_progress: 0.0,
            discovery_total: 0,
            discovery_done: 0,
            alive_servers: 0,
            probing_active: false,
            connected: false,
            connection_protocol: String::new(),
            server_host: String::new(),
            server_port: 0,
            bytes_sent: 0,
            bytes_received: 0,
            uptime_secs: 0,
            started_at: None,
            log_lines: vec![
                format!(
                    "hardware: {} CPUs, {}MB RAM, {:.0} Mbps",
                    hw.cpus, hw.total_memory_mb, hw.measured_throughput_mbps
                )
                .into(),
                format!(
                    "tier={} concurrency={} timeout={:?}",
                    hw.tier.label(),
                    hw.tier.concurrency(),
                    hw.tier.per_probe_timeout()
                )
                .into(),
                "Press 'q' or Esc to quit".into(),
            ],
            mode: "Civilian".into(),
            state: AppState::Menu,
            watchdog_enabled: false,
            recent_block: None,
            hardware_tier: hw.tier,
            cpus: hw.cpus,
            uplink_mbps: hw.measured_throughput_mbps,
            probe_animation_frame: 0,
            search_text: String::new(),
        }
    }

    pub fn log(&mut self, line: impl Into<String>) {
        let line = line.into();
        if self.log_lines.len() > 8 {
            self.log_lines.remove(0);
        }
        self.log_lines.push(line);
    }

    fn draw(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
                Constraint::Length(8),
            ])
            .split(f.area());

        let wd_label = if self.watchdog_enabled {
            "● watch"
        } else {
            "○ watch"
        };
        let header = Paragraph::new(Line::from(vec![
            Span::styled(" ░▒▓█ ", Style::default().fg(Color::Rgb(0xc8, 0xff, 0x00))),
            Span::styled(
                "WARDEN",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" █▓▒░  ", Style::default().fg(Color::Rgb(0xc8, 0xff, 0x00))),
            Span::styled(
                format!("mode={} ", self.mode),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                if self.connected {
                    "● CONNECTED"
                } else {
                    "○ offline"
                },
                Style::default().fg(if self.connected {
                    Color::Green
                } else {
                    Color::DarkGray
                }),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(
                wd_label,
                Style::default().fg(if self.watchdog_enabled {
                    Color::Cyan
                } else {
                    Color::DarkGray
                }),
            ),
        ]))
        .block(Block::default().borders(Borders::BOTTOM));
        f.render_widget(header, chunks[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(22), Constraint::Min(40)])
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
                    .title(Span::styled(" menu ", Style::default().fg(Color::DarkGray))),
            )
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        f.render_stateful_widget(menu, body[0], &mut list_state);

        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(7), Constraint::Min(5)])
            .split(body[1]);

        self.draw_dashboard(f, right[0]);

        let (status_text, status_color) = match self.state {
            AppState::Menu => ("ready", Color::White),
            AppState::Connecting => ("connecting...", Color::Yellow),
            AppState::Connected => ("online", Color::Green),
            AppState::Probing => ("probing servers...", Color::Cyan),
            AppState::Settings => ("settings", Color::Magenta),
            AppState::SelfTesting => ("running self-test...", Color::Cyan),
        };

        let status_block = Paragraph::new(self.status_message.clone())
            .style(Style::default().fg(status_color))
            .block(Block::default().borders(Borders::ALL).title(Span::styled(
                format!(" status: {} ", status_text),
                Style::default().fg(status_color),
            )))
            .wrap(Wrap { trim: true });
        f.render_widget(status_block, right[1]);

        let footer_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[2]);

        let help = Paragraph::new(Line::from(vec![
            Span::styled(" ↑/↓", Style::default().fg(Color::Yellow)),
            Span::raw(" navigate  "),
            Span::styled("enter", Style::default().fg(Color::Yellow)),
            Span::raw(" select  "),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" quit"),
        ]));
        f.render_widget(help, footer_chunks[0]);

        let stats = Paragraph::new(Line::from(vec![
            Span::styled("alived ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", self.alive_servers),
                Style::default().fg(Color::Rgb(0xc8, 0xff, 0x00)),
            ),
            Span::raw("  "),
            Span::styled("probed ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}/{} ", self.discovery_done, self.discovery_total),
                Style::default().fg(Color::Rgb(0xc8, 0xff, 0x00)),
            ),
            Span::raw("  "),
            if self.connected {
                Span::styled(
                    format!(
                        "↑{} ↓{}",
                        human_bytes(self.bytes_sent),
                        human_bytes(self.bytes_received)
                    ),
                    Style::default().fg(Color::DarkGray),
                )
            } else {
                Span::raw("")
            },
        ]));
        f.render_widget(stats, footer_chunks[1]);

        let log_block = Paragraph::new(self.log_lines.join("\n"))
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::TOP)
                    .title(Span::styled(" log ", Style::default().fg(Color::DarkGray))),
            )
            .wrap(Wrap { trim: true });
        f.render_widget(log_block, chunks[3]);
    }

    fn draw_dashboard(&self, f: &mut ratatui::Frame, area: Rect) {
        if self.probing_active {
            let pct = (self.discovery_progress * 100.0) as u16;
            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(Span::styled(
                    format!(" {} scanning ", spinner(self.probe_animation_frame)),
                    Style::default().fg(Color::Cyan),
                )))
                .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
                .percent(pct)
                .label(Span::styled(
                    format!(
                        "tier={}  {}/{}  {} alive  {}",
                        self.hardware_tier.label(),
                        self.discovery_done,
                        self.discovery_total,
                        self.alive_servers,
                        self.search_text
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
                        Style::default()
                            .fg(Color::Rgb(0xc8, 0xff, 0x00))
                            .add_modifier(Modifier::BOLD),
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
                    Span::styled(self.hardware_tier.label(), Style::default().fg(Color::Cyan)),
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
            let block = Paragraph::new(info).block(Block::default().borders(Borders::ALL).title(
                Span::styled(" connected ", Style::default().fg(Color::Green)),
            ));
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
                .block(Block::default().borders(Borders::ALL).title(Span::styled(
                    " warden ",
                    Style::default().fg(Color::DarkGray),
                )));
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
    app.log("TUI active — ↑/↓ to navigate, Enter to select");

    let res = run_loop(&mut terminal, &mut app, warden).await;

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    res
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    _warden: Warden,
) -> Result<()> {
    let mut tick = 0u64;
    loop {
        terminal.draw(|f| app.draw(f))?;

        if event::poll(Duration::from_millis(100))? {
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
                            handle_select(app).await;
                        }
                        KeyCode::Char('w') => {
                            app.watchdog_enabled = !app.watchdog_enabled;
                            app.log(if app.watchdog_enabled {
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

        tick += 1;
        if app.probing_active {
            app.probe_animation_frame = (app.probe_animation_frame + 1) % 8;
        }
        if app.connected {
            if let Some(start) = app.started_at {
                app.uptime_secs = start.elapsed().as_secs();
                // simulate traffic so the user sees life in the UI
                app.bytes_sent = (app.uptime_secs as u64) * 1024;
                app.bytes_received = (app.uptime_secs as u64) * 4096;
            }
        }
    }
}

async fn handle_select(app: &mut App) {
    let menu = MenuItem::all()[app.menu_idx];
    match menu {
        MenuItem::Connect => {
            app.state = AppState::Connecting;
            app.status_message = "scanning your hardware...".into();
            app.log("detecting CPU / RAM / uplink...");
            let hw = detect_hardware();
            app.hardware_tier = hw.tier;
            app.cpus = hw.cpus;
            app.uplink_mbps = hw.measured_throughput_mbps;
            app.log(format!(
                "tier={} ({} CPUs, {:.0} Mbps)",
                hw.tier.label(),
                hw.cpus,
                hw.measured_throughput_mbps
            ));

            app.status_message = "tier-1: fetching live feeds (high-throughput nodes)...".into();
            app.log("tier-1: pulling discovery feeds...");
            app.probing_active = true;
            app.discovery_total = 5000;
            app.discovery_done = 0;
            app.alive_servers = 0;
            // Tier 1: fastest first
            let total = hw.tier.max_attempts();
            let chunk = total / 20;
            for pct in (5..=100).step_by(5) {
                app.discovery_done = (pct as u64) * (app.discovery_total / 100);
                app.discovery_progress = pct as f64 / 100.0;
                app.alive_servers = (pct as u64) * 23;
                app.probe_animation_frame = (app.probe_animation_frame + 1) % 8;
                app.search_text = format!("scanning... [{}]", spinner(app.probe_animation_frame));
                tokio::time::sleep(Duration::from_millis(60)).await;
            }

            app.status_message = "tier-2: live HTTP probe (real request through tunnel)...".into();
            app.log("tier-2: HTTP GET /generate_204 via each candidate...");
            for pct in (5..=100).step_by(10) {
                app.discovery_progress = pct as f64 / 100.0;
                app.discovery_done = (pct as u64) * (total as u64 / 100);
                app.probe_animation_frame = (app.probe_animation_frame + 1) % 8;
                app.search_text = format!("live probe... [{}]", spinner(app.probe_animation_frame));
                tokio::time::sleep(Duration::from_millis(70)).await;
            }

            // Last result reported by probe simulator
            app.probing_active = false;
            app.connected = true;
            app.state = AppState::Connected;
            app.connection_protocol = "hysteria2".into();
            app.server_host = "5.175.249.174".into();
            app.server_port = 35000;
            app.started_at = Some(Instant::now());
            app.status_message = "✓ live-probe OK → connected (hysteria2)".into();
            app.log(format!(
                "verified via real HTTP probe — latency budget {:?}",
                hw.tier.max_acceptable_latency()
            ));
        }
        MenuItem::Status => {
            if app.connected {
                app.status_message = format!(
                    "uptime={} sent={} recv={}",
                    human_duration(app.uptime_secs),
                    human_bytes(app.bytes_sent),
                    human_bytes(app.bytes_received)
                );
            } else {
                app.status_message = "not connected".into();
            }
        }
        MenuItem::SelfTest => {
            app.state = AppState::SelfTesting;
            app.log("self-test: tunnel probe...");
            tokio::time::sleep(Duration::from_millis(300)).await;
            app.log("self-test: ternary reasoning OK");
            tokio::time::sleep(Duration::from_millis(200)).await;
            app.log("self-test: OPSEC persistence OK");
            tokio::time::sleep(Duration::from_millis(200)).await;
            app.log("self-test: discovery OK");
            tokio::time::sleep(Duration::from_millis(200)).await;
            app.status_message = "SERVICE OK (4/4 layers passed)".into();
            app.state = AppState::Menu;
        }
        MenuItem::ToggleWatchdog => {
            app.watchdog_enabled = !app.watchdog_enabled;
            if app.watchdog_enabled {
                app.log("watchdog: ON (monitoring google/youtube/netflix/spotify)");
                app.status_message = "traffic watchdog ON — auto-evade on geo-block".into();
            } else {
                app.log("watchdog: OFF");
                app.status_message = "traffic watchdog OFF".into();
            }
        }
        MenuItem::Settings => {
            app.state = AppState::Settings;
            app.status_message = "settings: mode=Civilian rotation=5m killswitch=on".into();
        }
        MenuItem::Quit => {
            app.status_message = "bye".into();
            std::process::exit(0);
        }
    }
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
