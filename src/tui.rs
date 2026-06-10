//! Интерактивный текстовый интерфейс (флаг `--interactive`).
//!
//! Показывает графики скорости отправки/приёма пакетов (TX/RX) и список активных
//! соединений с типом, целью, IP-протоколом транспорта и объёмом трафика в каждую
//! сторону. Данные берутся из общего [`Stats`] (см. [`crate::stats`]); UI работает
//! на отдельном потоке и только читает счётчики, не вмешиваясь в работу туннеля.
//!
//! Выход - `q`, `Esc` или `Ctrl-C` (завершает процесс).

use crate::stats::{proto_name, ConnKind, Snapshot, Stats};
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table};
use ratatui::{Frame, Terminal};
use std::io::{self};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Неизменные за время работы сведения для заголовка.
pub struct Meta {
    pub mode: String,
    pub listen: String,
    pub server: String,
    pub protos: String,
}

/// Число точек в графиках скорости (примерно столько секунд истории).
const HIST: usize = 240;

struct App {
    stats: Arc<Stats>,
    meta: Meta,
    start: Instant,
    last: Snapshot,
    last_tick: Instant,
    tx_pps: Vec<u64>,
    rx_pps: Vec<u64>,
    cur_tx_pps: u64,
    cur_rx_pps: u64,
    cur_tx_bps: u64,
    cur_rx_bps: u64,
}

impl App {
    fn new(stats: Arc<Stats>, meta: Meta) -> App {
        let last = stats.snapshot();
        App {
            stats,
            meta,
            start: Instant::now(),
            last,
            last_tick: Instant::now(),
            tx_pps: Vec::new(),
            rx_pps: Vec::new(),
            cur_tx_pps: 0,
            cur_rx_pps: 0,
            cur_tx_bps: 0,
            cur_rx_bps: 0,
        }
    }

    /// Считывает кумулятивный снимок, переводит дельту в скорость за секунду и
    /// дописывает точку в графики.
    fn sample(&mut self) {
        let now = self.stats.snapshot();
        let dt = self.last_tick.elapsed().as_secs_f64().max(0.001);
        let d_sp = now.send_packet.saturating_sub(self.last.send_packet);
        let d_rp = now.recv_packet.saturating_sub(self.last.recv_packet);
        let d_ss = now.send_size.saturating_sub(self.last.send_size);
        let d_rs = now.recv_size.saturating_sub(self.last.recv_size);
        self.cur_tx_pps = (d_sp as f64 / dt) as u64;
        self.cur_rx_pps = (d_rp as f64 / dt) as u64;
        self.cur_tx_bps = (d_ss as f64 / dt) as u64;
        self.cur_rx_bps = (d_rs as f64 / dt) as u64;
        push(&mut self.tx_pps, self.cur_tx_pps);
        push(&mut self.rx_pps, self.cur_rx_pps);
        self.last = now;
        self.last_tick = Instant::now();
    }

    fn render(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4), // заголовок
                Constraint::Length(9), // графики
                Constraint::Min(3),    // соединения
                Constraint::Length(1), // подсказка
            ])
            .split(f.area());

        self.render_header(f, chunks[0]);
        self.render_graphs(f, chunks[1]);
        self.render_conns(f, chunks[2]);
        self.render_footer(f, chunks[3]);
    }

    fn render_header(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let total = self.stats.snapshot();
        let mut l1 = vec![
            Span::styled(
                "pingtunnel",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(format!("[{}]", self.meta.mode), Style::default().fg(Color::Yellow)),
            Span::raw(format!("  uptime {}", fmt_dur(self.start.elapsed()))),
            Span::raw(format!("  protos: {}", self.meta.protos)),
        ];
        if !self.meta.listen.is_empty() {
            l1.push(Span::raw(format!("  listen {}", self.meta.listen)));
        }
        if !self.meta.server.is_empty() {
            l1.push(Span::raw(format!("  server {}", self.meta.server)));
        }
        let l2 = Line::from(vec![
            Span::styled("TX ", Style::default().fg(Color::Green)),
            Span::raw(format!(
                "{} pkt  {}   ",
                total.send_packet,
                fmt_bytes(total.send_size)
            )),
            Span::styled("RX ", Style::default().fg(Color::Cyan)),
            Span::raw(format!(
                "{} pkt  {}",
                total.recv_packet,
                fmt_bytes(total.recv_size)
            )),
        ]);
        let p = Paragraph::new(vec![Line::from(l1), l2]).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" pingtunnel monitor "),
        );
        f.render_widget(p, area);
    }

    fn render_graphs(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        let tx = Sparkline::default()
            .block(Block::default().borders(Borders::ALL).title(format!(
                " TX  {} pkt/s  {}/s ",
                self.cur_tx_pps,
                fmt_bytes(self.cur_tx_bps)
            )))
            .data(&self.tx_pps)
            .style(Style::default().fg(Color::Green));
        f.render_widget(tx, cols[0]);

        let rx = Sparkline::default()
            .block(Block::default().borders(Borders::ALL).title(format!(
                " RX  {} pkt/s  {}/s ",
                self.cur_rx_pps,
                fmt_bytes(self.cur_rx_bps)
            )))
            .data(&self.rx_pps)
            .style(Style::default().fg(Color::Cyan));
        f.render_widget(rx, cols[1]);
    }

    fn render_conns(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let mut rows = self.stats.conns_snapshot();
        // Самые «тяжёлые» соединения - вверху.
        rows.sort_by(|a, b| {
            (b.send_bytes + b.recv_bytes).cmp(&(a.send_bytes + a.recv_bytes))
        });
        let n = rows.len();
        let table_rows: Vec<Row> = rows
            .into_iter()
            .map(|c| {
                let kind_style = match c.kind {
                    ConnKind::Tcp => Style::default().fg(Color::Magenta),
                    ConnKind::Udp => Style::default().fg(Color::Blue),
                    ConnKind::UdpReliable => Style::default().fg(Color::LightBlue),
                };
                Row::new(vec![
                    Cell::from(short_id(&c.id)),
                    Cell::from(c.kind.as_str()).style(kind_style),
                    Cell::from(c.target),
                    Cell::from(proto_name(c.proto)),
                    Cell::from(fmt_dur(Duration::from_secs(c.age_secs))),
                    Cell::from(fmt_bytes(c.send_bytes)).style(Style::default().fg(Color::Green)),
                    Cell::from(fmt_bytes(c.recv_bytes)).style(Style::default().fg(Color::Cyan)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(16),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(11),
            Constraint::Length(11),
        ];
        let table = Table::new(table_rows, widths)
            .header(
                Row::new(vec!["ID", "TYPE", "TARGET", "IP-PROTO", "AGE", "TX", "RX"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Connections: {n} ")),
            );
        f.render_widget(table, area);
    }

    fn render_footer(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let p = Paragraph::new(Line::from(vec![Span::styled(
            " q / Esc / Ctrl-C - выход ",
            Style::default().fg(Color::DarkGray),
        )]));
        f.render_widget(p, area);
    }
}

fn push(buf: &mut Vec<u64>, v: u64) {
    buf.push(v);
    if buf.len() > HIST {
        let drop = buf.len() - HIST;
        buf.drain(0..drop);
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Человекочитаемый размер: B/K/M/G.
fn fmt_bytes(n: u64) -> String {
    const K: f64 = 1024.0;
    let n = n as f64;
    if n < K {
        format!("{n:.0}B")
    } else if n < K * K {
        format!("{:.1}K", n / K)
    } else if n < K * K * K {
        format!("{:.1}M", n / (K * K))
    } else {
        format!("{:.2}G", n / (K * K * K))
    }
}

/// Длительность как HH:MM:SS или MM:SS.
fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}:{m:02}:{sec:02}")
    } else {
        format!("{m:02}:{sec:02}")
    }
}

/// Восстанавливает терминал из raw-режима/альт-экрана при выходе или панике.
struct TermGuard;
impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Запускает TUI-цикл (блокирующий). Вызывается в main, пока туннель крутится в
/// фоне на runtime tokio. `done` взводится фоновой задачей при завершении туннеля
/// (обычно при ошибке) - тогда цикл выходит и восстанавливает терминал.
pub fn run(stats: Arc<Stats>, meta: Meta, done: Arc<AtomicBool>) -> io::Result<()> {
    // Паник-хук восстанавливает терминал даже при panic=abort (хук вызывается до
    // аборта), иначе после паники в любом потоке экран остаётся изуродованным.
    let orig = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        orig(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _guard = TermGuard;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app = App::new(stats, meta);
    loop {
        if done.load(Ordering::SeqCst) {
            break;
        }
        terminal.draw(|f| app.render(f))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break,
                        _ => {}
                    }
                }
            }
        }
        if app.last_tick.elapsed() >= Duration::from_secs(1) {
            app.sample();
        }
    }
    Ok(())
}
