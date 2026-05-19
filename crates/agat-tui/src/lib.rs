//! Ratatui shell for agat.
//!
//! Phase 0: a minimal sample browser. Left pane is a scrollable list
//! of ingested samples; right pane shows basic overview metadata for
//! the selected sample. Future phases bolt on analyzer-specific tabs
//! (Disasm, Entropy, Strings, AI-Signals, Variants).

use agat_core::Vault;
use agat_store::{Store, StoredSample};
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::time::Duration;

pub fn run(_vault: Vault, store: Store) -> Result<()> {
    let samples = store.list_samples()?;
    let mut app = App::new(samples);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

struct App {
    samples: Vec<StoredSample>,
    list_state: ListState,
}

impl App {
    fn new(samples: Vec<StoredSample>) -> Self {
        let mut list_state = ListState::default();
        if !samples.is_empty() {
            list_state.select(Some(0));
        }
        Self { samples, list_state }
    }

    fn next(&mut self) {
        if self.samples.is_empty() {
            return;
        }
        let i = self
            .list_state
            .selected()
            .map(|i| (i + 1) % self.samples.len())
            .unwrap_or(0);
        self.list_state.select(Some(i));
    }

    fn prev(&mut self) {
        if self.samples.is_empty() {
            return;
        }
        let i = self
            .list_state
            .selected()
            .map(|i| if i == 0 { self.samples.len() - 1 } else { i - 1 })
            .unwrap_or(0);
        self.list_state.select(Some(i));
    }

    fn selected(&self) -> Option<&StoredSample> {
        self.list_state.selected().and_then(|i| self.samples.get(i))
    }
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.prev(),
                    _ => {}
                }
            }
        }
    }
}

fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " agat ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{} samples", app.samples.len()),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(40), Constraint::Min(0)])
        .split(chunks[1]);

    let items: Vec<ListItem> = if app.samples.is_empty() {
        vec![ListItem::new(Span::styled(
            "(no samples ingested yet)",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        app.samples
            .iter()
            .map(|s| {
                ListItem::new(Line::from(vec![
                    Span::styled(s.sample.id.short(), Style::default().fg(Color::Yellow)),
                    Span::raw("  "),
                    Span::styled(
                        format!("{:<9}", s.sample.kind),
                        Style::default().fg(Color::Green),
                    ),
                ]))
            })
            .collect()
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" samples "))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    let mut state = app.list_state.clone();
    f.render_stateful_widget(list, body[0], &mut state);

    let detail_block = Block::default().borders(Borders::ALL).title(" overview ");
    let detail_text: Vec<Line<'static>> = match app.selected() {
        Some(s) => vec![
            kv("sha256", s.sample.id.to_hex()),
            kv("kind", s.sample.kind.to_string()),
            kv("size", format!("{} bytes", s.sample.size)),
            kv(
                "filename",
                s.sample
                    .metadata
                    .original_filename
                    .clone()
                    .unwrap_or_else(|| "-".into()),
            ),
            kv(
                "ingested",
                s.ingested_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            ),
            Line::from(""),
            Line::from(Span::styled(
                "Phase 1+ analyzer panes coming. For now agat-tui only shows ingest state.",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )),
        ],
        None => vec![Line::from(Span::styled(
            "Ingest samples with `agat ingest <path>` to populate the vault.",
            Style::default().fg(Color::DarkGray),
        ))],
    };
    let detail = Paragraph::new(detail_text)
        .block(detail_block)
        .wrap(Wrap { trim: false });
    f.render_widget(detail, body[1]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            " j/k ",
            Style::default().fg(Color::Black).bg(Color::Gray),
        ),
        Span::raw(" navigate    "),
        Span::styled(
            " q ",
            Style::default().fg(Color::Black).bg(Color::Gray),
        ),
        Span::raw(" quit "),
    ]));
    f.render_widget(footer, chunks[2]);
}

fn kv(key: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{:<10}", key),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(value.into()),
    ])
}
