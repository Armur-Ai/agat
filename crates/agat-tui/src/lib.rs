//! Ratatui shell for agat.
//!
//! Phase 2: tabs over the right pane (Overview, Disasm). Sample
//! browser on the left, tabbed analyzer view on the right. Disasm
//! pane shows arch/section info and the first ~40 instructions of
//! the listing, colored by control-flow kind.

use agat_core::{SampleId, Vault};
use agat_disasm::{DisasmFeatures, FlowKind};
use agat_static::StaticFeatures;
use agat_store::{Store, StoredSample};
use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use std::collections::HashMap;
use std::io;
use std::time::Duration;

pub fn run(_vault: Vault, store: Store) -> Result<()> {
    let samples = store.list_samples()?;
    let mut static_features: HashMap<SampleId, StaticFeatures> = HashMap::new();
    let mut disasm_features: HashMap<SampleId, DisasmFeatures> = HashMap::new();
    for s in &samples {
        if let Ok(Some(rec)) = store.get_features(&s.sample.id, "static") {
            if let Ok(sf) = serde_json::from_value::<StaticFeatures>(rec.features) {
                static_features.insert(s.sample.id, sf);
            }
        }
        if let Ok(Some(rec)) = store.get_features(&s.sample.id, "disasm") {
            if let Ok(df) = serde_json::from_value::<DisasmFeatures>(rec.features) {
                disasm_features.insert(s.sample.id, df);
            }
        }
    }
    let mut app = App::new(samples, static_features, disasm_features);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Disasm,
}

impl Tab {
    fn index(self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Disasm => 1,
        }
    }
    fn cycle(self) -> Tab {
        match self {
            Tab::Overview => Tab::Disasm,
            Tab::Disasm => Tab::Overview,
        }
    }
}

struct App {
    samples: Vec<StoredSample>,
    static_features: HashMap<SampleId, StaticFeatures>,
    disasm_features: HashMap<SampleId, DisasmFeatures>,
    list_state: ListState,
    active_tab: Tab,
}

impl App {
    fn new(
        samples: Vec<StoredSample>,
        static_features: HashMap<SampleId, StaticFeatures>,
        disasm_features: HashMap<SampleId, DisasmFeatures>,
    ) -> Self {
        let mut list_state = ListState::default();
        if !samples.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            samples,
            static_features,
            disasm_features,
            list_state,
            active_tab: Tab::Overview,
        }
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

    fn selected_static(&self) -> Option<&StaticFeatures> {
        self.selected()
            .and_then(|s| self.static_features.get(&s.sample.id))
    }

    fn selected_disasm(&self) -> Option<&DisasmFeatures> {
        self.selected()
            .and_then(|s| self.disasm_features.get(&s.sample.id))
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
                    KeyCode::Char('1') => app.active_tab = Tab::Overview,
                    KeyCode::Char('2') => app.active_tab = Tab::Disasm,
                    KeyCode::Tab => app.active_tab = app.active_tab.cycle(),
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

    let analyzed = app.static_features.len();
    let with_disasm = app.disasm_features.len();
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
            format!(
                "{} samples · {} analyzed · {} disasm",
                app.samples.len(),
                analyzed,
                with_disasm
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(40), Constraint::Min(0)])
        .split(chunks[1]);

    // Sample list (left)
    let items: Vec<ListItem> = if app.samples.is_empty() {
        vec![ListItem::new(Span::styled(
            "(no samples ingested yet)",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        app.samples
            .iter()
            .map(|s| {
                let has_analysis = app.static_features.contains_key(&s.sample.id);
                let marker = if has_analysis { "●" } else { "○" };
                let marker_color = if has_analysis {
                    Color::Green
                } else {
                    Color::DarkGray
                };
                ListItem::new(Line::from(vec![
                    Span::styled(marker, Style::default().fg(marker_color)),
                    Span::raw(" "),
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

    // Right pane: tabs + content
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(body[1]);

    let tab_titles = vec![Line::from(" Overview "), Line::from(" Disasm ")];
    let tabs = Tabs::new(tab_titles)
        .select(app.active_tab.index())
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");
    f.render_widget(tabs, right_chunks[0]);

    let content_lines = match app.active_tab {
        Tab::Overview => build_overview(app),
        Tab::Disasm => build_disasm(app),
    };
    let content_block = Block::default().borders(Borders::ALL);
    let content = Paragraph::new(content_lines)
        .block(content_block)
        .wrap(Wrap { trim: false });
    f.render_widget(content, right_chunks[1]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" j/k ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" navigate    "),
        Span::styled(" 1/2/Tab ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" switch tab    "),
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" quit "),
    ]));
    f.render_widget(footer, chunks[2]);
}

fn build_overview(app: &App) -> Vec<Line<'static>> {
    let Some(s) = app.selected() else {
        return vec![Line::from(Span::styled(
            "Ingest samples with `agat ingest <path>` to populate the vault.",
            Style::default().fg(Color::DarkGray),
        ))];
    };

    let mut lines = vec![
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
    ];

    let Some(f) = app.selected_static() else {
        lines.push(Line::from(Span::styled(
            format!(
                "(no analyzer features yet — run `agat analyze {}`)",
                s.sample.id.short()
            ),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
        return lines;
    };

    lines.push(section_header("static analysis"));
    lines.push(kv(
        "format",
        format!("{} / {} / {}-bit", f.parsed.format, f.parsed.arch, f.parsed.bits),
    ));
    lines.push(kv("entry", format!("0x{:08x}", f.parsed.entry_point)));
    lines.push(kv("md5", f.hashes.md5.clone()));
    if let Some(imphash) = &f.hashes.imphash {
        lines.push(kv("imphash", imphash.clone()));
    }
    lines.push(kv(
        "entropy",
        format!(
            "{:.3} overall · {} high regions",
            f.entropy.overall,
            f.entropy.high_entropy_regions.len()
        ),
    ));
    lines.push(kv(
        "strings",
        format!(
            "{} ASCII · {} UTF-16LE",
            f.strings.ascii_count, f.strings.utf16le_count
        ),
    ));

    if let Some(df) = app.selected_disasm() {
        if df.bitness > 0 {
            lines.push(kv(
                "disasm",
                format!(
                    "{} ins · {} blocks · ~{} fns",
                    df.instruction_count, df.block_count, df.function_estimate
                ),
            ));
        }
    }

    if !f.parsed.sections.is_empty() {
        lines.push(Line::from(""));
        lines.push(section_header(&format!(
            "sections ({})",
            f.parsed.sections.len()
        )));
        for sect in f.parsed.sections.iter().take(10) {
            let rwx = format!(
                "{}{}{}",
                if sect.characteristics.readable { "R" } else { "-" },
                if sect.characteristics.writable { "W" } else { "-" },
                if sect.characteristics.executable {
                    "X"
                } else {
                    "-"
                },
            );
            lines.push(Line::from(format!(
                "  {:<16} {}  ent {:>4.2}  {:>8} bytes",
                sect.name, rwx, sect.entropy, sect.file_size
            )));
        }
        if f.parsed.sections.len() > 10 {
            lines.push(Line::from(format!(
                "  ... +{} more",
                f.parsed.sections.len() - 10
            )));
        }
    }

    if !f.parsed.imports.is_empty() {
        lines.push(Line::from(""));
        lines.push(section_header(&format!(
            "imports ({})",
            f.parsed.imports.len()
        )));
        for imp in f.parsed.imports.iter().take(10) {
            let lib = if imp.library.is_empty() {
                "<elf>".to_string()
            } else {
                imp.library.clone()
            };
            lines.push(Line::from(format!("  {}: {}", lib, imp.name)));
        }
        if f.parsed.imports.len() > 10 {
            lines.push(Line::from(format!(
                "  ... +{} more",
                f.parsed.imports.len() - 10
            )));
        }
    }

    lines
}

fn build_disasm(app: &App) -> Vec<Line<'static>> {
    let Some(s) = app.selected() else {
        return vec![Line::from(Span::styled(
            "(no sample selected)",
            Style::default().fg(Color::DarkGray),
        ))];
    };
    let Some(df) = app.selected_disasm() else {
        return vec![Line::from(Span::styled(
            format!(
                "(no disasm features — run `agat analyze {}`)",
                s.sample.id.short()
            ),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        ))];
    };

    if df.bitness == 0 {
        return vec![
            kv("arch", df.arch.to_string()),
            Line::from(""),
            Line::from(Span::styled(
                "(architecture not supported by Phase 2 disasm; need x86/x64)",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )),
        ];
    }

    let mut lines = vec![
        kv("arch", format!("{} ({}-bit)", df.arch, df.bitness)),
        kv(
            "section",
            df.disassembled_section
                .clone()
                .unwrap_or_else(|| "-".into()),
        ),
        kv("base", format!("0x{:08x}", df.section_base)),
        kv("instructions", df.instruction_count.to_string()),
        kv("blocks", df.block_count.to_string()),
        kv("~functions", df.function_estimate.to_string()),
    ];

    if !df.opcode_histogram.is_empty() {
        let mut hist: Vec<(&String, &usize)> = df.opcode_histogram.iter().collect();
        hist.sort_by(|a, b| b.1.cmp(a.1));
        let preview: Vec<String> = hist
            .iter()
            .take(6)
            .map(|(m, c)| format!("{} ({})", m, c))
            .collect();
        lines.push(kv("top opcodes", preview.join(", ")));
    }

    if df.listing_preview.is_empty() {
        return lines;
    }

    lines.push(Line::from(""));
    lines.push(section_header(&format!(
        "listing (first {})",
        df.listing_preview.len().min(40)
    )));
    for l in df.listing_preview.iter().take(40) {
        let mnem_style = match l.flow {
            FlowKind::Branch | FlowKind::Jump => Style::default().fg(Color::Yellow),
            FlowKind::Call => Style::default().fg(Color::Magenta),
            FlowKind::Return => Style::default().fg(Color::Red),
            FlowKind::Indirect => Style::default().fg(Color::Yellow),
            FlowKind::Invalid => Style::default().fg(Color::Red),
            FlowKind::Next => Style::default(),
        };
        let bytes_col = if l.bytes_hex.len() > 14 {
            format!("{}…", &l.bytes_hex[..13])
        } else {
            format!("{:<14}", l.bytes_hex)
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("0x{:08x}  ", l.address),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(bytes_col, Style::default().fg(Color::Cyan)),
            Span::raw("  "),
            Span::styled(
                format!("{:<8}", l.mnemonic),
                mnem_style.add_modifier(Modifier::BOLD),
            ),
            Span::styled(l.operands.clone(), Style::default().fg(Color::White)),
        ]));
    }

    lines
}

fn section_header(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("── {} ──", text),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn kv(key: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{:<11}", key),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(value.into()),
    ])
}
