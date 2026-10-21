//! Ratatui shell for agat.
//!
//! Phase 2: tabs over the right pane (Overview, Disasm). Sample
//! browser on the left, tabbed analyzer view on the right. Disasm
//! pane shows arch/section info and the first ~40 instructions of
//! the listing, colored by control-flow kind.

use agat_ai::AiFeatures;
use agat_core::{SampleId, Vault};
use agat_disasm::{DisasmFeatures, FlowKind};
use agat_meta::MetaFeatures;
use agat_poly::{PolyFeatures, Signal};
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
    let mut poly_features: HashMap<SampleId, PolyFeatures> = HashMap::new();
    let mut meta_features: HashMap<SampleId, MetaFeatures> = HashMap::new();
    let mut ai_features: HashMap<SampleId, AiFeatures> = HashMap::new();
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
        if let Ok(Some(rec)) = store.get_features(&s.sample.id, "poly") {
            if let Ok(pf) = serde_json::from_value::<PolyFeatures>(rec.features) {
                poly_features.insert(s.sample.id, pf);
            }
        }
        if let Ok(Some(rec)) = store.get_features(&s.sample.id, "meta") {
            if let Ok(mf) = serde_json::from_value::<MetaFeatures>(rec.features) {
                meta_features.insert(s.sample.id, mf);
            }
        }
        if let Ok(Some(rec)) = store.get_features(&s.sample.id, "ai") {
            if let Ok(af) = serde_json::from_value::<AiFeatures>(rec.features) {
                ai_features.insert(s.sample.id, af);
            }
        }
    }
    let mut app = App::new(
        samples,
        static_features,
        disasm_features,
        poly_features,
        meta_features,
        ai_features,
    );

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
    Poly,
    Meta,
    Ai,
}

impl Tab {
    fn index(self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Disasm => 1,
            Tab::Poly => 2,
            Tab::Meta => 3,
            Tab::Ai => 4,
        }
    }
    fn cycle(self) -> Tab {
        match self {
            Tab::Overview => Tab::Disasm,
            Tab::Disasm => Tab::Poly,
            Tab::Poly => Tab::Meta,
            Tab::Meta => Tab::Ai,
            Tab::Ai => Tab::Overview,
        }
    }
}

struct App {
    samples: Vec<StoredSample>,
    static_features: HashMap<SampleId, StaticFeatures>,
    disasm_features: HashMap<SampleId, DisasmFeatures>,
    poly_features: HashMap<SampleId, PolyFeatures>,
    meta_features: HashMap<SampleId, MetaFeatures>,
    ai_features: HashMap<SampleId, AiFeatures>,
    list_state: ListState,
    active_tab: Tab,
}

impl App {
    fn new(
        samples: Vec<StoredSample>,
        static_features: HashMap<SampleId, StaticFeatures>,
        disasm_features: HashMap<SampleId, DisasmFeatures>,
        poly_features: HashMap<SampleId, PolyFeatures>,
        meta_features: HashMap<SampleId, MetaFeatures>,
        ai_features: HashMap<SampleId, AiFeatures>,
    ) -> Self {
        let mut list_state = ListState::default();
        if !samples.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            samples,
            static_features,
            disasm_features,
            poly_features,
            meta_features,
            ai_features,
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
            .map(|i| {
                if i == 0 {
                    self.samples.len() - 1
                } else {
                    i - 1
                }
            })
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

    fn selected_poly(&self) -> Option<&PolyFeatures> {
        self.selected()
            .and_then(|s| self.poly_features.get(&s.sample.id))
    }

    fn selected_meta(&self) -> Option<&MetaFeatures> {
        self.selected()
            .and_then(|s| self.meta_features.get(&s.sample.id))
    }

    fn selected_ai(&self) -> Option<&AiFeatures> {
        self.selected()
            .and_then(|s| self.ai_features.get(&s.sample.id))
    }

    /// Other samples that share this sample's CFG fingerprint.
    fn meta_cluster(&self, this: SampleId) -> Vec<&StoredSample> {
        let Some(this_meta) = self.meta_features.get(&this) else {
            return vec![];
        };
        if !this_meta.has_fingerprint() {
            return vec![];
        }
        let mut out = Vec::new();
        for s in &self.samples {
            if s.sample.id == this {
                continue;
            }
            if let Some(m) = self.meta_features.get(&s.sample.id) {
                if m.cfg_fingerprint == this_meta.cfg_fingerprint {
                    out.push(s);
                }
            }
        }
        out
    }
}

fn run_loop<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
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
                    KeyCode::Char('3') => app.active_tab = Tab::Poly,
                    KeyCode::Char('4') => app.active_tab = Tab::Meta,
                    KeyCode::Char('5') => app.active_tab = Tab::Ai,
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
    let poly_hits = app
        .poly_features
        .values()
        .filter(|p| p.is_polymorphic())
        .count();
    // Count distinct meta fingerprints (treats families)
    let mut seen_fps = std::collections::HashSet::new();
    let mut families = 0;
    for m in app.meta_features.values() {
        if m.has_fingerprint() && seen_fps.insert(m.cfg_fingerprint.clone()) {
            families += 1;
        }
    }
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
                "{} samples · {} analyzed · {} disasm · {} poly-hit · {} families",
                app.samples.len(),
                analyzed,
                with_disasm,
                poly_hits,
                families
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

    let tab_titles = vec![
        Line::from(" Overview "),
        Line::from(" Disasm "),
        Line::from(" Poly "),
        Line::from(" Meta "),
        Line::from(" AI "),
    ];
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
        Tab::Poly => build_poly(app),
        Tab::Meta => build_meta(app),
        Tab::Ai => build_ai(app),
    };
    let content_block = Block::default().borders(Borders::ALL);
    let content = Paragraph::new(content_lines)
        .block(content_block)
        .wrap(Wrap { trim: false });
    f.render_widget(content, right_chunks[1]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" j/k ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" navigate    "),
        Span::styled(
            " 1/2/3/4/5/Tab ",
            Style::default().fg(Color::Black).bg(Color::Gray),
        ),
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
        format!(
            "{} / {} / {}-bit",
            f.parsed.format, f.parsed.arch, f.parsed.bits
        ),
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
                if sect.characteristics.readable {
                    "R"
                } else {
                    "-"
                },
                if sect.characteristics.writable {
                    "W"
                } else {
                    "-"
                },
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

fn build_poly(app: &App) -> Vec<Line<'static>> {
    let Some(s) = app.selected() else {
        return vec![Line::from(Span::styled(
            "(no sample selected)",
            Style::default().fg(Color::DarkGray),
        ))];
    };
    let Some(p) = app.selected_poly() else {
        return vec![Line::from(Span::styled(
            format!(
                "(no poly features — run `agat analyze {}`)",
                s.sample.id.short()
            ),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        ))];
    };

    let verdict_style = if p.is_polymorphic() {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    let verdict = if p.is_polymorphic() {
        "LIKELY POLYMORPHIC"
    } else {
        "no strong signal"
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{:<11}", "verdict"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(verdict, verdict_style),
        ]),
        kv("confidence", format!("{:.2}", p.confidence)),
        Line::from(""),
        section_header(&format!("signals ({})", p.signals.len())),
    ];

    if p.signals.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (none)",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for s in &p.signals {
            match s {
                Signal::EntropyBoundary {
                    boundary_offset,
                    before_entropy,
                    after_entropy,
                } => lines.push(Line::from(format!(
                    "  entropy boundary at 0x{:08x}  {:.2} → {:.2}",
                    boundary_offset, before_entropy, after_entropy
                ))),
                Signal::BackwardJumpInPrelude { from, to } => lines.push(Line::from(format!(
                    "  backward jump  0x{:08x} → 0x{:08x}",
                    from, to
                ))),
                Signal::DecryptorLoop {
                    op,
                    instruction_address,
                    key,
                } => {
                    let key_str = match key {
                        Some(k) => format!("key 0x{:02x}", k),
                        None => "key unknown (register source)".to_string(),
                    };
                    lines.push(Line::from(vec![
                        Span::raw("  decryptor loop at "),
                        Span::styled(
                            format!("0x{:08x}", instruction_address),
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::raw("  "),
                        Span::styled(
                            format!("{} byte", op.label()),
                            Style::default().fg(Color::Magenta),
                        ),
                        Span::raw("  "),
                        Span::raw(key_str),
                    ]));
                }
            }
        }
    }

    if let Some(rec) = &p.recovered {
        lines.push(Line::from(""));
        lines.push(section_header("recovered payload"));
        lines.push(kv(
            "region",
            format!(
                "0x{:08x}..0x{:08x}  ({} bytes)",
                rec.region_start, rec.region_end, rec.region_size
            ),
        ));
        lines.push(kv(
            "operation",
            format!("{} with 0x{:02x}", rec.operation.label(), rec.key),
        ));
        lines.push(kv(
            "entropy",
            format!(
                "{:.3} → {:.3}  (drop {:+.3})",
                rec.original_entropy, rec.decrypted_entropy, -rec.entropy_drop
            ),
        ));
        lines.push(kv("score", format!("{:.2}", rec.recovery_score)));
        if !rec.preview_hex.is_empty() {
            lines.push(Line::from(""));
            lines.push(section_header("hex preview"));
            for (i, chunk) in rec.preview_hex.as_bytes().chunks(32).enumerate().take(4) {
                let raw: String = chunk.iter().map(|&b| b as char).collect();
                let spaced = raw
                    .as_bytes()
                    .chunks(2)
                    .map(|c| std::str::from_utf8(c).unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join(" ");
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  0x{:04x}      ", i * 16),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(spaced, Style::default().fg(Color::Cyan)),
                ]));
            }
        }
        if !rec.recovered_strings.is_empty() {
            lines.push(Line::from(""));
            lines.push(section_header(&format!(
                "strings recovered ({})",
                rec.recovered_strings.len()
            )));
            for s in &rec.recovered_strings {
                let trunc: String = if s.len() > 70 {
                    format!("{}...", &s[..67])
                } else {
                    s.clone()
                };
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{:?}", trunc), Style::default().fg(Color::Green)),
                ]));
            }
        }
    } else if p.detected_pattern.is_some() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "(pattern detected but no high-entropy region to decrypt)",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
    }

    lines
}

fn build_meta(app: &App) -> Vec<Line<'static>> {
    let Some(s) = app.selected() else {
        return vec![Line::from(Span::styled(
            "(no sample selected)",
            Style::default().fg(Color::DarkGray),
        ))];
    };
    let Some(m) = app.selected_meta() else {
        return vec![Line::from(Span::styled(
            format!(
                "(no meta features — run `agat analyze {}`)",
                s.sample.id.short()
            ),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        ))];
    };

    if !m.has_fingerprint() {
        return vec![
            kv("blocks", "0"),
            Line::from(""),
            Line::from(Span::styled(
                "(no CFG fingerprint — sample is non-x86 or wasn't disassembled)",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )),
        ];
    }

    let cluster = app.meta_cluster(s.sample.id);
    let cluster_size = cluster.len() + 1;
    let cluster_label = if cluster_size > 1 {
        format!("{} members in family", cluster_size)
    } else {
        "singleton".to_string()
    };
    let cluster_color = if cluster_size > 1 {
        Color::Red
    } else {
        Color::DarkGray
    };

    let mut lines = vec![
        kv("fingerprint", m.cfg_fingerprint.clone()),
        Line::from(vec![
            Span::styled(
                format!("{:<11}", "cluster"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                cluster_label,
                Style::default()
                    .fg(cluster_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        kv("blocks", format!("{}", m.block_count)),
        kv("edges", format!("{}", m.edge_count)),
        kv(
            "instructions",
            format!(
                "{} → {} (after canonicalization)",
                m.instruction_count, m.normalized_instruction_count
            ),
        ),
    ];

    if cluster_size > 1 {
        lines.push(Line::from(""));
        lines.push(section_header(&format!(
            "family members ({})",
            cluster_size
        )));
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("● {}", s.sample.id.short()),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                s.sample
                    .metadata
                    .original_filename
                    .clone()
                    .unwrap_or_else(|| "-".into()),
                Style::default().fg(Color::Green),
            ),
            Span::styled("  (this sample)", Style::default().fg(Color::DarkGray)),
        ]));
        for other in cluster.iter().take(8) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    format!("● {}", other.sample.id.short()),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw("  "),
                Span::raw(
                    other
                        .sample
                        .metadata
                        .original_filename
                        .clone()
                        .unwrap_or_else(|| "-".into()),
                ),
            ]));
        }
    }

    if !m.canonical_preview.is_empty() {
        lines.push(Line::from(""));
        lines.push(section_header(&format!(
            "canonical form ({} instructions)",
            m.canonical_preview.len()
        )));
        for c in &m.canonical_preview {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    format!("{:<8} ", c.mnemonic),
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(c.operands.clone(), Style::default().fg(Color::White)),
            ]));
        }
    }

    lines
}

fn build_ai(app: &App) -> Vec<Line<'static>> {
    let Some(s) = app.selected() else {
        return vec![Line::from(Span::styled(
            "(no sample selected)",
            Style::default().fg(Color::DarkGray),
        ))];
    };
    let Some(a) = app.selected_ai() else {
        return vec![Line::from(Span::styled(
            format!(
                "(no AI features — run `agat analyze {}`)",
                s.sample.id.short()
            ),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        ))];
    };

    let (verdict, verdict_color) = if a.is_ai_rewritten() {
        ("LIKELY AI-REWRITTEN", Color::Red)
    } else {
        ("no strong AI signal", Color::Green)
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{:<14}", "verdict"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                verdict,
                Style::default()
                    .fg(verdict_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        kv("combined", format!("{:.2}", a.combined_score)),
        kv("stylometry", format!("{:.2}", a.signal_scores.stylometry)),
        kv("artifacts", format!("{:.2}", a.signal_scores.artifact_scan)),
        kv(
            "perplexity",
            match (&a.perplexity_result, a.signal_scores.perplexity) {
                (Some(r), Some(s)) => {
                    format!("{:.2}  (raw {:.1} via {})", s, r.value, r.backend.label())
                }
                (Some(r), None) => format!("raw {:.1} via {}", r.value, r.backend.label()),
                _ => "(corpus too small)".to_string(),
            },
        ),
    ];

    if !a.artifacts.is_empty() {
        lines.push(Line::from(""));
        lines.push(section_header(&format!(
            "artifacts ({})",
            a.artifacts.len()
        )));
        for hit in a.artifacts.iter().take(15) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    format!("[{:<14}]", hit.category.label()),
                    Style::default().fg(Color::Magenta),
                ),
                Span::raw("  "),
                Span::styled(hit.rule_name.clone(), Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("  @ 0x{:08x}", hit.offset),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }

    let s = &a.stylometry;
    lines.push(Line::from(""));
    lines.push(section_header("stylometry"));
    lines.push(kv(
        "  opcode div",
        format!("{:.3} bits", s.opcode_diversity),
    ));
    lines.push(kv("  mean block", format!("{:.2} ins", s.mean_block_size)));
    lines.push(kv(
        "  mean strlen",
        format!("{:.1} chars", s.mean_string_length),
    ));
    lines.push(kv("  underscore", format!("{:.3}", s.underscore_density)));
    lines.push(kv("  long strs", format!("{}", s.long_string_count)));

    if !s.llm_idiom_hits.is_empty() {
        lines.push(Line::from(""));
        lines.push(section_header(&format!(
            "LLM idioms ({})",
            s.llm_idiom_hits.len()
        )));
        for hit in s.llm_idiom_hits.iter().take(10) {
            let ctx_trim: String = hit.context.chars().take(56).collect();
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    hit.idiom.clone(),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  →  "),
                Span::styled(format!("{:?}", ctx_trim), Style::default().fg(Color::White)),
            ]));
        }
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
        Span::styled(format!("{:<11}", key), Style::default().fg(Color::DarkGray)),
        Span::raw(value.into()),
    ])
}
