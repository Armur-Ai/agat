//! Ratatui shell for agat.
//!
//! Sample browser on the left, colored by each sample's verdict; tabbed
//! views on the right: the immune verdict (recognition, danger, model),
//! then each analyzer (overview, disassembly, polymorphic, metamorphic,
//! AI signals). Read-only over the store, so it needs no vault password.

use agat_ai::AiFeatures;
use agat_core::{SampleId, ScanResult, Severity};
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

pub fn run(store: Store) -> Result<()> {
    let samples = store.list_samples()?;
    // Verdicts from the active model, if one has been trained or imported.
    let model = agat_engine::ImmuneModel::load(&store).ok();
    let mut verdicts: HashMap<SampleId, ScanResult> = HashMap::new();
    if let Some(model) = &model {
        for s in &samples {
            if let Ok(map) = agat_engine::feature_map(&store, &s.sample.id) {
                let name = s.sample.metadata.original_filename.clone();
                if let Ok(r) = model.scan(&s.sample.id, name, &map) {
                    verdicts.insert(s.sample.id, r);
                }
            }
        }
    }
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
    let mut app = App::new(samples, verdicts, model.is_some());
    app.static_features = static_features;
    app.disasm_features = disasm_features;
    app.poly_features = poly_features;
    app.meta_features = meta_features;
    app.ai_features = ai_features;

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
    Immune,
    Overview,
    Disasm,
    Poly,
    Meta,
    Ai,
}

impl Tab {
    fn index(self) -> usize {
        match self {
            Tab::Immune => 0,
            Tab::Overview => 1,
            Tab::Disasm => 2,
            Tab::Poly => 3,
            Tab::Meta => 4,
            Tab::Ai => 5,
        }
    }
    fn cycle_back(self) -> Tab {
        match self {
            Tab::Immune => Tab::Ai,
            Tab::Overview => Tab::Immune,
            Tab::Disasm => Tab::Overview,
            Tab::Poly => Tab::Disasm,
            Tab::Meta => Tab::Poly,
            Tab::Ai => Tab::Meta,
        }
    }
    fn cycle(self) -> Tab {
        match self {
            Tab::Immune => Tab::Overview,
            Tab::Overview => Tab::Disasm,
            Tab::Disasm => Tab::Poly,
            Tab::Poly => Tab::Meta,
            Tab::Meta => Tab::Ai,
            Tab::Ai => Tab::Immune,
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
    verdicts: HashMap<SampleId, ScanResult>,
    has_model: bool,
    list_state: ListState,
    active_tab: Tab,
    /// Vertical scroll offset of the content pane.
    content_scroll: u16,
    /// Help overlay visible.
    show_help: bool,
    /// Live filter over the sample list; `None` unless search is active.
    filter: Option<String>,
}

impl App {
    /// An app over `samples` with their verdicts; the per-analyzer
    /// feature maps start empty and are filled in by the caller.
    fn new(
        samples: Vec<StoredSample>,
        verdicts: HashMap<SampleId, ScanResult>,
        has_model: bool,
    ) -> Self {
        let mut list_state = ListState::default();
        if !samples.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            samples,
            static_features: HashMap::new(),
            disasm_features: HashMap::new(),
            poly_features: HashMap::new(),
            meta_features: HashMap::new(),
            ai_features: HashMap::new(),
            verdicts,
            has_model,
            list_state,
            active_tab: Tab::Immune,
            content_scroll: 0,
            show_help: false,
            filter: None,
        }
    }

    /// Indices into `samples` that match the active filter (all of them
    /// when no filter is set), newest-first order preserved.
    fn visible(&self) -> Vec<usize> {
        match &self.filter {
            None => (0..self.samples.len()).collect(),
            Some(q) => {
                let q = q.to_ascii_lowercase();
                (0..self.samples.len())
                    .filter(|&i| {
                        let s = &self.samples[i];
                        s.sample.id.to_hex().contains(&q)
                            || s.sample
                                .metadata
                                .original_filename
                                .as_deref()
                                .map(|n| n.to_ascii_lowercase().contains(&q))
                                .unwrap_or(false)
                    })
                    .collect()
            }
        }
    }

    fn next(&mut self) {
        let n = self.visible().len();
        if n == 0 {
            return;
        }
        let i = self.list_state.selected().map(|i| (i + 1) % n).unwrap_or(0);
        self.list_state.select(Some(i));
        self.content_scroll = 0;
    }

    fn prev(&mut self) {
        let n = self.visible().len();
        if n == 0 {
            return;
        }
        let i = self
            .list_state
            .selected()
            .map(|i| if i == 0 { n - 1 } else { i - 1 })
            .unwrap_or(0);
        self.list_state.select(Some(i));
        self.content_scroll = 0;
    }

    /// The selected sample, mapped through the active filter.
    fn selected(&self) -> Option<&StoredSample> {
        let visible = self.visible();
        let pos = self.list_state.selected()?;
        visible.get(pos).map(|&i| &self.samples[i])
    }

    fn set_tab(&mut self, tab: Tab) {
        self.active_tab = tab;
        self.content_scroll = 0;
    }

    /// Clamp the list selection into the visible range (after filtering).
    fn clamp_selection(&mut self) {
        let n = self.visible().len();
        if n == 0 {
            self.list_state.select(None);
        } else {
            let i = self.list_state.selected().unwrap_or(0).min(n - 1);
            self.list_state.select(Some(i));
        }
    }

    fn selected_verdict(&self) -> Option<&ScanResult> {
        self.selected()
            .and_then(|s| self.verdicts.get(&s.sample.id))
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
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(());
                }
                // Search mode captures typing.
                if let Some(q) = app.filter.as_mut() {
                    match key.code {
                        KeyCode::Esc => {
                            app.filter = None;
                            app.clamp_selection();
                        }
                        KeyCode::Enter => {
                            if q.is_empty() {
                                app.filter = None;
                            }
                            app.clamp_selection();
                        }
                        KeyCode::Backspace => {
                            q.pop();
                            app.clamp_selection();
                        }
                        KeyCode::Char(c) => {
                            q.push(c);
                            app.clamp_selection();
                        }
                        _ => {}
                    }
                    continue;
                }
                if app.show_help {
                    // Any key dismisses help.
                    app.show_help = false;
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.prev(),
                    KeyCode::Char('/') => {
                        app.filter = Some(String::new());
                        app.list_state.select(Some(0));
                    }
                    KeyCode::Char('?') => app.show_help = true,
                    KeyCode::PageDown | KeyCode::Char(' ') => {
                        app.content_scroll = app.content_scroll.saturating_add(10)
                    }
                    KeyCode::PageUp => app.content_scroll = app.content_scroll.saturating_sub(10),
                    KeyCode::Char('J') => app.content_scroll = app.content_scroll.saturating_add(1),
                    KeyCode::Char('K') => app.content_scroll = app.content_scroll.saturating_sub(1),
                    KeyCode::Char('g') => app.content_scroll = 0,
                    KeyCode::Char('1') => app.set_tab(Tab::Immune),
                    KeyCode::Char('2') => app.set_tab(Tab::Overview),
                    KeyCode::Char('3') => app.set_tab(Tab::Disasm),
                    KeyCode::Char('4') => app.set_tab(Tab::Poly),
                    KeyCode::Char('5') => app.set_tab(Tab::Meta),
                    KeyCode::Char('6') => app.set_tab(Tab::Ai),
                    KeyCode::Tab => app.set_tab(app.active_tab.cycle()),
                    KeyCode::BackTab => app.set_tab(app.active_tab.cycle_back()),
                    KeyCode::Right | KeyCode::Char('l') => app.set_tab(app.active_tab.cycle()),
                    KeyCode::Left | KeyCode::Char('h') => app.set_tab(app.active_tab.cycle_back()),
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
    let tally = |sev: Severity| {
        app.verdicts
            .values()
            .filter(|r| r.severity() == sev)
            .count()
    };
    let verdict_summary = if app.has_model {
        format!(
            "  ·  {} malicious · {} suspicious · {} review · {} clean",
            tally(Severity::Malicious),
            tally(Severity::Suspicious),
            tally(Severity::Review),
            tally(Severity::Clean)
        )
    } else {
        "  ·  no model yet".to_string()
    };
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
        Span::styled(verdict_summary, Style::default().fg(Color::Gray)),
    ]));
    f.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(40), Constraint::Min(0)])
        .split(chunks[1]);

    // Sample list (left), filtered by the active search.
    let visible = app.visible();
    let items: Vec<ListItem> = if app.samples.is_empty() {
        vec![ListItem::new(Span::styled(
            "(no samples ingested yet)",
            Style::default().fg(Color::DarkGray),
        ))]
    } else if visible.is_empty() {
        vec![ListItem::new(Span::styled(
            "(no samples match)",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        visible
            .iter()
            .map(|&i| &app.samples[i])
            .map(|s| {
                let (marker, marker_color) = match app.verdicts.get(&s.sample.id) {
                    Some(r) => ("●", severity_color(r.severity())),
                    None if app.static_features.contains_key(&s.sample.id) => ("○", Color::Gray),
                    None => ("○", Color::DarkGray),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(marker, Style::default().fg(marker_color)),
                    Span::raw(" "),
                    Span::styled(s.sample.id.short(), Style::default().fg(Color::Yellow)),
                    Span::raw("  "),
                    Span::styled(
                        {
                            let name = s
                                .sample
                                .metadata
                                .original_filename
                                .as_deref()
                                .unwrap_or("-");
                            if name.chars().count() > 20 {
                                format!("{}…", name.chars().take(19).collect::<String>())
                            } else {
                                name.to_string()
                            }
                        },
                        Style::default().fg(Color::Gray),
                    ),
                ]))
            })
            .collect()
    };
    let list_title = match &app.filter {
        Some(q) => format!(" search: {q}▏ "),
        None => format!(" samples ({}) ", app.samples.len()),
    };
    let list_border = if app.filter.is_some() {
        Color::Cyan
    } else {
        Color::Reset
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(list_border))
                .title(list_title),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        )
        .highlight_symbol("▶ ");
    let mut state = app.list_state.clone();
    f.render_stateful_widget(list, body[0], &mut state);

    // Empty store: a logo splash instead of tabs.
    if app.samples.is_empty() {
        draw_empty_state(f, body[1]);
        let key = |k: &str| {
            Span::styled(
                format!(" {k} "),
                Style::default().fg(Color::Black).bg(Color::Gray),
            )
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![key("q"), Span::raw(" quit ")])),
            chunks[2],
        );
        return;
    }

    // Right pane: tabs + content
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(body[1]);

    let tab_titles = vec![
        Line::from(" Immune "),
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
        Tab::Immune => build_immune(app),
        Tab::Overview => build_overview(app),
        Tab::Disasm => build_disasm(app),
        Tab::Poly => build_poly(app),
        Tab::Meta => build_meta(app),
        Tab::Ai => build_ai(app),
    };
    let total_lines = content_lines.len() as u16;
    let view_h = right_chunks[1].height.saturating_sub(2);
    let max_scroll = total_lines.saturating_sub(view_h);
    let scroll = app.content_scroll.min(max_scroll);
    let scroll_hint = if max_scroll > 0 {
        format!(
            " {}–{}/{} ",
            scroll + 1,
            (scroll + view_h).min(total_lines),
            total_lines
        )
    } else {
        String::new()
    };
    let content_block = Block::default().borders(Borders::ALL).title(
        Line::from(Span::styled(
            scroll_hint,
            Style::default().fg(Color::DarkGray),
        ))
        .right_aligned(),
    );
    let content = Paragraph::new(content_lines)
        .block(content_block)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(content, right_chunks[1]);

    let key = |k: &str| {
        Span::styled(
            format!(" {k} "),
            Style::default().fg(Color::Black).bg(Color::Gray),
        )
    };
    let footer_spans = if app.filter.is_some() {
        vec![
            key("type"),
            Span::raw(" filter  "),
            key("↵"),
            Span::raw(" apply  "),
            key("esc"),
            Span::raw(" cancel "),
        ]
    } else {
        vec![
            key("j/k"),
            Span::raw(" sample  "),
            key("h/l"),
            Span::raw(" tab  "),
            key("PgUp/Dn"),
            Span::raw(" scroll  "),
            key("/"),
            Span::raw(" search  "),
            key("?"),
            Span::raw(" help  "),
            key("q"),
            Span::raw(" quit "),
        ]
    };
    f.render_widget(Paragraph::new(Line::from(footer_spans)), chunks[2]);

    if app.show_help {
        draw_help(f);
    }
}

/// Centered logo + hint shown when the sample library is empty.
fn draw_empty_state(f: &mut Frame, area: ratatui::layout::Rect) {
    const LOGO: [&str; 6] = [
        "  █████╗  ██████╗  █████╗ ████████╗",
        " ██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝",
        " ███████║██║  ███╗███████║   ██║   ",
        " ██╔══██║██║   ██║██╔══██║   ██║   ",
        " ██║  ██║╚██████╔╝██║  ██║   ██║   ",
        " ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ",
    ];
    let grad = [
        Color::Cyan,
        Color::Cyan,
        Color::LightBlue,
        Color::LightMagenta,
        Color::Magenta,
        Color::Magenta,
    ];
    let mut lines: Vec<Line> = vec![Line::from(""), Line::from("")];
    for (row, col) in LOGO.iter().zip(grad) {
        lines.push(Line::from(Span::styled(*row, Style::default().fg(col))).centered());
    }
    lines.push(Line::from(""));
    lines.push(
        Line::from(Span::styled(
            "an adaptive immune system for binaries",
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD),
        ))
        .centered(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(Span::styled(
            "no samples in this agat home yet",
            Style::default().fg(Color::DarkGray),
        ))
        .centered(),
    );
    lines.push(
        Line::from(Span::styled(
            "agat ingest <files…>   then   agat analyze",
            Style::default().fg(Color::Gray),
        ))
        .centered(),
    );
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

/// A centered help overlay listing every key binding.
fn draw_help(f: &mut Frame) {
    let area = f.area();
    let w = 52u16.min(area.width.saturating_sub(4));
    let h = 18u16.min(area.height.saturating_sub(2));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let popup = ratatui::layout::Rect {
        x,
        y,
        width: w,
        height: h,
    };
    f.render_widget(ratatui::widgets::Clear, popup);
    let cyan = Style::default().fg(Color::Cyan);
    let k = |key: &str, desc: &str| {
        Line::from(vec![
            Span::styled(format!("  {key:<12}"), Style::default().fg(Color::Yellow)),
            Span::raw(desc.to_string()),
        ])
    };
    let lines = vec![
        Line::from(Span::styled(
            "  agat — key bindings",
            cyan.add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        k("j / k ↑ ↓", "previous / next sample"),
        k("h / l ← →", "previous / next tab"),
        k("Tab", "cycle tabs forward"),
        k("1 … 6", "jump to a tab"),
        k("PgUp/PgDn", "scroll the view"),
        k("J / K", "scroll by one line"),
        k("g", "scroll to top"),
        k("/", "search samples (id / name)"),
        k("?", "toggle this help"),
        k("q / Esc", "quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  press any key to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let help = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(cyan)
            .title(" help "),
    );
    f.render_widget(help, popup);
}

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Malicious => Color::Red,
        Severity::Suspicious => Color::Yellow,
        Severity::Review => Color::Cyan,
        Severity::Clean => Color::Green,
    }
}

/// The immune verdict for the selected sample: the fused severity, then
/// the two independent axes and the model that produced them.
fn build_immune(app: &App) -> Vec<Line<'static>> {
    let dim = Style::default().fg(Color::DarkGray);
    if !app.has_model {
        return vec![
            Line::from(Span::styled("No trained model in this agat home yet.", dim)),
            Line::from(""),
            Line::from("Train one:  agat self build <benign ids…> && agat repertoire generate"),
            Line::from("or import:  agat repertoire import <pack> --trust <key.pub>"),
        ];
    }
    let Some(r) = app.selected_verdict() else {
        return vec![Line::from(Span::styled(
            "No verdict for this sample (run `agat analyze` first).",
            dim,
        ))];
    };
    let sev = r.severity();
    let label = match sev {
        Severity::Malicious => " MALICIOUS ",
        Severity::Suspicious => " SUSPICIOUS ",
        Severity::Review => " REVIEW ",
        Severity::Clean => " CLEAN ",
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                label,
                Style::default()
                    .fg(Color::Black)
                    .bg(severity_color(sev))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::raw(r.verdict.summary.clone()),
        ]),
        Line::from(""),
    ];
    if let Some(p) = &r.verdict.policy {
        lines.push(Line::from(Span::styled(
            format!("verdict set by operator policy ({p}); the axes below are unchanged"),
            dim,
        )));
        lines.push(Line::from(""));
    }

    let rec = &r.recognition;
    lines.push(section_header("recognition: is it non-self?"));
    lines.push(kv("verdict", rec.verdict.clone()));
    lines.push(kv(
        "family",
        rec.family.clone().unwrap_or_else(|| "-".into()),
    ));
    lines.push(kv("affinity", format!("{:.3}", rec.affinity)));
    lines.push(kv(
        "memory",
        if rec.secondary_response {
            "yes (secondary response)"
        } else {
            "no"
        },
    ));
    if let Some(d) = rec.self_surface_distance {
        lines.push(kv("from self", format!("{d:+.3}")));
    }
    lines.push(Line::from(""));

    let d = &r.danger;
    lines.push(section_header("danger: is it harmful?"));
    lines.push(kv(
        "score",
        format!(
            "{:.3}  ({})  P {:.2} / D {:.2} / S {:.2}",
            d.score, d.context, d.pamp, d.danger, d.safe
        ),
    ));
    for sig in d.signals.iter().take(8) {
        let color = match sig.class.as_str() {
            "pamp" => Color::Red,
            "danger" => Color::Yellow,
            _ => Color::Green,
        };
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(format!("{:<7}", sig.class), Style::default().fg(color)),
            Span::raw(format!("{:<32} {:.2}", sig.name, sig.value)),
        ]));
    }
    lines.push(Line::from(""));

    if let Some(m) = &r.model {
        lines.push(section_header("model"));
        let who = match m.source.as_str() {
            "pack" => format!(
                "pack {} v{} · {}",
                m.name.as_deref().unwrap_or("?"),
                m.version.as_deref().unwrap_or("?"),
                m.signer
                    .as_deref()
                    .map(|k| format!("signed by {k}"))
                    .unwrap_or_else(|| "unsigned".into())
            ),
            _ => "trained locally".to_string(),
        };
        lines.push(kv("source", who));
    }
    lines
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

#[cfg(test)]
mod tests {
    use super::*;
    use agat_core::{
        AntigenSummary, DangerSummary, ModelRef, RecognitionSummary, Sample, SampleKind,
        SampleMetadata, SampleRef, SignalSummary, Verdict,
    };
    use ratatui::backend::TestBackend;

    fn sample(id: u8, name: &str) -> StoredSample {
        StoredSample {
            sample: Sample {
                id: SampleId([id; 32]),
                kind: SampleKind::Elf64,
                size: 4096,
                metadata: SampleMetadata {
                    original_filename: Some(name.to_string()),
                    ..Default::default()
                },
            },
            ingested_at: chrono::Utc::now(),
        }
    }

    fn verdict(id: SampleId, sev: Severity, family: Option<&str>) -> ScanResult {
        ScanResult {
            schema_version: agat_core::SCAN_SCHEMA_VERSION.into(),
            agat_version: "test".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            sample: SampleRef {
                id: id.to_hex(),
                short: id.short(),
                name: None,
            },
            antigen: AntigenSummary {
                dim: 47,
                blocks: 3,
                cfg_fingerprint: None,
                plaintext_fingerprint: None,
            },
            recognition: RecognitionSummary {
                recognized: sev != Severity::Clean,
                verdict: "non-self — family (secondary response)".into(),
                family: family.map(String::from),
                affinity: 0.923,
                bound_detectors: 1,
                secondary_response: family.is_some(),
                self_surface_distance: Some(0.85),
                known_families: 1,
            },
            danger: DangerSummary {
                score: 0.667,
                context: "dangerous".into(),
                pamp: 0.7,
                danger: 1.0,
                safe: 0.6,
                signals: vec![SignalSummary {
                    class: "pamp".into(),
                    name: "decryptor_with_recovered_key".into(),
                    value: 0.7,
                }],
            },
            verdict: Verdict {
                severity: sev,
                summary: "recognition and danger agree".into(),
                policy: None,
            },
            model: Some(ModelRef {
                source: "pack".into(),
                name: Some("acme-threats".into()),
                version: Some("2026.10".into()),
                sha256: None,
                signer: Some("ec73e23d226e8fdc".into()),
                antigen_fingerprint: "f".repeat(64),
            }),
        }
    }

    fn render(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn app_with(verdicts: Vec<ScanResult>, samples: Vec<StoredSample>, has_model: bool) -> App {
        App::new(
            samples,
            verdicts
                .into_iter()
                .map(|r| (SampleId::from_hex(&r.sample.id).unwrap(), r))
                .collect(),
            has_model,
        )
    }

    #[test]
    fn immune_tab_shows_verdict_axes_and_model() {
        let a = sample(1, "unseen_variant.bin");
        let b = sample(2, "baseline_tool.bin");
        let app = app_with(
            vec![
                verdict(a.sample.id, Severity::Malicious, Some("metamorph")),
                verdict(b.sample.id, Severity::Clean, None),
            ],
            vec![a, b],
            true,
        );
        let screen = render(&app);
        if std::env::var_os("SHOW_SCREEN").is_some() {
            println!("{screen}");
        }
        for needle in [
            "Immune",
            "MALICIOUS",
            "recognition: is it non-self?",
            "metamorph",
            "0.923",
            "danger: is it harmful?",
            "decryptor_with_recovered_key",
            "pack acme-threats v2026.10",
            "1 malicious",
            "1 clean",
        ] {
            assert!(screen.contains(needle), "missing {needle:?} in:\n{screen}");
        }
    }

    #[test]
    fn search_filters_the_sample_list() {
        let a = sample(1, "unseen_variant.bin");
        let b = sample(2, "baseline_tool.bin");
        let c = sample(3, "ai_rewritten.bin");
        let mut app = app_with(vec![], vec![a, b, c], false);
        assert_eq!(app.visible().len(), 3);
        app.filter = Some("baseline".into());
        let v = app.visible();
        assert_eq!(v.len(), 1);
        assert_eq!(
            app.samples[v[0]]
                .sample
                .metadata
                .original_filename
                .as_deref(),
            Some("baseline_tool.bin")
        );
        // A non-matching query hides everything; selection clamps to None.
        app.filter = Some("zzz".into());
        app.clamp_selection();
        assert!(app.visible().is_empty());
        assert_eq!(app.list_state.selected(), None);
    }

    #[test]
    fn empty_store_shows_the_logo_splash() {
        let app = app_with(vec![], vec![], false);
        let screen = render(&app);
        assert!(
            screen.contains("no samples in this agat home yet"),
            "{screen}"
        );
        assert!(screen.contains("agat ingest"), "{screen}");
    }

    #[test]
    fn help_overlay_renders_key_bindings() {
        let mut app = app_with(vec![], vec![sample(1, "x.bin")], false);
        app.show_help = true;
        let screen = render(&app);
        assert!(screen.contains("key bindings"), "{screen}");
        assert!(screen.contains("search samples"), "{screen}");
    }

    #[test]
    fn immune_tab_explains_a_missing_model() {
        let app = app_with(vec![], vec![sample(1, "x.bin")], false);
        let screen = render(&app);
        assert!(screen.contains("No trained model"), "{screen}");
        assert!(screen.contains("no model yet"), "{screen}");
    }
}
