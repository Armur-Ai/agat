//! agat command-line entry point.

use agat_core::{AnalysisContext, Analyzer, Sample, SampleId, SampleKind, SampleMetadata, Vault};
use agat_disasm::{DisasmAnalyzer, DisasmFeatures, FlowKind};
use agat_poly::{PolyAnalyzer, PolyFeatures, Signal};
use agat_static::{
    entropy::EntropyCurve, strings::StringEncoding, StaticAnalyzer, StaticFeatures,
};
use agat_store::{Store, StoredSample};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "agat",
    version,
    about = "Polymorphic, metamorphic, and AI-rewritten malware analysis"
)]
struct Cli {
    /// Override the agat data directory (defaults to ~/.agat or $AGAT_HOME).
    #[arg(long, global = true)]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Ingest one or more files into the encrypted vault.
    Ingest {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// List samples currently in the store.
    List,
    /// Run all analyzers on one sample or every sample.
    Analyze {
        /// Sample id (full SHA-256 or unique prefix). Omit for all samples.
        id: Option<String>,
        /// Re-analyze even when features for the current version already exist.
        #[arg(long)]
        force: bool,
    },
    /// Show analyzer results for a sample.
    Show {
        /// Sample id (full SHA-256 or unique prefix).
        id: String,
        /// Include a disassembly preview at the bottom of the output.
        #[arg(long)]
        disasm: bool,
        /// Include polymorphic-engine analysis (signals, key, recovered payload).
        #[arg(long)]
        poly: bool,
    },
    /// Launch the interactive TUI.
    Tui,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let agat_home = resolve_home(cli.home.as_deref())?;
    std::fs::create_dir_all(&agat_home)
        .with_context(|| format!("creating agat home at {}", agat_home.display()))?;
    let vault_path = agat_home.join("vault");
    let store_path = agat_home.join("store.db");

    let password = read_password()?;
    let vault = Vault::open_or_create(&vault_path, &password).context("opening vault")?;
    let store = Store::open(&store_path).context("opening store")?;

    match cli.command {
        Cmd::Ingest { paths } => cmd_ingest(paths, &vault, &store),
        Cmd::List => cmd_list(&store),
        Cmd::Analyze { id, force } => cmd_analyze(id, force, &vault, &store),
        Cmd::Show { id, disasm, poly } => cmd_show(id, disasm, poly, &store),
        Cmd::Tui => agat_tui::run(vault, store).context("running tui"),
    }
}

fn resolve_home(cli_override: Option<&std::path::Path>) -> Result<PathBuf> {
    if let Some(p) = cli_override {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("AGAT_HOME") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir().context("could not locate home directory")?;
    Ok(home.join(".agat"))
}

fn read_password() -> Result<String> {
    if let Ok(p) = std::env::var("AGAT_VAULT_PASSWORD") {
        return Ok(p);
    }
    rpassword::prompt_password("Vault password: ").context("reading vault password")
}

fn resolve_sample_id(input: &str, store: &Store) -> Result<SampleId> {
    if input.len() == 64 {
        return SampleId::from_hex(input).map_err(|e| anyhow::anyhow!("{e}"));
    }
    let samples = store.list_samples()?;
    let matches: Vec<&StoredSample> = samples
        .iter()
        .filter(|s| s.sample.id.to_hex().starts_with(input))
        .collect();
    match matches.len() {
        0 => anyhow::bail!("no sample matching prefix '{}'", input),
        1 => Ok(matches[0].sample.id),
        n => {
            let preview: Vec<String> =
                matches.iter().take(5).map(|s| s.sample.id.short()).collect();
            anyhow::bail!(
                "ambiguous prefix '{}' matches {} samples (e.g. {})",
                input,
                n,
                preview.join(", ")
            )
        }
    }
}

fn cmd_ingest(paths: Vec<PathBuf>, vault: &Vault, store: &Store) -> Result<()> {
    let mut ingested = 0;
    let mut skipped = 0;
    for path in &paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let id = SampleId::from_bytes(&bytes);
        let kind = SampleKind::detect(&bytes);
        if vault.has(&id) {
            tracing::info!(sample = %id.short(), "already in vault, skipping");
            skipped += 1;
            continue;
        }
        let original_filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(String::from);
        let sample = Sample {
            id,
            kind,
            size: bytes.len() as u64,
            metadata: SampleMetadata {
                original_filename,
                ..Default::default()
            },
        };
        vault.store(&id, &bytes)?;
        store.insert_sample(&sample)?;
        println!(
            "ingested  {}  {:>10}B  {:<10}  {}",
            id.short(),
            bytes.len(),
            kind,
            path.display()
        );
        ingested += 1;
    }
    eprintln!("\n{ingested} ingested, {skipped} skipped");
    Ok(())
}

fn cmd_list(store: &Store) -> Result<()> {
    let samples = store.list_samples()?;
    if samples.is_empty() {
        eprintln!("no samples in store");
        return Ok(());
    }
    println!(
        "{:<14}  {:>10}  {:<10}  {:<25}  ORIGINAL FILENAME",
        "ID", "SIZE", "KIND", "INGESTED"
    );
    for s in samples {
        println!(
            "{:<14}  {:>10}  {:<10}  {:<25}  {}",
            s.sample.id.short(),
            s.sample.size,
            s.sample.kind,
            s.ingested_at.format("%Y-%m-%d %H:%M:%S"),
            s.sample
                .metadata
                .original_filename
                .as_deref()
                .unwrap_or("-")
        );
    }
    Ok(())
}

fn cmd_analyze(target: Option<String>, force: bool, vault: &Vault, store: &Store) -> Result<()> {
    let analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(StaticAnalyzer::default()),
        Box::new(DisasmAnalyzer::default()),
        Box::new(PolyAnalyzer),
    ];

    let targets: Vec<StoredSample> = match target {
        Some(input) => {
            let id = resolve_sample_id(&input, store)?;
            let stored = store
                .get_sample(&id)?
                .ok_or_else(|| anyhow::anyhow!("sample {} not found in store", id.short()))?;
            vec![stored]
        }
        None => store.list_samples()?,
    };

    if targets.is_empty() {
        eprintln!("no samples to analyze (ingest some with `agat ingest`)");
        return Ok(());
    }

    let mut total_analyzed = 0u64;
    let mut total_skipped = 0u64;
    for stored in &targets {
        let id = &stored.sample.id;
        // Fresh context per sample; downstream analyzers read upstream
        // features from `ctx.previous_features` rather than re-parsing.
        let mut ctx = AnalysisContext::new(vault);

        for analyzer in &analyzers {
            if !force {
                if let Some(existing) = store.get_features(id, analyzer.name())? {
                    if existing.version == analyzer.version() {
                        ctx.previous_features
                            .insert(analyzer.name().to_string(), existing.features);
                        tracing::debug!(
                            sample = %id.short(),
                            analyzer = analyzer.name(),
                            "already at current version"
                        );
                        total_skipped += 1;
                        continue;
                    }
                }
            }
            // Make sure declared dependencies are present in the context.
            for dep in analyzer.dependencies() {
                if !ctx.previous_features.contains_key(*dep) {
                    if let Some(rec) = store.get_features(id, dep)? {
                        ctx.previous_features.insert((*dep).to_string(), rec.features);
                    } else {
                        tracing::warn!(
                            "analyzer {} requires upstream '{}' which has no features yet",
                            analyzer.name(),
                            dep
                        );
                    }
                }
            }

            let bundle = analyzer.analyze(&stored.sample, &ctx)?;
            ctx.previous_features
                .insert(analyzer.name().to_string(), bundle.features.clone());
            store.insert_features(id, &bundle)?;
            println!(
                "analyzed  {}  {} v{}",
                id.short(),
                analyzer.name(),
                analyzer.version()
            );
            total_analyzed += 1;
        }
    }
    eprintln!(
        "\n{total_analyzed} analyses run, {total_skipped} skipped{}",
        if total_skipped > 0 && !force {
            " (already at current version; use --force to re-run)"
        } else {
            ""
        }
    );
    Ok(())
}

fn cmd_show(input: String, disasm: bool, poly: bool, store: &Store) -> Result<()> {
    let id = resolve_sample_id(&input, store)?;
    let stored = store
        .get_sample(&id)?
        .ok_or_else(|| anyhow::anyhow!("sample {} not found", id.short()))?;
    let static_rec = store.get_features(&id, "static")?;
    let disasm_rec = store.get_features(&id, "disasm")?;
    let poly_rec = store.get_features(&id, "poly")?;

    println!(
        "{}  {}",
        id.to_hex(),
        stored
            .sample
            .metadata
            .original_filename
            .as_deref()
            .unwrap_or("-")
    );
    println!(
        "{:<10}{} ({} bytes)  ingested {}",
        "kind",
        stored.sample.kind,
        stored.sample.size,
        stored.ingested_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    let Some(rec) = static_rec else {
        println!(
            "\n(no analyzer features yet — run `agat analyze {}`)",
            id.short()
        );
        return Ok(());
    };

    let feat: StaticFeatures = serde_json::from_value(rec.features)
        .context("decoding static analyzer features")?;
    print_static_features(&feat);

    if disasm {
        match disasm_rec {
            None => println!(
                "\n(no disasm features yet — run `agat analyze {} --force`)",
                id.short()
            ),
            Some(rec) => {
                let df: DisasmFeatures = serde_json::from_value(rec.features)
                    .context("decoding disasm features")?;
                print_disasm_features(&df);
            }
        }
    }
    if poly {
        match poly_rec {
            None => println!(
                "\n(no poly features yet — run `agat analyze {} --force`)",
                id.short()
            ),
            Some(rec) => {
                let pf: PolyFeatures =
                    serde_json::from_value(rec.features).context("decoding poly features")?;
                print_poly_features(&pf);
            }
        }
    }
    Ok(())
}

fn print_static_features(f: &StaticFeatures) {
    println!();
    println!(
        "{:<10}{} / {} / {}-bit  entry 0x{:08x}",
        "format", f.parsed.format, f.parsed.arch, f.parsed.bits, f.parsed.entry_point
    );

    println!("\nhashes");
    println!("  {:<8} {}", "sha256", f.hashes.sha256);
    println!("  {:<8} {}", "md5", f.hashes.md5);
    println!(
        "  {:<8} {}",
        "imphash",
        f.hashes.imphash.as_deref().unwrap_or("-")
    );

    println!(
        "\n{:<10}{:.3} bits/byte overall  ({} high-entropy region{})",
        "entropy",
        f.entropy.overall,
        f.entropy.high_entropy_regions.len(),
        if f.entropy.high_entropy_regions.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    let spark = entropy_sparkline(&f.entropy, 64);
    if !spark.is_empty() {
        println!("  [{spark}]");
    }
    for r in &f.entropy.high_entropy_regions {
        println!(
            "  0x{:08x}..0x{:08x}  mean {:.3}",
            r.start, r.end, r.mean_entropy
        );
    }

    if !f.parsed.sections.is_empty() {
        println!("\nsections ({})", f.parsed.sections.len());
        for s in &f.parsed.sections {
            let rwx = format!(
                "{}{}{}",
                if s.characteristics.readable { "R" } else { "-" },
                if s.characteristics.writable { "W" } else { "-" },
                if s.characteristics.executable { "X" } else { "-" },
            );
            println!(
                "  {:<16}  {}  ent {:>4.2}  {:>8} bytes",
                s.name, rwx, s.entropy, s.file_size
            );
        }
    }

    if !f.parsed.imports.is_empty() {
        println!("\nimports ({})", f.parsed.imports.len());
        for imp in f.parsed.imports.iter().take(20) {
            let lib = if imp.library.is_empty() {
                "<elf>"
            } else {
                imp.library.as_str()
            };
            println!("  {}: {}", lib, imp.name);
        }
        if f.parsed.imports.len() > 20 {
            println!("  ... +{} more", f.parsed.imports.len() - 20);
        }
    }

    if !f.parsed.exports.is_empty() {
        println!("\nexports ({})", f.parsed.exports.len());
        for exp in f.parsed.exports.iter().take(20) {
            println!("  {} @ 0x{:08x}", exp.name, exp.address);
        }
        if f.parsed.exports.len() > 20 {
            println!("  ... +{} more", f.parsed.exports.len() - 20);
        }
    }

    println!(
        "\nstrings  {} ASCII · {} UTF-16LE  (min len {}; showing first {})",
        f.strings.ascii_count,
        f.strings.utf16le_count,
        f.strings.min_len,
        f.strings.samples.len()
    );
    for s in f.strings.samples.iter().take(20) {
        let enc = match s.encoding {
            StringEncoding::Ascii => "ascii ",
            StringEncoding::Utf16Le => "utf16 ",
        };
        let truncated: String = if s.value.len() > 80 {
            format!("{}...", &s.value[..77])
        } else {
            s.value.clone()
        };
        println!("  0x{:08x}  {}  {}", s.offset, enc, truncated);
    }
}

fn print_disasm_features(df: &DisasmFeatures) {
    println!("\ndisassembly");
    if df.bitness == 0 {
        println!(
            "  (architecture {} not supported by Phase 2 disasm; need x86/x64)",
            df.arch
        );
        return;
    }
    println!(
        "  arch          {} ({}-bit)",
        df.arch, df.bitness
    );
    println!(
        "  section       {}  (base 0x{:08x}, {} bytes)",
        df.disassembled_section.as_deref().unwrap_or("?"),
        df.section_base,
        df.disassembled_bytes
    );
    println!(
        "  instructions  {}  blocks {}  ~functions {}",
        df.instruction_count, df.block_count, df.function_estimate
    );

    if !df.opcode_histogram.is_empty() {
        let mut hist: Vec<(&String, &usize)> = df.opcode_histogram.iter().collect();
        hist.sort_by(|a, b| b.1.cmp(a.1));
        let preview: Vec<String> = hist
            .iter()
            .take(8)
            .map(|(m, c)| format!("{} ({})", m, c))
            .collect();
        println!("  top opcodes   {}", preview.join(", "));
    }

    if df.listing_preview.is_empty() {
        return;
    }
    println!("\n  listing preview (first {} instructions)", df.listing_preview.len().min(40));
    for l in df.listing_preview.iter().take(40) {
        let flow_marker = match l.flow {
            FlowKind::Branch => " ↳",
            FlowKind::Jump => " ↦",
            FlowKind::Call => " →",
            FlowKind::Return => " ⏎",
            FlowKind::Indirect => " ?",
            FlowKind::Invalid => " ✗",
            FlowKind::Next => "  ",
        };
        let bytes_col = if l.bytes_hex.len() > 16 {
            format!("{}…", &l.bytes_hex[..15])
        } else {
            format!("{:<16}", l.bytes_hex)
        };
        println!(
            "  0x{:08x}  {}  {:<8}{}{}",
            l.address, bytes_col, l.mnemonic, l.operands, flow_marker
        );
    }
}

fn print_poly_features(p: &PolyFeatures) {
    println!("\npolymorphic-engine analysis");
    println!("  confidence  {:.2}", p.confidence);
    let verdict = if p.is_polymorphic() {
        "LIKELY POLYMORPHIC"
    } else {
        "no strong signal"
    };
    println!("  verdict     {}", verdict);

    if p.signals.is_empty() {
        println!("  (no signals)");
    } else {
        println!("  signals:");
        for s in &p.signals {
            match s {
                Signal::EntropyBoundary {
                    boundary_offset,
                    before_entropy,
                    after_entropy,
                } => println!(
                    "    entropy boundary at 0x{:08x}  {:.2} → {:.2}",
                    boundary_offset, before_entropy, after_entropy
                ),
                Signal::BackwardJumpInPrelude { from, to } => println!(
                    "    backward jump at 0x{:08x} → 0x{:08x}",
                    from, to
                ),
                Signal::DecryptorLoop {
                    op,
                    instruction_address,
                    key,
                } => match key {
                    Some(k) => println!(
                        "    decryptor loop at 0x{:08x}  {} byte  key 0x{:02x}",
                        instruction_address,
                        op.label(),
                        k
                    ),
                    None => println!(
                        "    decryptor loop at 0x{:08x}  {} byte  key unknown (register source)",
                        instruction_address,
                        op.label()
                    ),
                },
            }
        }
    }

    if let Some(rec) = &p.recovered {
        println!("\nrecovered payload");
        println!(
            "  region      0x{:08x}..0x{:08x}  ({} bytes)",
            rec.region_start, rec.region_end, rec.region_size
        );
        println!("  operation   {} with 0x{:02x}", rec.operation.label(), rec.key);
        println!(
            "  entropy     {:.3} → {:.3}  (drop {:+.3})",
            rec.original_entropy, rec.decrypted_entropy, -rec.entropy_drop
        );
        println!("  score       {:.2}", rec.recovery_score);
        if !rec.preview_hex.is_empty() {
            // Show as classic xxd-style: 16 bytes per line, max 4 lines.
            let bytes_per_row = 32; // 32 hex chars = 16 bytes
            for (i, chunk) in rec.preview_hex.as_bytes().chunks(bytes_per_row).enumerate().take(4)
            {
                let line: String = chunk.iter().map(|&b| b as char).collect();
                let spaced = line
                    .as_bytes()
                    .chunks(2)
                    .map(|c| std::str::from_utf8(c).unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("  0x{:04x}      {}", i * 16, spaced);
            }
        }
        if !rec.recovered_strings.is_empty() {
            println!("  strings:");
            for s in &rec.recovered_strings {
                let truncated: String = if s.len() > 70 {
                    format!("{}...", &s[..67])
                } else {
                    s.clone()
                };
                println!("    {:?}", truncated);
            }
        }
    } else if p.detected_pattern.is_some() {
        println!("\n  (pattern detected but no high-entropy region to decrypt)");
    }
}

fn entropy_sparkline(curve: &EntropyCurve, width: usize) -> String {
    if curve.points.is_empty() {
        return String::new();
    }
    const BLOCKS: [char; 9] = [
        ' ', '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
        '\u{2588}',
    ];
    let n = curve.points.len();
    let cols = width.min(n).max(1);
    let stride = ((n as f64) / (cols as f64)).ceil() as usize;
    let mut out = String::with_capacity(cols);
    for i in 0..cols {
        let start = i * stride;
        let end = ((i + 1) * stride).min(n);
        if start >= end {
            break;
        }
        let avg: f64 = curve.points[start..end]
            .iter()
            .map(|p| p.entropy)
            .sum::<f64>()
            / (end - start) as f64;
        let idx = (avg.max(0.0).min(8.0) * (BLOCKS.len() as f64 - 1.0) / 8.0).round() as usize;
        out.push(BLOCKS[idx.min(BLOCKS.len() - 1)]);
    }
    out
}
