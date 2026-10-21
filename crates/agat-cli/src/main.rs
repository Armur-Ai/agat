//! agat command-line entry point.

mod config;
mod immune;

use agat_ai::AiFeatures;
use agat_core::{AnalysisContext, Sample, SampleId, SampleKind, SampleMetadata, Vault};
use agat_disasm::{DisasmFeatures, FlowKind};
use agat_meta::MetaFeatures;
use agat_poly::{PolyFeatures, Signal};
use agat_static::{entropy::EntropyCurve, strings::StringEncoding, StaticFeatures};
use agat_store::{Store, StoredSample};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::{HashMap, HashSet};
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

    /// Config file (defaults to `config.toml` in the agat data directory).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

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
        /// Include metamorphic canonical form and CFG fingerprint.
        #[arg(long)]
        meta: bool,
        /// Include AI-signal analysis (artifacts, stylometry, verdict).
        #[arg(long)]
        ai: bool,
    },
    /// Group samples by metamorphic CFG fingerprint.
    Cluster,
    /// Cross-sample divergence analysis: flag samples that share a
    /// recovered-plaintext family but have a different CFG fingerprint
    /// from the rest of the family. This is the algorithm-substitution
    /// signature of LLM rewriting.
    Divergence,
    /// Artificial Immune System: model benign "self" from a corpus.
    #[command(name = "self")]
    SelfNs {
        #[command(subcommand)]
        cmd: SelfCmd,
    },
    /// Artificial Immune System: the negative-selection detector repertoire.
    Repertoire {
        #[command(subcommand)]
        cmd: RepertoireCmd,
    },
    /// Mature the repertoire onto a confirmed family variant (clonal selection).
    Mature {
        /// Sample id (full SHA-256 or unique prefix).
        id: String,
        /// Family label to attach to the matured memory cell.
        #[arg(long)]
        family: String,
    },
    /// Recognize a sample: antigen, matched detector/family, affinity, danger.
    Recognize {
        /// Sample id (full SHA-256 or unique prefix).
        id: String,
        #[command(flatten)]
        out: OutputArgs,
    },
    /// Scan files or directories end to end: analyze and recognize in one
    /// shot. Stateless by default — files are analyzed in memory and
    /// nothing is written, so no vault password is needed. Requires a
    /// trained model (`self build` + `repertoire generate`).
    Scan {
        /// Files, or directories to scan recursively.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Also ingest each file into the encrypted vault sample library
        /// (and persist its features), as `agat ingest` + `analyze` would.
        #[arg(long)]
        ingest: bool,
        #[command(flatten)]
        out: OutputArgs,
    },
    /// Launch the interactive TUI.
    Tui,
}

/// Output and exit-code flags shared by `scan` and `recognize`. Each
/// overrides the corresponding `[scan]` setting in the config file.
#[derive(clap::Args)]
struct OutputArgs {
    /// Output format: text, json (an object for one file, an array for a
    /// batch), sarif (SARIF 2.1.0, one finding per non-clean sample), or
    /// table (one line per file).
    #[arg(long, value_enum, conflicts_with_all = ["json", "sarif"])]
    output: Option<config::OutputFormat>,
    /// Shorthand for `--output json`.
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    /// Shorthand for `--output sarif`.
    #[arg(long)]
    sarif: bool,
    /// Lowest severity that makes the command exit non-zero
    /// (default: review).
    #[arg(long, value_enum)]
    fail_on: Option<config::FailOn>,
}

impl OutputArgs {
    fn resolve(&self, cfg: &config::Config) -> (config::OutputFormat, config::FailOn) {
        let format = if self.json {
            config::OutputFormat::Json
        } else if self.sarif {
            config::OutputFormat::Sarif
        } else {
            self.output
                .or(cfg.scan.output)
                .unwrap_or(config::OutputFormat::Text)
        };
        let fail_on = self
            .fail_on
            .or(cfg.scan.fail_on)
            .unwrap_or(config::FailOn::Review);
        (format, fail_on)
    }
}

#[derive(Subcommand)]
enum SelfCmd {
    /// Build the self-model from benign samples (ids, or all tagged "benign").
    Build {
        ids: Vec<String>,
        /// Neighbors used to size each self ball.
        #[arg(long, default_value_t = 3)]
        k: usize,
    },
}

#[derive(Subcommand)]
enum RepertoireCmd {
    /// Generate the repertoire by negative selection against the self-model.
    Generate {
        #[arg(long)]
        max_detectors: Option<usize>,
        /// Self-tolerance threshold (how close to self a detector may sit).
        #[arg(long)]
        tolerance: Option<f64>,
        /// Target non-self coverage in [0, 1).
        #[arg(long)]
        coverage: Option<f64>,
        /// RNG seed for reproducible repertoires.
        #[arg(long)]
        seed: Option<u64>,
    },
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
    let cfg = config::Config::load(cli.config.as_deref(), &agat_home)?;
    let vault_path = agat_home.join("vault");
    let store_path = agat_home.join("store.db");

    // The encrypted vault holds raw sample bytes; only commands that read
    // or write those bytes need it. Recognition, listing, and the immune
    // commands all operate on the extracted features in the store, so they
    // run without a password — which is what makes `agat scan`/`recognize`
    // usable non-interactively in a pipeline.
    let needs_vault = matches!(
        cli.command,
        Cmd::Ingest { .. } | Cmd::Analyze { .. } | Cmd::Scan { ingest: true, .. } | Cmd::Tui
    );
    let vault = if needs_vault {
        let password = read_password()?;
        Some(Vault::open_or_create(&vault_path, &password).context("opening vault")?)
    } else {
        None
    };
    let store = Store::open(&store_path).context("opening store")?;

    match cli.command {
        Cmd::Ingest { paths } => cmd_ingest(paths, vault.as_ref().expect("ingest needs a vault"), &store),
        Cmd::List => cmd_list(&store),
        Cmd::Analyze { id, force } => cmd_analyze(id, force, vault.as_ref().expect("analyze needs a vault"), &store),
        Cmd::Show {
            id,
            disasm,
            poly,
            meta,
            ai,
        } => cmd_show(id, disasm, poly, meta, ai, &store),
        Cmd::Cluster => cmd_cluster(&store),
        Cmd::Divergence => cmd_divergence(&store),
        Cmd::SelfNs { cmd } => match cmd {
            SelfCmd::Build { ids, k } => immune::cmd_self_build(ids, k, &store),
        },
        Cmd::Repertoire { cmd } => match cmd {
            RepertoireCmd::Generate {
                max_detectors,
                tolerance,
                coverage,
                seed,
            } => immune::cmd_repertoire_generate(max_detectors, tolerance, coverage, seed, &store),
        },
        Cmd::Mature { id, family } => immune::cmd_mature(id, family, &store),
        Cmd::Recognize { id, out } => {
            let (format, fail_on) = out.resolve(&cfg);
            let severity = immune::cmd_recognize(id, format, cfg.policy()?, &store)?;
            // The verdict severity is the command's real result, surfaced
            // as the process exit code. Drop the store first so sqlite
            // flushes cleanly before we exit.
            drop(store);
            std::process::exit(fail_on.exit_code(severity));
        }
        Cmd::Scan { paths, ingest: _, out } => {
            let (format, fail_on) = out.resolve(&cfg);
            let worst = cmd_scan(&paths, format, cfg.policy()?, vault.as_ref(), &store)?;
            drop(store);
            std::process::exit(fail_on.exit_code(worst));
        }
        Cmd::Tui => agat_tui::run(vault.expect("tui needs a vault"), store).context("running tui"),
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

pub(crate) fn resolve_sample_id(input: &str, store: &Store) -> Result<SampleId> {
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

/// Ingest one file into the vault + store. Returns the sample id and
/// whether it was newly added (false ⇒ it was already in the vault).
/// Idempotent: a sample already present is left untouched.
fn ingest_one(path: &std::path::Path, vault: &Vault, store: &Store) -> Result<(SampleId, bool)> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let id = SampleId::from_bytes(&bytes);
    if vault.has(&id) {
        tracing::info!(sample = %id.short(), "already in vault");
        return Ok((id, false));
    }
    let kind = SampleKind::detect(&bytes);
    let original_filename = path.file_name().and_then(|s| s.to_str()).map(String::from);
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
    Ok((id, true))
}

/// Recursively collect regular files under `path` (or `[path]` if it is
/// itself a file), sorted for deterministic output.
fn collect_files(path: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(out);
    }
    if !path.is_dir() {
        anyhow::bail!("{} is not a file or directory", path.display());
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("reading directory {}", dir.display()))?
        {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// `agat scan <path...>` — the operator front door: analyze and recognize
/// every file given (directories are walked recursively), then render the
/// results. Returns the worst verdict severity over the batch. Requires a
/// trained model to be present.
///
/// With `vault` = `None` the scan is stateless: each file is analyzed in
/// memory and nothing is written. With a vault (`--ingest`), each file is
/// also added to the sample library and its features persisted.
fn cmd_scan(
    paths: &[PathBuf],
    format: immune::OutputFormat,
    policy: agat_engine::ScanPolicy,
    vault: Option<&Vault>,
    store: &Store,
) -> Result<agat_core::Severity> {
    let mut files = Vec::new();
    for p in paths {
        files.extend(collect_files(p)?);
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        anyhow::bail!("no files to scan");
    }
    let single = files.len() == 1;

    // Load the trained model once for the whole batch.
    let model = agat_engine::ImmuneModel::load(store)?.with_policy(policy);
    let mut results = Vec::with_capacity(files.len());
    for file in &files {
        let name = file.to_str().map(String::from);
        let result = match vault {
            Some(vault) => {
                let (id, _newly) = ingest_one(file, vault, store)?;
                let stored = store.get_sample(&id)?.ok_or_else(|| {
                    anyhow::anyhow!("sample {} missing from store after ingest", id.short())
                })?;
                // Analyze (idempotent — skips analyzers already at the current version).
                run_analyzers(&stored, false, vault, store, true)?;
                model.scan(&id, name, &agat_engine::feature_map(store, &id)?)?
            }
            None => {
                let bytes =
                    std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
                model.scan_bytes(&bytes, name)?
            }
        };
        results.push(result);
    }
    // The table prints its own tally; elsewhere note batch size on stderr.
    if !single && format != immune::OutputFormat::Table {
        eprintln!("scanned {} file(s)", results.len());
    }

    match format {
        immune::OutputFormat::Sarif => {
            println!(
                "{}",
                serde_json::to_string_pretty(&agat_engine::sarif::to_sarif(&results))?
            );
        }
        immune::OutputFormat::Json => {
            if single {
                println!("{}", serde_json::to_string_pretty(&results[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
        }
        immune::OutputFormat::Text => {
            for (i, r) in results.iter().enumerate() {
                if i > 0 {
                    println!("\n{}", "─".repeat(60));
                }
                immune::print_report(r);
            }
        }
        immune::OutputFormat::Table => immune::print_table(&results),
    }

    // Worst severity across the batch drives the exit code.
    Ok(results
        .iter()
        .map(|r| r.severity())
        .max()
        .unwrap_or(agat_core::Severity::Clean))
}

fn cmd_ingest(paths: Vec<PathBuf>, vault: &Vault, store: &Store) -> Result<()> {
    let mut ingested = 0;
    let mut skipped = 0;
    for path in &paths {
        let (id, newly) = ingest_one(path, vault, store)?;
        if newly {
            let stored = store.get_sample(&id)?;
            let (size, kind) = stored
                .map(|s| (s.sample.size, s.sample.kind))
                .unwrap_or((0, SampleKind::Unknown));
            println!(
                "ingested  {}  {:>10}B  {:<10}  {}",
                id.short(),
                size,
                kind,
                path.display()
            );
            ingested += 1;
        } else {
            skipped += 1;
        }
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

/// Run the full analyzer pipeline over one stored sample, persisting each
/// bundle. Returns `(analyzed, skipped)` analyzer counts. `quiet`
/// suppresses the per-analyzer progress lines (used by `scan`).
fn run_analyzers(
    stored: &StoredSample,
    force: bool,
    vault: &Vault,
    store: &Store,
    quiet: bool,
) -> Result<(u64, u64)> {
    let id = &stored.sample.id;
    let mut analyzed = 0u64;
    let mut skipped = 0u64;
    // Fresh context per sample; downstream analyzers read upstream
    // features from `ctx.previous_features` rather than re-parsing.
    let mut ctx = AnalysisContext::new(vault);

    for analyzer in &agat_engine::analyzers() {
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
                    skipped += 1;
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
        if !quiet {
            println!(
                "analyzed  {}  {} v{}",
                id.short(),
                analyzer.name(),
                analyzer.version()
            );
        }
        analyzed += 1;
    }
    Ok((analyzed, skipped))
}

fn cmd_analyze(target: Option<String>, force: bool, vault: &Vault, store: &Store) -> Result<()> {
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
        let (a, s) = run_analyzers(stored, force, vault, store, false)?;
        total_analyzed += a;
        total_skipped += s;
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

fn cmd_show(
    input: String,
    disasm: bool,
    poly: bool,
    meta: bool,
    ai: bool,
    store: &Store,
) -> Result<()> {
    let id = resolve_sample_id(&input, store)?;
    let stored = store
        .get_sample(&id)?
        .ok_or_else(|| anyhow::anyhow!("sample {} not found", id.short()))?;
    let static_rec = store.get_features(&id, "static")?;
    let disasm_rec = store.get_features(&id, "disasm")?;
    let poly_rec = store.get_features(&id, "poly")?;
    let meta_rec = store.get_features(&id, "meta")?;
    let ai_rec = store.get_features(&id, "ai")?;

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
    if meta {
        match meta_rec {
            None => println!(
                "\n(no meta features yet — run `agat analyze {} --force`)",
                id.short()
            ),
            Some(rec) => {
                let mf: MetaFeatures =
                    serde_json::from_value(rec.features).context("decoding meta features")?;
                print_meta_features(&mf, store, &id)?;
            }
        }
    }
    if ai {
        match ai_rec {
            None => println!(
                "\n(no ai features yet — run `agat analyze {} --force`)",
                id.short()
            ),
            Some(rec) => {
                let af: AiFeatures =
                    serde_json::from_value(rec.features).context("decoding ai features")?;
                print_ai_features(&af);
            }
        }
    }
    Ok(())
}

fn cmd_divergence(store: &Store) -> Result<()> {
    let samples = store.list_samples()?;
    if samples.is_empty() {
        eprintln!("no samples in store");
        return Ok(());
    }

    // Gather (sample, plaintext_fp, meta_fp, ai_score) for every sample.
    struct Row {
        sample: StoredSample,
        plaintext_fp: Option<String>,
        meta_fp: Option<String>,
        ai_score: Option<f64>,
    }
    let mut rows = Vec::new();
    for s in samples {
        let poly = store.get_features(&s.sample.id, "poly")?;
        let meta = store.get_features(&s.sample.id, "meta")?;
        let ai = store.get_features(&s.sample.id, "ai")?;
        let plaintext_fp = poly.and_then(|r| {
            serde_json::from_value::<PolyFeatures>(r.features)
                .ok()
                .and_then(|p| p.recovered.map(|r| r.plaintext_fingerprint))
                .filter(|s: &String| !s.is_empty())
        });
        let meta_fp = meta.and_then(|r| {
            serde_json::from_value::<MetaFeatures>(r.features)
                .ok()
                .map(|m| m.cfg_fingerprint)
                .filter(|s: &String| !s.is_empty())
        });
        let ai_score = ai.and_then(|r| {
            serde_json::from_value::<AiFeatures>(r.features)
                .ok()
                .map(|a| a.combined_score)
        });
        rows.push(Row {
            sample: s,
            plaintext_fp,
            meta_fp,
            ai_score,
        });
    }

    // Group rows by plaintext fingerprint.
    let mut groups: HashMap<String, Vec<&Row>> = HashMap::new();
    for r in &rows {
        if let Some(pfp) = &r.plaintext_fp {
            groups.entry(pfp.clone()).or_default().push(r);
        }
    }

    let mut groups_vec: Vec<(String, Vec<&Row>)> = groups.into_iter().collect();
    groups_vec.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let mut any_divergence = false;
    for (pfp, members) in &groups_vec {
        let meta_fps: HashSet<String> = members
            .iter()
            .filter_map(|r| r.meta_fp.clone())
            .collect();
        if members.len() < 2 || meta_fps.len() < 2 {
            continue;
        }
        any_divergence = true;
        println!(
            "\nPolymorphic family {} ({} samples, {} distinct CFG)",
            &pfp[..pfp.len().min(16)],
            members.len(),
            meta_fps.len()
        );
        // Determine the "majority" CFG fingerprint — the one most
        // samples in this family share. Divergent samples are those
        // whose CFG differs from the majority.
        let mut fp_counts: HashMap<String, usize> = HashMap::new();
        for r in members.iter() {
            if let Some(m) = &r.meta_fp {
                *fp_counts.entry(m.clone()).or_insert(0) += 1;
            }
        }
        let majority_fp = fp_counts
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(fp, _)| fp.clone());
        for r in members.iter() {
            let cfg = r.meta_fp.as_deref().unwrap_or("-");
            let is_divergent = match (&r.meta_fp, &majority_fp) {
                (Some(m), Some(maj)) => m != maj,
                _ => false,
            };
            let ai = r
                .ai_score
                .map(|s| format!("ai {:.2}", s))
                .unwrap_or_else(|| "ai  -  ".to_string());
            let prefix = if is_divergent { "  ★" } else { "   " };
            let suffix = if is_divergent {
                "  ← divergent"
            } else {
                ""
            };
            println!(
                "{}  {}  cfg {:<16}  {}  {}{}",
                prefix,
                r.sample.sample.id.short(),
                &cfg[..cfg.len().min(16)],
                ai,
                r.sample
                    .sample
                    .metadata
                    .original_filename
                    .as_deref()
                    .unwrap_or("-"),
                suffix,
            );
        }
        println!(
            "\n  Algorithm substitution within a single plaintext family is the\n  \
             signature of LLM-rewritten malware — classical polymorphic and\n  \
             metamorphic engines never produce this pattern."
        );
    }

    if !any_divergence {
        println!("no divergence detected — all plaintext families share one CFG fingerprint.");
    }
    Ok(())
}

fn cmd_cluster(store: &Store) -> Result<()> {
    let samples = store.list_samples()?;
    if samples.is_empty() {
        eprintln!("no samples in store");
        return Ok(());
    }
    let mut clusters: HashMap<String, Vec<StoredSample>> = HashMap::new();
    let mut unfingerprinted: Vec<StoredSample> = Vec::new();
    for s in samples {
        if let Some(rec) = store.get_features(&s.sample.id, "meta")? {
            let mf: MetaFeatures = serde_json::from_value(rec.features)
                .context("decoding meta features")?;
            if mf.has_fingerprint() {
                clusters
                    .entry(mf.cfg_fingerprint.clone())
                    .or_default()
                    .push(s);
                continue;
            }
        }
        unfingerprinted.push(s);
    }
    let mut sorted: Vec<(String, Vec<StoredSample>)> = clusters.into_iter().collect();
    sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    for (fp, members) in &sorted {
        let label = if members.len() == 1 {
            "singleton"
        } else {
            "family"
        };
        println!(
            "\n{} {} ({} member{})",
            label,
            &fp[..fp.len().min(16)],
            members.len(),
            if members.len() == 1 { "" } else { "s" }
        );
        for s in members {
            println!(
                "  {}  {}",
                s.sample.id.short(),
                s.sample
                    .metadata
                    .original_filename
                    .as_deref()
                    .unwrap_or("-")
            );
        }
    }
    if !unfingerprinted.is_empty() {
        println!("\nunfingerprinted ({} sample{}):", unfingerprinted.len(), if unfingerprinted.len() == 1 { "" } else { "s" });
        for s in &unfingerprinted {
            println!(
                "  {}  {}",
                s.sample.id.short(),
                s.sample
                    .metadata
                    .original_filename
                    .as_deref()
                    .unwrap_or("-")
            );
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

fn print_ai_features(a: &AiFeatures) {
    println!("\nAI-signal analysis");
    println!("  combined score   {:.2}", a.combined_score);
    let verdict = if a.is_ai_rewritten() {
        "LIKELY AI-REWRITTEN"
    } else {
        "no strong AI signal"
    };
    println!("  verdict          {}", verdict);
    let ppl_score = a
        .signal_scores
        .perplexity
        .map(|p| format!("{:.2}", p))
        .unwrap_or_else(|| "  -".to_string());
    println!(
        "  signals:  stylometry {:.2}  ·  artifact-scan {:.2}  ·  perplexity {}",
        a.signal_scores.stylometry, a.signal_scores.artifact_scan, ppl_score
    );

    if let Some(r) = &a.perplexity_result {
        println!(
            "  perplexity       {:.2}  ({}; {} chars corpus)",
            r.value,
            r.backend.label(),
            r.corpus_chars
        );
    }

    if !a.artifacts.is_empty() {
        println!("\n  artifacts ({})", a.artifacts.len());
        for hit in &a.artifacts {
            println!(
                "    [{}]  {}  @ 0x{:08x}",
                hit.category.label(),
                hit.rule_name,
                hit.offset
            );
        }
    }

    let s = &a.stylometry;
    println!("\n  stylometry");
    println!("    opcode diversity     {:.3} bits", s.opcode_diversity);
    println!("    mean block size      {:.2} instructions", s.mean_block_size);
    println!("    mean string length   {:.1} chars", s.mean_string_length);
    println!("    underscore density   {:.3}", s.underscore_density);
    println!("    long strings (>30)   {}", s.long_string_count);
    if !s.llm_idiom_hits.is_empty() {
        println!("\n  LLM idioms ({})", s.llm_idiom_hits.len());
        for hit in s.llm_idiom_hits.iter().take(10) {
            let ctx_trim: String = hit.context.chars().take(60).collect();
            println!("    {}  →  {:?}", hit.idiom, ctx_trim);
        }
    }
}

fn print_meta_features(m: &MetaFeatures, store: &Store, this_id: &SampleId) -> Result<()> {
    println!("\nmetamorphic analysis");
    if !m.has_fingerprint() {
        println!("  (no CFG fingerprint — non-x86 or no disassembly)");
        return Ok(());
    }
    println!("  fingerprint   {}", m.cfg_fingerprint);
    println!(
        "  blocks        {}  edges {}",
        m.block_count, m.edge_count
    );
    println!(
        "  instructions  {} → {} (after canonicalization)",
        m.instruction_count, m.normalized_instruction_count
    );

    // Find cluster members
    let samples = store.list_samples()?;
    let mut members: Vec<(SampleId, Option<String>)> = Vec::new();
    for s in &samples {
        if s.sample.id == *this_id {
            continue;
        }
        if let Some(rec) = store.get_features(&s.sample.id, "meta")? {
            if let Ok(mf) = serde_json::from_value::<MetaFeatures>(rec.features) {
                if mf.cfg_fingerprint == m.cfg_fingerprint {
                    members.push((s.sample.id, s.sample.metadata.original_filename.clone()));
                }
            }
        }
    }
    if members.is_empty() {
        println!("  cluster       singleton");
    } else {
        println!("  cluster       {} other member{}", members.len(), if members.len() == 1 { "" } else { "s" });
        for (id, name) in members.iter().take(8) {
            println!("    {}  {}", id.short(), name.as_deref().unwrap_or("-"));
        }
    }

    if !m.canonical_preview.is_empty() {
        println!("\n  canonical form (first {})", m.canonical_preview.len());
        for c in &m.canonical_preview {
            println!("    {:<8}  {}", c.mnemonic, c.operands);
        }
    }
    Ok(())
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
