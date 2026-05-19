//! agat command-line entry point.

use agat_core::{Sample, SampleId, SampleKind, SampleMetadata, Vault};
use agat_store::Store;
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
