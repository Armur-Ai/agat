//! `agat key …` and `agat repertoire export|import|info`: moving a trained
//! model between machines as a signed pack (see `agat_engine::pack`).

use agat_engine::pack::{self, PackFile, TrustPolicy};
use agat_engine::{load_memory, load_repertoire, load_self_model};
use agat_store::Store;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// Directory (inside the agat home) whose `*.pub` keys are always trusted.
pub const TRUSTED_KEYS_DIR: &str = "trusted_keys";

/// `agat key generate <prefix>`: write `<prefix>.key` (secret, mode 0600)
/// and `<prefix>.pub`. Refuses to overwrite either.
pub fn cmd_key_generate(prefix: &Path, comment: Option<&str>) -> Result<()> {
    let secret_path = with_suffix(prefix, "key");
    let public_path = with_suffix(prefix, "pub");
    for p in [&secret_path, &public_path] {
        if p.exists() {
            bail!(
                "{} already exists; refusing to overwrite a key",
                p.display()
            );
        }
    }
    let key = pack::generate_signing_key();
    write_secret(&secret_path, &pack::signing_key_to_text(&key))?;
    std::fs::write(
        &public_path,
        pack::public_key_to_text(&key.verifying_key(), comment),
    )
    .with_context(|| format!("writing {}", public_path.display()))?;

    println!("signing key  {}  (keep it secret)", secret_path.display());
    println!(
        "public key   {}  (share it with whoever imports your packs)",
        public_path.display()
    );
    println!("key id       {}", pack::key_id(&key.verifying_key()));
    Ok(())
}

fn with_suffix(prefix: &Path, ext: &str) -> PathBuf {
    let mut s = prefix.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

#[cfg(unix)]
fn write_secret(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, text: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

/// Options for `agat repertoire export`.
pub struct ExportArgs<'a> {
    pub out: &'a Path,
    pub name: &'a str,
    pub version: &'a str,
    pub description: Option<String>,
    pub sign: Option<&'a Path>,
    pub unsigned: bool,
}

/// `agat repertoire export`: seal the active model into a pack file.
pub fn cmd_export(args: ExportArgs, store: &Store) -> Result<()> {
    let key = match (args.sign, args.unsigned) {
        (Some(path), _) => Some(pack::signing_key_from_text(
            &std::fs::read_to_string(path)
                .with_context(|| format!("reading signing key {}", path.display()))?,
        )?),
        (None, true) => None,
        (None, false) => bail!(
            "refusing to export an unsigned pack by default.\n\
             sign it:  agat repertoire export … --sign <key>   (create one with `agat key generate`)\n\
             or opt out explicitly with --unsigned"
        ),
    };
    if args.out.exists() {
        bail!(
            "{} already exists; refusing to overwrite",
            args.out.display()
        );
    }
    let payload = pack::build_payload(store, args.name, args.version, args.description)?;
    let file = pack::seal(&payload, key.as_ref())?;
    std::fs::write(args.out, serde_json::to_string(&file)?)
        .with_context(|| format!("writing {}", args.out.display()))?;

    let m = &payload.manifest;
    println!(
        "exported pack {} v{} → {}",
        m.name,
        m.version,
        args.out.display()
    );
    print_manifest(m);
    println!("  sha256      {}", file.payload_sha256);
    match &file.signature {
        Some(s) => println!("  signed by   {}", s.key_id),
        None => println!("  signed by   (unsigned)"),
    }
    Ok(())
}

/// Options for `agat repertoire import`.
pub struct ImportArgs<'a> {
    pub pack: &'a Path,
    pub trust: &'a [PathBuf],
    pub allow_unsigned: bool,
    pub dry_run: bool,
}

/// `agat repertoire import`: verify a pack and install it as the active model.
pub fn cmd_import(
    args: ImportArgs,
    config_trusted: &[PathBuf],
    home: &Path,
    store: &Store,
) -> Result<()> {
    let text = std::fs::read_to_string(args.pack)
        .with_context(|| format!("reading {}", args.pack.display()))?;
    let file: PackFile = serde_json::from_str(&text)
        .with_context(|| format!("{} is not an agat pack", args.pack.display()))?;

    let mut key_paths: Vec<PathBuf> = args.trust.to_vec();
    key_paths.extend(config_trusted.iter().cloned());
    let dir = home.join(TRUSTED_KEYS_DIR);
    if dir.is_dir() {
        let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "pub"))
            .collect();
        found.sort();
        key_paths.extend(found);
    }
    let mut trusted_keys = Vec::new();
    for p in &key_paths {
        let t = std::fs::read_to_string(p)
            .with_context(|| format!("reading public key {}", p.display()))?;
        trusted_keys
            .push(pack::public_key_from_text(&t).with_context(|| format!("in {}", p.display()))?);
    }

    let verified = pack::verify(
        &file,
        &TrustPolicy {
            trusted_keys,
            allow_unsigned: args.allow_unsigned,
        },
    )?;
    let m = &verified.payload.manifest;
    println!("pack {} v{} verified", m.name, m.version);
    print_manifest(m);
    println!("  sha256      {}", verified.payload_sha256);
    match &verified.signer {
        Some(id) => println!("  signed by   {id}  (trusted)"),
        None => println!("  signed by   (unsigned — accepted by --allow-unsigned)"),
    }

    if args.dry_run {
        println!("\ndry run: nothing installed.");
        return Ok(());
    }
    let replaced = load_repertoire(store)?.is_some();
    pack::install(store, &verified)?;
    println!(
        "\ninstalled as the active model{}.",
        if replaced {
            " (replaced the previous one)"
        } else {
            ""
        }
    );
    Ok(())
}

fn print_manifest(m: &pack::PackManifest) {
    if let Some(d) = &m.description {
        println!("  {d}");
    }
    println!("  built       {} by agat {}", m.created_at, m.agat_version);
    println!(
        "  model       {} self points · {} detectors · antigen {}…",
        m.self_points,
        m.detectors,
        &m.antigen_fingerprint[..12.min(m.antigen_fingerprint.len())]
    );
    if m.families.is_empty() {
        println!("  families    (none — anomaly detection only)");
    } else {
        println!("  families");
        for f in &m.families {
            println!(
                "    {:<20} {} cell{} · {} variant{}",
                f.name,
                f.cells,
                if f.cells == 1 { "" } else { "s" },
                f.variants,
                if f.variants == 1 { "" } else { "s" }
            );
        }
    }
}

/// `agat repertoire info`: what the active model is and where it came from.
pub fn cmd_info(store: &Store) -> Result<()> {
    let Some(repertoire) = load_repertoire(store)? else {
        println!("no model yet — train one (`agat self build`, `agat repertoire generate`)");
        println!("or import a pack (`agat repertoire import <file.agatpack>`).");
        return Ok(());
    };
    let self_points = load_self_model(store)?.map(|s| s.points.len()).unwrap_or(0);
    let memory = load_memory(store)?;
    let (naive, matured) = repertoire.composition();

    match pack::installed(store)? {
        Some(p) => {
            println!("active model: pack {} v{}", p.name, p.version);
            println!("  sha256      {}", p.payload_sha256);
            println!(
                "  signed by   {}",
                p.signer.as_deref().unwrap_or("(unsigned)")
            );
            println!("  installed   {}", p.installed_at);
        }
        None => println!("active model: trained locally"),
    }
    println!(
        "  model       {self_points} self points · {} detectors ({naive} naive, {matured} matured) · dim {}",
        repertoire.len(),
        repertoire.dim
    );
    println!(
        "  antigen     {}",
        agat_engine::antigen_config().fingerprint()
    );
    let families = memory.families();
    if families.is_empty() {
        println!("  families    (none — anomaly detection only)");
    } else {
        println!("  families");
        for f in families {
            let cells: Vec<_> = memory.cells.iter().filter(|c| c.family == f).collect();
            let variants: u32 = cells.iter().map(|c| c.variants).sum();
            println!(
                "    {:<20} {} cell{} · {} variant{}",
                f,
                cells.len(),
                if cells.len() == 1 { "" } else { "s" },
                variants,
                if variants == 1 { "" } else { "s" }
            );
        }
    }
    Ok(())
}
