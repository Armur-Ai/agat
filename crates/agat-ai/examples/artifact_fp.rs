//! Count AI-artifact rule hits across a directory of benign binaries, as a
//! false-positive check on the rule set.
//!   cargo run --release -p agat-ai --example artifact_fp -- DIR
use agat_ai::artifacts::scan;

fn main() -> std::io::Result<()> {
    let dir = std::env::args().nth(1).expect("usage: artifact_fp DIR");
    let (mut files, mut hits) = (0u32, 0u32);
    let mut paths: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    for p in &paths {
        let bytes = std::fs::read(p)?;
        files += 1;
        for h in scan(&bytes) {
            hits += 1;
            println!(
                "{}  {}  @{}",
                p.file_name().unwrap().to_string_lossy(),
                h.rule_name,
                h.offset
            );
        }
    }
    println!("{files} files · {hits} artifact hits");
    Ok(())
}
