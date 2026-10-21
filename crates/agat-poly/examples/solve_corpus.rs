//! Stress-test key-less recovery for false positives.
//!
//! The analyzer only solves for a key when it has found a decryptor loop.
//! This example removes that gate: it runs `agat_poly::solve::solve` under
//! every operation on **every non-executable section** of every file in a
//! directory of benign binaries, and reports each "recovered" key. On
//! benign software every one of those is a false positive of the
//! acceptance rule itself.
//!
//!   cargo run --release -p agat-poly --example solve_corpus -- DIR
//!
//! Set SHOW_TEXT=1 to print readable runs from each accepted decryption.

use agat_poly::solve::{decrypt, solve, MIN_TEXT_RUN};
use agat_poly::Operation;
use agat_static::parse::parse;

fn main() -> std::io::Result<()> {
    let dir = std::env::args().nth(1).expect("usage: solve_corpus DIR");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    paths.sort();

    let (mut files, mut sections, mut attempts, mut accepted) = (0, 0, 0, 0);
    for path in &paths {
        let bytes = std::fs::read(path)?;
        files += 1;
        for s in parse(&bytes).sections {
            if s.characteristics.executable || s.file_size == 0 {
                continue;
            }
            let start = s.file_offset as usize;
            let end = (start + s.file_size as usize).min(bytes.len());
            if start >= end {
                continue;
            }
            sections += 1;
            for op in [Operation::Xor, Operation::Add, Operation::Sub] {
                attempts += 1;
                if let Some(k) = solve(&bytes[start..end], op) {
                    accepted += 1;
                    if std::env::var_os("SHOW_TEXT").is_some() {
                        let plain = decrypt(&bytes[start..end], op, &k.key);
                        for run in plain
                            .split(|b| !(0x20..=0x7e).contains(b))
                            .filter(|r| r.len() >= MIN_TEXT_RUN)
                            .take(2)
                        {
                            println!("TEXT {}", String::from_utf8_lossy(run));
                        }
                    }
                    println!(
                        "ACCEPTED {} {} {:?} key {}",
                        path.display(),
                        s.name,
                        op,
                        k.key.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    );
                }
            }
        }
    }
    println!(
        "{files} files · {sections} non-executable sections · {attempts} solve attempts · {accepted} keys accepted"
    );
    Ok(())
}
