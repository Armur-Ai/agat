//! Capture build metadata for `agat --version`: the target triple, the
//! build profile, and the rustc version. All optional — absent values
//! just don't appear in the version string.

use std::process::Command;

fn main() {
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=AGAT_TARGET={target}");
    }
    if let Ok(profile) = std::env::var("PROFILE") {
        println!("cargo:rustc-env=AGAT_PROFILE={profile}");
    }
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    if let Ok(out) = Command::new(rustc).arg("--version").output() {
        if let Ok(v) = String::from_utf8(out.stdout) {
            println!("cargo:rustc-env=AGAT_RUSTC={}", v.trim());
        }
    }
    // Re-run if the git HEAD moves (best-effort; no failure if absent).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    if let Ok(out) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if out.status.success() {
            if let Ok(h) = String::from_utf8(out.stdout) {
                println!("cargo:rustc-env=AGAT_COMMIT={}", h.trim());
            }
        }
    }
}
