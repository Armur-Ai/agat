//! Static analysis of binary samples.
//!
//! Phase 1 of the agat pipeline. Provides:
//!
//! - PE/ELF parsing via goblin (sections, imports, exports, arch)
//! - Sliding-window Shannon entropy + high-entropy region detection
//! - ASCII + UTF-16LE string extraction
//! - Hashing: SHA-256, MD5, and imphash (for PE)
//!
//! The crate exposes both a low-level API (per-module functions) and
//! the [`StaticAnalyzer`], which is the [`agat_core::Analyzer`]
//! implementation wired into the pipeline.

pub mod analyzer;
pub mod entropy;
pub mod features;
pub mod hashes;
pub mod parse;
pub mod strings;

pub use analyzer::StaticAnalyzer;
pub use features::{StaticFeatures, StringSummary};

/// One-shot convenience: run the full static analysis on raw bytes
/// without going through the [`agat_core::Analyzer`] trait.
pub fn analyze(bytes: &[u8]) -> StaticFeatures {
    let parsed = parse::parse(bytes);
    let hashes = hashes::compute_hashes(bytes, &parsed);
    let entropy = entropy::entropy_curve(bytes, 256, 256);
    let all_strings = strings::extract_strings(bytes, 6);
    let ascii_count = all_strings
        .iter()
        .filter(|s| s.encoding == strings::StringEncoding::Ascii)
        .count();
    let utf16le_count = all_strings
        .iter()
        .filter(|s| s.encoding == strings::StringEncoding::Utf16Le)
        .count();
    let samples = all_strings.into_iter().take(256).collect();
    StaticFeatures {
        size: bytes.len() as u64,
        parsed,
        hashes,
        entropy,
        strings: StringSummary {
            min_len: 6,
            ascii_count,
            utf16le_count,
            samples,
        },
    }
}
