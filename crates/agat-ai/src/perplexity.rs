//! Perplexity scoring (Phase 6 — signal 2 of the AI-detection arc).
//!
//! Two backends:
//!
//! 1. **llama.cpp sidecar** (`PerplexityBackend::LlamaCpp`) — invokes
//!    `llama-perplexity` against a GGUF code model. Configured via
//!    `AGAT_LLAMA_BIN` (and optionally `AGAT_LLAMA_MODEL`, or place
//!    a model at `~/.agat/models/code.gguf`). This is the canonical
//!    signal the design doc calls for.
//! 2. **Approximation** (`PerplexityBackend::Approximation`) — a
//!    character-bigram-entropy fallback that doesn't need any
//!    external dependencies. It's *not* perplexity in the rigorous
//!    sense, but it captures the same essential property: text
//!    that's compressible because it follows natural-language
//!    patterns scores low; random / encrypted / binary content
//!    scores high. Used by default so the demo runs anywhere.
//!
//! The score function maps the raw value (low → natural-text-like)
//! to a 0..1 AI-signal contribution.

use agat_static::strings::ExtractedString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PerplexityBackend {
    LlamaCpp,
    Approximation,
}

impl PerplexityBackend {
    pub fn label(self) -> &'static str {
        match self {
            PerplexityBackend::LlamaCpp => "llama.cpp",
            PerplexityBackend::Approximation => "approximation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerplexityResult {
    pub value: f64,
    pub backend: PerplexityBackend,
    pub corpus_chars: usize,
}

/// Below this corpus size the unigram-entropy approximation gets too
/// noisy to be informative — the byte distribution is dominated by
/// whatever few strings the binary happens to ship. Returning `None`
/// here is much better than reporting a confident-but-wrong number.
const CORPUS_MIN_CHARS: usize = 200;
const STRING_MIN_LEN: usize = 10;

/// Compute perplexity over the natural-text-likely subset of the
/// binary's extracted strings. Returns `None` if the filtered
/// corpus is too small to be informative.
pub fn compute(strings: &[ExtractedString]) -> Option<PerplexityResult> {
    let corpus = build_corpus(strings);
    if corpus.len() < CORPUS_MIN_CHARS {
        return None;
    }
    // llama.cpp is opt-in via env var — we don't want to slow down
    // analyze runs unexpectedly. Approximation is the default.
    if std::env::var("AGAT_LLAMA_BIN").is_ok() {
        if let Some(real) = try_llama_cpp(&corpus) {
            return Some(real);
        }
        tracing::warn!(
            "AGAT_LLAMA_BIN set but invocation failed; falling back to approximation"
        );
    }
    Some(PerplexityResult {
        value: approximate(&corpus),
        backend: PerplexityBackend::Approximation,
        corpus_chars: corpus.len(),
    })
}

/// 0..1 AI-signal contribution from a raw perplexity value. Lower
/// perplexity → more natural-text-like → stronger signal.
///
/// Thresholds are calibrated for the unigram-entropy approximation
/// scale described in `approximate()`; real llama.cpp perplexity
/// values land in a similar range (CodeLlama on text in the 10-50
/// range, on random bytes in the 1000+ range) so the same buckets
/// roughly work for both backends.
pub fn score(ppl: f64) -> f64 {
    if ppl < 24.0 {
        0.9
    } else if ppl < 48.0 {
        0.7
    } else if ppl < 96.0 {
        0.4
    } else if ppl < 200.0 {
        0.2
    } else {
        0.05
    }
}

fn build_corpus(strings: &[ExtractedString]) -> String {
    strings
        .iter()
        .filter(|s| s.value.len() >= STRING_MIN_LEN)
        .map(|s| s.value.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn try_llama_cpp(corpus: &str) -> Option<PerplexityResult> {
    let bin = std::env::var("AGAT_LLAMA_BIN").ok()?;
    let model = resolve_model()?;
    let tmp = write_temp_corpus(corpus).ok()?;

    let out = Command::new(&bin)
        .arg("-m").arg(&model)
        .arg("-f").arg(&tmp)
        .arg("-c").arg("512")
        .arg("--no-warmup")
        .output()
        .ok()?;
    let _ = std::fs::remove_file(&tmp);

    if !out.status.success() {
        tracing::debug!(
            stderr = %String::from_utf8_lossy(&out.stderr),
            "llama-perplexity exited non-zero"
        );
        return None;
    }
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let value = parse_perplexity(&combined)?;
    Some(PerplexityResult {
        value,
        backend: PerplexityBackend::LlamaCpp,
        corpus_chars: corpus.len(),
    })
}

fn resolve_model() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AGAT_LLAMA_MODEL") {
        return Some(PathBuf::from(p));
    }
    let home = dirs::home_dir()?;
    let p = home.join(".agat").join("models").join("code.gguf");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn write_temp_corpus(corpus: &str) -> std::io::Result<PathBuf> {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut path = std::env::temp_dir();
    path.push(format!("agat-ppl-{:016x}.txt", t));
    let mut f = std::fs::File::create(&path)?;
    f.write_all(corpus.as_bytes())?;
    Ok(path)
}

/// Scan the combined stdout+stderr of `llama-perplexity` for a
/// reasonable perplexity number. Line formats vary across versions,
/// so we look for any line mentioning "ppl" or "perplexity" and
/// pull the first plausible float out of it.
fn parse_perplexity(text: &str) -> Option<f64> {
    for line in text.lines().rev() {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("ppl") || lower.contains("perplexity")) {
            continue;
        }
        for tok in line.split(|c: char| {
            !(c.is_ascii_digit() || c == '.' || c == '-' || c == 'e' || c == 'E')
        }) {
            if let Ok(v) = tok.parse::<f64>() {
                if v > 0.5 && v < 1e8 {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Character-frequency-entropy approximation of perplexity.
///
/// Unigram (byte-frequency) entropy turns out to discriminate
/// natural language from random/encrypted bytes more reliably than
/// bigram entropy at the small corpus sizes we see in extracted
/// strings (a few hundred chars). Natural English has a narrow
/// character distribution dominated by a few letters and the space
/// character; random ASCII spreads its mass over the full printable
/// range; encrypted bytes spread it over all 256 values.
///
/// Interpretation (value = 2^entropy):
/// - natural English text → entropy ~4-4.5 bits → value 16-22
/// - mixed code-like text → 4.5-5.5 → 22-45
/// - random ASCII printable → 5.5-6.5 → 45-90
/// - high-entropy bytes → 7-8 → 128-256
fn approximate(corpus: &str) -> f64 {
    let bytes = corpus.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h.exp2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_static::strings::StringEncoding;

    fn mk(v: &str) -> ExtractedString {
        ExtractedString {
            offset: 0,
            encoding: StringEncoding::Ascii,
            value: v.to_string(),
        }
    }

    #[test]
    fn approximation_lower_on_natural_text() {
        let natural = vec![
            mk("This is a natural sentence in English language used for testing purposes."),
            mk("Another reasonable sentence with common words like the, is, and, with."),
            mk("Long descriptive comments are typical of LLM-generated code output."),
            mk("Variable names like user_input or error_message are common in such code."),
            mk("Refusal phrases say something like: I cannot help with that request."),
            mk("This document contains plenty of words to push us past the threshold."),
        ];
        let random = vec![
            mk("zX9k$qPm@vL2!nB7sR3wK#xQ$pN&jH+yT@uM%aF*hG^dE"),
            mk("9j2M#kP!vL$qR5n@b8XwQ#z!N$kP+aB&yC%dE^fG*hJ"),
            mk("X3#nL@9k$qP7vB2!mQwZ$kT+xR#nF&jD%cE^fG*hH"),
            mk("kQ#7vM$X2!nL@b9PrS+wH&xT$mE#nF%aE^fG*hJ"),
            mk("R5$nQ#kP!2vM+xB@wL$pT&jH#yE+uK%dF^gH*jK"),
            mk("Z7$xP@kQ#vN!nM$bL@hR+sT%dE^fG*hJ&yC#wK"),
        ];
        let n = compute(&natural).expect("natural corpus");
        let r = compute(&random).expect("random corpus");
        assert!(
            n.value < r.value,
            "expected natural < random; got natural={:.2} ({} chars) random={:.2} ({} chars)",
            n.value, n.corpus_chars, r.value, r.corpus_chars
        );
        assert_eq!(n.backend, PerplexityBackend::Approximation);
    }

    #[test]
    fn small_corpus_returns_none() {
        let small = vec![mk("abc"), mk("def")];
        assert!(compute(&small).is_none());
        // Even with a moderately-sized single string we still bail
        // out — needs to pass the 200-char threshold.
        let still_small = vec![mk(&"x".repeat(150))];
        assert!(compute(&still_small).is_none());
    }

    #[test]
    fn score_is_monotone_decreasing_in_ppl() {
        // Each pair sits in distinct buckets.
        assert!(score(10.0) > score(35.0)); // 0.9 > 0.7
        assert!(score(35.0) > score(70.0)); // 0.7 > 0.4
        assert!(score(70.0) > score(150.0)); // 0.4 > 0.2
        assert!(score(150.0) > score(500.0)); // 0.2 > 0.05
    }

    #[test]
    fn parse_perplexity_handles_typical_output() {
        let sample = "perplexity: 12.3456 +/- 0.1234";
        assert_eq!(parse_perplexity(sample), Some(12.3456));
        let sample = "Final estimate: PPL = 4.5678";
        assert_eq!(parse_perplexity(sample), Some(4.5678));
    }
}
