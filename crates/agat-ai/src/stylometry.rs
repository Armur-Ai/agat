//! Stylometric features over the binary's strings and disassembly.
//!
//! LLM-generated code reads differently from human-compiled code.
//! At the binary level — where we've lost variable names, comments,
//! and indentation — the surviving tells are in the *strings* the
//! binary embeds and in the *opcode-distribution shape* the
//! compiler emitted. This module computes both.

use agat_disasm::DisasmFeatures;
use agat_static::StaticFeatures;
use serde::{Deserialize, Serialize};

/// String-content patterns that LLM-generated code tends to ship
/// with: verbose, named, hyper-descriptive. None of these are
/// dispositive on their own — the signal is the *density*.
const LLM_IDIOMS: &[&str] = &[
    // "Helpful" verbose comments
    "// TODO",
    "// FIXME",
    "// NOTE",
    "// Refactored",
    "// Validate",
    "// Initialize",
    // Verbose snake_case identifiers
    "user_input",
    "error_message",
    "result_value",
    "data_payload",
    "response_data",
    "input_payload",
    "output_data",
    "validation_result",
    "_validation",
    "_handler",
    "_processor",
    "_manager",
    "_controller",
    // Defensive idioms
    "is_valid",
    "should_process",
    "has_error",
    "is_null",
    "is_empty",
    // Common error-message phrasings
    "Invalid input",
    "Error processing",
    "Successfully",
    "Failed to ",
    "Could not ",
    "Please provide",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StylometricFeatures {
    /// Shannon entropy of the opcode mnemonic histogram. Higher =
    /// more diverse instruction selection. LLM-rewritten code can
    /// shift this in either direction depending on the rewrite goal.
    pub opcode_diversity: f64,
    /// Mean instructions per basic block. LLM-emitted code at
    /// `-O0` often has shorter blocks (more branches per fn).
    pub mean_block_size: f64,
    /// Mean length of extracted ASCII strings. Verbose LLM idioms
    /// pull this up.
    pub mean_string_length: f64,
    /// Density of `_` characters across all extracted strings —
    /// a proxy for snake_case identifier prevalence.
    pub underscore_density: f64,
    /// Count of strings longer than 30 chars (proxy for descriptive
    /// comments or verbose error messages).
    pub long_string_count: usize,
    /// LLM idioms matched in strings, with the substring that fired.
    pub llm_idiom_hits: Vec<IdiomHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdiomHit {
    pub idiom: String,
    pub context: String,
}

pub fn compute(sf: &StaticFeatures, df: &DisasmFeatures) -> StylometricFeatures {
    let opcode_diversity = histogram_entropy(&df.opcode_histogram);
    let mean_block_size = if df.block_count > 0 {
        df.instruction_count as f64 / df.block_count as f64
    } else {
        0.0
    };

    let strings = &sf.strings.samples;
    let (mean_string_length, underscore_density, long_string_count) = if strings.is_empty() {
        (0.0, 0.0, 0)
    } else {
        let total_chars: usize = strings.iter().map(|s| s.value.len()).sum();
        let underscores: usize = strings
            .iter()
            .flat_map(|s| s.value.chars())
            .filter(|c| *c == '_')
            .count();
        let mean = total_chars as f64 / strings.len() as f64;
        let density = if total_chars > 0 {
            underscores as f64 / total_chars as f64
        } else {
            0.0
        };
        let long = strings.iter().filter(|s| s.value.len() > 30).count();
        (mean, density, long)
    };

    let mut llm_idiom_hits = Vec::new();
    for s in strings {
        let lower = s.value.to_ascii_lowercase();
        for idiom in LLM_IDIOMS {
            if lower.contains(&idiom.to_ascii_lowercase()) {
                let context: String = s
                    .value
                    .chars()
                    .take(70)
                    .collect::<String>();
                llm_idiom_hits.push(IdiomHit {
                    idiom: (*idiom).to_string(),
                    context,
                });
                break;
            }
        }
    }

    StylometricFeatures {
        opcode_diversity,
        mean_block_size,
        mean_string_length,
        underscore_density,
        long_string_count,
        llm_idiom_hits,
    }
}

fn histogram_entropy(histogram: &std::collections::HashMap<String, usize>) -> f64 {
    let total: usize = histogram.values().sum();
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut h = 0.0;
    for &count in histogram.values() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total_f;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_static::features::StringSummary;
    use agat_static::hashes::Hashes;
    use agat_static::parse::{Arch, BinaryFormat, ParsedBinary};
    use agat_static::strings::{ExtractedString, StringEncoding};
    use agat_static::entropy::EntropyCurve;

    fn fake_static(strings: Vec<&str>) -> StaticFeatures {
        StaticFeatures {
            size: 0,
            parsed: ParsedBinary {
                format: BinaryFormat::Unknown,
                arch: Arch::Other,
                bits: 0,
                entry_point: 0,
                sections: vec![],
                imports: vec![],
                exports: vec![],
            },
            hashes: Hashes {
                sha256: String::new(),
                md5: String::new(),
                imphash: None,
            },
            entropy: EntropyCurve {
                window_size: 0,
                step: 0,
                overall: 0.0,
                points: vec![],
                high_entropy_regions: vec![],
            },
            strings: StringSummary {
                min_len: 4,
                ascii_count: strings.len(),
                utf16le_count: 0,
                samples: strings
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| ExtractedString {
                        offset: i as u64,
                        encoding: StringEncoding::Ascii,
                        value: v.to_string(),
                    })
                    .collect(),
            },
        }
    }

    fn fake_disasm() -> DisasmFeatures {
        DisasmFeatures {
            arch: Arch::X86_64,
            bitness: 64,
            disassembled_section: None,
            section_base: 0,
            disassembled_bytes: 0,
            instruction_count: 0,
            block_count: 0,
            function_estimate: 0,
            listing_preview: vec![],
            blocks: vec![],
            edges: vec![],
            opcode_histogram: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn idiom_hits_fire_on_llm_strings() {
        let sf = fake_static(vec![
            "validate_user_input",
            "result_value = process_data(payload)",
            "// TODO: refactor",
        ]);
        let df = fake_disasm();
        let s = compute(&sf, &df);
        assert!(s.llm_idiom_hits.len() >= 3, "got {}", s.llm_idiom_hits.len());
    }

    #[test]
    fn no_hits_on_terse_strings() {
        let sf = fake_static(vec!["/bin/sh", "/proc/self/exe"]);
        let df = fake_disasm();
        let s = compute(&sf, &df);
        assert!(s.llm_idiom_hits.is_empty());
    }
}
