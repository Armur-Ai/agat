//! Payload recovery: apply the inverse of a detected DecryptorPattern
//! to the largest high-entropy region and score the result.

use crate::detect::{DecryptorPattern, Operation};
use agat_static::{entropy::shannon_entropy, strings::extract_ascii, StaticFeatures};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredPayload {
    pub region_start: u64,
    pub region_end: u64,
    pub region_size: u64,
    pub operation: Operation,
    pub key: u8,
    pub original_entropy: f64,
    pub decrypted_entropy: f64,
    pub entropy_drop: f64,
    /// First 128 bytes of the decrypted blob, hex-encoded.
    pub preview_hex: String,
    /// First few ASCII strings extracted from the decrypted blob —
    /// often the "tell" that recovery worked.
    pub recovered_strings: Vec<String>,
    pub recovery_score: f64,
    /// 16-char hex hash of the sorted set of recovered strings ≥10
    /// chars. Used by `agat divergence` to group samples that
    /// recovered the same logical plaintext (even if they used
    /// different decryptor implementations). Empty when no
    /// long-enough strings came out of recovery.
    #[serde(default)]
    pub plaintext_fingerprint: String,
}

/// Attempt to recover the payload described by `pattern` against
/// the most likely encrypted region of `bytes`. The region is picked
/// by [`locate_payload_region`] — preferring the largest high-entropy
/// span, but falling back to the largest non-executable section so
/// low-entropy XOR'd ASCII still recovers.
pub fn try_recover(
    pattern: DecryptorPattern,
    sf: &StaticFeatures,
    bytes: &[u8],
) -> Option<RecoveredPayload> {
    let (region_start, region_end) = locate_payload_region(sf, bytes.len())?;
    let start = region_start as usize;
    let end = (region_end as usize).min(bytes.len());
    if start >= end {
        return None;
    }
    let original = &bytes[start..end];
    // The detected instruction *is* the decryptor: run it forward
    // (`add [mem], k` decrypts as c + k), as the stub itself would.
    let decrypted = crate::solve::decrypt(original, pattern.op, &[pattern.key]);
    let original_entropy = shannon_entropy(original);
    let decrypted_entropy = shannon_entropy(&decrypted);
    let entropy_drop = original_entropy - decrypted_entropy;

    let strings = extract_ascii(&decrypted, 4);
    let recovered_strings: Vec<String> = strings.iter().take(8).map(|s| s.value.clone()).collect();
    let preview_hex = hex::encode(&decrypted[..decrypted.len().min(128)]);
    let recovery_score = score_recovery(entropy_drop, &recovered_strings);
    let plaintext_fingerprint =
        fingerprint_plaintext(&strings.iter().map(|s| s.value.clone()).collect::<Vec<_>>());

    Some(RecoveredPayload {
        region_start,
        region_end,
        region_size: (end - start) as u64,
        operation: pattern.op,
        key: pattern.key,
        original_entropy,
        decrypted_entropy,
        entropy_drop,
        preview_hex,
        recovered_strings,
        recovery_score,
        plaintext_fingerprint,
    })
}

/// Hash the sorted set of recovered strings (filtered to ≥10 chars to
/// suppress random-byte noise) into a short hex token. Two samples
/// that decrypted to the same logical plaintext will share a
/// fingerprint, even when their decryptor implementations differ
/// wildly — which is exactly the cross-sample signal `agat divergence`
/// relies on to flag AI-rewritten variants.
fn fingerprint_plaintext(strings: &[String]) -> String {
    let mut filtered: Vec<&str> = strings
        .iter()
        .filter(|s| s.len() >= 10)
        .map(|s| s.as_str())
        .collect();
    if filtered.is_empty() {
        return String::new();
    }
    filtered.sort();
    let joined = filtered.join("|");
    let h = sha2::Sha256::digest(joined.as_bytes());
    hex::encode(&h[..8])
}

/// Pick the byte range to attempt decryption on. Strategy:
///
/// 1. Largest high-entropy region from the static entropy curve.
/// 2. Otherwise, the largest non-executable section in the parsed
///    binary (typical home of an encrypted `.data` blob).
/// 3. Otherwise, give up — we have no idea where to look.
fn locate_payload_region(sf: &StaticFeatures, file_size: usize) -> Option<(u64, u64)> {
    if let Some(r) = sf
        .entropy
        .high_entropy_regions
        .iter()
        .max_by(|a, b| (a.end - a.start).cmp(&(b.end - b.start)))
    {
        return Some((r.start, r.end));
    }
    let candidate = sf
        .parsed
        .sections
        .iter()
        .filter(|s| !s.characteristics.executable && s.file_size > 16)
        .max_by_key(|s| s.file_size)?;
    let start = candidate.file_offset;
    let end = (candidate.file_offset + candidate.file_size).min(file_size as u64);
    if start >= end {
        return None;
    }
    Some((start, end))
}

/// Crude success score in [0, 1]. String recovery is the dominant
/// signal (single-byte XOR is entropy-preserving, so we can't lean
/// on entropy drop as the primary indicator — but it does help for
/// ADD/SUB variants).
fn score_recovery(entropy_drop: f64, strings: &[String]) -> f64 {
    let mut score: f64 = 0.0;
    if !strings.is_empty() {
        score += 0.5;
    }
    if strings.len() >= 3 {
        score += 0.2;
    }
    if strings.len() >= 8 {
        score += 0.1;
    }
    if entropy_drop > 1.5 {
        score += 0.2;
    }
    score.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_static::entropy::{EntropyCurve, EntropyPoint, HighEntropyRegion};
    use agat_static::features::StringSummary;
    use agat_static::hashes::Hashes;
    use agat_static::parse::ParsedBinary;

    /// Minimal StaticFeatures whose only high-entropy region covers `len`
    /// bytes from offset 0.
    fn features_over(len: usize) -> StaticFeatures {
        StaticFeatures {
            size: len as u64,
            parsed: ParsedBinary {
                format: agat_static::parse::BinaryFormat::Unknown,
                arch: agat_static::parse::Arch::Other,
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
                high_entropy_regions: vec![HighEntropyRegion {
                    start: 0,
                    end: len as u64,
                    mean_entropy: 7.5,
                }],
            },
            strings: StringSummary {
                min_len: 4,
                ascii_count: 0,
                utf16le_count: 0,
                samples: vec![],
            },
        }
    }

    #[test]
    fn add_and_sub_decryptors_run_forward() {
        // A stub that decrypts with `add [mem], k` holds plain - k; one
        // that decrypts with `sub [mem], k` holds plain + k.
        let plain = b"/bin/sh\0Hello, world!\n";
        for (op, cipher) in [
            (
                Operation::Add,
                plain
                    .iter()
                    .map(|b| b.wrapping_sub(0x21))
                    .collect::<Vec<u8>>(),
            ),
            (
                Operation::Sub,
                plain
                    .iter()
                    .map(|b| b.wrapping_add(0x21))
                    .collect::<Vec<u8>>(),
            ),
        ] {
            let pattern = DecryptorPattern {
                op,
                key: 0x21,
                instruction_address: 0,
            };
            let rec = try_recover(pattern, &features_over(cipher.len()), &cipher).expect("recover");
            assert!(
                rec.recovered_strings.iter().any(|s| s.contains("Hello")),
                "{op:?} recovered {:?}",
                rec.recovered_strings
            );
        }
    }

    #[test]
    fn recovers_known_xor_plaintext() {
        // Plaintext: "/bin/sh\0Hello, world!\n" XOR'd with 0x42.
        let plain = b"/bin/sh\0Hello, world!\n";
        let key: u8 = 0x42;
        let ciphertext: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        // Build a fake StaticFeatures whose only high-entropy region
        // covers the entire ciphertext slot.
        let sf = StaticFeatures {
            size: ciphertext.len() as u64,
            parsed: ParsedBinary {
                format: agat_static::parse::BinaryFormat::Unknown,
                arch: agat_static::parse::Arch::Other,
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
                points: vec![EntropyPoint {
                    offset: 0,
                    entropy: 7.0,
                }],
                high_entropy_regions: vec![HighEntropyRegion {
                    start: 0,
                    end: ciphertext.len() as u64,
                    mean_entropy: 7.5,
                }],
            },
            strings: StringSummary {
                min_len: 4,
                ascii_count: 0,
                utf16le_count: 0,
                samples: vec![],
            },
        };
        let pattern = DecryptorPattern {
            op: Operation::Xor,
            key,
            instruction_address: 0,
        };
        let rec = try_recover(pattern, &sf, &ciphertext).expect("should recover");
        assert!(rec.recovered_strings.iter().any(|s| s.contains("/bin/sh")));
        assert!(rec.recovered_strings.iter().any(|s| s.contains("Hello")));
        // Single-byte XOR preserves byte-frequency entropy, so we
        // don't assert on entropy drop. String recovery is the real
        // tell.
        assert!(
            rec.recovery_score >= 0.5,
            "string recovery should yield a reasonable score, got {}",
            rec.recovery_score
        );
    }
}
