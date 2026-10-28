//! Stable content identities for memory cells and detectors (R1 · herd
//! immunity). A content id lets two nodes recognize "the same" learned
//! artifact when they merge antibody packs, so the union is deterministic and
//! idempotent regardless of arrival order.
//!
//! Ids are derived (never stored), so existing serialized models stay readable.
//! Coordinates are quantized before hashing so a cell re-serialized through
//! JSON hashes identically to the in-memory one.

use sha2::{Digest, Sha256};

/// Quantization grid for signature coordinates (4 decimal places). Matches the
/// precision at which antigen signatures are meaningfully distinct.
const GRID: f64 = 1.0e4;

fn q(x: f64) -> i64 {
    (x * GRID).round() as i64
}

/// A stable 16-hex-char id from a label, a center vector, and any extra scalars
/// (e.g. a radius) that are part of the artifact's identity.
pub(crate) fn hash_id(label: &str, center: &[f64], extra: &[f64]) -> String {
    let mut h = Sha256::new();
    h.update((label.len() as u64).to_le_bytes());
    h.update(label.as_bytes());
    h.update((center.len() as u64).to_le_bytes());
    for &c in center {
        h.update(q(c).to_le_bytes());
    }
    for &e in extra {
        h.update(q(e).to_le_bytes());
    }
    let d = h.finalize();
    hex::encode(&d[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_under_tiny_noise_within_grid() {
        let a = hash_id("fam", &[0.50001, 0.25], &[]);
        let b = hash_id("fam", &[0.50002, 0.25], &[]);
        assert_eq!(a, b, "sub-grid differences must not change the id");
    }

    #[test]
    fn distinct_for_different_labels_and_centers() {
        assert_ne!(hash_id("a", &[0.5], &[]), hash_id("b", &[0.5], &[]));
        assert_ne!(hash_id("a", &[0.5], &[]), hash_id("a", &[0.6], &[]));
        assert_ne!(hash_id("a", &[0.5], &[0.1]), hash_id("a", &[0.5], &[0.2]));
    }
}
