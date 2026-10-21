//! Shannon entropy in bits/byte over arbitrary byte slices.

use serde::{Deserialize, Serialize};

/// Shannon entropy of `bytes`, in bits per byte. Returns 0.0 for an
/// empty input.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyPoint {
    pub offset: u64,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighEntropyRegion {
    pub start: u64,
    pub end: u64,
    pub mean_entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyCurve {
    pub window_size: usize,
    pub step: usize,
    pub overall: f64,
    pub points: Vec<EntropyPoint>,
    pub high_entropy_regions: Vec<HighEntropyRegion>,
}

/// Sliding-window entropy across `bytes`. Each point reports the
/// entropy of a `window`-byte window starting at the given offset;
/// the window advances by `step`. High-entropy regions (mean ≥ 7.0)
/// are computed from the resulting curve.
pub fn entropy_curve(bytes: &[u8], window: usize, step: usize) -> EntropyCurve {
    let overall = shannon_entropy(bytes);
    let mut points = Vec::new();
    if window == 0 || step == 0 || bytes.len() < window {
        return EntropyCurve {
            window_size: window,
            step,
            overall,
            points,
            high_entropy_regions: vec![],
        };
    }
    let mut offset = 0;
    while offset + window <= bytes.len() {
        let h = shannon_entropy(&bytes[offset..offset + window]);
        points.push(EntropyPoint {
            offset: offset as u64,
            entropy: h,
        });
        offset += step;
    }
    let high_entropy_regions = detect_regions(&points, window, 7.0);
    EntropyCurve {
        window_size: window,
        step,
        overall,
        points,
        high_entropy_regions,
    }
}

fn detect_regions(
    points: &[EntropyPoint],
    window: usize,
    threshold: f64,
) -> Vec<HighEntropyRegion> {
    let mut out = Vec::new();
    let mut start: Option<u64> = None;
    let mut sum = 0.0;
    let mut count = 0u64;
    let mut last_offset = 0u64;
    for p in points {
        last_offset = p.offset;
        if p.entropy >= threshold {
            if start.is_none() {
                start = Some(p.offset);
            }
            sum += p.entropy;
            count += 1;
        } else if let Some(s) = start.take() {
            out.push(HighEntropyRegion {
                start: s,
                end: p.offset,
                mean_entropy: sum / count.max(1) as f64,
            });
            sum = 0.0;
            count = 0;
        }
    }
    if let Some(s) = start {
        out.push(HighEntropyRegion {
            start: s,
            end: last_offset + window as u64,
            mean_entropy: sum / count.max(1) as f64,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros_is_zero() {
        assert_eq!(shannon_entropy(&[0u8; 1024]), 0.0);
    }

    #[test]
    fn entropy_of_uniform_is_eight() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
        let h = shannon_entropy(&bytes);
        assert!((h - 8.0).abs() < 0.01, "expected ~8.0, got {h}");
    }

    #[test]
    fn empty_input_yields_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn curve_detects_high_entropy_block() {
        // Low-entropy padding around a random block.
        let mut bytes = vec![0u8; 4096];
        for i in 0..1024 {
            bytes[2048 + i] = (i * 37 + 11) as u8;
        }
        let curve = entropy_curve(&bytes, 256, 256);
        assert!(!curve.points.is_empty());
        assert!(curve.overall > 0.0);
    }
}
