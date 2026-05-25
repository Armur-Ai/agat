//! Signal collection for polymorphic-engine detection.

use agat_disasm::{DisasmFeatures, DisasmLine, FlowKind};
use agat_static::{entropy::EntropyCurve, StaticFeatures};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Xor,
    Add,
    Sub,
}

impl Operation {
    pub fn label(self) -> &'static str {
        match self {
            Operation::Xor => "XOR",
            Operation::Add => "ADD",
            Operation::Sub => "SUB",
        }
    }
}

/// A statically-identified decryptor candidate: a memory-modifying
/// instruction whose immediate key we could pluck off, sitting inside
/// a tight backward-jumping loop.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DecryptorPattern {
    pub op: Operation,
    pub key: u8,
    pub instruction_address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signal {
    EntropyBoundary {
        boundary_offset: u64,
        before_entropy: f64,
        after_entropy: f64,
    },
    BackwardJumpInPrelude {
        from: u64,
        to: u64,
    },
    DecryptorLoop {
        op: Operation,
        instruction_address: u64,
        key: Option<u8>,
    },
}

impl Signal {
    pub fn weight(&self) -> f64 {
        match self {
            Signal::EntropyBoundary { .. } => 0.35,
            Signal::BackwardJumpInPrelude { .. } => 0.20,
            Signal::DecryptorLoop { key: Some(_), .. } => 0.45,
            Signal::DecryptorLoop { key: None, .. } => 0.30,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Signal::EntropyBoundary { .. } => "entropy boundary",
            Signal::BackwardJumpInPrelude { .. } => "backward jump in prelude",
            Signal::DecryptorLoop { .. } => "decryptor loop",
        }
    }
}

/// Collect all signals for a sample. Returns them in detection order;
/// callers may want to rank by `weight()`.
pub fn collect_signals(sf: &StaticFeatures, df: &DisasmFeatures) -> Vec<Signal> {
    let mut out = Vec::new();
    if let Some(s) = detect_entropy_boundary(&sf.entropy) {
        out.push(s);
    }
    if let Some(s) = detect_backward_jump(&df.listing_preview) {
        out.push(s);
    }
    if let Some(s) = detect_decryptor_loop(&df.listing_preview) {
        out.push(s);
    }
    out
}

/// Combined confidence in `[0.0, 0.95]`. We never claim 100% — the
/// talk's whole point is these are heuristics in a constellation.
pub fn confidence(signals: &[Signal]) -> f64 {
    let sum: f64 = signals.iter().map(|s| s.weight()).sum();
    sum.min(0.95)
}

/// First strongly-supported DecryptorPattern. Picked from
/// DecryptorLoop signals that have a key.
pub fn strongest_pattern(signals: &[Signal]) -> Option<DecryptorPattern> {
    signals.iter().find_map(|s| match s {
        Signal::DecryptorLoop {
            op,
            instruction_address,
            key: Some(k),
        } => Some(DecryptorPattern {
            op: *op,
            key: *k,
            instruction_address: *instruction_address,
        }),
        _ => None,
    })
}

fn detect_entropy_boundary(curve: &EntropyCurve) -> Option<Signal> {
    let n = curve.points.len();
    if n < 8 {
        return None;
    }
    // Compare the first quarter (assumed-stub region) to the rest.
    let split = (n / 4).max(1);
    let before: f64 =
        curve.points[..split].iter().map(|p| p.entropy).sum::<f64>() / split as f64;
    let after: f64 = curve.points[split..].iter().map(|p| p.entropy).sum::<f64>()
        / (n - split) as f64;
    // Stub is meaningfully calmer than the body, and the body is itself high-entropy.
    if after - before > 2.0 && after > 6.0 {
        Some(Signal::EntropyBoundary {
            boundary_offset: curve.points[split].offset,
            before_entropy: before,
            after_entropy: after,
        })
    } else {
        None
    }
}

fn detect_backward_jump(lines: &[DisasmLine]) -> Option<Signal> {
    for l in lines.iter().take(80) {
        if matches!(l.flow, FlowKind::Branch | FlowKind::Jump) {
            if let Some(t) = l.branch_target {
                if t <= l.address && l.address - t < 256 {
                    return Some(Signal::BackwardJumpInPrelude {
                        from: l.address,
                        to: t,
                    });
                }
            }
        }
    }
    None
}

fn detect_decryptor_loop(lines: &[DisasmLine]) -> Option<Signal> {
    for (idx, l) in lines.iter().enumerate().take(120) {
        let op = match l.mnemonic.as_str() {
            "xor" => Operation::Xor,
            "add" => Operation::Add,
            "sub" => Operation::Sub,
            _ => continue,
        };
        // Decryptor loops rewrite memory in place.
        if !l.writes_memory {
            continue;
        }
        // Is this inside (or directly before) a backward-jumping loop?
        let has_loop = lines
            .iter()
            .skip(idx)
            .take(40)
            .any(|n| {
                matches!(n.flow, FlowKind::Branch | FlowKind::Jump)
                    && n.branch_target.is_some_and(|t| t <= l.address)
            });
        if !has_loop {
            continue;
        }
        // Static key extraction: take the immediate, narrowed to a byte.
        let key = l.immediate.map(|imm| (imm & 0xFF) as u8);
        return Some(Signal::DecryptorLoop {
            op,
            instruction_address: l.address,
            key,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_disasm::FlowKind;

    fn line(addr: u64, mnem: &str, ops: &str, flow: FlowKind, target: Option<u64>, imm: Option<u64>, wm: bool) -> DisasmLine {
        DisasmLine {
            address: addr,
            bytes_hex: String::new(),
            mnemonic: mnem.to_string(),
            operands: ops.to_string(),
            flow,
            branch_target: target,
            immediate: imm,
            writes_memory: wm,
        }
    }

    #[test]
    fn detects_xor_loop_with_immediate_key() {
        let lines = vec![
            line(0x00, "mov", "ecx,100h", FlowKind::Next, None, Some(0x100), false),
            line(0x05, "mov", "esi,offset payload", FlowKind::Next, None, None, false),
            line(0x0A, "xor", "byte ptr [esi],42h", FlowKind::Next, None, Some(0x42), true),
            line(0x0E, "inc", "esi", FlowKind::Next, None, None, false),
            line(0x10, "dec", "ecx", FlowKind::Next, None, None, false),
            line(0x12, "jne", "0Ah", FlowKind::Branch, Some(0x0A), None, false),
            line(0x14, "ret", "", FlowKind::Return, None, None, false),
        ];
        let s = detect_decryptor_loop(&lines).expect("should detect xor loop");
        match s {
            Signal::DecryptorLoop { op, key, .. } => {
                assert_eq!(op, Operation::Xor);
                assert_eq!(key, Some(0x42));
            }
            _ => panic!("wrong signal"),
        }
    }

    #[test]
    fn rejects_non_loop_xor() {
        // xor without a backward jump — not a decryptor.
        let lines = vec![
            line(0x00, "xor", "byte ptr [esi],42h", FlowKind::Next, None, Some(0x42), true),
            line(0x04, "ret", "", FlowKind::Return, None, None, false),
        ];
        assert!(detect_decryptor_loop(&lines).is_none());
    }

    #[test]
    fn detects_sub_loop() {
        let lines = vec![
            line(0x00, "sub", "byte ptr [esi],5", FlowKind::Next, None, Some(0x05), true),
            line(0x04, "jne", "0", FlowKind::Branch, Some(0x00), None, false),
        ];
        let s = detect_decryptor_loop(&lines).expect("should detect sub loop");
        match s {
            Signal::DecryptorLoop { op, key, .. } => {
                assert_eq!(op, Operation::Sub);
                assert_eq!(key, Some(5));
            }
            _ => panic!("wrong signal"),
        }
    }
}
