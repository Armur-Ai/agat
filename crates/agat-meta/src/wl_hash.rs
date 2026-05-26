//! Weisfeiler-Lehman hashing for control-flow graphs.
//!
//! Each block starts with a label that's a hash of its canonical
//! instruction sequence. Then we iterate: every block's new label is
//! a hash of its old label plus the sorted multiset of its
//! predecessor and successor labels. After K iterations the labels
//! are graph-isomorphism-invariant (modulo WL's known limitations);
//! we hash the sorted set of final labels to get the CFG fingerprint.

use crate::features::CanonicalInstruction;
use sha2::{Digest, Sha256};

/// Iterate this many WL refinement steps before computing the final
/// fingerprint. Three is enough to discriminate the small CFGs we
/// see in malware decryptors; larger benchmarks would want 5+.
pub const WL_ITERATIONS: usize = 3;

/// Compute a CFG fingerprint over normalized basic blocks and their
/// edges. Edges are `(from_block_index, to_block_index)` pairs.
pub fn wl_hash(blocks: &[Vec<CanonicalInstruction>], edges: &[(usize, usize)]) -> String {
    if blocks.is_empty() {
        return String::new();
    }
    let mut labels: Vec<String> = blocks.iter().map(|b| hash_block(b)).collect();

    let mut succ: Vec<Vec<usize>> = vec![vec![]; blocks.len()];
    let mut pred: Vec<Vec<usize>> = vec![vec![]; blocks.len()];
    for &(from, to) in edges {
        if from < blocks.len() && to < blocks.len() {
            succ[from].push(to);
            pred[to].push(from);
        }
    }

    for _ in 0..WL_ITERATIONS {
        let mut next = Vec::with_capacity(blocks.len());
        for i in 0..blocks.len() {
            let mut s: Vec<&str> = succ[i].iter().map(|&n| labels[n].as_str()).collect();
            let mut p: Vec<&str> = pred[i].iter().map(|&n| labels[n].as_str()).collect();
            s.sort();
            p.sort();
            let combined = format!(
                "{}|s:[{}]|p:[{}]",
                labels[i],
                s.join(","),
                p.join(",")
            );
            next.push(sha8(&combined));
        }
        labels = next;
    }

    let mut sorted = labels;
    sorted.sort();
    sha8(&sorted.join("|"))
}

pub fn hash_block(instrs: &[CanonicalInstruction]) -> String {
    let text: Vec<String> = instrs
        .iter()
        .map(|i| format!("{}|{}", i.mnemonic, i.operands))
        .collect();
    sha8(&text.join(";"))
}

fn sha8(s: &str) -> String {
    let h = Sha256::digest(s.as_bytes());
    hex::encode(&h[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instr(m: &str, o: &str) -> CanonicalInstruction {
        CanonicalInstruction {
            mnemonic: m.to_string(),
            operands: o.to_string(),
        }
    }

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(wl_hash(&[], &[]), "");
    }

    #[test]
    fn isomorphic_graphs_get_same_fingerprint() {
        let v1 = vec![
            vec![instr("mov", "R0,IMM"), instr("xor", "[R0],IMM")],
            vec![instr("ret", "")],
        ];
        let v2 = vec![
            vec![instr("mov", "R0,IMM"), instr("xor", "[R0],IMM")],
            vec![instr("ret", "")],
        ];
        let e = vec![(0, 1)];
        assert_eq!(wl_hash(&v1, &e), wl_hash(&v2, &e));
    }

    #[test]
    fn different_block_contents_differ() {
        let v1 = vec![vec![instr("mov", "R0,IMM")], vec![instr("ret", "")]];
        let v2 = vec![vec![instr("add", "R0,IMM")], vec![instr("ret", "")]];
        let e = vec![(0, 1)];
        assert_ne!(wl_hash(&v1, &e), wl_hash(&v2, &e));
    }
}
