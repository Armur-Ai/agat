//! Basic-block construction and intra-procedural CFG.
//!
//! Standard textbook approach: identify "leaders" (first instruction
//! of each block) by scanning the listing for branch targets and
//! fall-through-after-branch addresses, then group instructions by
//! leader. Edges are typed by the terminator of the source block.

use crate::disasm::{DisasmLine, FlowKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: usize,
    pub start: u64,
    pub end: u64,
    pub instruction_count: usize,
    pub terminator: BlockTerminator,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockTerminator {
    Fallthrough,
    Jump,
    Branch,
    Call,
    Return,
    Indirect,
    Invalid,
    EndOfRange,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeKind {
    Fallthrough,
    Jump,
    BranchTaken,
    BranchNotTaken,
    Call,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub kind: EdgeKind,
}

pub fn build_cfg(lines: &[DisasmLine]) -> (Vec<BasicBlock>, Vec<Edge>) {
    if lines.is_empty() {
        return (vec![], vec![]);
    }

    let mut sorted: Vec<DisasmLine> = lines.to_vec();
    sorted.sort_by_key(|l| l.address);

    let line_addresses: BTreeSet<u64> = sorted.iter().map(|l| l.address).collect();
    let line_by_addr: BTreeMap<u64, usize> = sorted
        .iter()
        .enumerate()
        .map(|(i, l)| (l.address, i))
        .collect();

    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(sorted[0].address);
    for (i, line) in sorted.iter().enumerate() {
        match line.flow {
            FlowKind::Branch | FlowKind::Jump | FlowKind::Call => {
                if let Some(next) = sorted.get(i + 1) {
                    leaders.insert(next.address);
                }
                if let Some(t) = line.branch_target {
                    if line_addresses.contains(&t) {
                        leaders.insert(t);
                    }
                }
            }
            FlowKind::Return | FlowKind::Indirect | FlowKind::Invalid => {
                if let Some(next) = sorted.get(i + 1) {
                    leaders.insert(next.address);
                }
            }
            FlowKind::Next => {}
        }
    }

    let leader_vec: Vec<u64> = leaders.iter().copied().collect();
    let leader_to_block: HashMap<u64, usize> = leader_vec
        .iter()
        .enumerate()
        .map(|(i, &a)| (a, i))
        .collect();

    let mut blocks = Vec::with_capacity(leader_vec.len());
    let mut edges = Vec::new();

    for (block_id, &leader_addr) in leader_vec.iter().enumerate() {
        let block_start_idx = match line_by_addr.get(&leader_addr) {
            Some(&i) => i,
            None => continue,
        };
        let next_leader_addr = leader_vec.get(block_id + 1).copied();
        let block_end_idx = match next_leader_addr.and_then(|a| line_by_addr.get(&a).copied()) {
            Some(i) => i, // exclusive
            None => sorted.len(),
        };
        if block_end_idx <= block_start_idx {
            blocks.push(BasicBlock {
                id: block_id,
                start: leader_addr,
                end: leader_addr,
                instruction_count: 0,
                terminator: BlockTerminator::EndOfRange,
            });
            continue;
        }
        let last = &sorted[block_end_idx - 1];
        let (terminator, fallthrough_addr) = match last.flow {
            FlowKind::Next => (BlockTerminator::Fallthrough, sorted.get(block_end_idx).map(|n| n.address)),
            FlowKind::Branch => (BlockTerminator::Branch, sorted.get(block_end_idx).map(|n| n.address)),
            FlowKind::Jump => (BlockTerminator::Jump, None),
            FlowKind::Call => (BlockTerminator::Call, sorted.get(block_end_idx).map(|n| n.address)),
            FlowKind::Return => (BlockTerminator::Return, None),
            FlowKind::Indirect => (BlockTerminator::Indirect, None),
            FlowKind::Invalid => (BlockTerminator::Invalid, None),
        };
        blocks.push(BasicBlock {
            id: block_id,
            start: leader_addr,
            end: last.address,
            instruction_count: block_end_idx - block_start_idx,
            terminator,
        });

        match terminator {
            BlockTerminator::Fallthrough => {
                if let Some(fa) = fallthrough_addr {
                    if let Some(&to) = leader_to_block.get(&fa) {
                        edges.push(Edge {
                            from: block_id,
                            to,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
            }
            BlockTerminator::Branch => {
                if let Some(t) = last.branch_target {
                    if let Some(&to) = leader_to_block.get(&t) {
                        edges.push(Edge {
                            from: block_id,
                            to,
                            kind: EdgeKind::BranchTaken,
                        });
                    }
                }
                if let Some(fa) = fallthrough_addr {
                    if let Some(&to) = leader_to_block.get(&fa) {
                        edges.push(Edge {
                            from: block_id,
                            to,
                            kind: EdgeKind::BranchNotTaken,
                        });
                    }
                }
            }
            BlockTerminator::Jump => {
                if let Some(t) = last.branch_target {
                    if let Some(&to) = leader_to_block.get(&t) {
                        edges.push(Edge {
                            from: block_id,
                            to,
                            kind: EdgeKind::Jump,
                        });
                    }
                }
            }
            BlockTerminator::Call => {
                if let Some(t) = last.branch_target {
                    if let Some(&to) = leader_to_block.get(&t) {
                        edges.push(Edge {
                            from: block_id,
                            to,
                            kind: EdgeKind::Call,
                        });
                    }
                }
                if let Some(fa) = fallthrough_addr {
                    if let Some(&to) = leader_to_block.get(&fa) {
                        edges.push(Edge {
                            from: block_id,
                            to,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    (blocks, edges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::recursive_descent;

    #[test]
    fn small_program_yields_three_blocks() {
        // je +1 ; ret ; ret
        // Leaders: 0x1000 (start), 0x1002 (fallthrough after branch), 0x1003 (branch target)
        let bytes = [0x74, 0x01, 0xC3, 0xC3];
        let lines = recursive_descent(&bytes, 0x1000, 64, &[0x1000], 32);
        let (blocks, edges) = build_cfg(&lines);
        assert_eq!(blocks.len(), 3, "expected 3 blocks, got {}", blocks.len());
        let branch_taken = edges
            .iter()
            .filter(|e| e.kind == EdgeKind::BranchTaken)
            .count();
        let branch_not_taken = edges
            .iter()
            .filter(|e| e.kind == EdgeKind::BranchNotTaken)
            .count();
        assert_eq!(branch_taken, 1);
        assert_eq!(branch_not_taken, 1);
    }

    #[test]
    fn empty_input_yields_empty_cfg() {
        let (b, e) = build_cfg(&[]);
        assert!(b.is_empty());
        assert!(e.is_empty());
    }
}
