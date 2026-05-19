//! Linear-sweep and recursive-descent disassembly on top of iced-x86.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowKind {
    Next,
    Branch,
    Jump,
    Call,
    Return,
    Indirect,
    Invalid,
}

impl From<FlowControl> for FlowKind {
    fn from(fc: FlowControl) -> Self {
        match fc {
            FlowControl::Next => FlowKind::Next,
            FlowControl::UnconditionalBranch => FlowKind::Jump,
            FlowControl::IndirectBranch => FlowKind::Indirect,
            FlowControl::ConditionalBranch => FlowKind::Branch,
            FlowControl::Call => FlowKind::Call,
            FlowControl::IndirectCall => FlowKind::Indirect,
            FlowControl::Return => FlowKind::Return,
            FlowControl::Interrupt => FlowKind::Indirect,
            FlowControl::XbeginXabortXend => FlowKind::Indirect,
            FlowControl::Exception => FlowKind::Invalid,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmLine {
    pub address: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands: String,
    pub flow: FlowKind,
    /// Direct target of a near branch/jump/call. `None` for fall-
    /// through, returns, indirect transfers, and invalid decodes.
    pub branch_target: Option<u64>,
}

/// Disassemble `bytes` (mapped at `base_address`) in linear order
/// until decoding can't continue, the end of the buffer is reached,
/// or `max_instructions` instructions have been emitted.
pub fn linear_sweep(
    bytes: &[u8],
    base_address: u64,
    bitness: u32,
    max_instructions: usize,
) -> Vec<DisasmLine> {
    let mut decoder = Decoder::with_ip(bitness, bytes, base_address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instr = Instruction::default();
    let mut out = Vec::with_capacity(256);
    while decoder.can_decode() && out.len() < max_instructions {
        decoder.decode_out(&mut instr);
        out.push(make_line(bytes, base_address, &instr, &mut formatter));
    }
    out
}

/// Recursive descent from `roots`. Each root is decoded sequentially;
/// on conditional/unconditional branches and calls the direct target
/// is added to the worklist. Indirect transfers and returns terminate
/// the current sweep. Bounded by `max_instructions` total decodes.
pub fn recursive_descent(
    bytes: &[u8],
    base_address: u64,
    bitness: u32,
    roots: &[u64],
    max_instructions: usize,
) -> Vec<DisasmLine> {
    let mut visited: HashSet<u64> = HashSet::new();
    let end_address = base_address + bytes.len() as u64;
    let mut work: VecDeque<u64> = roots
        .iter()
        .copied()
        .filter(|a| *a >= base_address && *a < end_address)
        .collect();
    let mut all: BTreeMap<u64, DisasmLine> = BTreeMap::new();
    let mut formatter = IntelFormatter::new();
    let mut instr = Instruction::default();

    while let Some(addr) = work.pop_front() {
        if all.len() >= max_instructions {
            break;
        }
        if addr < base_address || addr >= end_address {
            continue;
        }
        if visited.contains(&addr) {
            continue;
        }

        let mut decoder = Decoder::with_ip(
            bitness,
            &bytes[(addr - base_address) as usize..],
            addr,
            DecoderOptions::NONE,
        );

        while decoder.can_decode() && all.len() < max_instructions {
            decoder.decode_out(&mut instr);
            let ip = instr.ip();
            if visited.contains(&ip) {
                break;
            }
            visited.insert(ip);
            let line = make_line(bytes, base_address, &instr, &mut formatter);
            let flow = line.flow;
            let target = line.branch_target;
            all.insert(ip, line);

            match flow {
                FlowKind::Next => continue,
                FlowKind::Branch | FlowKind::Call => {
                    if let Some(t) = target {
                        if !visited.contains(&t) {
                            work.push_back(t);
                        }
                    }
                    // Fall-through continues with the linear walk.
                    continue;
                }
                FlowKind::Jump => {
                    if let Some(t) = target {
                        if !visited.contains(&t) {
                            work.push_back(t);
                        }
                    }
                    break;
                }
                FlowKind::Return | FlowKind::Indirect | FlowKind::Invalid => break,
            }
        }
    }

    all.into_values().collect()
}

fn make_line(
    bytes: &[u8],
    base_address: u64,
    instr: &Instruction,
    formatter: &mut IntelFormatter,
) -> DisasmLine {
    let ip = instr.ip();
    let len = instr.len();
    let off = (ip - base_address) as usize;
    let bytes_hex = if off + len <= bytes.len() {
        hex::encode(&bytes[off..off + len])
    } else {
        String::new()
    };
    let mut formatted = String::new();
    formatter.format(instr, &mut formatted);
    let (mnemonic, operands) = split_mnemonic(&formatted);
    let flow: FlowKind = instr.flow_control().into();
    let branch_target = match instr.flow_control() {
        FlowControl::ConditionalBranch
        | FlowControl::UnconditionalBranch
        | FlowControl::Call => {
            let t = instr.near_branch_target();
            if t == 0 {
                None
            } else {
                Some(t)
            }
        }
        _ => None,
    };
    DisasmLine {
        address: ip,
        bytes_hex,
        mnemonic,
        operands,
        flow,
        branch_target,
    }
}

fn split_mnemonic(formatted: &str) -> (String, String) {
    let trimmed = formatted.trim_start();
    if let Some(idx) = trimmed.find(char::is_whitespace) {
        (
            trimmed[..idx].to_string(),
            trimmed[idx..].trim_start().to_string(),
        )
    } else {
        (trimmed.to_string(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_sweep_simple_x64() {
        // mov rax, 1 ; add rax, 2 ; ret
        let bytes = [
            0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x02, 0xC3,
        ];
        let lines = linear_sweep(&bytes, 0x1000, 64, 16);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].mnemonic, "mov");
        assert_eq!(lines[1].mnemonic, "add");
        assert_eq!(lines[2].mnemonic, "ret");
        assert_eq!(lines[2].flow, FlowKind::Return);
    }

    #[test]
    fn recursive_descent_follows_jcc() {
        // 0x1000  cmp rax, 0
        // 0x1004  je  0x1009   (4-byte short rel)  -- short jcc takes 2 bytes; let's use je rel8
        //   je 0x05 ;  bytes: 74 05  → target = 0x1002 + 2 + 5 = 0x1009
        // 0x1006  mov rax, 1    bytes: 48 C7 C0 01 00 00 00 (7 bytes)
        // 0x100D  ret           bytes: C3
        // Actually let me reconstruct: simpler with `je +2; ret; ret`
        let bytes = [
            0x74, 0x01, // je  +1   target = 0x1003
            0xC3,       // ret  (fallthrough at 0x1002)
            0xC3,       // ret  (branch target at 0x1003)
        ];
        let lines = recursive_descent(&bytes, 0x1000, 64, &[0x1000], 16);
        assert!(lines.len() >= 3, "expected ≥3 instructions, got {}", lines.len());
        // First instruction is the conditional branch
        let je = &lines[0];
        assert_eq!(je.flow, FlowKind::Branch);
        assert_eq!(je.branch_target, Some(0x1003));
    }
}
