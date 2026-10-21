//! AArch64 (ARM64) instruction decoding on top of `yaxpeax-arm`.
//!
//! Produces the same architecture-neutral [`DisasmLine`] as the x86
//! backend (flow kind, direct branch target, first immediate, whether
//! the instruction stores to memory), so the recursive descent, CFG,
//! metamorphic, and antigen layers downstream work unchanged.
//! Instructions are a fixed 4 bytes.

use crate::disasm::{DisasmLine, FlowKind};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand};

/// Width of every A64 instruction.
pub const INSN_LEN: usize = 4;

/// Decode the instruction at `addr` (inside `bytes`, mapped at `base`).
/// Returns `None` past the end of the buffer; an undecodable word yields
/// an `Invalid` line so descent stops there.
pub fn decode_at(bytes: &[u8], base: u64, addr: u64) -> Option<(DisasmLine, usize)> {
    let off = addr.checked_sub(base)? as usize;
    let word = bytes.get(off..off + INSN_LEN)?;
    let decoder = InstDecoder::default();
    let mut reader = U8Reader::new(word);
    let line = match decoder.decode(&mut reader) {
        Ok(inst) => line_for(&inst, addr, word),
        Err(_) => DisasmLine {
            address: addr,
            bytes_hex: hex::encode(word),
            mnemonic: "(bad)".to_string(),
            operands: String::new(),
            flow: FlowKind::Invalid,
            branch_target: None,
            immediate: None,
            writes_memory: false,
        },
    };
    Some((line, INSN_LEN))
}

fn line_for(inst: &Instruction, addr: u64, word: &[u8]) -> DisasmLine {
    let text = inst.to_string();
    let (mnemonic, operands) = match text.split_once(' ') {
        Some((m, o)) => (m.to_string(), o.trim().to_string()),
        None => (text.clone(), String::new()),
    };
    let pc_target = inst.operands.iter().find_map(|o| match o {
        Operand::PCOffset(off) => Some(addr.wrapping_add(*off as u64)),
        _ => None,
    });
    let flow = match inst.opcode {
        Opcode::B => FlowKind::Jump,
        Opcode::BL => FlowKind::Call,
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
            FlowKind::Branch
        }
        Opcode::BR
        | Opcode::BRAA
        | Opcode::BRAAZ
        | Opcode::BRAB
        | Opcode::BLR
        | Opcode::BLRAA
        | Opcode::BLRAAZ
        | Opcode::BLRAB => FlowKind::Indirect,
        Opcode::RET | Opcode::RETAA | Opcode::RETAB | Opcode::ERET => FlowKind::Return,
        Opcode::UDF | Opcode::BRK | Opcode::HLT => FlowKind::Invalid,
        _ => FlowKind::Next,
    };
    let branch_target = match flow {
        FlowKind::Jump | FlowKind::Call | FlowKind::Branch => pc_target,
        _ => None,
    };
    let immediate = inst.operands.iter().find_map(|o| match o {
        Operand::Immediate(v) => Some(*v as u64),
        Operand::ImmShift(v, shift) => Some((*v as u64) << shift),
        _ => None,
    });
    // Stores: str/strb/strh/stp/stur*/stnp/stlr*/stxr*/st1..st4.
    let writes_memory = mnemonic.starts_with("st");
    DisasmLine {
        address: addr,
        bytes_hex: hex::encode(word),
        mnemonic,
        operands,
        flow,
        branch_target,
        immediate,
        writes_memory,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn decodes_flow_targets_immediates_and_stores() {
        // 0x1000 movz w2, #0x200      52804002
        // 0x1004 ldrb w3, [x1]        39400023
        // 0x1008 eor  w3, w3, w4      4a040063
        // 0x100c strb w3, [x1], #1    38001423
        // 0x1010 subs w2, w2, #1      71000442
        // 0x1014 b.ne 0x1004          54ffff81
        // 0x1018 bl   0x1020          94000002
        // 0x101c ret                  d65f03c0
        let code = le(&[
            0x52804002, 0x39400023, 0x4a040063, 0x38001423, 0x71000442, 0x54ffff81, 0x94000002,
            0xd65f03c0,
        ]);
        let at = |a: u64| decode_at(&code, 0x1000, a).unwrap().0;

        let movz = at(0x1000);
        assert_eq!(movz.immediate, Some(0x200));
        assert_eq!(movz.flow, FlowKind::Next);

        assert!(!at(0x1004).writes_memory, "ldrb loads");
        assert_eq!(at(0x1008).mnemonic, "eor");
        assert!(at(0x100c).writes_memory, "strb stores");

        let bne = at(0x1014);
        assert_eq!(bne.flow, FlowKind::Branch);
        assert_eq!(bne.branch_target, Some(0x1004));

        let bl = at(0x1018);
        assert_eq!(bl.flow, FlowKind::Call);
        assert_eq!(bl.branch_target, Some(0x1020));

        assert_eq!(at(0x101c).flow, FlowKind::Return);
        assert!(decode_at(&code, 0x1000, 0x1020).is_none(), "past the end");
    }
}
