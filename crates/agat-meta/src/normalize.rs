//! Tokenizer-based canonicalization for x86/x64 disassembly operands.
//!
//! Goal: produce a register-name-independent, immediate-value-
//! independent textual form per instruction, so two variants of the
//! same metamorphic family hash identically.

use crate::features::CanonicalInstruction;
use agat_disasm::DisasmLine;
use std::collections::HashMap;

/// Mapping from x86 register names (any width) to a canonical family
/// representative. Used so `eax`, `ax`, `al`, and `rax` all hash the
/// same — metamorphic engines often switch the operand width.
fn register_family(reg: &str) -> Option<&'static str> {
    Some(match reg {
        "rax" | "eax" | "ax" | "ah" | "al" => "rax",
        "rbx" | "ebx" | "bx" | "bh" | "bl" => "rbx",
        "rcx" | "ecx" | "cx" | "ch" | "cl" => "rcx",
        "rdx" | "edx" | "dx" | "dh" | "dl" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        _ => return None,
    })
}

/// Stateful renamer: assigns `R0`, `R1`, ... to each unique register
/// family on first appearance. Rsp and rbp pass through unchanged
/// because their semantic role (stack/base pointer) shouldn't be
/// confused with general-purpose registers.
pub struct RegisterRenamer {
    map: HashMap<&'static str, String>,
    next: usize,
}

impl RegisterRenamer {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            next: 0,
        }
    }

    pub fn rename(&mut self, family: &'static str) -> String {
        if matches!(family, "rsp" | "rbp") {
            return family.to_string();
        }
        if let Some(name) = self.map.get(family) {
            return name.clone();
        }
        let name = format!("R{}", self.next);
        self.next += 1;
        self.map.insert(family, name.clone());
        name
    }
}

impl Default for RegisterRenamer {
    fn default() -> Self {
        Self::new()
    }
}

pub fn canonicalize_operands(operands: &str, renamer: &mut RegisterRenamer) -> String {
    let mut out = String::with_capacity(operands.len());
    let mut chars = operands.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_alphabetic() || c == '_' {
            // Identifier (register, keyword like "byte", "ptr", "qword", etc.)
            let mut tok = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphanumeric() || c == '_' {
                    tok.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            let lower = tok.to_ascii_lowercase();
            if let Some(family) = register_family(&lower) {
                out.push_str(&renamer.rename(family));
            } else {
                out.push_str(&lower);
            }
        } else if c.is_ascii_digit() {
            // Numeric literal (decimal, hex with 'h' suffix, or 0x prefix).
            // Consume until non-alphanumeric.
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphanumeric() {
                    chars.next();
                } else {
                    break;
                }
            }
            out.push_str("IMM");
        } else {
            // Punctuation: , [ ] + - * space etc.
            if !c.is_whitespace() {
                out.push(c);
            }
            chars.next();
        }
    }
    out
}

/// Returns true if a (canonicalized) instruction is semantically a
/// no-op and can be dropped during normalization.
pub fn is_canonical_nop(mnemonic: &str, operands: &str) -> bool {
    if mnemonic == "nop" {
        return true;
    }
    // `xchg R0,R0` (or any same-register xchg) is a no-op.
    if mnemonic == "xchg" {
        if let Some((a, b)) = operands.split_once(',') {
            if a == b {
                return true;
            }
        }
    }
    // `mov R0,R0` is a no-op.
    if mnemonic == "mov" {
        if let Some((a, b)) = operands.split_once(',') {
            if a == b {
                return true;
            }
        }
    }
    false
}

/// Canonicalize a function-level instruction listing.
///
/// All instructions share one [`RegisterRenamer`], so register-family
/// IDs are consistent across the function (a `R0` in block 0 is the
/// same physical register as a `R0` in block 5).
pub fn canonicalize_lines(lines: &[&DisasmLine]) -> Vec<CanonicalInstruction> {
    let mut renamer = RegisterRenamer::new();
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        let mnemonic = line.mnemonic.to_ascii_lowercase();
        let operands = canonicalize_operands(&line.operands, &mut renamer);
        if is_canonical_nop(&mnemonic, &operands) {
            continue;
        }
        out.push(CanonicalInstruction { mnemonic, operands });
    }
    out
}

/// Per-block canonicalization that shares a renamer with the rest of
/// the function. Used by the analyzer when it walks blocks in order.
pub fn canonicalize_block_with(
    lines: &[&DisasmLine],
    renamer: &mut RegisterRenamer,
) -> Vec<CanonicalInstruction> {
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        let mnemonic = line.mnemonic.to_ascii_lowercase();
        let operands = canonicalize_operands(&line.operands, renamer);
        if is_canonical_nop(&mnemonic, &operands) {
            continue;
        }
        out.push(CanonicalInstruction { mnemonic, operands });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_rename_in_first_use_order() {
        let mut r = RegisterRenamer::new();
        assert_eq!(r.rename("rsi"), "R0");
        assert_eq!(r.rename("rcx"), "R1");
        assert_eq!(r.rename("rsi"), "R0"); // stable
        assert_eq!(r.rename("rdi"), "R2");
    }

    #[test]
    fn rsp_rbp_pass_through() {
        let mut r = RegisterRenamer::new();
        assert_eq!(r.rename("rsp"), "rsp");
        assert_eq!(r.rename("rbp"), "rbp");
        assert_eq!(r.rename("rax"), "R0");
    }

    #[test]
    fn width_family_collapses_to_canonical() {
        let mut r = RegisterRenamer::new();
        // rsi, esi, si, sil all live in the same family → same canonical name
        let a = canonicalize_operands("rsi", &mut r);
        let b = canonicalize_operands("esi", &mut r);
        let c = canonicalize_operands("si", &mut r);
        assert_eq!(a, "R0");
        assert_eq!(b, "R0");
        assert_eq!(c, "R0");
    }

    #[test]
    fn operands_canonicalize() {
        let mut r = RegisterRenamer::new();
        assert_eq!(canonicalize_operands("byte ptr [rsi],42h", &mut r), "byteptr[R0],IMM");
        // Reset renamer for a fresh function
        let mut r = RegisterRenamer::new();
        assert_eq!(canonicalize_operands("[rsp+8]", &mut r), "[rsp+IMM]");
    }

    #[test]
    fn equivalent_decryptors_canonicalize_identically() {
        let mut r1 = RegisterRenamer::new();
        let mut r2 = RegisterRenamer::new();
        let v1 = canonicalize_operands("rsi,0x401000", &mut r1);
        let v2 = canonicalize_operands("rdi,0x401000", &mut r2);
        // Different physical regs but same canonical role → same canonical text.
        assert_eq!(v1, "R0,IMM");
        assert_eq!(v2, "R0,IMM");
    }
}
