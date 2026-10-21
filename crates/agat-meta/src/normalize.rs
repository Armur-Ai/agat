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
        // `sp` is also AArch64's stack pointer; one canonical name fits both.
        "rsp" | "esp" | "sp" | "spl" | "wsp" => "rsp",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        // AArch64 registers with a fixed role pass through by name.
        "x29" | "w29" | "fp" => "x29",
        "x30" | "w30" | "lr" => "x30",
        "xzr" | "wzr" => "xzr",
        _ => return arm64_family(reg),
    })
}

/// AArch64 general-purpose registers `x0`–`x28` / `w0`–`w28` (the 64-
/// and 32-bit views share a family, like `rax`/`eax`).
fn arm64_family(reg: &str) -> Option<&'static str> {
    const X: [&str; 29] = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28",
    ];
    let digits = reg.strip_prefix('x').or_else(|| reg.strip_prefix('w'))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    X.get(digits.parse::<usize>().ok()?).copied()
}

/// Stateful renamer: assigns `R0`, `R1`, ... to each unique register
/// family on first appearance. Registers with a fixed semantic role
/// (x86 `rsp`/`rbp`; AArch64 `x29`/`x30`/`xzr`, and `sp` as `rsp`) pass through
/// unchanged, so they aren't confused with general-purpose registers.
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
        // Registers with a fixed semantic role keep their names: the x86
        // stack/base pointers, and AArch64's frame pointer, link register,
        // stack pointer and zero register.
        if matches!(family, "rsp" | "rbp" | "x29" | "x30" | "xzr") {
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

/// Fold semantically-equivalent instruction forms onto one representative:
/// instruction substitution, the half of metamorphism that register
/// renaming and NOP removal don't touch. Operands are already canonical
/// (registers as `R0…`, immediates as `IMM`), so the folds work on text:
///
/// | forms | folded to |
/// |---|---|
/// | `inc X`, `dec X`, `sub X,IMM`, `add X,±IMM` | `add X,IMM` |
/// | `lea X,[X±IMM]` | `add X,IMM` |
/// | `lea X,[Y]` | `mov X,Y` |
/// | `xor X,X`, `sub X,X` (zeroing) | `mov X,IMM` |
/// | `test X,X`, `or X,X`, `and X,X` (flag test) | `cmp X,IMM` |
/// | `add X,X`, `lea X,[X+X]` (doubling) | `shl X,IMM` |
///
/// Immediate values are already erased, so the sign of an erased
/// immediate (`-IMM`) carries nothing and is dropped too. The pair fold
/// `push A; pop B` → `mov B,A` lives in [`fold_block`].
pub fn fold_instruction(mnemonic: &str, operands: &str) -> (String, String) {
    let ops = operands.replace("-IMM", "IMM");
    let pair = ops.split_once(',');
    let folded = match (mnemonic, pair) {
        ("inc" | "dec", None) if !ops.is_empty() => Some(("add", format!("{ops},IMM"))),
        ("sub", Some((x, "IMM"))) => Some(("add", format!("{x},IMM"))),
        ("xor" | "sub", Some((x, y))) if x == y => Some(("mov", format!("{x},IMM"))),
        ("test" | "or" | "and", Some((x, y))) if x == y => Some(("cmp", format!("{x},IMM"))),
        ("add", Some((x, y))) if x == y => Some(("shl", format!("{x},IMM"))),
        ("lea", Some((x, mem))) => {
            let inner = mem.strip_prefix('[').and_then(|m| m.strip_suffix(']'));
            match inner {
                Some(m) if m == format!("{x}+IMM") => Some(("add", format!("{x},IMM"))),
                Some(m) if m == format!("{x}+{x}") => Some(("shl", format!("{x},IMM"))),
                Some(m) if !m.contains(['+', '*']) => Some(("mov", format!("{x},{m}"))),
                _ => None,
            }
        }
        _ => None,
    };
    match folded {
        Some((m, o)) => (m.to_string(), o),
        None => (mnemonic.to_string(), ops),
    }
}

/// Fold a canonicalized block: per-instruction folds, then the pair fold
/// `push A; pop B` → `mov B,A` (a register or immediate moved through the
/// stack), then drop instructions that became no-ops (`mov X,X`).
pub fn fold_block(block: Vec<CanonicalInstruction>) -> Vec<CanonicalInstruction> {
    let folded: Vec<CanonicalInstruction> = block
        .into_iter()
        .map(|c| {
            let (mnemonic, operands) = fold_instruction(&c.mnemonic, &c.operands);
            CanonicalInstruction { mnemonic, operands }
        })
        .collect();
    let mut out = Vec::with_capacity(folded.len());
    let mut i = 0;
    while i < folded.len() {
        let cur = &folded[i];
        if cur.mnemonic == "push" {
            if let Some(next) = folded.get(i + 1).filter(|n| n.mnemonic == "pop") {
                if !cur.operands.contains('[') && !next.operands.contains('[') {
                    out.push(CanonicalInstruction {
                        mnemonic: "mov".to_string(),
                        operands: format!("{},{}", next.operands, cur.operands),
                    });
                    i += 2;
                    continue;
                }
            }
        }
        out.push(cur.clone());
        i += 1;
    }
    out.retain(|c| !is_canonical_nop(&c.mnemonic, &c.operands));
    out
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
    fold_block(out)
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
    fold_block(out)
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
        assert_eq!(
            canonicalize_operands("byte ptr [rsi],42h", &mut r),
            "byteptr[R0],IMM"
        );
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

    fn ins(m: &str, o: &str) -> CanonicalInstruction {
        CanonicalInstruction {
            mnemonic: m.to_string(),
            operands: o.to_string(),
        }
    }

    #[test]
    fn arm64_registers_rename_and_fixed_roles_pass_through() {
        let mut r1 = RegisterRenamer::new();
        let mut r2 = RegisterRenamer::new();
        // The same loop with different register allocation.
        let a = canonicalize_operands("w3, [x1], #0x1", &mut r1);
        let b = canonicalize_operands("w9, [x5], #0x1", &mut r2);
        assert_eq!(a, b);
        assert_eq!(a, "R0,[R1],#IMM");
        // w3 and x3 are one family.
        assert_eq!(canonicalize_operands("x3", &mut r1), "R0");
        // Fixed roles keep their names; x86 tokens are untouched.
        let mut r = RegisterRenamer::new();
        assert_eq!(
            canonicalize_operands("x29, x30, [sp, #-0x20]!", &mut r),
            "x29,x30,[rsp,#-IMM]!"
        );
        assert_eq!(canonicalize_operands("xzr", &mut r), "xzr");
        assert_eq!(canonicalize_operands("xmm0, word", &mut r), "xmm0,word");
    }

    #[test]
    fn substitution_forms_fold_to_one_representative() {
        let f = |m: &str, o: &str| fold_instruction(m, o);
        let add = ("add".to_string(), "R0,IMM".to_string());
        for (m, o) in [
            ("inc", "R0"),
            ("dec", "R0"),
            ("sub", "R0,IMM"),
            ("add", "R0,-IMM"),
            ("add", "R0,IMM"),
            ("lea", "R0,[R0+IMM]"),
        ] {
            assert_eq!(f(m, o), add, "{m} {o}");
        }
        let zero = ("mov".to_string(), "R1,IMM".to_string());
        assert_eq!(f("xor", "R1,R1"), zero);
        assert_eq!(f("sub", "R1,R1"), zero);
        assert_eq!(f("mov", "R1,IMM"), zero);
        let test = ("cmp".to_string(), "R0,IMM".to_string());
        assert_eq!(f("test", "R0,R0"), test);
        assert_eq!(f("or", "R0,R0"), test);
        assert_eq!(f("and", "R0,R0"), test);
        assert_eq!(f("add", "R0,R0"), ("shl".to_string(), "R0,IMM".to_string()));
        assert_eq!(
            f("lea", "R0,[R0+R0]"),
            ("shl".to_string(), "R0,IMM".to_string())
        );
        assert_eq!(
            f("lea", "R0,[R1]"),
            ("mov".to_string(), "R0,R1".to_string())
        );
    }

    #[test]
    fn different_semantics_do_not_fold_together() {
        let f = |m: &str, o: &str| fold_instruction(m, o);
        // xor/sub with different operands, memory increments, and scaled
        // lea are left alone.
        assert_eq!(f("xor", "R0,R1"), ("xor".to_string(), "R0,R1".to_string()));
        assert_eq!(f("sub", "R0,R1"), ("sub".to_string(), "R0,R1".to_string()));
        assert_eq!(
            f("lea", "R0,[R1+R2*IMM]"),
            ("lea".to_string(), "R0,[R1+R2*IMM]".to_string())
        );
        assert_ne!(f("xor", "R0,R0"), f("add", "R0,IMM"));
    }

    #[test]
    fn push_pop_pairs_fold_to_mov_and_noops_drop() {
        let out = fold_block(vec![
            ins("push", "IMM"),
            ins("pop", "R0"),
            ins("push", "R1"),
            ins("pop", "R2"),
            ins("lea", "R3,[R3]"), // mov R3,R3: a no-op
            ins("push", "[R0]"),   // memory operand: not folded
            ins("pop", "R1"),
        ]);
        assert_eq!(
            out,
            vec![
                ins("mov", "R0,IMM"),
                ins("mov", "R2,R1"),
                ins("push", "[R0]"),
                ins("pop", "R1"),
            ]
        );
    }
}
