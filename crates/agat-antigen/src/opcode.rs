//! Fixed opcode-class taxonomy.
//!
//! A sample's raw opcode histogram has an open-ended vocabulary, which
//! cannot be a fixed-dimensional vector. We fold every x86/x64 mnemonic
//! into one of [`OPCODE_CLASSES`] semantic buckets. The resulting
//! class-distribution is:
//!
//! - **fixed-dimensional** (so it can live in the antigen vector),
//! - **metamorphism-tolerant** (register renaming and width changes do
//!   not move a `mov` out of the data-movement bucket), and
//! - **sensitive to algorithm substitution** (word-wise vs byte-wise
//!   decryption shifts mass between the logic/shift/arith buckets).
//!
//! That is exactly the behavior we want the antigen geometry to encode.

/// Human-readable labels for each opcode class, indexed by class id.
pub const OPCODE_CLASSES: [&str; 16] = [
    "data_move", // 0
    "stack",     // 1
    "arith",     // 2
    "muldiv",    // 3
    "logic",     // 4
    "shift",     // 5
    "cmp_test",  // 6
    "jmp",       // 7
    "jcc",       // 8
    "call",      // 9
    "ret",       // 10
    "lea",       // 11
    "nop",       // 12
    "string",    // 13
    "simd_fp",   // 14
    "other",     // 15
];

pub const OPCODE_CLASS_COUNT: usize = OPCODE_CLASSES.len();

/// Map a lowercase mnemonic to its opcode-class id. Unknown or exotic
/// mnemonics fall into the `other` bucket (id 15) rather than being
/// dropped, so two samples are always compared over the same axes.
pub fn classify(mnemonic: &str) -> usize {
    let m = mnemonic.trim();
    // Conditional jumps and loop primitives — checked before the bare
    // `jmp` test so `jmp` itself is the only unconditional case.
    if m == "jmp" {
        return 7;
    }
    if (m.starts_with('j') && m != "jmp") || m.starts_with("loop") || m == "jcxz" || m == "jecxz"
        || m == "jrcxz"
    {
        return 8;
    }
    match m {
        // 0 — data movement
        "mov" | "movzx" | "movsx" | "movsxd" | "movabs" | "xchg" | "bswap" | "movbe" => 0,
        m if m.starts_with("cmov") => 0,
        // 1 — stack
        "push" | "pop" | "pusha" | "popa" | "pushad" | "popad" | "pushf" | "popf" | "pushfd"
        | "popfd" | "pushfq" | "popfq" | "enter" => 1,
        // 2 — additive arithmetic
        "add" | "sub" | "adc" | "sbb" | "inc" | "dec" | "neg" | "xadd" => 2,
        // 3 — multiply / divide
        "mul" | "imul" | "div" | "idiv" => 3,
        // 4 — bitwise logic
        "xor" | "and" | "or" | "not" | "andn" => 4,
        // 5 — shifts / rotates / bit twiddling
        "shl" | "sal" | "shr" | "sar" | "rol" | "ror" | "rcl" | "rcr" | "shld" | "shrd" | "bt"
        | "bts" | "btr" | "btc" | "bsf" | "bsr" | "popcnt" | "lzcnt" | "tzcnt" => 5,
        // 6 — compare / test
        "cmp" | "test" | "cmpxchg" | "cmpxchg8b" | "cmpxchg16b" => 6,
        // 9 — call
        "call" => 9,
        // 10 — returns / frame teardown
        "ret" | "retn" | "retf" | "iret" | "iretd" | "iretq" | "leave" => 10,
        // 11 — address computation
        "lea" => 11,
        // 12 — no-ops
        "nop" | "endbr32" | "endbr64" | "pause" | "fnop" => 12,
        // 13 — string / rep-prefixed block ops
        m if m.starts_with("movs")
            || m.starts_with("stos")
            || m.starts_with("lods")
            || m.starts_with("scas")
            || m.starts_with("cmps")
            || m.starts_with("rep") => 13,
        // 14 — SIMD / x87 floating point
        m if m.starts_with('p')      // packed integer SIMD (paddb, pxor, ...)
            || m.starts_with('v')    // AVX VEX-encoded forms
            || m.starts_with('f')    // x87 (fadd, fmul, fld, ...)
            || m.ends_with("ps")
            || m.ends_with("pd")
            || m.ends_with("ss")
            || m.ends_with("sd")
            || m.starts_with("xmm")
            || m.starts_with("cvt") => 14,
        // 15 — everything else (int, syscall, cpuid, hlt, in/out, ...)
        _ => 15,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_mnemonics_classify() {
        assert_eq!(OPCODE_CLASSES[classify("mov")], "data_move");
        assert_eq!(OPCODE_CLASSES[classify("push")], "stack");
        assert_eq!(OPCODE_CLASSES[classify("add")], "arith");
        assert_eq!(OPCODE_CLASSES[classify("imul")], "muldiv");
        assert_eq!(OPCODE_CLASSES[classify("xor")], "logic");
        assert_eq!(OPCODE_CLASSES[classify("shl")], "shift");
        assert_eq!(OPCODE_CLASSES[classify("cmp")], "cmp_test");
        assert_eq!(OPCODE_CLASSES[classify("jmp")], "jmp");
        assert_eq!(OPCODE_CLASSES[classify("jne")], "jcc");
        assert_eq!(OPCODE_CLASSES[classify("loop")], "jcc");
        assert_eq!(OPCODE_CLASSES[classify("call")], "call");
        assert_eq!(OPCODE_CLASSES[classify("ret")], "ret");
        assert_eq!(OPCODE_CLASSES[classify("lea")], "lea");
        assert_eq!(OPCODE_CLASSES[classify("nop")], "nop");
    }

    #[test]
    fn width_variants_share_a_class() {
        // The whole point: width/register changes don't move the class.
        assert_eq!(classify("mov"), classify("movzx"));
        assert_eq!(classify("cmovne"), classify("mov"));
    }

    #[test]
    fn unknown_goes_to_other() {
        assert_eq!(OPCODE_CLASSES[classify("syscall")], "other");
        assert_eq!(OPCODE_CLASSES[classify("cpuid")], "other");
    }
}
