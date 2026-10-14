#!/usr/bin/env python3
"""
meta_gen.py — generate metamorphic-variant ELFs that share one
logical decryptor. The variants differ in physical register choice
and NOP padding; agat-meta's canonical-form normalization should
collapse all three to the same CFG fingerprint.

Variant A (v1): pointer in rsi, counter in ecx, no padding
Variant B (v2): pointer in rdi, counter in edx, no padding
Variant C (v3): pointer in rsi, counter in ecx, NOPs inserted in
                the prelude (loop body unchanged)

Beyond the three named variants, `--count N` synthesizes additional
metamorphic siblings (v4, v5, ...) by combining a register pair with a
deterministic NOP-padding pattern sprinkled through the *prelude only* —
the loop body keeps its byte offsets, so the short jump's displacement
stays correct. Every variant shares one plaintext family and must
canonicalize to the same CFG fingerprint. A larger family is what lets
the immune layer be trained on several variants and tested on a held-out
one — the generalization benchmark in `bench/`.

Usage:
    python3 tools/meta_gen.py [prefix]              # v1, v2, v3
    python3 tools/meta_gen.py [prefix] --count 8    # v1..v8
"""
import argparse
import itertools
import random
import struct
import sys

KEY = 0x42


def build_plaintext(size: int, seed: int) -> bytes:
    """Random padding sprinkled with recognizable strings (for the
    poly-recovery part of the demo)."""
    rng = random.Random(seed)
    embedded = [
        b"/bin/sh\x00",
        b"Hello from metamorphic variant\n",
        b"GET /payload HTTP/1.1\n",
        b"User-Agent: agat-test\n",
        b"AGAT_FLAG{metamorphic_recovery}\n",
    ]
    out = bytearray()
    for s in itertools.cycle(embedded):
        if len(out) >= size:
            break
        chunk = min(48, max(0, size - len(out) - len(s)))
        out.extend(rng.randrange(0, 256) for _ in range(chunk))
        if len(out) + len(s) <= size:
            out.extend(s)
    return bytes(out[:size])


def variant_a_decryptor(payload_vaddr: int, payload_len: int, key: int) -> bytes:
    """rsi/ecx, no padding."""
    return (
        b"\x48\xbe" + struct.pack("<Q", payload_vaddr)  # mov rsi, imm64
        + b"\xb9" + struct.pack("<I", payload_len)       # mov ecx, imm32
        + b"\x80\x36" + bytes([key & 0xFF])              # xor BYTE PTR [rsi], imm8
        + b"\x48\xff\xc6"                                 # inc rsi
        + b"\xff\xc9"                                     # dec ecx
        + b"\x75\xf6"                                     # jne short -10
        + b"\xf4"                                          # hlt
    )


def variant_b_decryptor(payload_vaddr: int, payload_len: int, key: int) -> bytes:
    """rdi/edx — same logic, different registers."""
    return (
        b"\x48\xbf" + struct.pack("<Q", payload_vaddr)  # mov rdi, imm64
        + b"\xba" + struct.pack("<I", payload_len)       # mov edx, imm32
        + b"\x80\x37" + bytes([key & 0xFF])              # xor BYTE PTR [rdi], imm8
        + b"\x48\xff\xc7"                                 # inc rdi
        + b"\xff\xca"                                     # dec edx
        + b"\x75\xf6"                                     # jne short -10
        + b"\xf4"                                          # hlt
    )


def variant_c_decryptor(payload_vaddr: int, payload_len: int, key: int) -> bytes:
    """rsi/ecx — NOPs sprinkled into the prelude before the loop label.

    The loop body keeps its byte offsets relative to the JNE, so the
    short jump's displacement (-10) stays correct.
    """
    return (
        b"\x48\xbe" + struct.pack("<Q", payload_vaddr)  # mov rsi
        + b"\x90\x90"                                     # 2 NOPs
        + b"\xb9" + struct.pack("<I", payload_len)       # mov ecx
        + b"\x90"                                         # 1 NOP
        + b"\x80\x36" + bytes([key & 0xFF])              # xor [rsi], imm8
        + b"\x48\xff\xc6"                                 # inc rsi
        + b"\xff\xc9"                                     # dec ecx
        + b"\x75\xf6"                                     # jne -10
        + b"\xf4"                                          # hlt
    )


# Register pairs: (ptr mov opcode, xor-ptr opcode, inc-ptr opcode,
# ctr mov opcode, dec-ctr opcode). The loop body (xor/inc/dec/jne) is
# always exactly 10 bytes so the `jne -10` displacement is register- and
# padding-invariant.
_REG_PAIRS = [
    # rsi / ecx
    (b"\x48\xbe", b"\x80\x36", b"\x48\xff\xc6", b"\xb9", b"\xff\xc9"),
    # rdi / edx
    (b"\x48\xbf", b"\x80\x37", b"\x48\xff\xc7", b"\xba", b"\xff\xca"),
]


def synth_decryptor(
    payload_vaddr: int, payload_len: int, key: int, pair_idx: int, nop_pattern
) -> bytes:
    """Build a metamorphic decryptor from a register pair plus a NOP
    pattern `(a, b, c)` giving NOP counts at three prelude positions:
    before the pointer mov, between the two movs, and after the counter
    mov. NOPs live only in the prelude, so the loop body's offsets — and
    the `jne -10` displacement — are untouched."""
    ptr_mov, xor_ptr, inc_ptr, ctr_mov, dec_ctr = _REG_PAIRS[pair_idx]
    a, b, c = nop_pattern
    nop = b"\x90"
    return (
        nop * a
        + ptr_mov + struct.pack("<Q", payload_vaddr)   # mov <ptr>, imm64
        + nop * b
        + ctr_mov + struct.pack("<I", payload_len)      # mov <ctr>, imm32
        + nop * c
        + xor_ptr + bytes([key & 0xFF])                 # xor BYTE PTR [ptr], imm8
        + inc_ptr                                        # inc <ptr>
        + dec_ctr                                        # dec <ctr>
        + b"\x75\xf6"                                     # jne short -10
        + b"\xf4"                                          # hlt
    )


def build_elf(decryptor: bytes, ciphertext: bytes) -> bytes:
    EHDR_SIZE = 64
    PHDR_SIZE = 56
    SHDR_SIZE = 64

    text_offset = EHDR_SIZE + PHDR_SIZE
    text_vaddr = 0x400000 + text_offset
    payload_offset = 0x1000
    payload_vaddr = 0x401000

    shstrtab = b"\x00.text\x00.data\x00.shstrtab\x00"
    shstrtab_offset = payload_offset + len(ciphertext)
    shoff = shstrtab_offset + len(shstrtab)
    num_sections = 4
    total_size = shoff + num_sections * SHDR_SIZE

    ehdr = (
        b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<H", 2)
        + struct.pack("<H", 62)
        + struct.pack("<I", 1)
        + struct.pack("<Q", text_vaddr)
        + struct.pack("<Q", EHDR_SIZE)
        + struct.pack("<Q", shoff)
        + struct.pack("<I", 0)
        + struct.pack("<H", EHDR_SIZE)
        + struct.pack("<H", PHDR_SIZE)
        + struct.pack("<H", 1)
        + struct.pack("<H", SHDR_SIZE)
        + struct.pack("<H", num_sections)
        + struct.pack("<H", 3)
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1, 7, 0, 0x400000, 0x400000,
        payload_offset + len(ciphertext),
        payload_offset + len(ciphertext),
        0x1000,
    )

    def shdr(name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size):
        return struct.pack(
            "<IIQQQQIIQQ",
            name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
            0, 0, 0x10, 0,
        )

    shdrs = b"".join([
        shdr(0, 0, 0, 0, 0, 0),
        shdr(1, 1, 0x6, text_vaddr, text_offset, len(decryptor)),
        shdr(7, 1, 0x3, payload_vaddr, payload_offset, len(ciphertext)),
        shdr(13, 3, 0, 0, shstrtab_offset, len(shstrtab)),
    ])

    out = bytearray(total_size)
    out[0:EHDR_SIZE] = ehdr
    out[EHDR_SIZE:EHDR_SIZE + PHDR_SIZE] = phdr
    out[text_offset:text_offset + len(decryptor)] = decryptor
    out[payload_offset:payload_offset + len(ciphertext)] = ciphertext
    out[shstrtab_offset:shstrtab_offset + len(shstrtab)] = shstrtab
    out[shoff:shoff + len(shdrs)] = shdrs
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("prefix", nargs="?", default="/tmp/meta_demo")
    ap.add_argument("--payload-size", type=int, default=512)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument(
        "--count",
        type=int,
        default=3,
        help="number of metamorphic variants to emit (>=1; v1..v3 are fixed, extras are synthesized)",
    )
    args = ap.parse_args()

    if args.count < 1:
        print("--count must be >= 1", file=sys.stderr)
        return 2

    plaintext = build_plaintext(args.payload_size, args.seed)
    ciphertext = bytes(b ^ KEY for b in plaintext)
    payload_vaddr = 0x401000
    clen = len(ciphertext)

    # The three named variants, byte-for-byte as before.
    named = [
        variant_a_decryptor(payload_vaddr, clen, KEY),
        variant_b_decryptor(payload_vaddr, clen, KEY),
        variant_c_decryptor(payload_vaddr, clen, KEY),
    ]

    variants = []
    rng = random.Random(args.seed ^ 0x5E70)
    seen = set()
    for i in range(args.count):
        if i < len(named):
            decryptor = named[i]
        else:
            # Synthesize a distinct metamorphic sibling: a register pair
            # plus a prelude NOP pattern not emitted before.
            while True:
                pair_idx = rng.randrange(len(_REG_PAIRS))
                pattern = (rng.randrange(0, 4), rng.randrange(0, 4), rng.randrange(0, 4))
                decryptor = synth_decryptor(payload_vaddr, clen, KEY, pair_idx, pattern)
                if decryptor not in seen:
                    break
        seen.add(decryptor)
        variants.append((f"v{i + 1}", decryptor))

    for label, decryptor in variants:
        elf = build_elf(decryptor, ciphertext)
        path = f"{args.prefix}_{label}.bin"
        with open(path, "wb") as f:
            f.write(elf)
        print(
            f"wrote {len(elf):>6d} bytes to {path}  "
            f"(decryptor {len(decryptor)} bytes)"
        )
    print(
        f"\nkey 0x{KEY:02x}; all {len(variants)} variant(s) share one plaintext "
        f"family and should canonicalize identically"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
