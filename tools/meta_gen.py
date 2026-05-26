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

Usage:
    python3 tools/meta_gen.py [prefix]    # writes prefix_v1.bin, _v2.bin, _v3.bin
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
    args = ap.parse_args()

    plaintext = build_plaintext(args.payload_size, args.seed)
    ciphertext = bytes(b ^ KEY for b in plaintext)
    payload_vaddr = 0x401000

    variants = [
        ("v1", variant_a_decryptor(payload_vaddr, len(ciphertext), KEY)),
        ("v2", variant_b_decryptor(payload_vaddr, len(ciphertext), KEY)),
        ("v3", variant_c_decryptor(payload_vaddr, len(ciphertext), KEY)),
    ]

    for label, decryptor in variants:
        elf = build_elf(decryptor, ciphertext)
        path = f"{args.prefix}_{label}.bin"
        with open(path, "wb") as f:
            f.write(elf)
        print(
            f"wrote {len(elf):>6d} bytes to {path}  "
            f"(decryptor {len(decryptor)} bytes)"
        )
    print(f"\nkey 0x{KEY:02x}; all three variants should canonicalize identically")
    return 0


if __name__ == "__main__":
    sys.exit(main())
