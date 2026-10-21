#!/usr/bin/env python3
"""
poly_gen.py — generate a tiny x86_64 ELF with a single-byte XOR
decryptor stub and an encrypted payload. Used to produce demo samples
for agat's polymorphic-engine analyzer (`agat-poly`).

Output: a small statically-linked x86_64 Linux ELF whose entry point
is the decryptor. The decryptor loops over a .data section, XORing
each byte in place with a fixed key, then halts.

This is *not* malware — there is no payload that actually runs, only a
decryption loop and an encoded blob whose plaintext contains
recognizable strings (so agat's recovery can show the strings popping
out of the noise). Use only for analyzing the analyzer.

Usage:
    python3 tools/poly_gen.py [output_path] [--key 0x42]
    python3 tools/poly_gen.py [output_path] --rolling-key de4dbeef   # register-held multi-byte key
"""
import argparse
import itertools
import random
import struct
import sys


def build_plaintext(target_size: int, seed: int) -> bytes:
    """High-entropy padding sprinkled with recognizable strings.

    Random padding raises the overall entropy of the payload so agat's
    EntropyBoundary signal fires; the strings give the recovery output
    something demo-worthy to print.
    """
    rng = random.Random(seed)
    embedded = [
        b"/bin/sh\x00",
        b"Hello, polymorphic world!\n",
        b"GET /payload HTTP/1.1\n",
        b"User-Agent: agat-test\n",
        b"This is a hidden message in the decrypted payload.\n",
        b"AGAT_FLAG{polymorphic_recovery_works}\n",
    ]
    out = bytearray()
    for s in itertools.cycle(embedded):
        if len(out) >= target_size:
            break
        chunk = min(64, max(0, target_size - len(out) - len(s)))
        out.extend(rng.randrange(0, 256) for _ in range(chunk))
        if len(out) + len(s) <= target_size:
            out.extend(s)
    return bytes(out[:target_size])


def build_decryptor(payload_vaddr: int, payload_len: int, key: int) -> bytes:
    """x86_64 decryptor stub. Encoded by hand so the bytes are stable.

    mov  rsi, payload_vaddr           ; 48 BE ?? ?? ?? ?? ?? ?? ?? ??
    mov  ecx, payload_len             ; B9 ?? ?? ?? ??
    .loop:
        xor  BYTE PTR [rsi], key      ; 80 36 KK
        inc  rsi                      ; 48 FF C6
        dec  ecx                      ; FF C9
        jne  .loop                    ; 75 F6  (rel8 = -10)
    hlt                               ; F4
    """
    return (
        b"\x48\xbe" + struct.pack("<Q", payload_vaddr)
        + b"\xb9" + struct.pack("<I", payload_len)
        + b"\x80\x36" + bytes([key & 0xFF])
        + b"\x48\xff\xc6"
        + b"\xff\xc9"
        + b"\x75\xf6"
        + b"\xf4"
    )


def build_rolling_decryptor(payload_vaddr: int, payload_len: int, key: bytes) -> bytes:
    """x86_64 decryptor whose key lives in a register and rotates: a
    repeating multi-byte XOR. No immediate key appears on the XOR, so a
    static key read finds nothing; recovering it takes cryptanalysis.

    mov  rsi, payload_vaddr           ; 48 BE ?? ?? ?? ?? ?? ?? ?? ??
    mov  ecx, payload_len             ; B9 ?? ?? ?? ??
    mov  rax, key64                   ; 48 B8 ?? ?? ?? ?? ?? ?? ?? ??
    .loop:
        xor  BYTE PTR [rsi], al       ; 30 06
        ror  rax, 8                   ; 48 C1 C8 08
        inc  rsi                      ; 48 FF C6
        dec  ecx                      ; FF C9
        jne  .loop                    ; 75 F3  (rel8 = -13)
    hlt                               ; F4

    `key` (1, 2, 4 or 8 bytes) is tiled to 8 bytes; byte i of the
    payload is XORed with key[i % len(key)].
    """
    key64 = (key * (8 // len(key)))[:8]
    return (
        b"\x48\xbe" + struct.pack("<Q", payload_vaddr)
        + b"\xb9" + struct.pack("<I", payload_len)
        + b"\x48\xb8" + key64
        + b"\x30\x06"
        + b"\x48\xc1\xc8\x08"
        + b"\x48\xff\xc6"
        + b"\xff\xc9"
        + b"\x75\xf3"
        + b"\xf4"
    )


def build_elf(decryptor: bytes, ciphertext: bytes, text_vaddr: int, payload_vaddr: int) -> bytes:
    EHDR_SIZE = 64
    PHDR_SIZE = 56
    SHDR_SIZE = 64

    text_offset = EHDR_SIZE + PHDR_SIZE  # 0x78
    payload_offset = 0x1000

    shstrtab = b"\x00.text\x00.data\x00.shstrtab\x00"
    shstrtab_offset = payload_offset + len(ciphertext)

    shoff = shstrtab_offset + len(shstrtab)
    num_sections = 4  # NULL, .text, .data, .shstrtab
    total_size = shoff + num_sections * SHDR_SIZE

    ehdr = (
        b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<H", 2)                  # e_type EXEC
        + struct.pack("<H", 62)                 # e_machine x86_64
        + struct.pack("<I", 1)                  # e_version
        + struct.pack("<Q", text_vaddr)         # e_entry
        + struct.pack("<Q", EHDR_SIZE)          # e_phoff
        + struct.pack("<Q", shoff)              # e_shoff
        + struct.pack("<I", 0)                  # e_flags
        + struct.pack("<H", EHDR_SIZE)
        + struct.pack("<H", PHDR_SIZE)
        + struct.pack("<H", 1)                  # e_phnum
        + struct.pack("<H", SHDR_SIZE)
        + struct.pack("<H", num_sections)
        + struct.pack("<H", 3)                  # e_shstrndx
    )
    assert len(ehdr) == EHDR_SIZE

    phdr = struct.pack(
        "<IIQQQQQQ",
        1,                                       # p_type LOAD
        7,                                       # p_flags R|W|X
        0,
        0x400000, 0x400000,
        payload_offset + len(ciphertext),
        payload_offset + len(ciphertext),
        0x1000,
    )
    assert len(phdr) == PHDR_SIZE

    def shdr(name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size):
        return struct.pack(
            "<IIQQQQIIQQ",
            name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
            0, 0, 0x10, 0,
        )

    shdrs = b"".join([
        shdr(0, 0, 0, 0, 0, 0),                              # NULL
        shdr(1, 1, 0x6, text_vaddr, text_offset, len(decryptor)),       # .text  AX
        shdr(7, 1, 0x3, payload_vaddr, payload_offset, len(ciphertext)),# .data  WA
        shdr(13, 3, 0, 0, shstrtab_offset, len(shstrtab)),              # .shstrtab
    ])
    assert len(shdrs) == num_sections * SHDR_SIZE

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
    ap.add_argument("output", nargs="?", default="/tmp/poly_demo.bin")
    ap.add_argument("--key", default="0x42", help="single-byte XOR key (hex or decimal)")
    ap.add_argument(
        "--rolling-key",
        help="multi-byte XOR key as hex (1, 2, 4 or 8 bytes, e.g. de4dbeef), held in "
        "a register and rotated each byte instead of an immediate operand",
    )
    ap.add_argument("--payload-size", type=int, default=512)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    plaintext = build_plaintext(args.payload_size, args.seed)
    text_vaddr = 0x400078
    payload_vaddr = 0x401000

    if args.rolling_key:
        try:
            rkey = bytes.fromhex(args.rolling_key)
        except ValueError:
            ap.error("--rolling-key must be hex")
        if len(rkey) not in (1, 2, 4, 8):
            ap.error("--rolling-key must be 1, 2, 4 or 8 bytes")
        ciphertext = bytes(b ^ rkey[i % len(rkey)] for i, b in enumerate(plaintext))
        decryptor = build_rolling_decryptor(payload_vaddr, len(ciphertext), rkey)
    else:
        key = int(args.key, 0)
        if not 0 <= key <= 0xFF:
            ap.error("key must be a single byte (0..255)")
        ciphertext = bytes(b ^ key for b in plaintext)
        decryptor = build_decryptor(payload_vaddr, len(ciphertext), key)
    elf = build_elf(decryptor, ciphertext, text_vaddr, payload_vaddr)

    with open(args.output, "wb") as f:
        f.write(elf)
    print(f"wrote {len(elf):>6d} bytes to {args.output}")
    print(f"  decryptor at file offset 0x{0x78:x} (vaddr 0x{text_vaddr:x})")
    print(f"  payload   at file offset 0x{0x1000:x} (vaddr 0x{payload_vaddr:x}, {len(ciphertext)} bytes)")
    if args.rolling_key:
        print(f"  XOR key   {rkey.hex()} (rolling, register-held)")
    else:
        print(f"  XOR key   0x{key:02x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
