#!/usr/bin/env python3
"""
ai_gen.py — generate a synthetic "AI-rewritten" variant whose payload
matches `tools/meta_gen.py`'s but whose decryptor uses a structurally
different algorithm (16-bit word-wise XOR with stride-2 pointer
advancement, instead of byte-wise with `inc`).

The plaintext (and therefore the polymorphic `plaintext_fingerprint`)
matches meta_gen's v1/v2/v3 — but the CFG fingerprint differs because
the canonical form changes. That co-occurrence (same plaintext family,
different CFG) is exactly the algorithm-substitution tell that
`agat divergence` flags.

The sample also embeds plaintext LLM artifacts at the end of .data —
refusal phrases, ChatML markers, verbose snake_case identifiers — so
`agat-ai`'s artifact-scan and stylometry signals fire.

This is **not** malware. It's a benign synthetic test fixture; the
"payload" plaintext is random padding sprinkled with recognizable
demo strings.

Usage:
    python3 tools/ai_gen.py [output.bin]
"""
import argparse
import itertools
import random
import struct
import sys

KEY = 0x42


def build_plaintext(size: int, seed: int) -> bytes:
    """Match meta_gen.py's plaintext exactly so plaintext_fingerprint
    is identical."""
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


def ai_variant_decryptor(payload_vaddr: int, payload_len_bytes: int, key: int) -> bytes:
    """16-bit word-wise XOR with `add rsi, 2` instead of `inc rsi`.

    Each byte of plaintext still gets XOR'd with `key` (because the
    16-bit immediate is `key | (key << 8)`), so the recovered plaintext
    is identical to the byte-wise variants — but the canonical form
    of the decryptor differs in three instructions, which is enough
    to change the WL fingerprint.

    Layout:
        0x00: mov rsi, payload_vaddr           ; 48 BE [imm64]   (10)
        0x0A: mov ecx, payload_len/2           ; B9 [imm32]      (5)
        0x0F: xor word ptr [rsi], 0xKKKK        ; 66 81 36 KK KK  (5)   <- loop
        0x14: add rsi, 2                        ; 48 83 C6 02     (4)
        0x18: dec ecx                           ; FF C9           (2)
        0x1A: jne short -13                     ; 75 F3           (2)
        0x1C: hlt                               ; F4              (1)
    """
    assert payload_len_bytes % 2 == 0, "word-XOR variant needs even payload length"
    word_count = payload_len_bytes // 2
    key16 = (key << 8) | key  # so each byte gets the same XOR key

    return (
        b"\x48\xbe" + struct.pack("<Q", payload_vaddr)   # mov rsi, imm64
        + b"\xb9" + struct.pack("<I", word_count)         # mov ecx, words
        + b"\x66\x81\x36" + struct.pack("<H", key16)      # xor word ptr [rsi], imm16
        + b"\x48\x83\xc6\x02"                              # add rsi, 2
        + b"\xff\xc9"                                      # dec ecx
        + b"\x75\xf3"                                      # jne short -13
        + b"\xf4"                                          # hlt
    )


# Plaintext LLM artifacts placed at the end of .data, visible to
# agat-ai's artifact scanner and stylometry feature extractor.
LLM_ARTIFACTS = (
    b"I cannot help with that request.\x00"
    b"As an AI language model, I cannot assist with this task.\x00"
    b"<|im_start|>system\nYou are a helpful assistant<|im_end|>\x00"
    b"\"role\":\"user\",\"content\":\"decrypt this\"\x00"
    b"validate_user_input(payload_data)\x00"
    b"error_message = generate_response(input_payload)\x00"
    b"result_value = process_data(should_process)\x00"
    b"// TODO: refactor this for clarity\x00"
    b"// NOTE: AI-generated optimization pass\x00"
    b"api.openai.com/v1/chat/completions\x00"
) + (b"\x00" * 16)


def build_elf(decryptor: bytes, payload_blob: bytes) -> bytes:
    EHDR_SIZE = 64
    PHDR_SIZE = 56
    SHDR_SIZE = 64

    text_offset = EHDR_SIZE + PHDR_SIZE
    text_vaddr = 0x400000 + text_offset
    payload_offset = 0x1000
    payload_vaddr = 0x401000

    shstrtab = b"\x00.text\x00.data\x00.shstrtab\x00"
    shstrtab_offset = payload_offset + len(payload_blob)
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
        payload_offset + len(payload_blob),
        payload_offset + len(payload_blob),
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
        shdr(7, 1, 0x3, payload_vaddr, payload_offset, len(payload_blob)),
        shdr(13, 3, 0, 0, shstrtab_offset, len(shstrtab)),
    ])

    out = bytearray(total_size)
    out[0:EHDR_SIZE] = ehdr
    out[EHDR_SIZE:EHDR_SIZE + PHDR_SIZE] = phdr
    out[text_offset:text_offset + len(decryptor)] = decryptor
    out[payload_offset:payload_offset + len(payload_blob)] = payload_blob
    out[shstrtab_offset:shstrtab_offset + len(shstrtab)] = shstrtab
    out[shoff:shoff + len(shdrs)] = shdrs
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("output", nargs="?", default="/tmp/ai_demo.bin")
    ap.add_argument("--payload-size", type=int, default=512)
    ap.add_argument("--seed", type=int, default=2026)
    args = ap.parse_args()

    plaintext = build_plaintext(args.payload_size, args.seed)
    ciphertext = bytes(b ^ KEY for b in plaintext)
    payload_blob = ciphertext + LLM_ARTIFACTS

    payload_vaddr = 0x401000
    decryptor = ai_variant_decryptor(payload_vaddr, len(ciphertext), KEY)
    elf = build_elf(decryptor, payload_blob)

    with open(args.output, "wb") as f:
        f.write(elf)
    print(f"wrote {len(elf):>6d} bytes to {args.output}")
    print(f"  decryptor      {len(decryptor)} bytes (word-XOR variant)")
    print(f"  ciphertext     {len(ciphertext)} bytes at offset 0x{0x1000:x}")
    print(f"  LLM artifacts  {len(LLM_ARTIFACTS)} bytes appended in .data")
    print(f"  key 0x{KEY:02x}; plaintext matches meta_gen.py output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
