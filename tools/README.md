# Fixture generators

Small, dependency-free Python scripts that synthesize the ELF samples the
tests, benchmarks and demo run against. **Everything here is synthetic and
benign**: tiny x86-64 / AArch64 decryptor stubs over encrypted blobs of
demo strings — no payload runs, nothing is obfuscated for evasion. They
exist so agat has something to analyze without shipping malware.

Run any with `-h` for its full options.

| script | produces | exercises |
|---|---|---|
| `poly_gen.py` | a single-byte XOR decryptor ELF (`--key`), or a register-held / multi-byte key (`--rolling-key`) over a demo payload | polymorphic detection, key recovery (`agat-poly`) |
| `meta_gen.py` | metamorphic variants of one decryptor: register/NOP variants (`--count N`) or instruction-substitution variants (`--substitute N`) | canonical form + CFG fingerprint (`agat-meta`) |
| `ai_gen.py` | a variant with the *same* payload behind a structurally different decryptor, plus embedded LLM artifacts | algorithm-substitution / AI-rewrite signals (`agat-ai`, `agat divergence`) |

## Shared design

Each sample is a minimal, hand-assembled Linux ELF: a `.text` decryptor at
a fixed entry point and an encrypted `.data` payload. The payload is
random padding sprinkled with recognizable strings (`/bin/sh`, an
`AGAT_FLAG{…}`, an HTTP request line), so recovery has something legible to
surface. Generation is deterministic given `--seed`.

The three generators share one plaintext construction, so a `meta_gen`
variant and the `ai_gen` variant decrypt to the **same** payload
(`plaintext_fingerprint`) while differing in control flow
(`cfg_fingerprint`) — the pairing `agat divergence` and `agat diff` flag
as an LLM rewrite.

## Examples

```sh
# one benign-looking XOR stub
python3 tools/poly_gen.py out.bin --key 0x42

# a register-held 4-byte key (no immediate on the xor — needs cryptanalysis)
python3 tools/poly_gen.py out.bin --rolling-key de4dbeef

# an 8-variant metamorphic family, and 12 instruction-substitution variants
python3 tools/meta_gen.py fam --count 8
python3 tools/meta_gen.py fam --substitute 12

# the AI-rewritten sibling (same payload, different algorithm)
python3 tools/ai_gen.py ai.bin
```

These are what `bench/*.sh` and `demo/run.sh` call; see `bench/README.md`.
