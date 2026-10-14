# agat benchmarks

Reproducible evidence for agat's central claim, runnable on any machine
with `python3` and the agat workspace.

## `generalize.sh` — recognition of unseen variants

agat's headline claim is that it recognizes metamorphic variants it has
**never seen** — not by matching a hash, but because clonal selection
grows a family *memory cell* that covers the family's neighborhood in
antigen space. This benchmark proves it end to end on real ELF binaries.

What it does:

1. synthesizes a benign "self" corpus (`tools/poly_gen.py`) and an
   N-variant metamorphic family (`tools/meta_gen.py --count N`) — every
   family variant differs in register choice and NOP padding but shares
   one plaintext payload and canonicalizes to the same CFG fingerprint;
2. ingests + analyzes everything, builds the self-model, and generates
   the negative-selection repertoire;
3. matures the family memory on variants `v1..v(N-1)`;
4. **holds out `vN`** — never shown during training — and recognizes it;
5. runs a **control**: a benign sample must not be pulled into the family.

It passes only if the held-out variant comes back non-self, attributed
to the family, with affinity ≥ 0.5, via a secondary (memory) response,
**and** the benign control is not swallowed into the family. Exit code
`0` on pass, `1` on fail.

### Run

```sh
bench/generalize.sh                 # default: 8-variant family
bench/generalize.sh --count 12      # larger family
bench/generalize.sh --agat ./target/release/agat
bench/generalize.sh --keep          # keep the temp AGAT_HOME for inspection
```

### Representative result

```
================ held-out variant v8 (never trained) ================
  recognized:         True
  family:             metamorph
  affinity:           0.941
  secondary response: True

================ control: benign sample ================
  family attribution: None   (must be None)

PASS: trained on 7 variants, recognized a held-out sibling
      (family 'metamorph', affinity 0.941) and kept benign out.
```

### Honest notes

- Generalization needs enough training variants to span the family: the
  memory cell's covering radius grows with each matured variant. Two or
  three variants are not enough for this synthetic family; by seven the
  radius comfortably covers the held-out sibling. This is a property of
  the data's spread, not a defect — the benchmark lets you see the
  threshold for yourself by varying `--count`.
- The corpus here is **synthetic and benign** (XOR-decryptor ELF stubs
  with recognizable demo strings). It exercises the metamorphic axis;
  it does not stand in for a real malware family. Measuring agat against
  a labeled real-world corpus is tracked as its own roadmap item.
