# agat benchmarks

Reproducible evidence for agat's central claim, runnable on any machine
with `python3` and the agat workspace.

| script | what it proves |
|---|---|
| `run.sh` | corpus-level **detection rate** on held-out variants and **false-positive rate** on held-out real benign binaries (CI-gateable) |
| `generalize.sh` | the single headline moment: one never-seen variant recognized as its family |
| `sweep.sh` | the affinity weights aren't a hand-tuned knife edge: detection/FP under 32 perturbed weightings |
| `keys.sh` | register-held and multi-byte decryptor keys are recovered *exactly*, and never "recovered" from benign data |
| `substitute.sh` | variants that swap instructions for equivalents collapse to one fingerprint and are recognized unseen |
| `fetch-benign.sh` | builds the real benign corpus `run.sh` and `sweep.sh` measure FPs on |

## `run.sh` — detection and false-positive rates

```sh
bench/fetch-benign.sh                                   # once; needs docker + network
bench/run.sh --benign-dir bench/corpus/debian-bin       # offline from here on
bench/run.sh --benign-dir bench/corpus/debian-bin --json  # machine-readable report
```

What it does:

1. synthesizes a 16-variant metamorphic family and 16 synthetic
   XOR-decryptor stubs; splits the real benign corpus (sorted,
   alternating) into a train half and a held-out half;
2. builds the self-model from the synthetic train half **plus** the real
   train half, generates the repertoire, and matures the family memory
   on variants `v1..v8`;
3. scans everything held out with the stateless `agat scan --json` (no
   vault, nothing written) and computes:
   - **detection rate**: held-out variants `v9..v16` that come back
     non-self *and* attributed to the family;
   - **false-positive rate**: held-out real benign binaries reported
     non-clean / malicious / attributed to the family;
   - **lookalike stress** (reported, never gated): fresh synthetic stubs
     that share the family's decryptor loop with a different payload.

Exit `0` if detection ≥ `--min-detect` (default 0.9) and the real
malicious-FP rate ≤ `--max-fp` (default 0); `1` otherwise. Without
`--benign-dir` the FP rate is reported as **not measured** and only
detection is gated.

### Representative result (debian:12-slim `/usr/bin`, 220 x86-64 ELFs)

```
================ detection: held-out family variants ================
  family size 16 · trained on 8 · held out 8
  detected (non-self + family)   8/8  = 100.0%
  severity mix                   malicious 8 · suspicious 0 · review 0 · clean 0
  affinity                       min 0.426 · median 0.803

================ false positives: real benign, held out ================
  [real benign, held out] n=110
    any non-clean     0/110  = 0.0%
    malicious         0/110  = 0.0%
    family swallowed  0/110

================ stress (reported, not gated): synthetic lookalike stubs ================
  [synthetic lookalike stubs] n=8
    any non-clean     8/8  = 100.0%
    malicious         1/8  = 12.5%
    family swallowed  7/8
```

### Second corpus: macOS (Mach-O)

`bench/fetch-benign.sh --macos` copies the local system binaries that carry
an x86-64 slice (896 on a current macOS install; no network). Same split,
same gate:

```
  detected (non-self + family)   8/8  = 100.0%
  [real benign, held out] n=448
    any non-clean     7/448  = 1.6%
    malicious         0/448  = 0.0%
    family swallowed  0/448
```

### Honest notes on `run.sh`

- **The self-model must be trained on benign software like the software
  you scan.** With a self-model built from 8 synthetic stubs alone, 28%
  of the same Debian binaries came back non-clean and 2.5% malicious:
  real programs are simply far from that tiny "self". Trained on half the
  real corpus, the other half comes back clean. That is the deployment
  model too: self is *your* benign baseline.
- **Lookalike stubs are matched to the family, and that is reported, not
  hidden.** They are the same XOR-decryptor loop as the family with a
  different encrypted payload; agat's antigen is dominated by that
  structure, so it attributes them to the family. Whether that is a
  false positive or a correct "same packer" call depends on what the
  family label means to you. It is why the gate uses real binaries only.
- n=110 benign files at 0 FPs bounds the true FP rate below ~2.7% at 95%
  confidence (rule of three), not at zero. A larger real corpus tightens
  that; the script takes any directory.
- The family is still synthetic. This measures the metamorphic axis on a
  controlled family, not detection of real-world malware.

## `sweep.sh` — affinity-weight sensitivity

The antigen's six group weights (opcode, block, struct, entropy, style,
imports) are engineered, all 1.0. `sweep.sh` retrains the whole pipeline
(self-model → negative selection → clonal maturation) under each weight
halved and doubled alone, then under 20 random vectors with every weight
in `[x0.5, x2]`, and re-measures on the `run.sh` split.

```sh
bench/sweep.sh                 # uses bench/corpus/debian-bin
bench/sweep.sh --random 50 --json
```

### Representative result

```
across 32 perturbed weightings (each weight x0.5..x2):
  detection     100.0% .. 100.0%   (default 100.0%)
  FP malicious  0.0% .. 0.0%   (default 0.0%)
  FP non-clean  0.0% .. 0.0%   (default 0.0%)
  verdicts changed vs default: mean 0.3%, worst 3.4%
```

"Verdicts changed" counts any held-out sample whose severity differs
from the default run (e.g. a family variant going malicious →
suspicious), not only detection/FP flips.

Honest note: the synthetic family is tiny stubs and the benign corpus is
real programs, so they sit far apart in antigen space and this is an
easy separation. Stability here shows the weights are not a knife edge on
this corpus; it does not show the same for a real malware family that
lives closer to benign software.

## `keys.sh` — key recovery without an immediate key

Many decryptor stubs keep their key in a register and rotate it
(`xor [rsi], al` / `ror rax, 8`), so no key appears in the instruction
stream. agat solves for the key from the ciphertext itself
(`agat_poly::solve`: per-column log-likelihood scoring, context
refinement, period selection). The benchmark generates random
register-held keys of 1, 2, 4 and 8 bytes (`tools/poly_gen.py
--rolling-key`) and requires the **exact** key: a near miss would
corrupt the plaintext fingerprint, so it counts as a failure.

```sh
bench/keys.sh                                          # 40 keys, 1 KiB payloads
bench/keys.sh --per-length 50 --payload-size 512       # the hard regime
bench/keys.sh --stress bench/corpus/debian-bin         # + false-positive stress
```

### Representative result (50 keys per length)

| payload | 1-byte | 2-byte | 4-byte | 8-byte |
|---|---|---|---|---|
| 512 B | 50/50 | 50/50 | 50/50 | 44/50 |
| 768 B | 50/50 | 50/50 | 50/50 | 48/50 |
| 1 KiB | 50/50 | 50/50 | 50/50 | **50/50** |
| 2 KiB | 50/50 | 50/50 | 50/50 | **50/50** |

Exact recovery needs about 128 ciphertext bytes per key byte. Below that,
8-byte keys sometimes come back with one byte a few bits off, and the
report says so.

### False-positive stress

`--stress DIR` removes the analyzer's gate (it only solves when it has
found a decryptor loop) and runs the solver under every operation on
every non-executable section of every benign binary in `DIR`:

```
220 files · 5388 non-executable sections · 16164 solve attempts · 0 keys accepted
```

On this Mac's own 896 system binaries (`bench/fetch-benign.sh --macos`, the
x86-64 slices of universal Mach-O files):

```
896 files · 7842 non-executable sections · 23526 solve attempts · 4 keys accepted
```

Those 4 (0.017%) are record-structured `__TEXT,__const` tables where a
"key" one record long turns the other records into letter-range gibberish.
They are reported, not hidden; in the analyzer the solver only runs when a
decryptor loop was found, and the full macOS FP benchmark below is clean.

That zero on Debian was earned. The first acceptance rule accepted 5,537 keys here,
by turning zero-filled tables into "text" made of spaces, then small-integer
tables into letter-range gibberish. The fixes (word-like text only, and
declining windows over 5% zero bytes, since true ciphertext measured ≤1.8%)
are documented in `crates/agat-poly/src/solve.rs`.

## `substitute.sh` — recognition across instruction substitution

Metamorphic engines swap instructions for equivalents: `inc rsi` ↔
`add rsi,1` ↔ `lea rsi,[rsi+1]`, `xor eax,eax` ↔ `mov eax,0`,
`mov rsi,imm` ↔ `push imm; pop rsi`. `tools/meta_gen.py --substitute`
builds all 54 combinations of one decryptor; the benchmark checks they
share one canonical CFG fingerprint, trains the family on 6 of them, and
scans the other 48 statelessly.

```
================ instruction substitution ================
  variants                      54
  distinct CFG fingerprints     1   (must be 1)
  trained on                    6
  held-out recognized + family  48/48
  affinity                      min 0.347 · median 0.544
```

Before the canonical form learned these folds (`agat-meta` 0.2.0), the
same 54 variants produced 54 different fingerprints.

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
