# How to read agat output

One page for the analyst who has to act on a result. Every `agat scan` /
`agat recognize` produces one **ScanResult** per file (schema
`agat.scan/v1`), shown as text, JSON, or SARIF. They all carry the same
facts.

## 1. Read the bottom line first

```
priority
  [MALICIOUS] non-self and dangerous — recognition and danger agree; investigate
```

| severity | means | exit code | do |
|---|---|---|---|
| **malicious** | outside your benign baseline **and** carries harm signals | `3` | investigate now |
| **suspicious** | outside the baseline, danger signals ambiguous | `2` | triage |
| **review** | only one axis fired: unusual-but-calm, or familiar-but-dangerous | `2` | a human glance |
| **clean** | inside the baseline, nothing notable | `0` | none |

Exit code `1` always means *agat itself failed* (bad path, no trained
model), never a verdict. For a batch, the exit code is the worst file's.
`--fail-on suspicious|malicious|never` (or `[scan] fail_on` in
`config.toml`) raises the bar for a non-zero exit.

If you see `(verdict set by operator policy …)` / `"policy": "allowlist"`
or `"denylist"`, a sha256 list in your config decided the severity. The
two axes below are still the engine's own reading.

## 2. The severity is fused from two independent axes

agat never collapses its evidence into one opaque score. The two axes
are reported separately so you can disagree with the fusion.

### Recognition: *is this outside what we know to be benign?*

```
recognition  (1 known family)
  verdict      non-self — family (secondary response)
  family       metamorph
  affinity     0.842
  bound detectors 1
  secondary response yes (memory cell)
  distance from self  +0.874
```

- **verdict / recognized**: `self` means no detector bound and the sample
  looks like your benign baseline. `non-self — anomaly` means it is outside
  the baseline but matches no known family. `non-self — family` means it
  matched a family agat has learned.
- **family**: the attributed family, set only by a family-bearing detector.
  Families exist only because someone ran `agat mature <id> --family X`.
- **affinity** (0–1): how deep inside the binding detector the sample sits.
  1.0 is the detector's center, near 0 is grazing its edge. A family hit
  at low affinity (< ~0.3) is weak evidence; read it as "near the family".
- **secondary response**: a learned *memory cell* bound, the fast
  "seen this family before" response. It is how agat recognizes **new
  variants** of a known family without their hash.
- **distance from self**: signed distance to the benign region. Negative
  means inside self; larger positive values mean further out.

### Danger: *does it carry signs of harm?*

```
danger  (DCA-style signal fusion)
  score 0.667  ·  context dangerous  ·  P 0.70 / D 1.00 / S 0.60
  signals:
    [PAMP  ] decryptor_with_recovered_key     0.70
    [danger] far_from_self                    0.50
    [safe  ] low_overall_entropy              0.40
```

Signals come in three classes and are fused with dendritic-cell-algorithm
math, not a biological simulation:

| class | signal | fires when |
|---|---|---|
| PAMP | `decryptor_with_recovered_key` | a decryptor loop was found **and** its key recovered |
| PAMP | `llm_artifact` | LLM artifacts embedded (refusals, ChatML, prompts, model magic) |
| danger | `high_entropy_region` / `very_high_overall_entropy` | packed or encrypted data |
| danger | `writable_executable_section` | a W+X section (self-modifying code) |
| danger | `suspicious_import` | an import used for injection, memory-protection changes, code loading or exec (`VirtualProtect`, `WriteProcessMemory`, `mprotect`, `ptrace`, `dlopen`, `execve`, `mmap`, …). Common in ordinary programs too, hence only a danger signal. |
| danger | `polymorphic_confidence` | polymorphic-engine signals, scaled by confidence |
| danger | `dense_llm_idioms` | ≥ 3 LLM-style identifier idioms |
| danger | `far_from_self` | outside the benign region (saturates at 0.5) |
| safe | `inside_self_region` | inside the benign region |
| safe | `low_overall_entropy`, `benign_import_profile`, `no_ai_artifacts` | ordinary-program traits |

**context**: `dangerous` (score ≥ 0.50), `ambiguous`, `safe` (score <
0.33), or `inconclusive` (too little signal to judge). Tune the cut-offs
in `[danger]` in `config.toml`.

## 3. Antigen: what was compared

```
antigen
  signature dim 47 · 3 canonical blocks
  cfg fingerprint   9dd5b9eda6dd9999
  plaintext finger  2f31df54ff38302a
```

The behavioral signature agat matched on. The **cfg fingerprint** is
mutation-invariant: metamorphic variants that only swap registers or pad
NOPs share it. The **plaintext fingerprint** is the hash of a payload agat
decrypted itself, so two samples sharing it carry the same hidden payload
under different encryption.

## 4. Model: which model made this call

```
model  pack acme-threats v2026.10 · signed by ec73e23d226e8fdc
```

The same file can score differently under a different model, so every
result names its own. `pack …` means an imported, verified model pack
(name, version, and the trusted signer's key id; JSON adds the pack's
`sha256` and the `antigen_fingerprint`). `trained locally` means the model
was built in this agat home. Keep it with the verdict when you file a case:
it is what makes the call reproducible.

## 5. In JSON and SARIF

JSON fields mirror the text one-to-one: `verdict.severity`,
`recognition.{recognized,family,affinity,secondary_response,self_surface_distance}`,
`danger.{score,context,signals[]}`,
`model.{source,name,version,sha256,signer,antigen_fingerprint}`. Optional fields are **omitted** when
empty (no `family` key means no family). A batch is an array.

SARIF emits one result per non-clean file. `ruleId` is
`agat/non-self-dangerous` (error), `agat/suspicious` or `agat/review`
(warning). The file path is the location, the sample sha256 is the
`partialFingerprints.agatSampleId`, and the axes and the model are in
`properties`.

## 6. What agat cannot tell you

- **Coverage**: x86/x64 PE/ELF only. Other architectures get static
  analysis but no structural (CFG) comparison, so recognition is weaker.
  Single-byte XOR/ADD/SUB decryptors only. No dynamic analysis.
- **Self is your baseline.** A self-model trained on a few samples flags
  ordinary software as non-self. Train it on benign software like what
  you scan (see `bench/README.md`).
- **"Clean" means "not distinguishable from your baseline"**, not "proven
  safe". agat complements signature AV/YARA by catching the *variants*
  they miss; it does not replace them.
