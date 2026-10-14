# agat architecture

agat detects polymorphic, metamorphic, and AI-rewritten malware variants
by **behavioral affinity** instead of signatures. A sample that has been
re-encrypted, register-swapped, NOP-padded, or rewritten by an LLM keeps
the same *behavior* even when every byte changes — and agat recognizes it
the way a biological immune system recognizes a mutated pathogen: by how
close it sits, in a behavioral metric space, to things it has learned are
hostile.

Everything runs **offline**. agat sends no sample, feature, or verdict
off the machine. Samples live in an encrypted vault; extracted features
and the learned immune state live in a local SQLite store.

```
                        ┌──────────────────────────────────────────┐
  sample bytes  ───────▶│  analysis pipeline (per-sample features)   │
   (ELF / PE)           │  static → disasm → poly → meta → ai        │
                        └───────────────────┬────────────────────────┘
                                            │  feature bundles
                                            ▼
                        ┌──────────────────────────────────────────┐
                        │  antigen presentation (agat-antigen)       │
                        │  features → one mutation-invariant         │
                        │  behavioral signature + affinity metric    │
                        └───────────────────┬────────────────────────┘
                                            │  antigen (metric space)
                                            ▼
                        ┌──────────────────────────────────────────┐
                        │  immune core (agat-immune)                 │
                        │  • negative selection  (self / non-self)   │
                        │  • clonal selection     (family memory)    │
                        │  • danger theory / DCA  (harm signals)     │
                        └───────────────────┬────────────────────────┘
                                            │  Recognition + DangerAssessment
                                            ▼
                        ┌──────────────────────────────────────────┐
                        │  scan facade (agat-engine)                 │
                        │  fuse both axes → ScanResult (agat-core)   │
                        └───────────────────┬────────────────────────┘
                                            │  ScanResult (JSON / exit code)
                                            ▼
                             operator CLI  ·  (future) agat serve
```

## The two axes, kept separate

agat deliberately reports **two independent judgements** and only fuses
them into advice at the very end:

- **Recognition** — *is this non-self, and whose family is it?* Driven by
  the detector repertoire (negative selection) and the learned family
  memory (clonal selection). A sample is non-self if any detector binds
  it; it is attributed to a family if the strongest family-bearing
  detector binds it; and it is a fast *secondary response* if that
  detector is a long-lived memory cell.
- **Danger** — *does this carry real harm signals?* A DCA-style fusion of
  concrete behavioral signals (a recovered decryptor + key, high-entropy
  regions, polymorphic confidence, distance from self, AI artifacts).

Keeping the axes separate is what makes agat honest: a sample can be
unusual without being dangerous, or dangerous-looking while still inside
the benign region. The fused [`Severity`](../crates/agat-core/src/scan.rs)
is only a recommendation; a consumer that disagrees with the fusion
policy can act on either raw axis from the same `ScanResult`.

## Crates

| crate           | role |
|-----------------|------|
| `agat-core`     | shared vocabulary: `Sample`/`SampleId`, the encrypted `Vault`, and the `ScanResult` verdict contract |
| `agat-store`    | SQLite-backed store for samples and analyzer feature bundles |
| `agat-static`   | PE/ELF parsing (goblin), entropy + high-entropy region detection |
| `agat-disasm`   | x86/x64 disassembly (iced-x86), basic-block & CFG construction |
| `agat-poly`     | polymorphic decryptor-stub detection + plaintext recovery |
| `agat-meta`     | metamorphic canonical form + Weisfeiler-Lehman CFG fingerprint |
| `agat-ai`       | AI-rewrite signals: stylometry, LLM artifacts, algorithm substitution |
| `agat-antigen`  | projects the feature bundles into one metric antigen + affinity |
| `agat-immune`   | the immune algorithms: negative selection, CLONALG, DCA danger |
| `agat-engine`   | scan facade: assembles a `ScanResult` from the immune outputs |
| `agat-cli`      | the `agat` operator command line |
| `agat-tui`      | interactive terminal UI |
| `agat-sandbox`  | *(stub)* planned dynamic/behavioral sandbox axis |
| `agat-rewriter` | *(stub)* planned variant generator for building training corpora |

## Why an antigen, and why a metric

Negative selection, clonal selection, and the dendritic-cell algorithm
all require a **metric space** — a notion of how *close* two things are.
agat's raw fingerprints are hashes: match is all-or-nothing, with no
graded affinity, so they cannot generalize to an unseen variant. The
antigen turns the real behavioral features into a genuine metric in which
**variants of one family are close and different families are far**. That
property is the foundation everything downstream rests on; it is pinned by
an acceptance test in `agat-antigen` and exercised end to end by
[`bench/generalize.sh`](../bench/README.md).

## The immune mechanisms

- **Negative selection** (Forrest et al., 1994; V-detector form, Ji &
  Dasgupta, 2004). From a corpus of benign "self" antigens, agat builds a
  self-model and then generates detectors that cover the space *outside*
  self. Any sample a detector binds is non-self. This is the innate,
  anomaly axis — it needs no malware to work.
- **Clonal selection / affinity maturation** (de Castro & Von Zuben,
  2002, CLONALG). When a confirmed family variant is matured in, the
  detectors that bind it best are cloned and hypermutated toward it, and
  the best clone is promoted to a long-lived **memory cell**. Over
  successive variants the memory cell becomes a covering ball over the
  family's neighborhood — so agat recognizes variants it has never seen.
  This is the adaptive axis, and the source of the generalization claim.
- **Danger theory / DCA** (Greensmith, Aickelin & Cayzer, 2005). Real
  behavioral signals are fused into a danger context, so non-self is
  weighed against evidence of actual harm rather than raising an alarm on
  novelty alone.

This is **bio-inspired computing**: agat implements the algorithms' logic
over real behavioral data. It is not a biological simulation.

## Data & trust boundaries

- **Vault** — raw sample bytes, encrypted at rest; only `ingest`,
  `analyze`, and the TUI open it, and only with the vault password.
- **Store** — extracted features and learned immune state (self-model,
  repertoire, memory pool). Recognition and the immune commands read this
  and never touch the vault, so they run non-interactively.
- **Network** — none. agat is designed to run air-gapped; this is a
  property to be proven by packaging (a `--network none` container run),
  not merely asserted.

## Verdict contract

`ScanResult` (in `agat-core`) is the stable, serializable answer: both
axes plus the fused `Severity`, tagged with `SCAN_SCHEMA_VERSION`. The CLI
renders it for humans and emits it as JSON (`agat recognize --json`); the
severity drives the process exit code (`0` clean · `2` needs a human ·
`3` non-self + dangerous). The fusion policy lives in exactly one place
(`ScanResult::fuse`) so every front end agrees.
