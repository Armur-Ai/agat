# Changelog

All notable changes to agat. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor versions may break).

## [Unreleased]

The release that turns the research engine into a deployable product.

### Added

**Operator surface**
- `agat scan <files|dirs…>`: stateless one-shot scanning. Files are analyzed
  in memory, nothing is written, no vault password is needed. `--ingest`
  keeps the library workflow. Files scan in parallel (`-j/--jobs`, default
  all cores; 10.7× on 18 cores) with deterministic, ordered output.
- Output formats `text`, `table` (one line per file, colored severities),
  `json` (`agat.scan/v1`), and `sarif` (SARIF 2.1.0); exit codes `0` clean ·
  `2` review/suspicious · `3` malicious · `1` error; `--fail-on`.
- `config.toml`: default output and fail threshold, danger thresholds, and
  sha256 allow/deny lists (overrides are marked in `verdict.policy`).
- `agat serve`: local HTTP API (`POST /v1/scan`, `GET /v1/model`,
  `GET /v1/schema`, `GET /healthz`) with an `X-Agat-Severity` header; loopback-only unless
  `--allow-remote`.
- `agat completions <shell>`, `agat man`, and a workflow-ordered `--help`.
- A JSON Schema for `agat.scan/v1` (`docs/schema/agat.scan.v1.json`,
  `agat schema`), generated from the types and checked in CI.
- `agat diff <a> <b>`: pairwise antigen comparison — blended affinity,
  cosine, Jaccard, shared CFG/plaintext fingerprints, per-feature-group
  similarity, and a plain-language read (metamorphic siblings, LLM rewrite,
  unrelated).
- `agat tui` is a verdict console: an Immune tab (severity, recognition and
  danger axes, model provenance), severity-colored sample list with file
  names, and a verdict tally; it no longer asks for the vault password.

**Signed model packs**
- `agat key generate`, `agat repertoire export | import | info`: a trained
  model ships as one `agat.pack/v1` file with a SHA-256 payload digest, an
  optional Ed25519 signature, and a pinned antigen-metric fingerprint.
  Import accepts only trusted signers (`--trust`, `[packs] trusted_keys`,
  `~/.agat/trusted_keys/`), refuses tampered, unsigned (unless allowed),
  and metric-incompatible packs.
- Every `ScanResult` carries `model` provenance (pack name, version,
  digest, signer, or "local").

**Detection depth**
- Key-less payload recovery (`agat_poly::solve`): register-held and
  multi-byte repeating XOR/ADD/SUB keys (periods 1–16) solved from the
  ciphertext by per-column log-likelihood cryptanalysis with context
  refinement. Exact keys from 1 KiB payloads; guarded against structured
  data, string sections, and noise.
- Instruction-substitution folding in the metamorphic canonical form
  (`inc` ≡ `add 1` ≡ `lea +1`, zeroing idioms, flag tests, doubling,
  `push; pop` ≡ `mov`).
- AArch64 (ARM64) disassembly (yaxpeax-arm) with prologue-seeded descent,
  and AArch64 register families in the metamorphic canonical form.
- Mach-O parsing, including the x86-64 slice of universal binaries;
  Mach-O sample kinds (with Java class-file disambiguation).
- Expanded, case-insensitive AI-artifact rule set (refusals, modern chat
  tokens, inference endpoints, weight-format magics): 0 hits across 1,336
  benign binaries, the AI-rewrite fixture lights up across categories.

**Evidence** (`bench/`)
- `run.sh`: detection rate on held-out variants and false-positive rate on
  held-out real benign binaries (Debian x86-64 and aarch64 via
  `fetch-benign.sh [--arch arm64]`, and macOS via `--macos`), CI-gateable.
- `sweep.sh`: affinity-weight sensitivity across 32 perturbed weightings.
- `keys.sh`: exact key recovery, plus `--stress` (the solver run ungated
  over every data section of a benign corpus).
- `substitute.sh`: recognition across instruction substitution.
- `evaluate.sh`: agat on a user-supplied labeled corpus (real families) —
  detection, attribution, confusion and benign FP, shipping no samples.

**Correctness & safety**
- A pipeline fuzz test asserts no analyzer panics on ~200 adversarial
  inputs (malformed/lying ELF/PE/Mach-O headers, noise); the analyzer
  crates have no unwrap/expect/panic in non-test code.
- End-to-end CLI tests drive the real binary (exit codes, stateless scans,
  formats, config errors, signed packs, schema) in ~1 s.

**Packaging and docs**
- ~12 MB `scratch` container; `demo/run.sh` with a `--network none`
  transcript comparison (the air-gap proof) and speaker notes.
- `docs/READING_OUTPUT.md`, `docs/ARCHITECTURE.md`, a rewritten README with
  banner, pipeline diagram and demo GIF, `CONTRIBUTING.md`, `SECURITY.md`,
  issue forms and a PR template.

### Changed
- The analyzer pipeline and recognition moved into the `agat-engine` facade
  (`ImmuneModel`, `analyze_bytes`, `scan_bytes`); the CLI is a thin layer.
- Memory cells track their exact covering spread instead of an
  ever-growing bound.
- The recursive-descent worklist is architecture-neutral (`disasm::descend`).
- `agat-disasm` 0.2.0, `agat-poly` 0.2.0, `agat-meta` 0.3.0 and `agat-ai` 0.3.0;
  `ANTIGEN_LAYOUT_VERSION` 2.
  Models trained before these versions must be retrained (old packs are
  refused at import).

### Fixed
- ADD/SUB decryptors were run inverted (`c − k` for `add [mem], k`), so
  their payloads never recovered.
- Floats now round-trip exactly through JSON; persisted models had drifted
  in the last bit on every save/load.
- The top-k opcode histogram was nondeterministic on count ties.
- Opcode-diversity entropy was summed in HashMap order, so the same file's
  affinities differed in the last bits between runs.
