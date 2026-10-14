<!--
SPDX-License-Identifier: AGPL-3.0-or-later
agat — Product Roadmap: research engine -> deployable product
Author-ready draft for Black Hat India talk prep. Status: proposal for review.
-->

# agat — Product Roadmap: from research engine to a product a CISO can deploy

## 0. Where we are (honest baseline)

The **detection engine and immune core are real and unit-tested** (static, disasm,
poly, meta, ai, antigen, and the NSA / CLONALG / DCA immune pipeline — 79 tests,
strongest coverage in `agat-immune`). What does **not** exist yet is everything
that turns a research CLI into a product someone can evaluate and run:

- No machine-readable output (everything is `println!`); no `--json`, SARIF, STIX, CSV.
- No single fused **verdict object** — the final call is printed as a sentence in
  `crates/agat-cli/src/immune.rs` (~L322–337), not a serializable result.
- No granular exit codes; mandatory interactive **vault password on every command**
  (blocks automation).
- No one-shot stateless scan, no recursive directory scan, no "scan a folder -> report".
- No container, CI, release binary, installer, man pages, or config file.
- No repertoire lifecycle (export / import / sign / version / update).
- Two advertised crates — `agat-sandbox`, `agat-rewriter` — are **empty stubs**.
- Doc drift: README/DESIGN reference a `bench/`, `docs/ARCHITECTURE.md`, and a `demo/`
  that do not exist; `docs/AIS_REBUILD_PLAN.md` still calls the (now-built) immune
  core an unwritten proposal.

## 1. Product thesis (one sentence for the CISO slide)

> **agat is an offline, air-gapped malware-variant detection engine that catches
> polymorphic, metamorphic, and AI-rewritten variants by behavioral _affinity_ —
> not signatures — ships as a single binary or container, emits standard
> machine-readable output for your pipeline, and never sends a byte off the box.**

Why a CISO leans in: it is a **complement to signature AV / YARA** (it catches the
variants those miss), it is **self-hosted and air-gapped** (no data egress, works in
a SCIF/OT network), it is **laptop-runnable** (no GPU, no cloud, no model required),
and it is **honest about its limits** (measured FP/coverage, documented scope).

## 2. Non-negotiable constraints (carry these through every phase)

1. **Air-gapped & offline** — zero network calls, ever. Already true; keep it true and *prove* it (Docker-with-`--network none` demo).
2. **Single artifact** — one static binary and one container image; no runtime deps, no model needed for the default path.
3. **Honest** — no claim the bench numbers don't support; keep the DESIGN honesty ledger front-and-center; document every coverage limit.
4. **Backwards-compatible** — the existing research CLI/TUI keeps working; product features are added, not swapped in.
5. **Tests green every stage; commit per stage** (match the repo's existing discipline).

---

## 3. Phased plan

Each phase is independently shippable, ends at a demoable gate, and notes the
CISO value. Phases P0–P3 are the **"CISO-credible MVP" cut line** for the talk
(see §4). P4–P7 deepen the product and can land before or after the talk.

### P0 — The verdict object + scan facade  *(linchpin; do first)*

The missing keystone. Everything machine-readable depends on a single fused result.

- **Add `ScanResult` / `Verdict`** in `agat-core` (new `verdict.rs`): one
  `Serialize`/`Deserialize` struct fusing `StaticFeatures`, `PolyFeatures`,
  `MetaFeatures`, `AiFeatures`, `Recognition`, and `DangerAssessment` into:
  `sample_id`, `kind`, `verdict` (Clean/Suspicious/Malicious/Inconclusive),
  `score` (0..1), `confidence`, `family` (if recognized), `danger_context`,
  `signals[]` (what fired + weight — the explainability payload), `engine_version`,
  `repertoire_version`, `limits_applied[]` (e.g. "non-x86 → structural analysis skipped").
- **Add a `agat-engine` facade crate** (or `agat::scan(bytes, &Config) -> ScanResult`):
  wires vault-optional store + the 5 analyzers + antigen + recognition + danger that
  `cmd_analyze`/`immune.rs` currently hand-assemble. One call in, one struct out.
- **Fuse the priority logic** that lives as printed text in `immune.rs:322–337` into a
  pure function returning `Verdict` (so CLI, JSON, API all agree).
- *Gate:* `agat_engine::scan` returns the same conclusion the CLI prints today, as a struct, with a round-trip serde test.
- *CISO value:* nothing else is possible without it; this is the data contract.

### P1 — Operator CLI: one-shot, batch, machine-readable

Turn the research CLI into something a blue-teamer runs in a pipeline.

- **`agat scan <path...>`** — a new top-level command: analyze file(s) **without
  ingesting into the vault** (stateless one-shot). Recursively walks directories
  (add `walkdir`), globs, and scans each file through the P0 facade.
- **Vault-optional**: one-shot `scan` and `recognize` must work **without a vault
  password** against a bundled/active repertoire. Keep the encrypted vault only for
  the *sample library* workflow (ingest/list/show). Fixes the automation blocker
  (`read_password` in `main.rs`).
- **Output formats** via `--output text|json|sarif` (+ `--json` shorthand):
  - `json`: array of `ScanResult`.
  - `sarif`: SARIF 2.1.0 so it drops into GitHub/GitLab code-scanning and most SIEMs.
  - `text`: keep today's human output as the default.
- **Granular exit codes**: `0` clean · `1` runtime error · `2` suspicious · `3` malicious
  (configurable threshold). Lets CI/cron gate on the result.
- **Config file** (`~/.agat/config.toml` + `--config`): thresholds, weights, allow/deny lists,
  default output. (Only env vars exist today.)
- *Gate:* `agat scan ./samples --json | jq` yields one verdict per file; `echo $?` reflects worst verdict; runs with no TTY and no vault password.
- *CISO value:* "point it at a folder / a build artifact / a quarantine dir and get JSON + an exit code." This is the demo a CISO pictures in their SOC.

### P2 — Packaging & the air-gap proof

Make "I can actually run this" a 60-second truth.

- **Static binary**: `x86_64-unknown-linux-musl` (and macOS arm64) release builds;
  everything already compiles in (rusqlite `bundled`), so a musl static build is realistic.
- **Dockerfile** (distroless/alpine, multi-stage): tiny image, no model, runs offline.
- **Reproducible offline demo** (the DESIGN `demo/` that's promised but missing):
  `demo/run.sh` (deterministic, single command), `demo/script.md` (timed speaker
  notes), `demo/asciinema/` fallback. **Hard rule from DESIGN: identical output on a
  laptop and in `docker run --network none`.** This *is* the air-gap proof on stage.
- **CI + release** (`cargo-dist` or a GitHub Actions matrix): tagged releases produce
  the static binaries + image + checksums + SBOM.
- **Install path**: one-line installer / `brew` / release tarball; man pages (`clap_mangen`).
- *Gate:* `docker run --network none agat scan /in` produces a verdict; a fresh machine goes from zero to a scan in under a minute.
- *CISO value:* air-gap + single artifact is the whole trust pitch. Show it, don't assert it.

### P3 — Evaluation & trust  (this is Stage 8, expanded)

The credibility backbone — for the product *and* the talk. Turns "cool idea" into "measured."

- **`bench/` reproducible generalization demo** (Stage 8): mature the repertoire on
  N polymorphic/metamorphic variants of a family, then **recognize a held-out variant
  it never saw**. Extend `tools/*_gen.py` to emit an N-variant family with a designated
  hold-out. This is your headline stage moment: *generalization, not memorization.*
- **Corpus-level metrics**: detection rate, **false-positive rate on a benign corpus**,
  and NSA non-self coverage — reported as numbers, not adjectives (honesty ledger #2).
- **Affinity-weight sensitivity sweep**: vary the `AntigenConfig` α/β weights and show
  the verdict is stable — pre-empts the "you hand-tuned it" critique (honesty ledger #3).
- **`docs/ARCHITECTURE.md`**: the pipeline diagram (adapt the ASCII one in the plan) + module map.
- **"How to read agat output" guide** (DESIGN §12 deliverable) — one page an attendee/analyst keeps.
- **Fix doc drift**: README examples that don't match clap; the stale "proposal, no code written" header in `AIS_REBUILD_PLAN.md`; dead references to `bench/`/`demo/`.
- *Gate:* `bench/run.sh` prints a held-out detection rate and a benign FP rate, reproducibly, offline.
- *CISO value:* "here are our measured FP numbers and here's the reproducible proof" is what separates a product from a demo.

### P4 — Detection-content lifecycle  (what CISOs call "updatable coverage")

Operators think in terms of detection content they can update and trust.

- **Named, exportable repertoires**: surface the `name` slot that already exists in the
  store (today hardcoded `"default"` in `immune.rs:25`). Add `agat repertoire
  export/import/list`. The detector/memory types are already `Serialize`.
- **Signed repertoires**: detached signature + version + provenance, so a shared
  repertoire is supply-chain-trustworthy (sign on export, verify on import).
- **Update mechanism**: an offline-friendly "detector pack" format (a file you side-load,
  not a phone-home) — matured families distributed as versioned, signed packs.
- **FP-control surface**: expose the tuning that's currently code-only — danger
  thresholds (`DangerConfig`), antigen weights (`AntigenConfig`), NSA tolerance/coverage —
  via config + flags, plus allowlist/denylist (hash and family).
- *Gate:* export a matured repertoire on machine A, verify-and-import on air-gapped machine B, reproduce the recognition.
- *CISO value:* "detection content I can vet, pin, roll back, and distribute internally — without calling home."

### P5 — Integration surfaces

Meet the SOC where it is.

- **`agat serve`**: a local REST daemon (`axum`) — `POST /scan` (bytes -> `ScanResult`),
  `GET /healthz`, bound to localhost by default. Still offline; just an integration port.
- **Library facade**: publish the P0 `agat-engine` crate as the embedding API.
- **Pipeline hooks**: a thin GitHub/GitLab CI action (uses SARIF from P1); a sample
  SIEM/SOAR ingestion recipe (the JSON schema + a Splunk/Elastic field mapping).
- **Positioning doc: "agat vs YARA/AV"** — not a replacement, a *variant-catching
  complement* that runs after your signature layer.
- *Gate:* `curl localhost:8080/scan --data-binary @sample` returns a verdict JSON; CI action fails a build on a malicious artifact.
- *CISO value:* "it plugs into the stack I already own."

### P6 — Demo enablers (talk-critical, ethically scoped)

- **Implement `agat-rewriter`** (today an empty stub) — the companion that produces the
  **AI-rewritten samples we need to demo detection against**. Keep it exactly as DESIGN
  scopes it: rewrites only benign / research-known payloads, **no evasion, persistence,
  or payload capability**, refuses AV-flagged inputs, clearly marked and separate. It
  exists solely to generate fixtures for agat to catch. *(This is the one item that
  needs an explicit ethics gate — see §5.)*
- **Curate the redistributable sample corpus**: 3 polymorphic + 3 metamorphic + 3
  AI-rewritten fixtures (public/synthesized), manifest-only in git (real bytes out of git).
- *Gate:* `agat-rewriter` turns a benign baseline into a variant that `agat scan` then recognizes as the same family — the full loop, on stage.

### P7 — Coverage expansion & depth  (mostly post-talk; pick high-value bits)

Honest scope today: **x86/x64 + PE/ELF only**, single-byte XOR/ADD/SUB poly, no dynamic analysis.
Expand deliberately; document until expanded.

- Multi-byte / register-key XOR recovery in `agat-poly` (currently immediate single-byte only).
- Mach-O parsing (`agat-static` detects but doesn't parse); ARM/aarch64 disasm.
- Instruction-folding / reordering normalization in `agat-meta`.
- **`agat-sandbox`** (empty stub): optional Docker/bollard dynamic analysis — nice-to-have, defer unless time allows; it breaks the pure-air-gap story, so gate it behind an opt-in.
- **TUI operator console**: today the TUI is a read-only viewer that ignores the vault and
  has no immune views — upgrade it to run scan/recognize for a live, projector-friendly demo.

---

## 4. The "CISO-credible MVP" cut line for Black Hat India

If time is tight, **P0 → P1 → P2 → P3** is the product you walk in with, plus the
P6 rewriter+corpus so the demo has samples. That yields:

- `agat scan <file|dir> --json|--sarif` with real exit codes, no vault friction.
- A single static binary **and** a container that runs `--network none`.
- A reproducible bench proving **generalization to a held-out variant** + a **measured FP rate**.
- `docs/ARCHITECTURE.md` + a one-page "how to read the output" handout.
- Honest, drift-free docs.

That is demonstrably "simple, deployable, and something a CISO can picture running" —
without overclaiming. P4 (signed updatable repertoires) is the strongest *next* slide
if you have the runway; P5 (serve/CI) is the "it fits my stack" closer.

## 5. Ethics & honesty gates (state these on stage)

- **`agat-rewriter` is the sensitive component.** Build it only within the DESIGN scope
  (benign/known payloads, no weaponization, refuses AV-flagged inputs), keep it a
  clearly-separated tool, and say plainly on stage why it exists (you cannot demo
  "we detect AI-rewritten malware" without AI-rewritten fixtures). If in doubt, demo
  with pre-generated fixtures and don't ship the rewriter.
- **Keep the DESIGN honesty ledger visible**: DCA is "signal-fusion math," not a running
  dendritic-cell population; NSA is a *complementary* anomaly layer with *measured* (not
  guaranteed) coverage; the affinity metric is *engineered* (hence the P3 sensitivity sweep);
  "self" is benign-behavior space, not biology.
- **Never claim completeness.** "Catches variants signatures miss," not "catches everything."
  Publish the coverage limits (§P7) next to the capabilities.

## 6. Suggested sequencing (≈ the weeks before the talk)

1. P0 (verdict object + facade) — unblocks all output work.
2. P1 (scan/batch/json/sarif/exit codes/config) — the operator surface.
3. P3 bench + metrics in parallel with P2 packaging — credibility + "runs anywhere".
4. P6 rewriter (scoped) + corpus — demo fuel.
5. P2 polish (Docker `--network none` demo, installer, man pages, CI release).
6. Stretch: P4 signed repertoires, P5 `agat serve` + CI action, TUI console.

## 7. Open questions for you

- Black Hat India date → fixes the real runway and the MVP cut line.
- Ship `agat-rewriter`, or demo with pre-generated fixtures only? (ethics call)
- Is `agat serve` (REST) worth it for the talk, or is the CLI + SARIF enough to tell the integration story?
- Target platforms for the release binary (Linux musl + macOS arm64 assumed).
