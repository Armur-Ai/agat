<!--
  IMPLEMENTATION.md — granular build plans for the capabilities in ROADMAP.md.
  Each phase: architecture → data model → algorithm → interfaces → task
  checklist → tests → risks → definition of done. Grounded in the current tree;
  function/type names are the real ones.
-->

# agat — Implementation Plan

Granular engineering plans for the five roadmap phases in
**[`ROADMAP.md`](ROADMAP.md)**. Each phase is written so a contributor can pick
up a milestone and work it end to end. Code references (`module::symbol`) point
at the **current** tree.

**Conventions**
- `[ ]` tasks are checkboxes — turn each milestone into a tracking issue.
- "New" = net‑new file/type; "Extend" = change an existing one.
- Every phase inherits the invariants in `ROADMAP.md` (offline, deterministic,
  defensive‑only, 0‑FP, explainable). Tasks that touch those are flagged ⚠️.
- Determinism rule: any randomness goes through a seeded `StdRng`, mirroring
  `NsaConfig::seed` / `ClonalConfig::seed`.

**Shared prerequisites (do before R2–R5)**
- [ ] **Evolution telemetry crate/module** `agat-eval` (or `agat-engine::eval`):
  a deterministic run‑report (`RunReport { coverage_curve, diversity, fp_delta,
  seed, inputs_hash }`) serialized to JSON; reused by R2/R3/R4.
- [ ] **Corpus harness**: extend `bench/` with a time‑split, labeled,
  diversity‑scored synthetic corpus built from `tools/*_gen.py`; a
  `bench/holdout.sh` that reports coverage + FP for a given model.
- [x] **Antigen‑space mutation library** `agat-antigen::mutate` — four
  `MutationClass` axes, fingerprint-invariant per class, deterministic, bounded.

## Landed so far (library layer)

The library core of **all five phases** is implemented, tested and
deterministic; CLI/`serve`/store wiring and the eval harness are the main
remaining work. What exists today:

| Phase | Implemented | Module / symbols |
|---|---|---|
| shared | mutation operators | `agat_antigen::mutate` (`MutationClass`, `mutate`, `variant_batch`) |
| R1 | content ids + union merge | `MemoryCell::cell_id`, `Detector::detector_id`, `MemoryPool::union`, `Repertoire::union`, `crate::ident` |
| R2 | self-play loop | `agat_immune::evolve` (`EvolveConfig`, `evolve`, `EvolveReport`) |
| R3 | forward projection + pre-immunize | `agat_immune::forecast` (`DriftModel`, `LinearDriftModel`, `forecast`) |
| R4 | living self + regulation + drift | `SelfModel::incorporate`, `agat_immune::regulation` (`Regulator`), `agat_immune::drift` (`classify`) |
| R5 | bounded inflammation | `agat_immune::inflammation` (`Cytokines`, `InflamConfig`, `neighborhood_key`) |

Still open per phase: pack delta/ledger + CLI (R1), diversity pressure + CLI
(R2), corpus-fit drift model + time-split eval + CLI (R3), re-censor pass +
serve hook + replay eval (R4), `danger::assess` modulation wiring + quarantine
tier + `serve --adaptive` (R5), and the shared eval harness. The per-milestone
checklists below mark what is done with `[x]`.

---

## R1 · Herd immunity
🟢 *Fleet immunity — delta antibody packs that merge across an air‑gapped fleet.*

### What exists
`agat-engine::pack` already builds, signs, verifies and installs a **whole**
model as `agat.pack/v1`: `build_payload(store, name, version, desc)` →
`PackPayload{manifest, self_model, repertoire, memory}`, `seal(payload,
Option<&SigningKey>)` → `PackFile`, `verify(pack, &TrustPolicy)` →
`VerifiedPack`, `install(store, &VerifiedPack)`. CLI: `agat repertoire
export/import`, `agat key generate`. The antigen‑metric fingerprint pinning in
`verify` already refuses a pack trained under an incompatible antigen layout.

### Gap to close
Today a pack is a full **replace**. A fleet needs **incremental, mergeable**
antibody packs: node A matures a response, emits *only* the new memory
cells/detectors, and B/C merge them without discarding their own, idempotently
and deterministically.

### Architecture
- **Extend** `agat-engine::pack`:
  - `PackKind { Full, Delta }` on `PackManifest`.
  - `build_delta(store, since: Option<&ModelRef>, name, version)` → a
    `PackPayload` whose `memory`/`repertoire` carry only cells/detectors absent
    from `since` (diff by `MemoryCell` identity — see data model).
  - `merge(store, &VerifiedPack)` → union‑merge into the active `MemoryPool` and
    `Repertoire` (vs. the current `install` which overwrites).
- **New** `agat-engine::ledger`: an append‑only provenance log of merged packs.
- **Extend** `agat-store`: `immune_ledger` table + accessors.
- **Extend** `agat-immune::memory::MemoryPool` and `detectors::Repertoire`: a
  deterministic `union(&mut self, other)` that dedupes by stable id and keeps
  the stronger cell on collision.

### Data model
- Give `MemoryCell` a **stable content id**: `cell_id = blake3(family ‖
  quantized(center) ‖ base_radius)` (quantize to the antigen layout's precision
  so it is reproducible). Add `cell_id()` accessor; do **not** store it (derive)
  to keep existing serialized models readable.
- New store table:
  ```sql
  CREATE TABLE IF NOT EXISTS immune_ledger (
      seq         INTEGER PRIMARY KEY AUTOINCREMENT,
      pack_sha256 TEXT NOT NULL,
      pack_name   TEXT NOT NULL,
      pack_version TEXT NOT NULL,
      signer      TEXT,                 -- key id, or NULL if unsigned
      kind        TEXT NOT NULL,        -- 'full' | 'delta'
      cells_added INTEGER NOT NULL,
      merged_at   TEXT NOT NULL
  );
  ```
- `merge` is **commutative + idempotent**: merging a pack already in the ledger
  (by `pack_sha256`) is a no‑op; order of two packs does not change the model.

### Interfaces
- CLI (`agat-cli/src/packs.rs`, `main.rs`):
  - `agat pack emit <out.agatpack> --since <pack.sha256|->` `--name --version --sign`
  - `agat pack merge <in.agatpack> --trust <key.pub>`
  - `agat pack log` (print the ledger)
- TUI (`agat-tui/src/actions.rs`): an "Import antibody pack…" action.

### Tasks
**M1 — delta format**
- [ ] Add `PackKind` to `PackManifest`; bump pack minor, keep `verify` back‑compat ⚠️(determinism: quantization constants pinned).
- [ ] `MemoryCell::cell_id()` + unit test for reproducibility across (de)serialize.
- [ ] `build_delta()` + `PackPayload` diff; golden test (full == emit from empty).

**M2 — merge engine**
- [ ] `MemoryPool::union()` / `Repertoire::union()` with collision rule + property tests (commutative, idempotent).
- [ ] `pack::merge()` wrapping union + `verify`'s fingerprint/trust checks.
- [ ] Reject merging a Full pack via `merge` (point user at `import`).

**M3 — ledger + CLI**
- [ ] `immune_ledger` migration + `Store::append_ledger/list_ledger`.
- [ ] `agat pack emit/merge/log` wired; colored output via `style`.
- [ ] TUI import action.

**M4 — proof**
- [ ] Integration test: mature on home A → emit delta → merge into B and C → all three reproduce A's verdict on a held‑out variant (bit‑identical table).
- [ ] Idempotency test: merge same pack twice → ledger has one row, model unchanged.

### Tests & validation
- Determinism: `union` output independent of input order (sort by `cell_id`).
- Air‑gap: delta carries only model artifacts — assert no sample bytes in the pack (extend the existing air‑gap transcript check).

### Risks
- **Conflict resolution** when two nodes mature overlapping families → defined by the collision rule (keep larger `variants` count, then larger radius); documented and tested. Low overall risk.

### Definition of done
`agat pack emit`→`merge` reproduces verdicts across nodes, idempotent, logged, air‑gapped, deterministic; docs + bench updated.

---

## R2 · The Germinal Center
🟡 *Self‑play affinity maturation — a synthetic adversary vs. the repertoire, in a loop.*

### What exists
- `negative_selection::generate(&SelfModel, dim, &NsaConfig) -> Repertoire` and
  `Repertoire::covers(sig)`.
- `clonal::mature(antigen, family, &mut MemoryPool, Option<&Repertoire>,
  &ClonalConfig) -> Maturation` (CLONALG: clone ∝ affinity, hypermutate ∝
  1‑affinity, promote to memory).
- `recognition::recognize(...)` for scoring a signature.
- `agat-rewriter` crate **stub** (intended as the variant generator) and
  `tools/{meta,poly,ai}_gen.py`.

### Gap to close
A bounded **generate → test → promote → re‑select** loop that runs unattended
and measurably seals coverage gaps, entirely in antigen/feature space (no
executable variants).

### Architecture
- **New** `agat-immune::evolve` module:
  - `EvolveConfig { generations, population, budget, diversity_pressure,
    coverage_target, seed }`.
  - `fn evolve(model: &mut ImmuneModel, seeds: &[Antigen], gen: &dyn Mutator,
    cfg: &EvolveConfig) -> EvolveReport`.
  - `trait Mutator { fn variants(&self, parent: &Antigen, rng: &mut StdRng, n:
    usize) -> Vec<Antigen>; }`.
- **Build out** `agat-antigen::mutate` as the default `Mutator`: perturb the
  signature within per‑group validated bounds + apply the four mutation classes
  symbolically (register slot swaps, re‑encryption → same plaintext fingerprint,
  CFG rewrite → WL‑hash neighborhood, LLM‑style substitution).
- **Extend** `agat-engine`: `ImmuneModel` needs mutable access to its
  `Repertoire`/`MemoryPool` and a re‑`generate`/`mature` path.
- **New** CLI command `Evolve` in `agat-cli`.

### Algorithm (one generation)
1. Draw a batch of variant antigens from current families via `Mutator`.
2. Score each against the current model; collect **evaders** (covered=false and
   not a memory match) — these are the valuable ones.
3. Promote evaders: `mature(evader, family, …)` and/or re‑`generate` the
   repertoire against an **augmented** self? No — augment *non‑self coverage*:
   re‑run `negative_selection::generate` seeded to prefer the evader regions.
4. Apply **diversity pressure**: penalize generators that resubmit near‑duplicate
   evaders (hash the WL/plaintext fingerprints); stop when coverage_target hit
   or budget exhausted.
5. Emit `EvolveReport` (per‑generation coverage, diversity, FP delta).

### Interfaces
- `agat evolve [--home H] [--generations N] [--budget M] [--seed S] [--report out.json]`
- `agat evolve --dry-run` prints the plan without mutating the model.
- TUI: the "Germinal center" action in the (future) capability console maps here.

### Tasks
**M1 — mutation library ⚠️(defensive‑only)**
- [ ] `agat-antigen::mutate::signature_perturb(&Antigen, rng, scale)` within group bounds; unit test invariants preserved (plaintext fp stable under re‑encryption class).
- [ ] Symbolic operators for the four classes; property test: a meta‑sibling maps into the same WL‑hash neighborhood.
- [ ] Guardrail test: `mutate` never emits parseable/executable bytes — it stays in feature space.

**M2 — evolve loop**
- [x] `EvolveConfig` + `evolve()` single‑generation, fully seeded.
- [x] Evader detection using `Repertoire::covers` + memory match.
- [ ] Promotion path (mature + targeted `generate`) with no benign‑FP regression check per generation.

**M3 — diversity & termination**
- [ ] Fingerprint‑dedup diversity pressure; coverage/budget termination.
- [x] `EvolveReport` (shared `agat-eval` format).

**M4 — CLI + proof**
- [ ] `agat evolve` command; colored progress; `--report`.
- [ ] Bench: on a held‑out variant set, one run raises recognition coverage ≥ X pts with **FP unchanged (0)**; deterministic across two runs with same seed.

### Tests & validation
- Determinism: identical `EvolveReport` for a fixed seed (golden JSON).
- 0‑FP gate ⚠️: rerun `bench/` benign corpora after evolve; abort/rollback on any new FP.
- Mode‑collapse guard: assert diversity metric stays above a floor.

### Risks
- **Mode collapse** → diversity pressure + coverage‑of‑space metric (not evasion count).
- **Overfitting to the generator** → hold out a *different* generator family for evaluation than the one used to evolve.

### Definition of done
`agat evolve` seals measured coverage gaps at 0 FP, deterministically, with a run report; mutation stays in antigen space; docs + bench updated.

---

## R3 · The Vaccine Forecaster
🔵 *Immunize against variants before they are written.*

### What exists
R2's mutation library + `clonal::mature` + a time‑split corpus (shared
prereq). `MemoryPool` already generalizes a family from few variants
(`ClonalConfig::generalization`, `MemoryCell::incorporate`).

### Gap to close
A **directional, forward** projection of a family's mutation space (vs. R2's
undirected search), producing attenuated antigens along realistic drift
trajectories, pre‑matured into memory.

### Architecture
- **New** `agat-immune::forecast`:
  - `trait DriftModel { fn trajectories(&self, family_center: &[f64], horizon:
    Horizon) -> Vec<Trajectory>; }` where a `Trajectory` is an ordered sequence
    of antigen‑space steps per drift kind (recompile/re‑encrypt/obfuscate/
    LLM‑rewrite).
  - `fn forecast(model: &mut ImmuneModel, family: &str, drift: &dyn DriftModel,
    cfg: &ForecastConfig) -> ForecastReport`.
- Default `DriftModel` v1: empirically‑fit step distributions estimated from the
  observed spread of known families in the corpus (per feature group), **not** a
  learned generative model — keep it inspectable.
- **New** CLI `Forecast`.

### Algorithm
1. Take a family's memory cell center(s).
2. For each drift kind, walk `k` steps along its trajectory, synthesizing an
   attenuated antigen at each (bounded so it stays recognizably in‑family).
3. `mature(projected, family, …)` for the projected points (pre‑immunization).
4. Record horizon, #strains, and expected coverage expansion.

### Interfaces
- `agat forecast <family> [--horizon short|medium|long] [--report out.json]`
- `agat forecast --explain` prints the trajectory assumptions (honesty).

### Tasks
**M1 — drift model**
- [ ] Estimate per‑group drift step distributions from the corpus; serialize a `DriftModel` config (deterministic, inspectable).
- [x] `Trajectory` synthesis reusing `agat-antigen::mutate` with a **direction**.

**M2 — forecast + pre‑immunize**
- [ ] `forecast()` pre‑maturing along trajectories; cap in‑family drift so projected cells don't swallow non‑self.
- [x] `ForecastReport` (horizon, strains, projected coverage).

**M3 — CLI + proof ⚠️(no overclaim)**
- [ ] `agat forecast` + `--explain`.
- [ ] **Time‑split eval**: train on vintage N, forecast, test detection of vintage N+1 of the same family vs. no‑forecast baseline; FP must stay 0. Report as *coverage of reachable space*, not prophecy.

### Tests & validation
- Guard: a projected cell must never reduce benign‑FP (0‑FP gate) nor misclassify a different family (inter‑family distance check).
- Determinism golden report.

### Risks
- **Forecast drift is a model, not truth** → ship `--explain`, bound in‑family, position as complement to the novelty+danger baseline (which still catches the genuinely novel).

### Definition of done
Forecasting a family raises future‑variant detection on a time‑split at 0 FP, with an explainable trajectory model and deterministic report.

---

## R4 · The Living Self
🔵 *Continuous re‑tolerization + a regulatory layer against autoimmunity.*

### What exists
`SelfModel::build(antigens, k)`, `surface_distance`, `is_self`;
`negative_selection::generate` (one‑shot). `Repertoire`/`Detector` with
`matches`/`affinity`. Today all learned once.

### Gap to close
Two controllers: (a) **re‑tolerization** — fold benign drift into `SelfModel`
incrementally and re‑censor detectors that now hit it; (b) **regulation** —
retire detector lineages that begin firing on benign software before they cause
an FP storm. Plus **drift classification** to tell benign from slow‑burn
malicious change.

### Architecture
- **Extend** `self_model`: `SelfModel::incorporate(&mut self, antigens)` — online
  update of centers/radii (streaming k‑means‑ish; deterministic).
- **New** `agat-immune::regulation`:
  - `struct Regulator { fp_pressure: HashMap<DetectorId, f64>, cfg: RegConfig }`.
  - `fn observe(&mut self, detector: &Detector, fired_on_benign: bool)` and
    `fn sweep(&mut self, repertoire: &mut Repertoire)` — retire detectors over an
    FP‑pressure threshold (digital Tregs).
  - Give `Detector` a stable `DetectorId` (like R1's `cell_id`).
- **New** `agat-immune::drift`:
  - `classify(point, &SelfModel, history) -> DriftVerdict { BenignDrift,
    Suspicious, Hold }` — benign drift = gradual move consistent with signed/
    known‑good context; "boil‑the‑frog" = flagged, not silently absorbed.
- **New** CLI `self watch` (and `agat serve` hook) driving the controllers over a
  stream.
- **Extend** `agat-store`: `immune_self_history`, `immune_regulation` tables.

### Algorithm (per new benign observation)
1. `drift::classify` the point. If `BenignDrift` and context safe →
   `SelfModel::incorporate`, then re‑censor the repertoire (`Repertoire` drop
   detectors now within `self_tolerance` of the updated self).
2. On each scan, `Regulator::observe` detectors that fire on confirmed‑benign
   samples; `sweep` retires chronic offenders and logs the retirement.
3. Suspicious/boil‑the‑frog drift is **not** absorbed — surfaced for review.

### Interfaces
- `agat self watch [--source dir|serve] [--dry-run]`
- `agat self history` / `agat regulation log`
- `agat serve`: optional online re‑tolerization behind an explicit flag.

### Tasks
**M1 — incremental self**
- [ ] `SelfModel::incorporate` + re‑censor pass; determinism + "self breathes" test (radius tracks a moving benign cluster).

**M2 — regulation (Tregs)**
- [x] `DetectorId`; `Regulator` with FP‑pressure accounting + `sweep`.
- [ ] Injected‑autoreactive‑detector test: regulator retires it before it fires on the benign corpus ⚠️.

**M3 — drift classification**
- [ ] `drift::classify` with an explicit threat model doc; unit tests for benign vs. staged‑malicious drift.

**M4 — CLI/serve + proof**
- [ ] `self watch`, history/log commands; serve hook (flagged).
- [ ] **Replay eval**: a multi‑month benign+malicious stream; FP stays ≈0 through churn with no manual retrain; staged "frog‑boil" attack is flagged, not absorbed.

### Tests & validation
- 0‑FP through churn (the headline metric) ⚠️.
- Determinism of the online update (seeded, order‑stable within a batch).

### Risks
- **Benign vs. slow malicious drift is unsolved in general** → conservative
  classification, "hold for review" default, regulatory layer as the rail;
  shipped with the threat model stated.

### Definition of done
A living `SelfModel` + regulator holds FP near zero under replayed churn without
human retraining, retires an injected autoreactive detector, and flags staged
malicious drift — all deterministic and documented.

---

## R5 · Adaptive Inflammation
🟣 *Cross‑analyzer danger signaling — sharper where it is probed, bounded by design.*

### What exists
`danger::assess(&DangerSignals, &DangerConfig)` and `signals_from_features(...)`
fuse PAMP/danger/safe **per sample, statelessly**. `DangerConfig` holds the
weights/thresholds.

### Gap to close
Make danger **stateful and local**: a strong reading in one analyzer transiently
raises sensitivity for *related* samples, then decays — with hard damping so an
attacker can't weaponize it into a self‑inflicted FP storm. Depends on R4's live
state for the neighborhood model.

### Architecture
- **New** `agat-immune::inflammation`:
  - `struct Cytokines { field: HashMap<NeighborhoodKey, f64>, cfg: InflamConfig }`
    where `NeighborhoodKey` buckets antigen space (e.g., coarse signature
    quantization / WL‑hash prefix).
  - `fn emit(&mut self, key, strength)` (on a strong danger reading) and
    `fn modulate(&self, base: &DangerConfig, key) -> DangerConfig` — returns a
    *locally* tightened config for a sample in that neighborhood.
  - `fn decay(&mut self, dt)` — exponential relaxation to baseline.
  - **Bounds** ⚠️: `InflamConfig { max_gain, half_life, rate_limit,
    global_cap }` — modulation is clamped; a global cap prevents fleet‑wide
    escalation; rate‑limit caps emissions per window.
- **Extend** `danger::assess` to accept an optional `modulated: Option<&DangerConfig>`.
- **Extend** `ImmuneModel`/`serve` to carry a `Cytokines` field across scans (stateful mode behind a flag; default stays stateless + deterministic).
- **New** graded response: `quarantine` verdict tier (reversible) distinct from a hard `Malicious`.

### Algorithm (per scan, stateful mode)
1. Compute base signals (`signals_from_features`).
2. `cfg' = cytokines.modulate(base_cfg, neighborhood(sample))` (clamped).
3. `assess(signals, &cfg')`; if strongly dangerous, `cytokines.emit(neighborhood,
   strength)` (rate‑limited, capped).
4. Time/decay between scans relaxes the field to baseline.

### Interfaces
- `agat serve --adaptive` (opt‑in stateful mode) with the bounds surfaced in
  `/healthz`.
- `agat scan --adaptive` for a batch (shared `Cytokines` across the batch).
- Metrics: current field heat per neighborhood (for the console/telemetry).

### Tasks
**M1 — stateless‑safe core ⚠️(determinism)**
- [x] `Cytokines` + `InflamConfig` with hard bounds; `modulate` clamped; property test: modulation never exceeds `max_gain`, never below baseline.
- [ ] Make it **opt‑in**: default path is byte‑identical to today (protect the air‑gap transcript).

**M2 — integration**
- [ ] `danger::assess` optional modulated config; `ImmuneModel` stateful mode; `scan --adaptive` batch path.
- [ ] Graded `quarantine` tier + exit‑code mapping.

**M3 — safety proofs ⚠️**
- [ ] Probe‑campaign sim: local sensitivity rises in the probed neighborhood, later probes caught, then self‑limits to baseline (decay test).
- [x] **Adversarial DoS test**: a deliberate attempt to induce a global FP storm is provably bounded by `global_cap`/`rate_limit` (the key safety result).

**M4 — serve/metrics**
- [ ] `serve --adaptive`, `/healthz` reports bounds; neighborhood heat metric.

### Tests & validation
- Default determinism preserved (adaptive strictly opt‑in) ⚠️.
- Bounds are hard (unit + adversarial tests) — this is the gating result.

### Risks
- **Weaponizable into self‑DoS** → the damping/bounds are the core deliverable, tested adversarially; feature stays opt‑in and depends on R4's reviewed state.

### Definition of done
Opt‑in adaptive danger raises local sensitivity under probing and self‑limits,
with provably bounded worst‑case FP behavior; the default stateless path is
unchanged and still deterministic/air‑gapped.

---

## Appendix — where each phase plugs into the tree

| Phase | New modules | Extends | New CLI | Store tables |
|---|---|---|---|---|
| R1 | `engine::ledger` | `engine::pack`, `immune::memory`/`detectors`, `store`, `cli::packs` | `pack emit/merge/log` | `immune_ledger` |
| R2 | `immune::evolve`, `antigen::mutate` | `engine::ImmuneModel`, `cli` | `evolve` | — |
| R3 | `immune::forecast` | `immune::clonal`, `cli` | `forecast` | — |
| R4 | `immune::regulation`, `immune::drift` | `immune::self_model`/`detectors`, `store`, `cli`, `serve` | `self watch`, `self history`, `regulation log` | `immune_self_history`, `immune_regulation` |
| R5 | `immune::inflammation` | `immune::danger`, `engine::ImmuneModel`, `serve`, `cli` | `scan --adaptive`, `serve --adaptive` | — |

> Keep this file and `ROADMAP.md` in lockstep. When a milestone lands, check its
> boxes here and flip the phase's status in `ROADMAP.md` and in `agat roadmap`
> (`crates/agat-cli/src/roadmap.rs`).
