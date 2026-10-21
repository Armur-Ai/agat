# agat user guide

A practical, end-to-end guide to running agat: install it, train it on your
environment, scan, read the results, and wire it into your stack. For the
"why" behind the immune model see [CONCEPTS.md](CONCEPTS.md); for the output
contract see [READING_OUTPUT.md](READING_OUTPUT.md).

- [Install](#install)
- [The mental model](#the-mental-model)
- [Training: teach agat your environment](#training-teach-agat-your-environment)
- [Scanning](#scanning)
- [Output formats and exit codes](#output-formats-and-exit-codes)
- [Configuration](#configuration)
- [Model packs: train once, deploy everywhere](#model-packs-train-once-deploy-everywhere)
- [The interactive console](#the-interactive-console)
- [Comparing samples](#comparing-samples)
- [The HTTP API](#the-http-api)
- [Troubleshooting](#troubleshooting)

---

## Install

agat is a single static binary with no runtime dependencies, no GPU, and no
model to download. It never makes a network call.

**Container** (≈12 MB, `scratch` base):

```bash
docker build -t agat .
docker run --rm --network none \
  -v "$HOME/.agat:/data" -v "$PWD:/scan:ro" \
  agat scan /scan --output table
```

**Release tarball** (tagged releases — Linux `x86_64`/`aarch64` static musl,
macOS `arm64`; each with a `.sha256` and a CycloneDX SBOM):

```bash
tar xzf agat-v*-x86_64-unknown-linux-musl.tar.gz
sudo install agat-*/agat /usr/local/bin/
```

**From source** (stable Rust ≥ the `rust-version` in `Cargo.toml`):

```bash
cargo install --locked --path crates/agat-cli
```

Shell completions and a man page are generated on demand:

```bash
agat completions zsh  > "${fpath[1]}/_agat"      # or bash|fish|elvish|powershell
agat man > /usr/local/share/man/man1/agat.1
```

---

## The mental model

agat works in two phases, and keeping them straight is the key to using it
well.

1. **Training (once, on your data).** You teach agat what *your* benign
   software looks like ("self") and, optionally, a few confirmed malware
   families. This produces a **model** — a self-model, a detector
   repertoire, and family memory — stored in the agat home directory
   (`~/.agat` by default, or `$AGAT_HOME`, or `--home PATH`).

2. **Scanning (per sample, offline).** You point agat at files. Each is
   distilled into a behavioral **antigen** and checked against the model on
   two independent axes — **recognition** (is it foreign to self? whose
   family?) and **danger** (does it carry harm signals?) — which fuse into a
   single **severity**.

The agat home holds two things: an **encrypted vault** of raw sample bytes
(only the training/library commands open it, and only with a password) and a
**store** of extracted features and the learned model (everything else reads
this, no password needed). That split is why `agat scan` runs unattended.

---

## Training: teach agat your environment

> agat's accuracy depends entirely on training `self` on benign software
> *like what you scan*. A model trained on the wrong baseline inflates the
> false-positive rate. Use a representative sample of your golden images,
> build outputs, or approved software.

The vault is encrypted at rest (AES-256-GCM, Argon2id key derivation), so
training commands need a password. Set it once for a session:

```bash
export AGAT_VAULT_PASSWORD='choose-a-strong-passphrase'
```

**1. Ingest and analyze** your benign baseline (and any confirmed family
samples):

```bash
agat ingest ./golden-image/bin/* ./confirmed-qakbot/*
agat analyze                      # runs every analyzer on every sample
agat list                         # ids, sizes, kinds, filenames
```

**2. Build the self-model** from your benign samples. Pass ids from
`agat list` (a unique prefix is enough), or tag samples `benign` and omit
the ids:

```bash
agat self build <benign-id> <benign-id> …
```

**3. Generate the detector repertoire** by negative selection. `--seed`
makes it reproducible:

```bash
agat repertoire generate --seed 1
```

At this point agat can already flag *anomalies* (anything outside self) — no
malware was needed. To recognize specific **families**, mature the memory on
confirmed variants:

```bash
agat mature <sample-id> --family qakbot      # repeat per confirmed variant
```

A family generalizes: after a few variants, the memory cell covers the
family's neighborhood and recognizes variants you never trained on.

Inspect the trained model at any time:

```bash
agat repertoire info
```

---

## Scanning

`agat scan` is **stateless** by default: files are analyzed in memory,
nothing is written to the vault or store, and no password is needed. It
takes any number of files and directories (walked recursively).

```bash
agat scan ./suspect.bin                      # one file, full report
agat scan ./quarantine ./build/out           # files and dirs
agat scan ./artifacts --output table         # one line per file
agat scan /mnt/share -j 8                     # 8 parallel workers (default: all cores)
```

Batch scans run in parallel and stay deterministic — output is identical to
a single-threaded run, and a progress line appears on the terminal for large
batches. Cap the workers with `-j N`.

Two global flags apply to every command: `--home PATH` (the agat data
directory) and `--color auto|always|never` (color control, honoring
`NO_COLOR`). `--config PATH` points at a specific config file.

To add a file to the sample library as you scan it (ingest + persist
features), pass `--ingest` (this needs the vault password):

```bash
agat scan ./new-sample.bin --ingest
```

Read a single sample from **stdin** with `-` (handy in pipelines):

```bash
curl -s https://host/suspect.bin | agat scan - --json
```

`agat recognize <sample-id>` produces the same report for a sample already
in the library.

---

## Output formats and exit codes

Pick the format with `--output text|table|json|sarif` (or the `--json` /
`--sarif` shorthands):

| format | use it for |
|---|---|
| `text` | a human reading one sample (the default for a single file) |
| `table` | a human scanning many files — one colored line each |
| `json` | pipelines, SIEMs — a single object, or an array for a batch (`agat.scan/v1`) |
| `sarif` | GitHub/GitLab code scanning and most SIEMs (SARIF 2.1.0) |

The **exit code** is the contract for automation:

| code | meaning |
|---|---|
| `0` | clean |
| `2` | review / suspicious — a human should glance |
| `3` | malicious — investigate |
| `1` | agat itself failed (bad path, no model) — never a verdict |

For a batch, the exit code is the worst file's. Raise the bar with
`--fail-on review|suspicious|malicious|never`:

```bash
agat scan ./release --fail-on malicious      # only a malicious verdict fails
echo $?
```

The JSON contract has a published schema
([`docs/schema/agat.scan.v1.json`](schema/agat.scan.v1.json), or `agat
schema`). Validate against it and gate on `schema_version`.

---

## Configuration

agat reads `~/.agat/config.toml` (or `--config PATH`); command-line flags
override it.

```toml
[scan]
output  = "table"        # text | table | json | sarif
fail_on = "suspicious"   # review | suspicious | malicious | never

[danger]
dangerous_at = 0.5       # danger score >= this  => dangerous
safe_below   = 0.33      # danger score <  this  => safe

[allowlist]
sha256 = ["<64-hex sha256>"]   # always reported clean

[denylist]
sha256 = ["<64-hex sha256>"]   # always reported malicious (wins over allowlist)

[packs]
trusted_keys = ["/etc/agat/secops.pub"]   # signers whose packs import accepts
```

An allow/deny-list override is recorded in the result's `verdict.policy`
field; the recognition and danger axes are still reported unchanged. A
malformed config fails fast at startup with a specific message.

---

## Model packs: train once, deploy everywhere

A trained model is portable as one signed file, so you train in one place
and scan everywhere — including air-gapped machines that only ever receive
the pack.

**Create a signing key** (Ed25519), once:

```bash
agat key generate keys/secops --comment "acme-secops"
# → keys/secops.key (secret, mode 0600) and keys/secops.pub (share this)
```

**Export** the active model, signed:

```bash
agat repertoire export acme-2026.10.agatpack \
  --name acme-threats --version 2026.10 --sign keys/secops.key
```

**Import** on the target, trusting your key:

```bash
agat repertoire import acme-2026.10.agatpack --trust keys/secops.pub
```

Import verifies the payload's SHA-256, the Ed25519 signature against keys you
trust (`--trust`, `[packs] trusted_keys`, or `~/.agat/trusted_keys/*.pub`),
and that the pack was trained in the same antigen metric space. Unsigned
packs are refused unless you pass `--allow-unsigned`; a single flipped byte
is refused as tampered; a pack from an incompatible agat version is refused
rather than mis-scored. Every scan result then names the pack that produced
it (`model.source`, `model.name`, `model.signer`). Retraining locally clears
that provenance.

See [DEPLOYMENT.md](DEPLOYMENT.md) for fleet operations.

---

## The interactive console

`agat tui` opens a terminal dashboard over the sample library (no password
needed). The sample list is colored by verdict; the Immune tab shows the
recognition and danger axes with meters and the model that made the call;
the other tabs drill into each analyzer.

| key | action |
|---|---|
| `j` / `k`, `↑` / `↓` | previous / next sample |
| `h` / `l`, `←` / `→`, `Tab` | switch tab |
| `1`–`6` | jump to a tab |
| `PgUp` / `PgDn`, `J` / `K`, `g` | scroll the view |
| `/` | search samples by id or name |
| `?` | toggle the help overlay |
| `q` / `Esc` | quit |

---

## Comparing samples

`agat diff <a> <b>` answers "are these two samples related, and where?" for
two samples in the library. It reports the blended affinity, cosine, Jaccard,
whether the CFG and recovered-plaintext fingerprints match, a per-feature-
group similarity breakdown, and a plain-language read:

- **same payload + different control flow** → the algorithm-substitution
  signature of an LLM rewrite;
- **same canonical control flow** → metamorphic siblings;
- otherwise → closely related / some shared / little in common.

---

## The HTTP API

`agat serve` exposes the scan engine over local HTTP for SOAR playbooks,
mail gateways, and pipelines. It loads the model once and binds `127.0.0.1`
by default (there is no built-in auth — put anything wider behind an
authenticating reverse proxy, then pass `--allow-remote`).

```
POST /v1/scan     raw bytes → ScanResult JSON  (?name=, ?format=sarif)
GET  /v1/model    the active model's provenance
GET  /v1/schema   the agat.scan/v1 JSON Schema
GET  /healthz     liveness + version + model
```

Every verdict is a `200` with the severity in the body and in an
`X-Agat-Severity` header, so a playbook can branch without parsing JSON.

```bash
agat serve
curl --data-binary @invoice.exe 'localhost:8080/v1/scan?name=invoice.exe'
```

See [INTEGRATION.md](INTEGRATION.md) for SIEM/SOAR/CI recipes.

---

## Troubleshooting

**"no repertoire yet"** — you haven't trained or imported a model. Run
`agat self build … && agat repertoire generate`, or `agat repertoire import
<pack>`.

**Everything scans as non-clean / high false positives** — your self-model
doesn't represent the software you're scanning. Retrain `self` on a
representative benign set. `bench/evaluate.sh` measures your FP rate on a
labeled corpus you supply.

**`agat scan` asks for a password** — you passed `--ingest`, which writes to
the vault. Plain `agat scan` never needs one.

**A pack won't import** — the signer isn't trusted (`--trust its.pub`), the
pack is unsigned (`--allow-unsigned` to accept), it was tampered with
(integrity check), or it was trained with a different agat version (retrain
it). The error says which.

**Non-x86/ARM binary, weak recognition** — agat disassembles x86/x64 and
AArch64; other architectures get static analysis only, so structural
recognition is weaker. See the coverage limits in the README.
