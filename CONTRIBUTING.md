# Contributing to agat

agat is a defensive-security commons. Contributions that make it detect
more, explain itself better, or run in more places are very welcome.

## Ground rules

1. **Offline, always.** agat never makes a network call. No telemetry, no
   update checks, no cloud lookups. A PR that adds one will not be merged.
2. **Claims need a benchmark.** If a change affects detection, show its
   effect with `bench/run.sh` / `bench/sweep.sh` (before and after) in the PR.
   Report regressions as plainly as improvements.
3. **No live malware in the repo.** Fixtures are synthetic and benign
   (`tools/*_gen.py`). Real samples are referenced by SHA-256 only.
4. **Defensive scope.** agat analyzes. It does not generate evasive code,
   weaponize payloads, or help anything avoid detection.

## Getting set up

```bash
git clone https://github.com/Armur-Ai/agat && cd agat
cargo build
cargo test --workspace
demo/run.sh                 # end-to-end smoke test: train + scan, offline
```

You need a stable Rust toolchain (see `rust-version` in `Cargo.toml`) and
`python3` for the fixture generators. Docker is optional (container, air-gap
compare, and `bench/fetch-benign.sh`).

## Before you open a PR

```bash
make check                          # = fmt --check + clippy -D warnings + test
bench/generalize.sh                 # the headline claim still holds
bench/run.sh --benign-dir bench/corpus/debian-bin   # if you touched detection
```

`make help` lists every task (build, release, bench, demo, gifs, docker,
airgap, clean).

CI runs the same gates, plus the `--network none` demo comparison.

## Where things live

| you want to… | look in |
|---|---|
| add or improve an analyzer | `crates/agat-{static,disasm,poly,meta,ai}` (implement `agat_core::Analyzer`) |
| change how samples become antigens | `crates/agat-antigen` |
| change detection / learning | `crates/agat-immune` |
| change the verdict or its JSON | `crates/agat-core/src/scan.rs` (bump `SCAN_SCHEMA_VERSION` on a breaking change) |
| change scanning, SARIF | `crates/agat-engine` |
| change the CLI | `crates/agat-cli` (styling in `style.rs`, the splash in `banner.rs`) |
| change the TUI | `crates/agat-tui` |
| add a diagram or doc | `docs/` (SVGs in `docs/assets/`, index in `docs/README.md`) |

The big picture is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Commit style

Small, focused commits with a message that explains *why*. Prefixes help
(`fix(disasm): …`, `docs: …`, `P4: …` for roadmap stages). One logical
change per commit; a refactor and a behavior change go in separate commits.

## Good first issues

- More LLM-artifact rules in `crates/agat-ai/src/artifacts.rs`
- Multi-byte XOR key recovery in `crates/agat-poly`
- Instruction folding in `crates/agat-meta` (`xor r,r` ≡ `mov r,0`, cancelling push/pop)
- Mach-O parsing in `crates/agat-static`

## License

By contributing you agree that your work is licensed under the
[GNU AGPL v3](LICENSE), the project's license.
