## What and why

<!-- What does this change, and what problem does it solve? -->

## Evidence

<!-- Tests added/updated. If detection behavior changed: bench/run.sh and
     bench/sweep.sh output before and after, regressions included. -->

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` are clean
- [ ] `cargo test --workspace` passes
- [ ] No network access added; still runs under `--network none`
- [ ] No real malware or non-redistributable binaries added
- [ ] `SCAN_SCHEMA_VERSION` bumped if the ScanResult JSON changed incompatibly
