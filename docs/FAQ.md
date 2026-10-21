# FAQ

### Is this antivirus? Does it replace my AV / EDR / YARA?

No. agat is a **variant-catching complement** that runs *after* your
signature layer. Signatures catch exact known threats; agat catches the
polymorphic, metamorphic, and AI-rewritten *variants* those miss, by
behavioral affinity rather than exact match. Run both. See the comparison
table in [DEPLOYMENT.md](DEPLOYMENT.md#where-agat-fits).

### Does agat use an AI model / LLM / neural network?

No. There is no neural network, no GPU, and nothing to download. The
"trained model" is a set of geometric immune structures — a self-model, a
detector repertoire, and family memory cells — fitted to *your* samples by
classical algorithms (negative selection, clonal selection). Training a few
hundred binaries takes seconds on a laptop. The AI-signal layer *detects*
LLM-rewritten code; it can optionally consult a local GGUF model via
`llama.cpp` for one perplexity signal, but defaults to a built-in
approximation, so nothing is required.

### Does it phone home / send samples anywhere?

Never. agat makes no outbound network connection, ever. You can prove it:
run under `docker run --network none` (the demo does exactly this and diffs
the output against a laptop run to show it's byte-identical).

### Why do I have to train it? Can't it just work out of the box?

The whole idea is that agat learns what *your* normal looks like, so it can
flag what's foreign. There's no universal "benign" — a model trained on the
wrong baseline flags ordinary software. Training is quick, and you can train
once and distribute a signed model to a whole fleet.

### What if my self-model is bad? How do I know?

Measure it. `bench/evaluate.sh --corpus DIR --labels labels.tsv` reports the
detection and false-positive rates on a labeled corpus you supply. A high FP
rate means your `self` isn't representative of what you're scanning — retrain
it on a better benign set.

### What does "clean" actually mean?

"Indistinguishable from the benign self you trained," not "proven safe." A
clean verdict means nothing fired on either axis relative to your baseline.
agat is honest about this: it catches variants signatures miss, and publishes
its coverage limits next to its capabilities.

### What files can it analyze?

x86/x64 and AArch64 (ARM64) binaries in PE, ELF, and Mach-O (including the
x86-64 slice of universal binaries). Other architectures get static analysis
only, so structural recognition is weaker. It is not a document/script
scanner.

### It flagged a benign file. Why?

Three possibilities: (1) your self-model doesn't represent that kind of
software — retrain; (2) the file genuinely shares structure with a family you
trained (check `agat diff`); (3) it's on your denylist. The report shows both
axes and any policy override, so you can see *why*. File a
[detection issue](https://github.com/Armur-Ai/agat/issues/new/choose) with
the ScanResult JSON (never the binary).

### Can I trust a model pack someone sent me?

Only if you trust its signer. Import verifies the SHA-256, the Ed25519
signature against keys *you* explicitly trust, and that the pack matches your
agat version's metric space. Unsigned packs are refused by default; tampered
packs are refused; a pack from an incompatible version is refused rather than
mis-scored.

### Is it fast enough for a pipeline?

Yes. Scanning is parallel across all cores; ~900 typical binaries scan in
about 2 seconds on an 18-core laptop. For high volume, run `agat serve` (the
model loads once) and POST files to it.

### Does the JSON output have a stable schema?

Yes — `agat.scan/v1`, with a published JSON Schema
([`schema/agat.scan.v1.json`](schema/agat.scan.v1.json), or `agat schema`).
Gate consumers on `schema_version`; a breaking change bumps the suffix.

### Is the "immune system" real biology?

It's bio-inspired *computing* — the algorithms' logic over real data, not a
simulation. [CONCEPTS.md](CONCEPTS.md) includes an honesty ledger on exactly
where the analogy is strong and where it's weaker.

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md). Good first issues include more
AI-artifact rules, multi-byte key recovery, instruction folding, and Mach-O
coverage. The ground rules: stay offline, back claims with a benchmark, and
never commit real malware.
