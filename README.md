# agat

**A research and analysis tool for polymorphic, metamorphic, and AI-rewritten malware.**

agat statically and dynamically dissects self-mutating binaries — the classical kind that have existed for decades, and the kind we expect to exist soon: malware that rewrites its own payload using AI coding agents. The goal is to give analysts a concrete toolkit and a concrete vocabulary for a class of threat that is *almost* here.

> This is defensive security research. agat analyzes samples; it does not generate them.

---

## Why agat?

Polymorphic and metamorphic obfuscation are well-understood. Decryptor stubs can be fingerprinted. Code can be normalized to canonical form and clustered. The literature is mature, the tools are mature, the techniques work.

That equilibrium is about to break.

LLMs capable of producing working, behavior-preserving rewrites of source code are now widely available. Coding agents that can iterate, test, and refine outputs without human supervision exist today. There is no meaningful technical barrier to a malware family using such an agent as a *runtime mutation engine* — one that rewrites payloads not by toggling registers and inserting NOPs, but by **substituting algorithms, restructuring control flow, and re-implementing functionality in a different style every time**.

This kind of malware does not exist in the wild — yet. agat is built for the day it does.

---

## What it does

**Classical analysis** — the foundation everything else builds on:

- PE (Windows) and ELF (Linux) parsing, x86/x64 disassembly, CFG construction
- Entropy analysis, string extraction, import/export inspection
- Hashing: SHA-256, imphash, telfhash, ssdeep, TLSH
- YARA rule engine integration

**Polymorphic engine analysis:**

- Decryptor stub fingerprinting against a signature library
- Entropy-curve heuristics for stub-vs-payload boundary detection
- Bounded `unicorn` emulation of decryptor stubs to recover plaintext payloads
- Key recovery for common cipher schemes

**Metamorphic engine analysis:**

- Multi-pass canonical-form normalization (junk removal, register canonicalization, instruction folding, dependence-order sort)
- Weisfeiler–Lehman hashing over normalized CFGs for variant equivalence
- Family clustering across the sample vault

**AI-signal analysis** — the novel contribution:

| # | Signal | Description |
|---|---|---|
| 1 | Stylometric AST features | Identifier verbosity, comment density, defensive-pattern density, LLM idiom counters |
| 2 | Perplexity scoring | Decompiled pseudo-C scored against a bundled local code model via `llama.cpp` |
| 3 | Artifact scan | YARA rules for refusal strings, tokenizer fragments, embedded prompts, model magic bytes |
| 4 | Cross-variant semantic divergence | Detects algorithm substitution — the signature of LLM rewriting that classical metamorphism never produces |
| 5 | Generator family fingerprint *(stretch)* | Forensic attribution of which model family generated a sample |

No single signal is a classifier. The argument is that *constellations* of these signals are what differentiate AI-rewritten malware from sophisticated metamorphism — and agat is the tool that surfaces those constellations.

**Optional dynamic analysis:**

- Dockerized sandbox runner (Wine for PE, Alpine for ELF)
- Syscall tracing, file/registry diffs, packet capture
- Opt-in only — agat never executes a sample without `--execute`

---

## Architecture

agat is a Cargo workspace of small, independently testable crates:

```
agat-core        traits, types, vault, pipeline
agat-static      goblin parse, entropy, strings, imports
agat-disasm      iced-x86 + CFG
agat-poly        polymorphic detector
agat-meta        metamorphic detector
agat-ai          AI-signal detectors
agat-sandbox     bollard-driven Docker runner
agat-store       rusqlite persistence
agat-cli         clap entry point
agat-tui         ratatui demo shell
```

A separate companion binary, **`agat-rewriter`**, produces AI-rewritten variants of benign or research-known payloads, *solely to provide samples for agat to analyze*. Its scope is intentionally limited to behavior-preserving stylistic rewrites; it refuses to operate on samples flagged as malicious. See [`crates/agat-rewriter/README.md`](crates/agat-rewriter/README.md) (forthcoming) for the full ethical scope.

---

## Usage

```bash
# Ingest samples into the encrypted vault
agat ingest ./samples/*.bin

# Run the full analyzer pipeline
agat analyze <sample-id>

# Inspect a single signal
agat show <sample-id> --signal ai

# Compare variants
agat compare <id1> <id2> <id3>

# Launch the TUI (the demo shell)
agat tui

# Opt-in dynamic analysis inside a sandboxed Docker container
agat sandbox <sample-id> --execute
```

The TUI lays out a sample browser, cluster sidebar, and per-sample analysis tabs: Overview, Disassembly, Entropy, Strings, AI-Signals, and a Variants tab for side-by-side diffing.

---

## Status

agat is in early development as the demonstration vehicle for an upcoming **VulnCon** talk on AI-driven self-rewriting malware. Roadmap:

| Phase | Status | Deliverable |
|---|---|---|
| 0 | in progress | Workspace scaffold, vault, core traits |
| 1 |  | `agat-static` |
| 2 |  | `agat-disasm` |
| 3 |  | `agat-poly` |
| 4 |  | `agat-meta` |
| 5 |  | `agat-ai` (signals 1, 3, 4) |
| 6 |  | `agat-ai` perplexity (signal 2) |
| 7 |  | `agat-rewriter` |
| 8 |  | TUI polish, demo script |
| 9 | optional | `agat-sandbox` |

The roadmap will move once Phase 0 is in.

---

## Talk

agat will be presented at **VulnCon**. Slides, recording, and demo asciinema will be linked here once the talk goes live.

---

## Ethics & responsible use

agat is built for analysts, researchers, educators, and CTF authors. It is a **defensive** tool.

- agat analyzes binaries. It does not weaponize them, exfiltrate them, or evade detection on behalf of them.
- The companion `agat-rewriter` tool is scoped to behavior-preserving stylistic rewrites of *benign or research-known* payloads, to produce demo samples for analysis. It refuses flagged-malicious inputs as a guardrail.
- Real in-the-wild samples used during research are not redistributed. The repository ships SHA-256 manifests; users fetch samples themselves from reputable sources (VirusTotal, MalwareBazaar) under their own accounts.
- If you find a way to misuse agat or its components, please open an issue or contact the maintainers privately.

---

## Contributing

Contributions are welcome once Phase 0 lands and the crate scaffolding is stable. In the meantime, issues and design discussion are open.

---

## License

To be determined.
