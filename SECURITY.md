# Security policy

agat processes untrusted, often hostile binaries. Bugs in how it parses
them are security bugs.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it
privately through GitHub's
[security advisory form](https://github.com/Armur-Ai/agat/security/advisories/new).

Include the agat version (`agat --version`), the platform, and a minimal
reproduction. If the trigger is a crafted file, attach a *minimal synthetic*
input or a script that generates one. Never attach live malware.

We aim to acknowledge reports within 3 business days and to ship a fix or a
mitigation plan within 30 days, crediting you unless you ask otherwise.

## In scope

- Crashes, hangs, or unbounded memory/CPU from a crafted input file
  (parsing, disassembly, decryption, canonicalization)
- Anything that makes agat execute, load, or write content from a scanned file
- Weaknesses in the encrypted sample vault (AES-256-GCM, Argon2id key derivation)
- Any network access by agat (it must make none)
- Verdict tampering, e.g. a crafted `config.toml` or store that silently
  changes results in a way the output doesn't disclose

## Out of scope

- Detection misses and false positives. Those are product issues; please use
  the *False positive / missed detection* issue template.
- Findings that require an attacker who already controls your agat home
  directory or binary.

## Hardening notes for operators

- `agat scan` is stateless: it reads files and writes nothing.
- Run scans in the container with `--network none`, a read-only mount
  (`-v "$PWD:/scan:ro"`), and the image's default non-root user.
