# agat demo: speaker notes

`demo/run.sh --pace 3` drives the whole thing. On stage, prefer
`demo/run.sh --docker agat:dev --pace 3`: the same demo under
`docker run --network none`. Total running time is about 4 minutes
with pacing.

Before the talk: `docker build -t agat:dev .` and
`demo/run.sh --compare agat:dev` once on the presenting laptop. It should
print `IDENTICAL`. That diff is the air-gap proof; keep it on a slide
in case the stage machine misbehaves.

All fixtures are **synthetic and benign** (XOR-decryptor ELF stubs from
`tools/*_gen.py`). Say so up front.

---

## Act 0: train (≈ 45 s)

> "agat doesn't ship signatures. It learns two things: what *your* benign
> software looks like, which is self, and, from a few confirmed samples,
> what a family looks like."

- `self build`: 4 baseline tools become the self-model.
- `repertoire generate`: negative selection grows detectors in the space
  *outside* self. No malware is needed for this step.
- `mature` ×7: clonal selection turns 7 confirmed variants into a family
  **memory cell**, a covering region in behavior space, not a hash list.

## Act 1: a variant it has never seen (≈ 60 s)

`unseen_variant.bin` is variant 8. It was never ingested and never trained on.

Point at:
- `cfg fingerprint 9dd5b9…`, the same as the family. Registers and padding
  changed, but the canonical control flow did not.
- `family metamorph · secondary response yes (memory cell)`, with affinity ~0.92.
- Danger agrees: a decryptor whose key agat recovered (PAMP).

> "No hash of this file existed anywhere. That's generalization, not
> memorization."

## Act 2: AI-rewritten (≈ 60 s)

`ai_rewritten.bin`: the same payload, but the decryptor was rewritten with
a *different algorithm* (16-bit word XOR, stride 2).

Point at:
- `plaintext finger 2f31df…`, **the same** as act 1. agat decrypted the
  payload itself, and it is the same payload.
- `cfg fingerprint 9eb50d…`, **different**. That's why it is *not* a
  family match: `non-self, anomaly (no family)`.
- Danger: `llm_artifact` PAMPs plus the recovered decryptor give **malicious**
  anyway.

> "Same payload, different algorithm: that combination is the tell of an
> LLM rewrite. Classical metamorphic engines don't swap algorithms.
> Two independent axes, both saying 'act'."

(Optional, from `demo/.work/<mode>/`: `agat --home home scan --ingest
suspects/ai_rewritten.bin` then `agat --home home divergence` lists the 8
same-plaintext samples with the rewrite starred as the one divergent
CFG. Divergence works over the library, so the file must be ingested.)

## Act 3: the baseline file (≈ 30 s)

`baseline_tool.bin` comes back **clean**: inside self, no detector binds.

Be honest: its danger reads *ambiguous* (it has a decryptor too), so the
**recognition** axis is what clears it. That is the point of keeping two
axes. Also note it is a file from the training baseline. Measured FP rates
on *held-out* real binaries are in `bench/run.sh` (0/110 on Debian
binaries), not in this demo.

## Act 4: the SOC view (≈ 30 s)

- `--sarif`: two findings (error level). The clean file produces none. This
  drops into GitHub code scanning or a SIEM unchanged.
- `echo $?` → `3`. CI can gate on it, and `--fail-on` tunes the bar.

> "One static binary, one container, no network, JSON and SARIF out.
> That's the whole deployment story."

---

## If something breaks

- `demo/.work/transcript-local.txt` / `transcript-docker.txt` hold the
  last good run. Show them from an editor.
- Rebuild the fixtures and model: just rerun `demo/run.sh`. It starts
  from an empty work tree every time.
