# Integration recipes

Concrete ways to wire agat into the tools you already run. All of these
assume a trained model is available on the runner/host (train once, import a
pack — see [DEPLOYMENT.md](DEPLOYMENT.md)).

- [CI: GitHub Actions](#ci-github-actions)
- [CI: GitLab](#ci-gitlab)
- [The JSON contract](#the-json-contract)
- [SIEM: Splunk](#siem-splunk)
- [SIEM: Elastic](#siem-elastic)
- [SOAR / playbooks (HTTP)](#soar--playbooks-http)
- [Quarantine / mail-gateway drop folder](#quarantine--mail-gateway-drop-folder)
- [Exit-code gating](#exit-code-gating)

---

## CI: GitHub Actions

Scan build artifacts, upload SARIF to code scanning, and fail the job on a
malicious verdict.

```yaml
# assumes the agat binary and a trained AGAT_HOME are on the runner
- name: agat variant scan
  run: agat scan dist/ --sarif --fail-on malicious > agat.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()               # upload findings even when the scan failed the job
  with:
    sarif_file: agat.sarif
```

The SARIF findings appear in the repository's **Security → Code scanning**
tab, one per non-clean artifact, with the severity mapped to SARIF levels
(`malicious` → error, `suspicious`/`review` → warning).

---

## CI: GitLab

```yaml
agat-scan:
  stage: test
  script:
    - agat scan dist/ --sarif --fail-on malicious > gl-agat.sarif
  artifacts:
    when: always
    reports:
      sast: gl-agat.sarif     # SARIF is accepted by GitLab's SAST report type
```

---

## The JSON contract

For anything bespoke, emit JSON and parse it. The shape is stable
(`schema_version: "agat.scan/v1"`) and has a published schema
([`schema/agat.scan.v1.json`](schema/agat.scan.v1.json), or `agat schema`).

```bash
agat scan ./artifacts --json | jq -c '.[]
  | select(.verdict.severity == "malicious")
  | {file: .sample.name, family: .recognition.family,
     affinity: .recognition.affinity, sha256: .sample.id}'
```

Key fields:

| field | meaning |
|---|---|
| `verdict.severity` | `clean` / `review` / `suspicious` / `malicious` |
| `verdict.policy` | `"allowlist"` / `"denylist"` if an operator policy set the verdict |
| `recognition.family` | attributed family, if any |
| `recognition.affinity` | binding strength, `[0,1]` |
| `danger.context` | `safe` / `ambiguous` / `dangerous` |
| `danger.signals[]` | the individual harm signals that fired |
| `sample.id` | the file's SHA-256 |
| `model` | which pack (or `local`) produced the verdict |

---

## SIEM: Splunk

**Via SARIF/JSON file.** Scan to a monitored directory and let the Universal
Forwarder pick it up:

```bash
agat scan /ingest/incoming --json --fail-on never \
  > /var/log/agat/$(date +%Y%m%d-%H%M%S).json
```

`inputs.conf`:

```ini
[monitor:///var/log/agat/*.json]
sourcetype = agat:scan
```

`props.conf` (one event per result, timestamp from the scan):

```ini
[agat:scan]
KV_MODE = json
TIME_PREFIX = "scanned_at":"
MAX_TIMESTAMP_LOOKAHEAD = 32
```

Then search, e.g. malicious verdicts by family:

```spl
sourcetype=agat:scan verdict.severity=malicious
| stats count by recognition.family
```

---

## SIEM: Elastic

Ship the JSON with Filebeat using the `ndjson` parser (scan with
`--json` and `jq -c '.[]'` to one object per line), or POST results
straight into an index:

```bash
agat scan /ingest --json --fail-on never \
  | jq -c '.[] | {"@timestamp": .scanned_at, event: {kind: "alert"},
                  agat: .}' \
  | while read -r doc; do
      curl -s -H 'Content-Type: application/json' \
        -XPOST 'http://es:9200/agat-scans/_doc' --data-binary "$doc" >/dev/null
    done
```

A suggested field mapping: `agat.verdict.severity` (keyword),
`agat.recognition.family` (keyword), `agat.recognition.affinity` (float),
`agat.sample.id` (keyword), `agat.danger.context` (keyword).

---

## SOAR / playbooks (HTTP)

Run the local API and submit files from a playbook. Every verdict is a `200`
with the severity in the `X-Agat-Severity` header, so a playbook can branch
without parsing JSON.

```bash
agat serve        # 127.0.0.1:8080; use --allow-remote behind an auth proxy
```

```bash
# submit a file, branch on the header
sev=$(curl -s -D - -o body.json \
        --data-binary @"$FILE" 'localhost:8080/v1/scan?name='"$(basename "$FILE")" \
      | awk -F': ' 'tolower($1)=="x-agat-severity"{print $2}' | tr -d '\r')
case "$sev" in
  malicious)  escalate body.json ;;
  suspicious|review) enqueue_triage body.json ;;
  clean)      : ;;
esac
```

Endpoints: `POST /v1/scan` (raw bytes; `?format=sarif` for SARIF),
`GET /v1/model` (provenance), `GET /v1/schema` (the contract),
`GET /healthz`.

---

## Quarantine / mail-gateway drop folder

Watch a drop folder and act on verdicts. With exit-code gating, a one-liner
per file suffices:

```bash
for f in /quarantine/incoming/*; do
  if agat scan "$f" --fail-on malicious >/dev/null 2>&1; then
    mv "$f" /quarantine/released/
  else
    mv "$f" /quarantine/held/
    agat scan "$f" --json >> /quarantine/held/verdicts.ndjson
  fi
done
```

For volume, keep `agat serve` running and POST to it instead of launching the
binary per file.

---

## Exit-code gating

The exit code is the integration primitive for anything that just needs a
pass/fail:

| code | meaning |
|---|---|
| `0` | clean (or below `--fail-on`) |
| `2` | review / suspicious |
| `3` | malicious |
| `1` | agat error (not a verdict) — treat as a pipeline failure, not a detection |

`--fail-on review|suspicious|malicious|never` sets where the non-zero line
is drawn; `[scan] fail_on` in `config.toml` sets a default. Distinguish `1`
(tooling failure) from `2`/`3` (findings) so a broken runner doesn't look
like a clean scan.
