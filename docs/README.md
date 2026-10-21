# agat documentation

| doc | what it covers |
|---|---|
| [GUIDE.md](GUIDE.md) | **Start here.** Install, train, scan, configure, deploy — end to end. |
| [CONCEPTS.md](CONCEPTS.md) | How agat thinks: the immune model, and where the analogy is honest. |
| [READING_OUTPUT.md](READING_OUTPUT.md) | How to read a verdict, field by field. |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production operations: fleets, signed packs, air gap, performance, hardening. |
| [INTEGRATION.md](INTEGRATION.md) | Recipes for CI, SIEM (Splunk/Elastic), SOAR, and quarantine folders. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The crate map and internal boundaries. |
| [PRODUCT_ROADMAP.md](PRODUCT_ROADMAP.md) | Where agat is going. |
| [AIS_REBUILD_PLAN.md](AIS_REBUILD_PLAN.md) | The immune-core design record and honesty ledger. |

Machine-readable contracts live in [`schema/`](schema/)
(`agat.scan.v1.json`). Reproducible evidence lives in
[`../bench/`](../bench/README.md). The fixture generators are documented in
[`../tools/`](../tools/README.md).

Diagrams in [`assets/`](assets/) (used throughout the docs):
`banner`, `pipeline`, `lifecycle`, `antigen`, `fusion`, `deployment`.
