# Shiftline — 3,000 Alerts, One Analyst

The home screen is **Analysis**: bulk ingestion, compact incident cards, filters and cached NVIDIA NIM insights. **Log Lab** preserves isolated single-event testing. **Analyst Report** generates evidence-linked drafts with Edit → Approve → Submit to local outbox. External delivery and security enforcement are not connected.

Use **Demo feed → Load 100 public logs** for sanitized, varied Splunk samples. **Start Auto Demo** adds 10–20 distinct events every 30 minutes for eight batches. Pause, Stop, Inject and Reset are available; reset archives only the separate demo database. My logs and Log Lab use separate databases. The lightweight in-process scheduler pauses when the server stops. NIM batch classification, read-only MITRE retrieval and priority-incident briefs run in bounded background workers; dashboard refreshes reuse cached output. Severity and asset criticality remain explainable, and AI conclusions require analyst review.

A deliberately small Python prototype: paste an original log, retrieve MITRE ATT&CK context from an existing Neo4j graph, generate a short NVIDIA Nemotron brief, then record an analyst decision. Batch ingestion supports up to 3,000 events; AI runs on the incident you select.

## Run on Windows

```powershell
.\start.ps1
```

Open http://127.0.0.1:8765. Credentials live in the ignored `.env` file. To configure another machine, copy `.env.example` to `.env` and fill it in. Python 3.11+ is recommended; this build was tested on Python 3.14.

## The working flow

1. Paste any text in **Single log**, or use a real Splunk sample. No input rewriting, trimming, or AI-generated dataset.
2. Choose asset criticality. Host override is optional; extraction recognizes simple JSON, key/value logs, and Sysmon XML.
3. **Analyze log** saves the exact submitted text in SQLite, asks Nemotron for candidate ATT&CK IDs/search terms, retrieves real graph technique descriptions and connected detection/mitigation/tactic context, and asks Nemotron for the brief.
4. Inspect supporting quotes and the original evidence. Confirm, mark false positive, or escalate with your name and a reason.
5. Export a short Markdown shift handoff. Enter a measured manual baseline to compare mean time to triage.

For **Batch**, paste a JSON array of objects, NDJSON alert objects, or concatenated complete Sysmon XML events. Grouping happens before AI. Each record's source slice and the complete original batch are retained. Batch analysis covers up to three distinct representative events, at most 120,000 characters combined, without truncating any selected event. Coverage is disclosed in the brief. All other originals remain inspectable. This is a bounded prototype, not exhaustive batch threat detection.

## Priority and grouping

Risk is `round(0.65 × severity_weight + 0.35 × asset_weight)`. Severity weights: unknown 30, low 20, medium 45, high 70, critical 90. Asset weights: low 15, standard 35, high 70, critical 100. Alert count never increases risk. Criticality is supplied by the analyst, not inferred from the technique or host name. Asset changes re-rank the queue and enter the audit trail.

Initial severity and technique hints use small transparent heuristics (PowerShell, suspicious PowerShell switches, LSASS dumping, Windows event-log clearing). Hints are hypotheses. The model reassesses severity after retrieval. An observed shell alone is low severity; an unknown event remains unknown.

Only matching host, user, first candidate behavior, and an event-time span of at most one hour group together. Unknown hosts, behavior, or timestamps remain separate. Reviewed incidents do not receive new events. New evidence invalidates the previous brief and requires fresh analysis. No duplicates are silently discarded.

## Evidence and human control

- The LLM proposes a bounded retrieval plan. Application-owned, parameterized read queries retrieve nodes from the supplied Neo4j schema (`ActiveTechnique`, `attack_id`, `domains`, `node_id`). The LLM never executes Cypher or commands. The application does not modify the ATT&CK graph.
- Results are schema-validated. A mapping requires a retrieved technique ID and an exact quote found in a selected original log. Invalid mappings are dropped. Quotes establish traceability, not proof of malicious intent. Analyst judgment remains required.
- Logs and graph content are framed as untrusted evidence in both model calls. The UI escapes model/log content. The app does not execute commands, browse indicator URLs, or automate containment.
- Analyst decisions, evidence additions, analysis, and asset changes are recorded in SQLite. Revision checks prevent stale reviews. This local audit trail is useful for a prototype but is not tamper-proof.

## Measuring triage time

Mean time to triage is the mean of `first analyst decision time − incident ingestion time`, including queue wait and processing. Later decision changes do not reset it. AI latency is reported separately. Reduction is calculated only after both a manually supplied baseline and a recorded review exist. A displayed percentage describes that local comparison; it is not a validated claim about analyst productivity. Compare equivalent workloads with a larger sample before drawing conclusions.

## Real data

Samples are from [`splunk/attack_data/datasets/attack_techniques`](https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques), downloaded at a pinned Git commit. `data/samples/manifest.json` records the source path, revision, bytes, URL, and SHA-256. The repository's license is preserved in `data/samples/LICENSE.splunk`. No synthetic logs are generated. Re-fetch with:

```powershell
.\.venv\Scripts\python.exe scripts/fetch_samples.py
```

## Checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/probe.py --graph --llm
```

The connection probe prints no credentials. Logs submitted for analysis are sent to the configured NVIDIA service; the Neo4j queries retrieve ATT&CK context. Raw originals are stored locally, not uploaded to Neo4j.

## Nine-parameter upgrade

See [CRITERIA.md](CRITERIA.md) for implemented behavior, tests and limits against all nine acceptance parameters. Analyst-approved ATT&CK mappings are now separate from model candidates. Explicit resolution measures MTTR separately from the first-review MTTT. The measurement dialog also shows AI p50/p95 latency, failure counts and ingestion time. The queue loads 50 incidents per page.

Each new submission has a SHA-256 and source metadata. A Splunk origin claim is accepted only after matching the pinned source file and its content. Analysis snapshots retain model, prompt version, graph context, selected alert IDs/hashes and timings; refreshing does not overwrite historical runs. Download an incident's evidence packet from its provenance panel. Integrity verification checks the append-only hash-linked audit, raw evidence and historical analysis snapshots. Historical events from before the upgrade are explicitly marked as backfilled. This is local tamper-evidence; a database owner can rebuild a chain, so an external anchor is still needed for independently verifiable enterprise auditing.

## Scope

This is an enterprise-oriented **local prototype**, bound to loopback, with evidence preservation, asset-aware risk, human decisions, provenance, and timing. It has no production identity/RBAC, tenant isolation, encrypted-at-rest evidence, distributed job queue, tamper-proof auditing, or validated 3,000-alert/day operational benchmark. Keep it local. Add those controls before team deployment. SQLite is intentionally the only added state layer; your MITRE graph remains read-only.

No production deployment was performed. Supplied credentials are excluded from Git and browser code. Rotate the NVIDIA key shared in chat before broader use.
