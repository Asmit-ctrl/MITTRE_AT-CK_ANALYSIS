# The nine acceptance parameters

| Parameter | Implemented behavior | Evidence / honest boundary |
|---|---|---|
| Asset criticality | Analyst selects low / standard / high / critical; asset changes immediately re-rank incidents. | Visible risk breakdown: 65% severity, 35% criticality. Alert count adds no risk. No CMDB integration. |
| MITRE ATT&CK mapping | Nemotron proposes bounded IDs/terms; parameterized read queries retrieve active enterprise techniques and connected context from the supplied graph. | A displayed mapping requires a retrieved ID and a literal original-log quote. Candidate IDs remain separate from analyst-approved mappings. |
| Short analyst brief | Two-sentence summary, concise next steps and stated uncertainty. | Display text is bounded even if the model ignores length guidance. AI claims require human assessment. |
| Evidence/citations | ATT&CK links and versions, exact quotes, original-alert IDs and SHA-256 hashes. | Raw originals stay intact. Versioned evidence export includes graph and model snapshots and input references. |
| Human-in-loop | Confirm, false positive, escalate; explicitly select approved ATT&CK IDs. Analyst name/reason and revision checks are required. | No automatic response or resolution. Names are self-declared in the local prototype, not authenticated enterprise identities. |
| Explainability | Expandable score contributions, severity source/reason, grouping rule, uncertainty and analysis coverage. | Model confidence is a qualitative assessment, not a calibrated probability. Exact quote matching proves traceability rather than semantic correctness. |
| MTTR/MTTT reduction | MTTT = ingestion to first review; MTTR = ingestion to explicit analyst resolution. Separate manual baselines and reductions. | No improvement is claimed before actual reviews/resolutions and comparable baselines exist. The resolution cohort includes all explicitly closed dispositions. |
| Enterprise audit/provenance | Append-only, hash-linked audit events; verify raw-alert/submission hashes and analysis snapshot hashes. Store model/prompt versions, source revisions, decision actors/reasons and analysis failures. | Local tamper-evidence, not WORM storage. No external chain anchor, SSO/RBAC, or independently authenticated actors. Historical pre-upgrade events are marked as backfilled. |
| Scale/latency | Up to 3,000 alerts per batch, database paging with 50 queue items, at most two concurrent analyses, 5-minute bounded graph cache, per-run/stage timings, AI p50/p95 and failure counts. | Real-data local benchmark is stored below. AI analyzes at most three distinct representative logs per selected incident; coverage is disclosed. No full-batch AI or distributed/day-scale SLA is claimed. |

## Verification

22 automated checks passed after the upgrade. Tests cover the original ingestion flow plus separate resolution timing, verified sample provenance, audit guards and deliberate tamper detection, analyst mapping approvals, preserved analysis versions, risk arithmetic, cache expiry, queue pagination, escaped JSON evidence, and endpoint timestamps/identity.

On the first 3,000 actual events in the pinned Splunk T1070 file, the local benchmark produced 2,618 conservative incidents. Ingestion alone took about 0.7 seconds; ingestion with verified source attribution and two queue-page reads took about 0.9–1.1 seconds across local test runs. All benchmark writes are isolated from the user's live database. AI latency is measured from real analysis attempts in the running app rather than inferred from this ingestion benchmark.

## Production boundary

These are implemented and testable prototype capabilities. Enterprise deployment still needs authenticated identities and roles, tenant isolation, protected evidence storage/retention, an externally anchored audit stream, a durable worker queue, and a workload-specific throughput/accuracy evaluation. The project remains intentionally simple and local rather than claiming those controls exist.
