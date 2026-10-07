# Prototype verification

Verified locally on 7 October 2026 (Asia/Calcutta).

- Python 3.14; dependencies installed and `pip check` passed.
- 12 automated checks passed: exact raw text and hashes, source slices, conservative grouping, asset-aware ranking, stale review rejection, first-decision timing, audit persistence, model evidence validation, failure/retry, input boundaries, origin protections, real sample provenance, and 3,000-event ingestion.
- A test ingested the first 3,000 actual events from the pinned Splunk T1070 log in approximately 0.7 seconds and produced 2,618 incidents. No event was dropped. This measures local ingestion only, not AI analysis of all records or operational throughput.
- Live Neo4j read queries retrieved PowerShell and LSASS Memory descriptions and connected tactic, detection-strategy, and mitigation nodes.
- Live NVIDIA `nvidia/nemotron-3.5-lightning-30b-a3b` calls generated a brief for the actual Splunk PowerShell sample. Accepted mappings referenced retrieved T1059.001 and T1059 nodes with literal original-log evidence.
- Browser interaction verified sample loading, ingestion, analysis and a ready-for-review brief. The retained example is unreviewed; no analyst decision or productivity result was fabricated.
- The app remains a loopback-only prototype. No production service was deployed and no enterprise readiness certification is claimed.

Known scope: batch AI uses at most three distinct representative original events with disclosed coverage. Unknown identity/time/behavior remains separate. Model suggestions still require analyst assessment; exact quotations establish traceability rather than semantic certainty. Measured triage reduction requires actual reviews and a comparable manual baseline.

## Nine-parameter upgrade verification

22 checks now pass. Additional checks cover explicit resolution separate from first triage, analyst approval of candidate ATT&CK IDs, append-only audit guards and deliberate tamper detection, source verification, preserved analysis snapshots, risk contributions, cache expiry, 50-item database queue pages, literal escaped-JSON command evidence, and endpoint agent IDs/millisecond timestamps.

The existing local database was backed up before migration; original alerts and analyst decisions were preserved. The migrated audit/raw-evidence integrity check passed. Pre-upgrade audit entries are marked as backfilled, while older analysis runs and submission source hashes are not invented. A live refresh of the user's endpoint incident returned exact-source-quote candidates for T1003, T1003.003 and T1059.001 with approval controls. No analyst review or resolution was performed on the user's behalf.

The real-data benchmark with source verification and two queue-page reads took about 0.9–1.1 seconds across test runs. UI runtime error checks returned none. Production boundaries and the nine-parameter acceptance matrix are recorded in CRITERIA.md.

## Current Tier-1 MVP verification

37 automated checks pass after the queue-first upgrade. They cover linked evidence spans, multi-stage correlation, multi-victim scan grouping, maximum affected-asset criticality, scoped business exceptions and follow-on compromise indicators, context records, playbooks, dispositions, approval-only response requests, handoff and prior audit protections.

The current benchmark ingests 3,000 actual pinned Splunk T1070 events into 2,353 conservative incidents without dropping events. Ingestion plus source verification and two queue-page reads takes approximately 1.4–1.8 seconds locally (latest run: 1.48 seconds). This is not model processing time or a production throughput guarantee. Earlier measurements above refer to earlier correlation implementations.

Live NVIDIA and read-only Neo4j processing produced four accepted evidence-linked claims and one T1059.001 mapping for the actual PowerShell sample. The UI shows two observed and two suspected claims and missing outcome evidence. Clicking a claim opens its exact original event span and source hashes. Desktop right-panel and narrow-layout views were checked. Existing raw alerts and human decisions were preserved; no business approval, disposition or productivity improvement was fabricated.

Production gaps and the implemented-versus-later feature boundary are documented in TIER1_MVP.md. Containment, IP blocking and account disabling record approval requests only; they do not execute enforcement.
