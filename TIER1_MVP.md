# Tier-1 decision workspace

The primary surface is a ranked incident queue and an investigation workspace, rather than a log editor or a graph visualization. Intake and exact raw evidence live in separate drawers/dialogs. The interface opens directly on the first ranked open incident when data exists.

## Implemented MVP

| Workflow | Behavior |
|---|---|
| Queue | Risk band, qualitative confidence, asset, attack hypothesis, status, age, assignee; 50-row database pages. Open incidents include reviewed but unresolved investigations. |
| Correlation | Shared host/user, host/source IP, user/source IP or host/process identity with a maximum one-hour span. Source-only scans across multiple victims use a ten-minute window. Technique fallback is restricted to missing process identity. Related scan/auth/process/network stages can join without requiring the same technique. Victim hosts and raw alert references remain available. |
| Summary | 2–4 evidence-linked model claims marked observed/suspected; missing outcome/context is explicit. Unsupported references are withheld. Legacy analyses fall back to source-linked observed event descriptions until refreshed. |
| Priority | Base severity and highest registered affected-victim criticality, plus explained observed authentication sequence, registered privilege/credential context and analyst-entered malicious source context. An exact approved business match can reduce priority, while still requiring review. Alert count does not inflate the score. |
| Timeline / drawer | Event-time chronology. Every normalized event refers to character offsets inside its retained original alert. Clicking a claim or event opens the exact source span, original alert ID and hashes. Full raw JSON is not the default screen. |
| Asset / user / IP | Editable, audited business records plus actual ingested login history, source IPs, first/last seen, targeted assets and event-type history. Missing fields and external reputation are labeled unknown; no owner, privilege, vulnerability or organizational approval is invented. |
| Benign reasoning | Explicit source/account/process scope, target hosts, event types, approved start/end and business justification. Process exceptions require an exact command. Out-of-scope activity or credential-access/log-clearing evidence in the target's follow-on hour prevents the benign suggestion. No percentage confidence or blanket safety claim is generated. |
| MITRE | Active enterprise nodes retrieved read-only from the supplied Neo4j graph; ID and exact quote required. Analyst approval stays separate from a model hypothesis. |
| Similar incidents | Bounded search over 300 recent local incidents by event-type overlap. Shows actual benign/false-positive and escalated dispositions; similarity is not a probability or confirmed equivalence. |
| Next steps / playbook | Brief recommendations and a dynamic persisted checklist for authentication, credential access, scanning, processes, network events or unclassified evidence. |
| Decisions / collaboration | True attack, attack attempt, benign trigger, false positive, unknown. One-click benign closure and Tier-2 escalation require analyst name/reason. Local assignment, notes and checklist history are audited. No external messages are sent. |
| Response approval | Contain host, block IP and disable account create requests against observed targets. A different named approver can record approval; no enforcement executes because no EDR/firewall/identity integration is connected. Names are self-declared in this prototype, not authenticated roles. |
| Feedback / handoff | Analyst outcomes appear in future comparable-case history. Approved scoped exception records affect later matching/ranking; dispositions never silently create blanket allowlists. Handoff includes all unresolved incidents, recent closures, notes, assignment, dispositions and recorded action requests. |
| Performance | Backlog, escalations, benign closures, measured MTTT/MTTR, latency p50/p95 and recorded analysis failures. No vanity graphs or fabricated improvement. |

## Evidence relationship layer

SQLite retains normalized events and entity links: source/destination IP, host, user, process identity, parent process and candidate technique. Those links are attached to exact original alert spans. The application uses them for correlation and context; the MITRE knowledge graph stays read-only. A large interactive graph is deliberately absent from the Tier-1 screen.

## Honest limits and later work

- AI still analyzes up to three distinct representative original alerts per selected incident; coverage is disclosed. A single original envelope can contain multiple internally linked events. Exact-reference validation guarantees traceability, not semantic correctness; analysts assess the interpretation.
- Historical daily counts describe ingested event days only. They are not a complete SIEM baseline and do not justify an invented rarity score. Statistical rarity detection needs a representative history and evaluation.
- Autonomous dismissal/containment, an incident chat copilot, automatic model/rule retraining, live CMDB/vulnerability/reputation feeds, and external mention/notification delivery remain later integrations. These are outside the user's explicit MVP workflow.
- Production still needs SSO/RBAC, independently anchored audit/evidence retention, tenancy, durable workers and validated operational throughput. Approved response requests are **not executed**.

The distinction between true attacks, attempts and business-justified benign triggers is informed by the [USENIX Security 2024 paper by Yang et al.](https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin). Its results are context for the design, not performance claims about this prototype.
