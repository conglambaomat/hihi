# CABTA Feature Truth Matrix

Last updated: 2026-04-14

This file is the operational audit baseline for CABTA after the current stabilization pass.

Use it to answer:

- what is genuinely working now
- what is only configured
- what is runtime-verified on localhost
- what is still manual, optional, or not wired

## Status Vocabulary

- `tested`: covered by automated tests
- `runtime-verified`: exercised on the running localhost web app
- `live-verified`: exercised against a real external dependency
- `manual`: visible/configurable but not wired to an automatic live workflow
- `optional`: subsystem exists but is not required for the main web demo path

## Severity Vocabulary

- `P0`: crash, route unavailable, blocking UX, data loss, startup failure
- `P1`: false success, incorrect logic, backend/UI mismatch, misleading status
- `P2`: degraded UX, weak messaging, incomplete health/status visibility

## Current Matrix

| Surface | Tested | Runtime-Verified | Live-Verified | Current State | Notes |
| --- | --- | --- | --- | --- | --- |
| Dashboard | Yes | Yes | Partial | Stable | Source health now distinguishes `configured`, `available`, `manual`, `optional`, `not_configured` |
| Settings | Yes | Yes | Partial | Stable | Sandbox type options now match backend semantics; approval config now round-trips coherently |
| IOC analysis | Yes | Partial | Partial | Stable | Core flow is working; key TI providers were probed live |
| File analysis | Yes | Partial | Partial | Degraded but honest | Static analysis path works; dynamic sandbox execution is not available on this Windows host |
| Email analysis | Yes | Partial | Partial | Stable | Web route is working; no new critical correctness issue found in this pass |
| History | Yes | Yes | N/A | Stable | Uses normalized job wrapper |
| Cases | Yes | Yes | N/A | Stable | Live cases no longer get polluted by seeded demo cases once user data exists; case tools now support create/link/note/status updates from agent and workflow flows |
| Reports | Yes | Yes | N/A | Stable | Report pages render from normalized job/result contracts |
| Agent chat | Yes | Partial | Partial | Optional | Agent loop exists and web surface loads; specialist roles, ATT&CK coverage tools, case-management helpers, workflow-backed handoffs, and explicit specialist task supervision are now available to agent/tool orchestration |
| Playbooks | Yes | Partial | Partial | Stable | Prior fixes remain in place; branching/input contract issues already addressed |
| Workflows | Yes | Yes | No | Stable | Markdown workflows now load from both `WORKFLOW.md` and `SKILL.md`; new full-investigation and forensic-analysis skills are available through the orchestration plane, and workflow sessions now expose specialist teams, active specialist, handoff history, and explicit specialist task records |
| Approvals | Yes | Yes | N/A | Stable | Governance approval queue is now first-class with list/detail/review APIs and a dedicated web surface |
| AI decision log | Yes | Yes | N/A | Stable | Meaningful workflow and agent decisions can now be logged, reviewed, and annotated with feedback |
| Case intelligence | Yes | Partial | N/A | Stable | Graph and timeline are generated from stored analyses, workflow sessions, approvals, decisions, notes, and case events |
| Headless SOC daemon | Yes | Partial | N/A | Optional | Optional daemon config/status scaffolding now includes a durable queue, lease recovery, retry/backoff, and queue-backed workflow dispatch; continuous background execution is still not enabled by default |
| MCP management | Yes | Partial | No | Optional | Client is present; no server is currently connected on this host |
| Splunk log hunting | Yes | Partial | No | Optional but wired | `search_logs` can now delegate to a read-only Splunk MCP backend with policy checks, audit logs, and approval-required results for broad hunts |
| Config / health endpoints | Yes | Yes | N/A | Stable | `/api/config/health` now reports mode and initialized subsystem checks |
| Sandbox status | Yes | Yes | Partial | Honest | Status now reports Docker/VM/local_static/cloud adapters instead of empty output |

## Critical Path Outcome

There are currently no known `P0` issues on the main localhost web path:

- `Dashboard`
- `IOC`
- `File`
- `Email`
- `History`
- `Cases`
- `Reports`
- `Settings`

## P1 Issues Resolved In This Pass

- Settings sandbox choice no longer writes unsupported `subprocess` values; it now maps to backend-supported modes.
- Settings approval toggle now persists a meaningful `require_approval_for` policy instead of a dead boolean-only field.
- Dashboard/source health no longer marks keyed integrations as implicitly `healthy`; it now separates `configured` from true readiness.
- URLScan is now surfaced as `manual` instead of being implied to be live-wired.
- Agent `sandbox_submit` can now use the app sandbox orchestrator instead of always creating a disconnected one-off orchestrator.
- Sandbox status no longer returns an empty list on normal localhost runs; it now exposes the actual local/static/dynamic situation.
- Joe Sandbox / Hybrid Analysis key aliases are now handled more safely across legacy/new key names.
- Workflow session routes no longer get shadowed by the dynamic workflow detail route.
- Governance approvals and AI decision logs are now persisted and exposed through dedicated APIs and pages.
- Case graph and timeline outputs are now built from stored case, analysis, workflow, and governance artifacts instead of placeholder structures.
- `search_logs` no longer stops at query generation only; it can now execute live Splunk hunts through MCP when the backend is connected and policy allows the query.
- Specialist agent coverage now includes correlator, MITRE analyst, identity analyst, enrichment specialist, network forensics, and compliance mapping roles.
- Workflow discovery now supports `SKILL.md` assets alongside `WORKFLOW.md`, enabling multi-agent skill-style orchestration without replacing the existing workflow registry.
- Chat-driven case-management helpers now exist as first-class agent tools: create case, load case context, add note, update status, and link analysis/workflow context.
- ATT&CK coverage and Navigator layer generation are now exposed as local agent tools, making detection-engineering and mapping workflows tool-backed instead of prompt-only.
- Detection engineering now has a backlog-planning loop that turns ATT&CK coverage gaps into prioritized engineering tasks with lifecycle review guidance.
- Specialist collaboration is now persisted as explicit `specialist_tasks`, making multi-agent workflow ownership visible beyond prompt metadata alone.

## Remaining Honest Limitations

- URLScan key storage exists, but CABTA does not yet call URLScan in the live IOC enrichment pipeline.
- On this Windows host, dynamic sandbox detonation is not currently available:
  - Docker is not available on PATH
  - VM staging is not configured
  - no cloud sandbox adapters are registered
- Headless daemon mode now has durable queue and retry semantics, but it is still not yet a continuously running scheduler service with full worker supervision.
- MCP exists as optional infrastructure, but there are no connected servers in the current runtime.
- Splunk-backed live hunting is now implemented, but it still requires an actual Splunk MCP server configuration with working credentials before the agent can pivot into live logs.
- Live verification in this pass focused on the highest-value configured integrations rather than every possible external source.

## Acceptance Snapshot

- Automated baseline: `783 passed`
- Runtime baseline:
  - `/` loads
  - `/settings` loads
  - `/api/config/info` returns live mode
  - `/api/config/health` returns initialized subsystem checks
  - `/api/dashboard/sources` reflects honest source states
  - `/api/agent/sandbox/status` reflects honest sandbox states
  - `/api/workflows` loads
  - `/agent/workflows` loads
  - `/agent/approvals` loads
  - `/agent/decisions` loads
  - `/api/governance/approvals` loads

## Recommended Next Pass

1. Wire URLScan into the IOC enrichment pipeline or downgrade it further in UI copy until it is implemented.
2. Decide whether CABTA should support Docker detonation, VM staging, or cloud adapter submission as the primary dynamic sandbox path on Windows localhost.
3. Add the same “truthful status” treatment to more optional integrations beyond the currently verified core set.

## Unresolved Questions

- None.
