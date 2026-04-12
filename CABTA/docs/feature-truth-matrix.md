# CABTA Feature Truth Matrix

Last updated: 2026-04-01

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
| Cases | Yes | Yes | N/A | Stable | Live cases no longer get polluted by seeded demo cases once user data exists |
| Reports | Yes | Yes | N/A | Stable | Report pages render from normalized job/result contracts |
| Agent chat | Yes | Partial | Partial | Optional | Agent loop exists and web surface loads; not required for main web demo path |
| Playbooks | Yes | Partial | Partial | Stable | Prior fixes remain in place; branching/input contract issues already addressed |
| MCP management | Yes | Partial | No | Optional | Client is present; no server is currently connected on this host |
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

## Remaining Honest Limitations

- URLScan key storage exists, but CABTA does not yet call URLScan in the live IOC enrichment pipeline.
- On this Windows host, dynamic sandbox detonation is not currently available:
  - Docker is not available on PATH
  - VM staging is not configured
  - no cloud sandbox adapters are registered
- MCP exists as optional infrastructure, but there are no connected servers in the current runtime.
- Live verification in this pass focused on the highest-value configured integrations rather than every possible external source.

## Acceptance Snapshot

- Automated baseline: `704 passed`
- Runtime baseline:
  - `/` loads
  - `/settings` loads
  - `/api/config/info` returns live mode
  - `/api/config/health` returns initialized subsystem checks
  - `/api/dashboard/sources` reflects honest source states
  - `/api/agent/sandbox/status` reflects honest sandbox states

## Recommended Next Pass

1. Wire URLScan into the IOC enrichment pipeline or downgrade it further in UI copy until it is implemented.
2. Decide whether CABTA should support Docker detonation, VM staging, or cloud adapter submission as the primary dynamic sandbox path on Windows localhost.
3. Add the same “truthful status” treatment to more optional integrations beyond the currently verified core set.

## Unresolved Questions

- None.
