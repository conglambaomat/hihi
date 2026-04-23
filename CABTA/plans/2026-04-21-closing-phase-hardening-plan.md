# CABTA Closing-Phase Hardening Plan

**Date:** 2026-04-21
**Status:** Active hardening baseline (updated after reasoning-competition tranche, chat-orchestrator shrink tranche, tool-observation bookkeeping shrink tranche, evidence-first reasoning calibration tranche, lifecycle-contract propagation tranche, workflow/daemon/case-reasoning truth tranche, snapshot-derived memory-contract unification tranche, runtime-truth / authoritative-memory precedence hardening tranche, case-reasoning memory-boundary truth fallback tranche, queued thread-command payload truth tranche, authoritative case-memory boundary precedence tranche, workflow run/runtime payload truth tranche, daemon runtime truth fallback hardening tranche, thread-snapshot boundary contract propagation tranche, case-memory snapshot contract propagation tranche, matched-session root-cause contract reuse tranche, workflow case-truth readiness hardening tranche, and agent-session restored-chat metadata surfacing tranche)
**Type:** Hardening / upgrade closeout

## Purpose

This plan replaces the remaining "future build-out" posture in the older upgrade plans with a code-audited closing phase.

It is grounded in the current CABTA repository state, especially:

- `docs/system-design.md`
- `docs/feature-truth-matrix.md`
- `docs/agentic-lead-investigator-upgrade-plan.md`
- `plans/260419-cabta-codex-upgrade-master-plan/plan.md`
- `plans/2026-04-19-investigator-grade-architecture-refactor-plan.md`
- the implemented code and tests under `src/agent/`, `src/web/`, `src/workflows/`, and `tests/`

This is not a greenfield roadmap.
It is the most accurate next-phase plan for upgrading CABTA from the state the codebase is already in.

## Executive Direction

CABTA is no longer mainly a tool-router prototype.
The current codebase already implements most of the structural seams that the earlier upgrade plans proposed:

- explicit investigation planning
- typed observation normalization
- structured reasoning state
- entity and relationship resolution with explicit vs inferred vs co-observed semantics
- root-cause assessment separated from deterministic verdicts
- thread, case, and governance persistence seams
- extracted prompt, provider, response, thread-sync, case-sync, routing, and next-action services
- workflow contract and specialist-task visibility

Because of that, the next phase should not be framed as "build the architecture."
The correct closing-phase strategy is:

1. harden the implemented architecture
2. tighten truth semantics where wording or lifecycle is still loose
3. close the highest-value gaps between implemented reasoning and production-trustworthy reasoning
4. revise or retire stale plan items that still describe already-landed work as future work

## Audited Current State

### Already implemented and should now be treated as baseline

The following are present in code and covered by focused tests.
They should no longer be described as primary future deliverables.

#### Agent runtime and extracted seams

Implemented:

- `src/agent/agent_loop.py` already operates as a real investigation runtime with session lifecycle, provider failover, approval gates, tool execution, workflow/playbook invocation, specialist coordination, reasoning refresh, and persistence hooks.
- `src/agent/investigation_planner.py` already exists and builds lightweight investigation plans.
- `src/agent/thread_sync_service.py`, `src/agent/case_sync_service.py`, `src/agent/provider_chat_gateway.py`, `src/agent/prompt_composer.py`, `src/agent/session_response_builder.py`, `src/agent/chat_intent_router.py`, `src/agent/specialist_router.py`, and `src/agent/next_action_planner.py` already exist as real seams.
- `src/agent/session_context_service.py` already handles follow-up restoration behavior and memory-boundary logic.

Evidence in tests includes:

- `tests/test_agent_loop_prompt_plumbing.py`
- `tests/test_thread_sync_service.py`
- `tests/test_case_sync_service.py`
- `tests/test_provider_chat_gateway.py`
- `tests/test_prompt_composer.py`
- `tests/test_session_response_builder.py`
- `tests/test_session_context_service.py`
- `tests/test_specialist_router.py`
- `tests/test_investigation_planner.py`

#### Structured reasoning and output split

Implemented:

- `src/agent/agent_state.py` already carries `reasoning_state`, `entity_state`, `evidence_state`, `deterministic_decision`, and `agentic_explanation`.
- `src/agent/hypothesis_manager.py` already owns structured reasoning bootstrap, revision, status derivation, missing-evidence derivation, and agentic explanation construction.
- `src/agent/root_cause_engine.py` already produces explicit `supported`, `inconclusive`, and `insufficient_evidence` style outcomes.
- `src/agent/agent_loop.py` already refreshes and persists split deterministic and agentic outputs.

Evidence in tests includes:

- `tests/test_agentic_reasoning.py`
- `tests/test_agent.py`

#### Fact plane, entity plane, and reasoning substrate

Implemented:

- `src/agent/observation_normalizer.py` already emits typed observations and fact-family schema summaries.
- `src/agent/entity_resolver.py` already distinguishes `explicit`, `inferred`, and `co_observed` relationship strength and applies guarded relation semantics.
- `src/agent/evidence_graph.py` already builds a lightweight evidence-support graph from observations, hypotheses, and root-cause support.
- `src/agent/root_cause_engine.py` already uses relationship quality, evidence quality, contradictions, and gap pressure.

Evidence in tests includes:

- typed observation coverage in `tests/test_agentic_reasoning.py`
- entity semantics coverage in `tests/test_agentic_reasoning.py`
- evidence graph coverage in `tests/test_agentic_reasoning.py`

#### Memory, case truth, governance, and workflow visibility

Implemented:

- `src/agent/thread_store.py` already supports snapshot lifecycle semantics and accepted/published retrieval behavior.
- `src/agent/case_memory_service.py` already materializes reasoning checkpoints into case-facing memory with lifecycle-aware publication behavior.
- `src/agent/governance_store.py` already supports durable approvals and AI decision logging.
- `src/case_intelligence/service.py` already reconstructs case graph/timeline/reasoning views from stored artifacts.
- `src/workflows/service.py` and `src/workflows/registry.py` already expose runtime contracts, validation, and run listing.
- specialist-task persistence already exists through the agent store and supervisor seams.

Evidence in tests includes:

- `tests/test_thread_store.py`
- `tests/test_case_memory_service.py`
- `tests/test_governance_store.py`
- `tests/test_workflow_service_contracts.py`
- `tests/test_workflow_registry_contracts.py`
- `tests/test_analyst_workflow_e2e.py`

### Partial or still not production-hardened

These are the real closing-phase targets.
They are more about hardening and semantic cleanup than first-time architecture delivery.

#### 1. `AgentLoop` is improved, but still overloaded

Current reality:

- major seams have been extracted
- `AgentLoop` still retains too much mixed responsibility for orchestration, runtime policy, reasoning refresh triggers, step bookkeeping, direct response paths, and approval/error branching

Closing-phase need:

- finish narrowing `AgentLoop` into a smaller coordinator
- reduce residual policy duplication across loop, prompt, response, routing, and context layers
- make orchestration boundaries easier to test in isolation

#### 2. Reasoning quality is stronger, but still partly heuristic

Current reality:

- `HypothesisManager` and `RootCauseEngine` are real and useful
- scoring and confidence still depend on heuristic weighting and text/topic cues in addition to structured evidence
- the system is closer to investigator-grade behavior, but not yet at a fully evidence-ranked reasoning standard

Closing-phase need:

- tighten evidence weighting rules
- reduce reliance on keyword/topic inference where typed evidence is available
- improve contradiction handling and hypothesis ranking calibration
- make root-cause support thresholds more explicit and testable by lane

#### 3. Memory semantics are better, but naming and lifecycle truth still need cleanup

Current reality:

- thread snapshot lifecycle exists
- accepted/published semantics are partially enforced
- older plan language and some code-path expectations still risk conflating working state, candidate state, accepted state, and published case truth

Closing-phase need:

- standardize vocabulary across docs, services, payloads, and UI
- route remaining memory lifecycle surfaces through `ThreadSyncService.resolve_memory_contract(...)`
- remove any remaining misleading "accepted" wording where the data is only working memory
- document exact publication/acceptance rules as operational truth

#### 4. Specialist routing is evidence-aware, but still not fully evidence-gap-driven end to end

Current reality:

- routing uses entity relations, observation families, missing evidence, and hypotheses
- some workflow progress and fallback heuristics still remain

Closing-phase need:

- finish moving routing preference toward evidence gaps, active hypotheses, and workflow contract needs
- verify handoff persistence and UI truth stay aligned with the selected routing rationale

#### 5. Workflow and daemon surfaces are real, but still optional infrastructure rather than hardened operational runtime

Current reality:

- workflows, queue-backed daemon scaffolding, and governance-backed execution are implemented
- `docs/feature-truth-matrix.md` correctly marks daemon and MCP/log hunting infrastructure as partial/optional

Closing-phase need:

- keep these optional
- harden readiness messaging, recovery semantics, and contract validation
- make workflow/daemon runtime truth explicit in returned contracts and enforcement payloads
- avoid presenting optional infrastructure as core-path complete unless runtime-verified in a real environment

#### 6. Documentation and plan truth are behind the code

Current reality:

- older upgrade plans still describe many already-landed seams as future phases
- the architecture docs are directionally correct, but the planning posture is stale

Closing-phase need:

- treat implemented seams as baseline architecture
- convert the remaining plan posture from build-out to hardening, truth alignment, and production-trust closure

## What Should Be Revised Or Dropped From Older Plans

### Revise from "new component to add" to "component to harden"

The following items from the older plans should no longer be framed as net-new architecture work:

- `investigation_planner`
- `observation_normalizer`
- `root_cause_engine`
- `thread_store`
- `chat_intent_router`
- `session_response_builder`
- `thread_sync_service`
- `case_sync_service`
- `provider_chat_gateway`
- `prompt_composer`
- `specialist_router`
- `next_action_planner`

These already exist and are integrated.
The remaining work is refinement, contract tightening, and behavior hardening.

### Drop any framing that CABTA lacks a meaningful test surface

This is outdated.
The repository already has broad focused coverage across the upgraded agentic architecture.
The closing phase should build on that test surface rather than planning as if it still needs to be created from scratch.

### Revise any plan language that centers architecture invention over truth alignment

The current problem is no longer mainly "what architecture should we build?"
It is now:

- are semantics accurate
- are lifecycle labels honest
- are reasoning thresholds sufficiently evidence-backed
- are optional capabilities surfaced truthfully
- are remaining overload points small enough to trust and evolve

### Drop broad rewrite posture

The audited codebase does not justify a rewrite-first next phase.
The architecture is already additive and seam-oriented in the way `docs/system-design.md` requires.
The closing phase should preserve that strategy.

### Recently hardened in code

- `src/web/routes/agent.py` now flattens restored chat-memory truth fields consistently, including `chat_context_restored` and `chat_context_restored_fact_family_schemas`, so investigation/session payloads expose the same follow-up restore contract already persisted by `SessionContextService`.
- `tests/test_web_api.py` now locks that API surface with a regression asserting restored-chat truth metadata survives round-trip through `/api/agent/sessions/{session_id}`.
- Targeted validation passed with `./.venv/bin/python -m pytest tests/test_web_api.py -k "restored_chat_memory_contract_metadata or agent_session_payload"`.

## Closing-Phase Workstreams

## Workstream 1 - Orchestration hardening

Goal:
Make `AgentLoop` a narrower coordinator without destabilizing the existing runtime.

Tasks:

- inventory residual responsibilities still living in `src/agent/agent_loop.py`
- extract duplicated decision/policy fragments into existing seam services instead of creating more new major services
- make response assembly, approval branching, reasoning refresh triggers, and follow-up restoration boundaries more explicit
- add regression coverage around high-risk orchestration branches

Exit criteria:

- `AgentLoop` owns flow coordination, not mixed policy detail
- critical branches are test-covered at the seam level
- no regression in deterministic verdict authority or approval behavior

## Workstream 2 - Reasoning quality hardening

Goal:
Improve investigator trust by raising the evidence standard for structured reasoning outcomes.

Tasks:

- calibrate `HypothesisManager` support/contradiction/confidence updates against typed evidence quality
- calibrate `RootCauseEngine` status thresholds per investigation lane where needed
- reduce text-heuristic dependence when typed observation and relationship evidence is available
- treat high-confidence evidence refs as typed/provenance-bearing even when the active observation payload is missing from the current in-memory slice
- expand tests for contradictory evidence, weak-support cases, mixed explicit/inferred relation cases, and ref-only evidence fallback paths

Exit criteria:

- root-cause status changes are easier to explain from evidence inputs
- explicit evidence outranks narrative similarity or keyword alignment
- insufficient-evidence outcomes are more predictable and trustworthy
- causal-chain and typed-evidence judgments remain stable when only persisted evidence refs are available

## Workstream 3 - Memory truth and lifecycle cleanup

Goal:
Make thread/session/case memory semantics unambiguous everywhere.

Tasks:

- standardize the meaning of `working`, `candidate`, `accepted`, and `published`
- audit thread, case, route, and UI payload labels for semantic drift
- ensure accepted/published retrieval paths match displayed language
- update docs to describe lifecycle truth using the same vocabulary the code uses
- keep authoritative case memory/thread boundary precedence explicit on restore and case-memory read paths

Exit criteria:

- no major path labels working memory as analyst-accepted truth by accident
- case reasoning views and thread snapshots use consistent lifecycle semantics
- docs and tests describe the same truth model

## Workstream 4 - Specialist and workflow trust alignment

Goal:
Keep multi-agent and workflow orchestration useful without overselling autonomy.

Tasks:

- tighten specialist routing rationale to evidence gaps and contract needs
- verify specialist task records, handoff history, workflow metadata, and case rollups stay aligned
- preserve workflow dependency and governance validation as non-optional guards
- treat interactive-only workflow runtime as blocked in top-level readiness/enforcement payloads, not just execution-surface detail
- keep MCP, Splunk, and daemon readiness messaging honest and capability-scoped

Exit criteria:

- specialist selection is explainable from evidence and workflow context
- workflow/session surfaces reflect actual execution truth, including interactive-only block states and dependency-status propagation
- optional integrations remain clearly optional and honestly reported

## Workstream 5 - Documentation and plan consolidation

Goal:
Make the docs reflect the real state of the codebase and the actual remaining upgrade path.

Tasks:

- treat this plan as the closing-phase baseline
- refresh upgrade references so older plans are understood as mostly implemented architecture history
- update `docs/feature-truth-matrix.md` and related summaries when hardening milestones land
- keep `docs/system-design.md` as the architecture source of truth and align planning language to it

Exit criteria:

- the active plan set no longer misstates already-landed work as future architecture
- contributors can tell what is implemented, partial, optional, and next without re-auditing the whole repo

## Prioritized Next-Phase Strategy

The most accurate next upgrade strategy from the current state is:

1. finish hardening the existing agentic architecture before adding more ambitious autonomy or more tool surface
2. prioritize reasoning-trust improvements over new feature count
3. prioritize lifecycle-truth cleanup over UI expansion
4. keep deterministic verdict authority and evidence-first design as the non-negotiable center
5. only expand optional runtime planes such as daemonized automation or live MCP hunting after truth semantics and recovery behavior are hardened

In practical terms, CABTA should now upgrade by becoming:

- more explicit
- more auditable
- more semantically honest
- more test-calibrated

not by becoming radically more complex.

## Explicit Non-Goals For This Closing Phase

- no rewrite of CABTA's deterministic scoring or verdict authority
- no replacement of the current seam-based architecture with a new framework
- no graph database or heavyweight persistence migration
- no UI-first redesign
- no expansion of optional integrations merely to increase feature count
- no framing of partially verified infrastructure as fully production-ready

## Suggested Milestone Order

### Milestone A - Semantic truth pass

- lifecycle vocabulary audit
- payload naming cleanup
- plan/doc truth alignment

### Milestone B - Reasoning calibration pass

Status snapshot:
- done: `HypothesisManager` competing-hypothesis ranking now carries competition metadata (`ranking_score`, `competition_score`, `competition.lead_margin`) and focused regression coverage
- done: `RootCauseEngine` keeps tightly ranked competing explanations inconclusive instead of over-promoting the local leader
- remaining: continue reducing keyword/topic overlap dependence where typed evidence and explicit relationship quality disagree
- remaining: add a few more contradiction and lane-threshold calibrations only where audits show unstable semantics

### Milestone C - Orchestrator shrink pass

Status snapshot:
- done: chat answer-sufficiency policy was extracted into `SessionResponseBuilder.chat_evidence_allows_answer_without_tools(...)`
- done: `AgentLoop` chat short-circuit / model-only answer branches now share `_chat_evidence_summary(...)` instead of duplicating policy checks
- done: approval wait outcome consumption now flows through `SessionResponseBuilder.consume_approval_outcome(...)`, keeping timeout/reject bookkeeping out of `AgentLoop`
- done: terminal session finalization now uses `SessionResponseBuilder.build_terminal_status_payload(...)` so completion status, thread-message recording, and final notify payload stay aligned
- done: approval review state mutation now flows through `SessionResponseBuilder.apply_approval_review(...)`, and approval request/rejection payload shaping now uses `build_approval_pending_payload(...)` plus `build_approval_rejection_transition(...)`
- done: chat-specific fallback lookup composition now lives in `SessionResponseBuilder.build_chat_specific_fallback(...)`, with `AgentLoop` reduced to delegation-only wiring
- done: deterministic summary reuse now flows through `SessionResponseBuilder.summary_from_final_answer(...)`, so final-answer reuse rules are no longer embedded directly in `AgentLoop`
- done: fallback evidence-point shaping and per-tool deterministic evidence summaries now flow through `SessionResponseBuilder.build_fallback_evidence_points(...)` and `SessionResponseBuilder.describe_fallback_evidence(...)`, removing another response-assembly helper cluster from `AgentLoop`
- done: fallback runtime-context shaping now flows through `SessionResponseBuilder.build_fallback_response_context(...)` and `SessionResponseBuilder.llm_unavailable_notice_from_context(...)`, shrinking `AgentLoop`'s residual summary/unavailable glue while keeping orchestration-local state ownership intact
- done: focused regression tests now cover the extracted fallback runtime-context helpers in addition to the prior chat fallback mapper, fallback evidence-point shaping, and final-answer summary reuse behavior
- done: duplicated tool-result bookkeeping inside `AgentLoop` main execution and auto-enrichment paths now flows through `_record_tool_observation(...)`, centralizing reasoning refresh, step progression, finding persistence, and live tool-result notification behind one seam with a focused regression in `tests/test_agent_loop_prompt_plumbing.py`
- audit result: no further high-value deterministic-summary/runtime-fallback pass-through helpers remain in `src/agent/agent_loop.py`; the residual builder calls are now thin orchestration wiring rather than duplicated response policy
- done: memory lifecycle truth cleanup started by centralizing `memory_kind`, `memory_is_authoritative`, and `publication_scope` semantics in `ThreadSyncService`, then reusing them across thread snapshots, case memory payloads, restored follow-up context metadata, and follow-up prompt assembly
- done: `src/web/routes/chat.py`, `src/agent/session_response_builder.py`, and `src/case_intelligence/service.py` now normalize working vs authoritative memory contract fields from the same lifecycle helpers, with focused regression coverage for working-context fallback wording
- done: `src/agent/session_context_service.py` now restores follow-up state from `case_memory_context.authoritative_snapshot` before the older `memory_snapshot`, so authoritative case truth wins over stale working-memory payloads on the restore path as well
- done: focused regressions in `tests/test_session_context_service.py` and `tests/test_web_api.py` now lock the authoritative-over-working precedence on both the restore path and chat follow-up wiring, validated with `./.venv/bin/python -m pytest tests/test_session_context_service.py tests/test_web_api.py -q` (`105 passed`)
- done: `src/workflows/service.py` now promotes interactive-only workflow runtime to a top-level blocked readiness state (`interactive_runtime_blocked`) instead of leaving that truth only inside `execution_surface`
- done: `src/daemon/service.py` now forwards validated dependency state into runtime-readiness evaluation so daemon enforcement payloads no longer drift to `dependency_status=unknown`
- done: `src/agent/case_memory_service.py` now resolves `thread_id` from authoritative memory payload / boundary before stale session metadata when returning case memory
- done: `src/web/routes/chat.py` now chooses authoritative case memory over non-authoritative thread snapshot on follow-up restore, while preserving thread snapshots when they remain the strongest truth source
- done: focused regressions in `tests/test_case_memory_service.py`, `tests/test_workflow_service_contracts.py`, `tests/test_headless_soc_daemon.py`, and `tests/test_web_api.py` now lock dependency-status propagation, interactive-runtime blocking semantics, authoritative thread-boundary precedence, and authoritative-over-working restore behavior, validated with `./.venv/bin/python -m pytest tests/test_case_memory_service.py tests/test_workflow_service_contracts.py tests/test_headless_soc_daemon.py tests/test_web_api.py` (`108 passed`)
- done: `src/agent/thread_sync_service.py` now exposes `resolve_memory_contract_from_snapshot(...)`, letting snapshot-only surfaces derive lifecycle truth from `snapshot_contract` plus `memory_boundary` without re-hand-rolling fallback rules
- done: `src/agent/thread_sync_service.py` now also exposes `resolve_session_memory_contract(...)`, so session-facing payloads can prefer explicit session contract fields but deterministically fall back to snapshot-derived lifecycle truth instead of open-coding that branch in each surface
- done: `src/web/routes/chat.py` now resolves follow-up memory contract fields through `resolve_session_memory_contract(...)`, keeping restored prompt wording and follow-up session metadata aligned even when case memory payloads only carry `publication_scope` while the authoritative truth lives in `authoritative_snapshot`
- done: `src/case_intelligence/service.py` now resolves reasoning-summary lifecycle truth through the same `resolve_session_memory_contract(...)` path, removing another local inference branch between workflow metadata and snapshot contract truth
- done: focused regressions in `tests/test_thread_sync_service.py` and `tests/test_web_api.py` now lock the snapshot-derived fallback path and authoritative-over-working chat restore precedence, validated with `./.venv/bin/python -m pytest tests/test_thread_sync_service.py tests/test_web_api.py tests/test_agentic_reasoning.py -k "resolve_session_memory_contract or chat_follow_up_prefers_authoritative_snapshot_over_memory_snapshot_in_restore_path or build_reasoning_summary_selects_root_cause_session"` (`2 passed, 171 deselected`)
- done: `src/agent/session_context_service.py` now persists restored follow-up memory contract fields (`authoritative_memory_scope`, `publication_scope`, `memory_kind`) alongside `memory_scope`, so downstream routing/chat surfaces do not need to infer lifecycle truth from scope alone after context restore
- done: focused regressions in `tests/test_session_context_service.py`, `tests/test_session_response_builder.py`, and `tests/test_specialist_router.py` now lock the richer restored-memory contract propagation, validated with `./.venv/bin/python -m pytest tests/test_session_context_service.py tests/test_specialist_router.py tests/test_session_response_builder.py -q` (`94 passed`)
- done: terminal thread snapshots now normalize non-published terminal sessions to `candidate` instead of silently upgrading them to authoritative case truth, with `src/agent/agent_loop.py` delegating publication normalization through a small `_normalize_terminal_snapshot_publication(...)` seam over `ThreadSyncService.finalize_lifecycle_for_state(...)`
- done: `src/daemon/service.py` now evaluates workflow runtime readiness against the same built workflow goal later dispatched to `agent_loop.investigate(...)`, removing a schedule-time semantic gap where daemon readiness could report blocked while the eventual runtime input would be runnable
- done: focused regressions in `tests/test_agent.py` and `tests/test_thread_sync_service.py` now lock candidate-vs-published terminal lifecycle defaults and daemon queue success against built-goal runtime readiness, validated with `./.venv/bin/python -m pytest tests/test_agent.py -k "normalize_terminal_snapshot_publication or daemon" tests/test_thread_sync_service.py tests/test_headless_soc_daemon.py` (`16 passed`)
- done: `src/web/routes/agent.py` now flattens restored follow-up memory-contract metadata (`chat_context_restored_*`) into session payloads, so API/UI consumers no longer need to reopen nested metadata to tell whether chat context came from working memory or authoritative case truth
- done: `src/case_intelligence/service.py` now carries the normalized lifecycle contract deeper into `reasoning_truth`, including `memory_kind`, `authoritative_memory_scope`, and `memory_boundary`, so case reasoning rollups expose one self-contained truth contract instead of splitting lifecycle facts across sibling fields
- done: `src/web/routes/chat.py` now preserves `case_memory_context.memory_boundary` when snapshot-only fallback payloads omit it, keeping follow-up session metadata aligned with the restored lifecycle boundary instead of silently dropping case/thread scope
- done: focused regressions in `tests/test_web_api.py`, `tests/test_reasoning_mirror_ui.py`, and `tests/test_agentic_reasoning.py` now lock restored chat memory-contract flattening, snapshot-fallback boundary preservation, and richer case reasoning truth payloads, validated with `./.venv/bin/python -m pytest tests/test_web_api.py::TestFastAPIEndpoints::test_agent_session_payload_flattens_restored_chat_memory_contract_metadata tests/test_web_api.py::TestFastAPIEndpoints::test_chat_follow_up_normalizes_non_authoritative_case_memory_contract tests/test_reasoning_mirror_ui.py::test_case_reasoning_api_returns_rollup_for_existing_case tests/test_agentic_reasoning.py::TestAgentLoopReasoning::test_case_reasoning_summary_keeps_root_cause_and_decision_from_same_session` (`4 passed`)
- done: `src/agent/session_response_builder.py` now resolves follow-up prompt contract wording through `ThreadSyncService.resolve_memory_contract(...)`, removing another local lifecycle-normalization branch and letting boundary-only `publication_scope` payloads resolve to the same authoritative-vs-working truth used elsewhere
- done: `src/agent/session_context_service.py` now builds restored chat-context flags through the same `resolve_memory_contract(...)` helper, so metadata-first and state-fallback restore paths share one memory-contract derivation instead of hand-rolled scope/publication/authority inference
- done: focused regressions in `tests/test_session_context_service.py` and `tests/test_session_response_builder.py` now lock metadata override semantics plus boundary-only publication-scope follow-up prompts, validated with `./.venv/bin/python -m pytest tests/test_session_context_service.py tests/test_session_response_builder.py -q` (`73 passed`)
- remaining: keep pushing lifecycle truth through any remaining payload/docs/UI surfaces that still hand-roll authoritative vs working semantics, without reopening broad `AgentLoop` extraction unless a new duplication hotspot appears
- done: `src/agent/thread_sync_service.py` now persists explicit queued-thread-command truth fields (`pending_thread_command_intent`, `pending_thread_command_requires_fresh_evidence`) alongside the raw payload when an active session consumes a queued follow-up command
- done: `src/web/routes/chat.py` now returns `queued_requires_fresh_evidence` plus the exact `queued_command_payload` for active-session follow-ups, so API/UI callers can read the queued directive contract without reopening thread storage
- done: focused regressions in `tests/test_thread_sync_service.py`, `tests/test_agent.py`, and `tests/test_web_api.py` now lock queued command metadata persistence and active-chat payload truth, validated with `./.venv/bin/python -m pytest tests/test_thread_sync_service.py -k pending_thread_command tests/test_agent.py -k pending_thread_command tests/test_web_api.py -k chat_follow_up_while_active` (`4 passed`)
- done: evidence-first reasoning calibration in `src/agent/hypothesis_manager.py` now gives deterministic legacy verdict-bearing observations typed weight without treating cross-lane keyword overlap as decisive support, and log-identity relation-aware observations now preserve explicit-link context without overpromoting closure
- done: `tests/test_agentic_reasoning.py` now reflects the stricter evidence-first contract by asserting calibrated support/contradiction behavior, neutral-yet-structured log-identity checkpoints, and current lane-specific planner/root-cause outputs instead of older heuristic-baseline expectations

### Milestone D - Optional-runtime hardening pass

Status snapshot:
- done: `src/workflows/service.py` now exposes `case_truth_ready`, `runtime_status`, and `headless_execution_eligible` directly in runtime-readiness and execution-surface contracts, so workflow callers can distinguish dependency health, case-truth readiness, and headless eligibility without inferring from older booleans
- done: `src/daemon/service.py` now forwards `runtime_truth_contract` alongside running and blocked dispatch payloads, so daemon callers can read the same workflow runtime-truth contract without reopening nested enforcement payloads
- done: `src/case_intelligence/service.py` now emits a `reasoning_truth` payload that names whether the case reasoning rollup is sourced from selected workflow metadata or a root-cause checkpoint, while preserving normalized memory-scope truth in the same contract
- done: focused regressions in `tests/test_workflow_service_contracts.py`, `tests/test_headless_soc_daemon.py`, `tests/test_reasoning_mirror_ui.py`, and `tests/test_agentic_reasoning.py` now lock the new workflow/daemon/case-reasoning truth surface, validated with `./.venv/bin/python -m pytest tests/test_workflow_service_contracts.py tests/test_headless_soc_daemon.py tests/test_reasoning_mirror_ui.py tests/test_agentic_reasoning.py -q` (`86 passed`)
- remaining: keep validating optional MCP/live-hunt readiness messaging against real runtime environments, but do not widen the daemon contract again unless a concrete truth gap appears
- done: `src/case_intelligence/service.py` now reuses root-cause checkpoint payload memory boundaries when the selected workflow metadata resolves only to default working scope with no boundary, so case reasoning rollups no longer drop case/session provenance even when truth is sourced from the matched workflow session
- done: `src/agent/case_memory_service.py` now derives returned case-memory lifecycle fields through `ThreadSyncService.resolve_memory_contract(...)`, preserving authoritative `publication_scope` / `session_id` boundary truth from payloads instead of rebuilding a partial boundary from stale session metadata
- done: `src/agent/case_memory_service.py` now also embeds the normalized memory contract (`memory_scope`, `authoritative_memory_scope`, `memory_kind`, `memory_is_authoritative`, `publication_scope`, `memory_boundary`) directly inside returned `authoritative_snapshot` / `memory_snapshot`, so follow-up restore and UI/read-model consumers can trust the snapshot payload itself without reopening sibling case-memory fields
- done: `tests/test_case_memory_service.py` now locks authoritative boundary precedence on case-memory reads, including preserved `case_id`, `session_id`, and `publication_scope` from authoritative payload boundaries plus the embedded snapshot contract on both authoritative and legacy fallback reads
- done: `tests/test_agentic_reasoning.py` now locks that fallback by asserting `build_reasoning_summary(...)` preserves `case_id` and `session_id` in the returned memory contract when the selected workflow matches the root-cause checkpoint but lacks explicit metadata boundary fields
- validated with `./.venv/bin/python -m pytest tests/test_case_memory_service.py tests/test_reasoning_mirror_ui.py tests/test_agentic_reasoning.py tests/test_session_context_service.py tests/test_session_response_builder.py tests/test_workflow_service_contracts.py` (`161 passed`)
- done: `src/web/routes/agent.py` now flattens restored follow-up provenance fields (`chat_context_restored_from_session_id`, `chat_context_restored_from_thread_id`, `chat_context_restored_snapshot_id`) alongside the existing restored memory contract, so API/UI consumers can read restore source truth without reopening nested metadata
- done: `src/workflows/service.py` now exposes interactive-runtime truth directly in per-run `runtime_contract` payloads (`supports_headless_execution`, `interactive_runtime_required`, `headless_blockers`) instead of leaving that contract only in readiness/evaluation surfaces
- done: focused regressions in `tests/test_web_api.py` and `tests/test_workflow_service_contracts.py` now lock restored follow-up provenance flattening plus per-run interactive-runtime payload truth, validated with `./.venv/bin/python -m pytest tests/test_workflow_service_contracts.py tests/test_web_api.py -q` (`92 passed`)

- done: `src/daemon/service.py` now derives top-level daemon dispatch truth (`headless_execution_eligible`, `case_truth_ready`) from the strongest available runtime contract, falling back to execution-surface and dependency-state semantics when workflow readiness payloads omit those booleans instead of silently collapsing them to `False`
- done: `src/workflows/service.py` now keeps `case_truth_ready` tied to dependency/runtime-truth availability even when execution is blocked for interactive-only analyst runtime, so workflow callers do not lose case-truth readiness just because headless eligibility is false
- done: focused regressions in `tests/test_workflow_service_contracts.py`, `tests/test_web_api.py`, and `tests/test_headless_soc_daemon.py` now lock that split between `status=blocked`, `interactive_runtime_blocked=true`, and `case_truth_ready=true`, validated with `./.venv/bin/python -m pytest tests/test_workflow_service_contracts.py tests/test_web_api.py tests/test_headless_soc_daemon.py` (`100 passed`)
- done: `src/agent/thread_sync_service.py` now persists normalized lifecycle truth directly inside `memory_boundary` (`publication_scope`, `authoritative_memory_scope`, `memory_kind`, `memory_is_authoritative`) when building thread snapshots, so downstream thread/case/UI surfaces can reuse one self-contained boundary contract instead of splitting snapshot truth across sibling payloads
- done: focused regressions in `tests/test_thread_sync_service.py` now lock working, candidate, and published snapshot boundaries against that richer contract, validated with `./.venv/bin/python -m pytest tests/test_thread_sync_service.py tests/test_session_context_service.py tests/test_session_response_builder.py tests/test_headless_soc_daemon.py tests/test_reasoning_mirror_ui.py` (`95 passed`)
- done: `src/case_intelligence/service.py` now reuses the root-cause checkpoint contract even when the selected workflow session matches that checkpoint, so case reasoning rollups stop falling back to default working semantics when the event already carries stronger published/accepted truth
- done: focused regressions in `tests/test_agentic_reasoning.py` and `tests/test_reasoning_mirror_ui.py` now lock the matched-session contract reuse path by asserting selected-session rollups preserve published `memory_scope`, `memory_kind`, `authoritative_memory_scope`, and `memory_boundary` from the root-cause checkpoint itself
- validated with `./.venv/bin/python -m pytest tests/test_agentic_reasoning.py tests/test_reasoning_mirror_ui.py tests/test_web_api.py -q` (`166 passed`)

## Immediate Next Slice

- Memory lifecycle truth tranche remains the highest-value active seam after the latest pass, but the next cut is now more likely in residual case-memory/UI payloads or workflow-facing docs than in `session_context_service.py` / `session_response_builder.py`, whose lifecycle derivation now rides the shared helper path.

From the codebase state after this tranche, the highest-value next step shifts back to the remaining memory/UI/doc truth edges and any truly residual `AgentLoop` overload seam:

- priority next: continue the memory lifecycle truth pass across any leftover payload/docs/UI surfaces beyond the now-aligned chat follow-up, queued active-session command payloads, snapshot-derived session metadata, restored chat-context payload flattening and provenance, snapshot-fallback boundary preservation, candidate-vs-published terminal snapshot defaults, boundary-embedded lifecycle truth in thread snapshots, case-intelligence reasoning summaries including checkpoint-derived and matched-session checkpoint contracts, authoritative case-memory read boundaries plus embedded snapshot contracts, workflow/daemon runtime contracts, per-run workflow runtime payloads, top-level daemon runtime-truth forwarding plus daemon fallback truth derivation, session-response, and follow-up-restore paths so `working`, `candidate`, `accepted`, and `published` semantics stay explicit and centrally derived
- keep `AgentLoop` stable unless a later audit finds a new duplication hotspot beyond the now-centralized tool-observation bookkeeping and prior response-policy seams; workflow/daemon truth now yields better ROI than another speculative loop split
- reasoning priority: only reopen evidence-first calibration when a concrete semantic miss appears around lane-specific closure thresholds, cross-lane support leakage, or case-rollup truth selection; the broad baseline in `tests/test_agentic_reasoning.py` is clean again after the current tranche
- keep plan/doc truth aligned after each tranche so this file stays a live baseline instead of drifting behind code reality

## Completion Standard

The closing phase is complete when:

- the active plans no longer describe already-implemented seams as future architecture
- the codebase uses consistent truth semantics for memory, reasoning, and publication
- reasoning outputs are more clearly explainable from evidence quality and relation strength
- `AgentLoop` is small enough to evolve safely
- optional runtime features remain honest, bounded, and non-misleading
- the upgrade path after this phase can focus on carefully chosen capability expansion instead of architectural debt repayment

## Relationship To Older Plans

Use the older plans as historical rationale and detailed seam background:

- `docs/agentic-lead-investigator-upgrade-plan.md`
- `plans/260419-cabta-codex-upgrade-master-plan/plan.md`
- `plans/2026-04-19-investigator-grade-architecture-refactor-plan.md`

Use this document as the current planning baseline for the next CABTA upgrade pass.
