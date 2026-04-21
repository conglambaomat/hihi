# CABTA Closing-Phase Hardening Plan

**Date:** 2026-04-21
**Status:** Active hardening baseline (updated after reasoning-competition tranche and chat-orchestrator shrink tranche)
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
- expand tests for contradictory evidence, weak-support cases, and mixed explicit/inferred relation cases

Exit criteria:

- root-cause status changes are easier to explain from evidence inputs
- explicit evidence outranks narrative similarity or keyword alignment
- insufficient-evidence outcomes are more predictable and trustworthy

## Workstream 3 - Memory truth and lifecycle cleanup

Goal:
Make thread/session/case memory semantics unambiguous everywhere.

Tasks:

- standardize the meaning of `working`, `candidate`, `accepted`, and `published`
- audit thread, case, route, and UI payload labels for semantic drift
- ensure accepted/published retrieval paths match displayed language
- update docs to describe lifecycle truth using the same vocabulary the code uses

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
- keep MCP, Splunk, and daemon readiness messaging honest and capability-scoped

Exit criteria:

- specialist selection is explainable from evidence and workflow context
- workflow/session surfaces reflect actual execution truth
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
- remaining: trim any still-duplicated provider-display / runtime-error glue around deterministic fallback paths in `AgentLoop`, but keep the current seam set and avoid inventing new coordinator-adjacent services unless a real duplication hotspot appears

### Milestone D - Optional-runtime hardening pass

- workflow/governance/daemon readiness truth
- MCP and live-hunt capability messaging validation

## Immediate Next Slice

From the codebase state after this tranche, the highest-value next step is still inside Milestone C rather than returning to broad reasoning work:

- priority next: continue shrinking `src/agent/agent_loop.py` around the last provider-display/runtime-error fallback helpers and any remaining deterministic summary wiring that still duplicates `SessionResponseBuilder` contracts
- do not reopen broad reasoning calibration unless a concrete failing semantic case appears in tests or audit review
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
