# CABTA Investigator-Grade Architecture Refactor Plan

**Date:** 2026-04-19
**Status:** Planning
**Type:** Refactor

## Goal

Refactor CABTA's agentic investigation architecture so it becomes more reliable, more explainable, easier to evolve, and closer to investigator-grade behavior without rewriting the whole system.

This plan must make the system cleaner while preserving the following core invariants:

- deterministic CABTA analyzers and scoring remain the source of truth for verdict-bearing outputs
- local-first behavior remains intact
- optional integrations continue to degrade gracefully
- current API and UI flows remain stable unless explicitly versioned
- the refactor proceeds incrementally, with behavior-preserving seams where possible

The target outcome is:

- `AgentLoop` becomes an orchestrator instead of a god object
- reasoning operates on a stronger fact plane
- entity and relation semantics become safer and more evidence-aware
- hypothesis and root-cause assessment become more evidence-aware and less heuristic
- thread/case/session memory semantics become explicit and less drift-prone
- specialist routing becomes evidence-driven
- provider/prompt behavior becomes more consistent across LLM backends
- runtime orchestration becomes easier to harden later for queue-backed and resumable execution

## Current Pain

- duplication:
  - prompt construction, provider handling, sync logic, and response shaping are spread across `agent_loop.py`
  - observation and reasoning normalization responsibilities overlap across multiple layers
- unclear ownership:
  - `AgentLoop` currently owns orchestration, sync, provider transport, prompt composition, specialist routing, and response generation
  - memory truth is split across session metadata, thread snapshots, and case events without a strict lifecycle
- naming drift:
  - "accepted snapshot" semantics do not match actual behavior in thread memory
  - "accepted facts" currently behave closer to high-quality working observations than analyst-published truth
- cross-layer leakage:
  - prompt/provider details leak into core orchestration
  - reasoning depends on mixed-quality tool payloads instead of a canonical fact plane
  - entity linking and root-cause ranking still depend heavily on heuristic text cues and shallow scoring
  - specialist routing still partially depends on step progress instead of evidence gaps or workflow state

## Non-Goals

- no rewrite-from-scratch of CABTA agent architecture
- no scoring change unless explicitly planned and tested
- no API contract change unless explicitly planned and versioned
- no user-facing rename without review
- no mandatory cloud or external service dependency
- no replacement of deterministic verdict paths with LLM reasoning
- no forced migration to a queue/worker runtime in the first refactor phases

## Architectural Outcomes

### Outcome A — Thin Orchestrator

`AgentLoop` should become a narrow coordinator for:

- session lifecycle
- phase transitions
- high-level think/act/observe orchestration
- cancellation / approval / notifications
- delegation to dedicated services

It should stop directly owning:

- prompt composition
- provider-specific transport details
- thread sync policy
- case sync policy
- specialist routing heuristics
- final response assembly
- memory restoration semantics
- reasoning refresh internals

### Outcome B — Fact Plane as Source of Reasoning Truth

All higher-level reasoning should increasingly depend on stable typed facts rather than arbitrary tool payloads.

Target fact families:

- `auth_event`
- `process_event`
- `network_event`
- `email_delivery`
- `ioc_enrichment`
- `sandbox_behavior`
- `vulnerability_exposure`
- `host_timeline_event`
- `correlation_observation` (temporary compatibility family only, to be reduced over time)

Each fact family should support:

- canonical fields
- stable provenance
- quality scoring
- canonical source paths
- explicit extraction method
- observation and evidence references

### Outcome C — Safer Entity/Relation Model

Entity resolution must better distinguish:

- explicit relations
- inferred relations
- co-observed relations

Relations should increasingly carry:

- canonical source and target
- relation confidence
- relation basis
- relation type / strength
- multiple evidence refs
- source paths
- domain-aware auth/session/host/user/process semantics

### Outcome D — Evidence-Aware Reasoning Core

`HypothesisManager` and `RootCauseEngine` should evolve from a heuristic scaffold into an evidence-aware reasoning core that considers:

- evidence quality
- provenance strength
- tool reliability
- contradiction strength
- entity coverage
- chain completeness
- missing evidence by lane and hypothesis
- explicit unsupported / inconclusive / insufficient evidence states

### Outcome E — Clean Memory Semantics

CABTA should explicitly separate:

1. working memory
2. session execution snapshot
3. thread conversation memory
4. case accepted memory

The system should stop treating "latest working state" as "accepted truth" by naming alone.

### Outcome F — Consistent Prompt / Provider Layer

Prompt composition and provider transport should use a consistent layered model:

- system instructions
- developer/policy instructions
- structured investigation context
- user intent / analyst goal

Provider-specific adapters may translate this structure, but the upstream representation should remain consistent.

## Acceptance Criteria

### Architecture

- `src/agent/agent_loop.py` is materially smaller and delegates major responsibilities to dedicated services
- thread/case sync logic is extracted from `AgentLoop`
- provider/prompt transport logic is extracted from `AgentLoop`
- final response assembly is extracted from `AgentLoop`

### Fact / Entity / Reasoning

- observations used for reasoning are typed and normalized consistently across major tool families
- relation semantics explicitly distinguish `explicit`, `inferred`, and `co_observed`
- root-cause output can explicitly land in supported / inconclusive / insufficient evidence states using richer evidence-aware signals
- specialist routing uses evidence gaps and active hypothesis state instead of step-progress fallback in normal flows

### Memory

- thread snapshot lifecycle no longer labels latest working state as accepted truth without explicit status
- case memory has a clearer accepted/published concept
- follow-up restoration chooses the correct memory layer for the question being answered

### Reliability

- focused tests cover:
  - fact normalization
  - entity relation semantics
  - hypothesis contradiction/support handling
  - root-cause ranking
  - memory lifecycle behavior
  - specialist routing behavior
  - provider prompt contract behavior

## Impacted Files

### Core orchestration

- `src/agent/agent_loop.py`
- `src/agent/agent_state.py`
- `src/agent/agent_store.py`

### Planning / routing / responses

- `src/agent/investigation_planner.py`
- `src/agent/chat_intent_router.py`
- `src/agent/session_response_builder.py`
- `src/agent/specialist_supervisor.py`

### Fact / entity / reasoning

- `src/agent/observation_normalizer.py`
- `src/agent/log_observation_normalizer.py`
- `src/agent/entity_resolver.py`
- `src/agent/evidence_graph.py`
- `src/agent/hypothesis_manager.py`
- `src/agent/root_cause_engine.py`
- `src/agent/log_query_planner.py`

### Memory / thread / case truth

- `src/agent/thread_store.py`
- `src/agent/case_memory_service.py`

### Provider / prompt / tool policy

- `src/agent/tool_registry.py`
- new prompt/provider helper modules under `src/agent/`

### Documentation

- `docs/system-design.md`
- `docs/codebase-summary.md`
- `docs/feature-truth-matrix.md`
- `docs/future-system-roadmap.md`
- `TEST-MANIFEST.md`

### Tests

- `tests/` and/or `src/agent/tests/` for newly added focused coverage
- targeted tests for memory, planning, normalization, routing, and provider behavior

## Refactor Strategy

Proceed in seams, not by rewrite.

Each phase must:

- preserve current public behavior where possible
- add focused tests before or during extraction
- keep deterministic verdict authority intact
- avoid large multi-subsystem rewrites in one commit

## Phase 0 — Baseline, Safety Rails, and Contract Capture

- [ ] inventory all `AgentLoop` responsibilities into explicit ownership buckets
- [ ] record current behavior contracts for:
  - reasoning refresh
  - thread snapshot sync
  - case checkpoint sync
  - specialist routing
  - provider prompt behavior
- [ ] add focused regression tests for current behavior that must remain stable
- [ ] document existing memory semantics and known ambiguities
- [ ] define canonical investigation memory model vocabulary:
  - working
  - candidate
  - accepted
  - published
- [ ] define target fact family schema envelopes
- [ ] define target relation taxonomy:
  - explicit
  - inferred
  - co_observed

### Phase 0 exit criteria

- key current contracts are captured in tests or written invariants
- no extraction begins without a behavioral baseline
- the team can name the target seams before moving code

## Phase 1 — Shrink AgentLoop Without Semantic Change

Create dedicated helper services but preserve behavior as much as possible.

### New services to introduce

- [x] `thread_sync_service.py`
- [x] `case_sync_service.py`
- [x] `provider_chat_gateway.py`
- [x] `prompt_composer.py`
- [x] `specialist_router.py`
- [x] `session_restore_service.py` (implemented via `session_context_service.py` seam expansion)
- [x] `next_action_planner.py`
- [x] `session_response_builder.py` (expanded to cover deterministic response assembly, summary selection, direct-chat response heuristics, and provider-unavailable fallback policy)

### Work

- [x] extract thread snapshot build/sync/command-consume logic from `AgentLoop`
- [x] extract case checkpoint sync logic from `AgentLoop`
- [x] extract provider-specific message transport from `AgentLoop`
- [x] extract prompt assembly blocks from `AgentLoop`
- [x] extract specialist routing logic from `AgentLoop`
- [x] extract snapshot restore/follow-up restore logic from `AgentLoop`
- [ ] keep `AgentLoop` as orchestrator only:
  - think
  - act
  - notify
  - transition
  - delegate

### Phase 1 constraints

- [ ] no intentional behavior change in verdict logic
- [ ] no memory semantics change yet
- [ ] no planner/routing intelligence increase yet unless needed for extraction safety

### Phase 1 exit criteria

- `AgentLoop` no longer contains most provider transport, sync, and prompt composition details
- new services are individually testable
- current chat/investigation/session flows still pass focused tests

Progress note:
- provider failover behavior is now routed through a shared gateway seam instead of duplicated chat/text logic
- provider chat request envelopes now expose stable intent/native-tooling metadata for orchestration-safe inspection
- prompt composition now returns explicit prompt-mode metadata and provider-context blocks for contract testing
- specialist routing now exposes explainable assessment metadata:
  - selected profile
  - routing reason
  - score breakdown
  - evidence signals
- thread snapshot sync now exposes additive snapshot contract metadata:
  - snapshot metrics
  - memory layer mapping
  - thread context
- case checkpoint sync now exposes additive checkpoint metadata:
  - checkpoint metrics
  - checkpoint summary
  - shared checkpoint payload shape across case-memory and case-event fallback
- session restore/follow-up context now exposes additive restore metadata:
  - restored counts
  - restored reasoning status
  - normalized restore summary payload for session metadata persistence
- reasoning-guided next-action selection now routes through a dedicated planner seam:
  - wrapper compatibility preserved in `AgentLoop`
  - search/bootstrap pivot logic extracted for narrower orchestration ownership
- deterministic response assembly and summary selection now route through `SessionResponseBuilder`:
  - fallback answer construction extracted from `AgentLoop`
  - evidence-backed response shaping extracted from `AgentLoop`
  - summary selection/fallback path extracted from `AgentLoop`
- direct-chat response heuristics now route through `SessionResponseBuilder`:
  - lightweight direct-response preference extracted from `AgentLoop`
  - follow-up-from-context answer heuristic extracted from `AgentLoop`
  - direct opening-answer construction extracted from `AgentLoop`
  - initial chat bootstrap tool decision extracted from `AgentLoop`
  - wrapper compatibility preserved in `AgentLoop`
- provider-unavailable and deterministic fallback policy now route through `SessionResponseBuilder`:
  - no-LLM fallback decision construction extracted from `AgentLoop`
  - direct-chat unavailable fallback answer extracted from `AgentLoop`
  - chat-model unavailable answer construction extracted from `AgentLoop`
  - provider troubleshooting copy extracted from `AgentLoop`
  - wrapper compatibility preserved in `AgentLoop`

## Phase 2 — Build the Fact Plane

### Goal

Turn normalized observations into a stronger canonical fact plane for reasoning.

### Work

- [x] define an additive typed observation schema envelope baseline shared across current normalized tool families
- [x] split generic normalization from typed domain normalization by extracting shared generic observation-type inference into `src/agent/observation_type_inference.py` and reusing it from `ObservationNormalizer` and `LogObservationNormalizer`
- [x] make IOC, email, malware, sandbox, and correlation outputs converge on stable fact-family tags at the observation envelope layer
- [x] add canonical provenance fields:
  - observation_id
  - source_kind
  - source_path(s)
  - extraction_method
  - raw/evidence refs
  - produced_at
- [x] standardize quality scoring semantics across families
- [x] keep `correlation_observation` as compatibility fallback only through typed fallback inference in `ObservationNormalizer` and `LogObservationNormalizer`
- [x] introduce an additive typed fact summary layer instead of relying only on arbitrary payload summaries
- [x] ensure accepted-facts derivation can carry typed fact semantics and provenance refs, not just thresholded summaries

### Fact-plane acceptance criteria

- [x] reasoning code now begins consuming additive typed/provenance fields in `HypothesisManager` evidence refs, assessment scoring, and observation tagging while preserving compatibility with legacy observation payloads
- [x] at least IOC, log, email, file, and sandbox families now emit consistent additive fact-envelope fields (`fact_family`, `typed_fact`, `provenance`, `entity_ids`) through `ObservationNormalizer`
- [x] provenance is materially more stable for downstream relation and root-cause logic through additive provenance refs and coverage summaries
- [x] additive quality semantics (`quality_semantics`, `quality_band`, family-level quality-band summaries) are now emitted centrally from `ObservationNormalizer` while preserving legacy numeric `quality`
- [x] `correlation_observation` is now constrained toward compatibility-fallback use by preferring typed inference for generic correlation and log aggregate payloads in `ObservationNormalizer` and `LogObservationNormalizer`
- [x] generic observation-type inference is now split from typed domain normalization through shared `observation_type_inference.py`, reducing duplicated fallback classification logic across `ObservationNormalizer` and `LogObservationNormalizer`

## Phase 3 — Strengthen Entity and Relation Semantics

### Goal

Move from soft linking toward safer investigator-grade relation semantics.

### Work

- [ ] formalize canonical entity model:
  - user
  - host
  - session
  - process
  - file
  - asset
  - ip
  - domain
  - url
  - hash
  - alert lineage
- [x] begin splitting relation derivation by domain-aware entity roles and canonical attributes for:
  - auth/session
  - process/host
  - network/process
  - email/delivery
  - vulnerability/asset
- [x] enrich relation payload:
  - strength
  - basis
  - evidence refs
  - source paths
  - canonical source/target value
  - confidence
- [x] reduce unsafe co-observed linking
- [x] require stronger evidence for sensitive relations such as:
  - user ↔ session
  - host ↔ process
  - process ↔ network destination
  - sender ↔ recipient
- [x] add multi-evidence merge semantics for the same relation
- [x] improve auth/session/host/user/process linking

### Entity/relation acceptance criteria

- [x] explicit vs inferred vs co-observed are now first-class reporting semantics via additive `relation_semantics`, `strength_breakdown`, `supporting_observation_count`, and `evidence_count` fields in `EntityResolver`
- [x] relations can be explained by basis and evidence refs, including additive source paths / extraction methods / relation-strength metadata in `EntityResolver`
- [x] soft-linking risk is lower in identity and process timelines through guarded sensitive-link degradation/skip logic and reduced co-observed fallback for risky entity pairs

## Phase 4 — Upgrade Planner, Hypothesis, and Root Cause

### Goal

Turn planning and reasoning into evidence-aware investigator support instead of mostly keyword/heuristic scaffolding.

### Planner work

- [x] evolve `InvestigationPlanner` from keyword lane bootstrapper into a first-step capability-aware planner using additive capability metadata and observable-derived lane/workflow hints
- [x] detect observables from goal and early facts through additive goal+metadata observable extraction in `InvestigationPlanner`
- [x] classify incident type with richer evidence and metadata through additive capability/typed-fact/entity-hint aware incident classification in `InvestigationPlanner`
- [x] choose workflow/profile by capability truth, not lane map only through workflow-registry truth scoring and default-agent-profile selection in `InvestigationPlanner`
- [x] seed hypotheses using lane + typed facts + entity hints through additive typed-fact/entity-hint aware hypothesis seeding in `InvestigationPlanner`
- [x] determine stopping criteria and escalation criteria based on evidence gaps through additive evidence-gap/typed-fact/entity-hint aware stopping and escalation logic in `InvestigationPlanner`
- [x] choose first pivots using observed entity/fact gaps and observable types, not goal keyword alone

### Hypothesis work

- [x] weight support and contradiction by:
  - evidence quality
  - provenance strength
  - tool reliability
  - contradiction severity
  - entity coverage
  - chain completeness
- [x] improve topic relevance from text-tag overlap to typed-hypothesis relevance through typed-topic expansion, family/type alignment, and reduced tag-only fallback in `HypothesisManager`
- [x] improve missing evidence derivation by lane and active hypothesis through additive lane-aware / hypothesis-aware evidence-gap derivation in `HypothesisManager`
- [x] support stronger unsupported / contradicted / inconclusive semantics through additive hypothesis/status transitions and reasoning-state status clarity in `HypothesisManager`

### Root cause work

- [x] replace simple top1/top2 margin dependence with evidence-aware ranking in `RootCauseEngine`
- [x] begin enriching root-cause quality and causal-chain assembly with typed fact and provenance-aware signals
- [x] explicitly represent:
  - supported
  - inconclusive
  - insufficient_evidence
  - unsupported_hypothesis
- [x] rank causal chains by chain completeness and evidence quality through additive chain-quality scoring in `RootCauseEngine`
- [x] separate "best explanation so far" from "confident root cause" in `RootCauseEngine` summary/status semantics
- [x] avoid simply formatting the top hypothesis as prose by deriving root-cause statements from supporting evidence and causal-chain relations when the chain is strong enough in `RootCauseEngine`

### Phase 4 acceptance criteria

- [x] planner output now begins incorporating observables, capability truth, and evidence gaps while preserving the existing lightweight plan contract
- [x] planner observable detection now merges goal-derived and metadata-derived observables while preserving the existing lightweight plan shape
- [x] planner incident classification now consumes capability hints plus typed-fact/entity-hint metadata for richer additive incident typing
- [x] planner workflow/profile selection now prefers workflow-registry truth (`capabilities`, `trigger_examples`, `default_agent_profile`) before lane-map fallback
- [x] planner hypothesis seeding now incorporates typed facts, entity hints, and observable-derived context instead of lane-only scaffolding
- [x] planner stopping/escalation criteria now incorporate evidence gaps, typed facts, entity hints, and observable-derived risk context instead of lane-only defaults
- [x] hypothesis scoring is now less keyword-driven through additive weighted support/contradiction semantics using evidence quality, tool reliability, entity coverage, and causal relevance in `HypothesisManager`
- [x] root-cause assessment now begins consuming typed/provenance-aware evidence quality and causal-chain provenance summaries while preserving existing supported / inconclusive / insufficient evidence contracts
- [x] root-cause ranking and status selection now use additive evidence-aware rank scoring, chain quality, and explicit `unsupported_hypothesis` handling in `RootCauseEngine`
- [x] root-cause output now derives the primary explanation from supporting evidence and causal-chain relation summaries when chain quality is sufficient, reducing top-hypothesis prose fallback in `RootCauseEngine`
- [x] contradiction handling is materially stronger through additive `unsupported_hypothesis` / `inconclusive` distinction and contradiction-aware next-action guidance in `HypothesisManager`
- [x] hypothesis topic relevance now prefers typed topic/family alignment over raw text-tag overlap through additive typed-topic expansion and reduced tag-only fallback in `HypothesisManager`

## Phase 5 — Clean Memory Semantics

### Goal

Separate working, candidate, accepted, and published truth across session/thread/case memory.

### Work

- [x] redesign thread snapshot storage model to include additive lifecycle state metadata in `ThreadSyncService`
- [x] expose lifecycle-aware latest thread snapshot semantics in `ThreadStore` while preserving backward-compatible legacy snapshot aliases
- [x] stop aliasing `last_snapshot_json` as `last_accepted_snapshot`
- [x] add explicit additive snapshot statuses:
  - working
  - candidate
  - accepted
  - published
- [x] clarify when follow-up chat may use:
  - working session context
  - thread memory
  - accepted case memory
- [x] define publication rules from session to thread memory through additive publication-state fields in `AgentState` plus terminal lifecycle normalization in `AgentLoop` before `ThreadSyncService` persistence
- [x] define publication rules from session/thread to case accepted memory
- [x] prevent root-cause and accepted-fact solidification too early
- [x] make case memory retrieval prefer published or accepted truth over latest mutable state through lifecycle-aware selection in `CaseMemoryService`
- [x] make authoritative case-session selection prefer published truth over accepted truth, and accepted truth over legacy heuristic summaries, in `CaseMemoryService`

### Phase 5 acceptance criteria

- [x] thread snapshots now carry additive lifecycle semantics (`snapshot_lifecycle`, `snapshot_contract`, `lifecycle_memory_layers`) while preserving legacy `snapshot_state` compatibility
- [x] thread-store retrieval now exposes lifecycle authority metadata (`authority_scope`, `snapshot_lifecycle`) and a neutral `last_thread_snapshot` alias while preserving legacy `last_accepted_snapshot` compatibility
- [x] follow-up restoration behavior is more deterministic and explainable through lifecycle-aware memory-scope selection in `SessionContextService`
- [x] thread and case truth drift is reduced through additive lifecycle-aware thread snapshot metadata, lifecycle-aware follow-up restoration, and case-memory retrieval preference for published/accepted payloads
- [x] legacy follow-up restore payloads now prefer `published` memory over `accepted` memory when both are present, aligning legacy `memory` envelopes with lifecycle-authoritative restore semantics in `SessionContextService`
- [x] case-memory session selection now uses lifecycle-authoritative precedence (`published` > `accepted` > legacy root-cause / accepted-facts heuristics) instead of timestamp-biased legacy summary heuristics
- [x] session-to-thread publication flow now has an explicit runtime contract through additive `snapshot_lifecycle` / `is_published` state fields in `AgentState` and terminal `accepted`/`published` normalization in `AgentLoop` before thread snapshot persistence

## Phase 6 — Evidence-Driven Specialist Routing

### Goal

Route specialist handoffs from evidence gaps, not step progress.

### Work

- [x] replace step-progress fallback in normal routing paths by keeping the current specialist owner when no stronger evidence-driven handoff signal exists in `SpecialistRouter`
- [x] route based on:
  - evidence type
  - missing evidence type
  - active hypothesis lane
  - entity gap
  - workflow phase completion
- [x] use typed fact-plane signals:
  - auth/session gaps
  - host/process evidence
  - network/C2 evidence
  - email delivery evidence
  - vulnerability exposure evidence
- [x] allow specialist reasoning to declare "stay with current specialist" if no stronger handoff exists through explicit `stay_with_current_specialist` routing decisions in `SpecialistRouter`

### Phase 6 acceptance criteria

- [x] specialist transitions are more explainable from evidence state through additive evidence-signal scoring plus explicit no-stronger-signal ownership retention and `stay_with_current_specialist` decisions in `SpecialistRouter`
- [x] progress-only routing is no longer the default control path in normal specialist-routing flows
- [x] route changes are testable and deterministic through focused specialist-routing contracts covering supported-root-cause, evidence-gap, ownership-retention, workflow-fallback, hypothesis-aware routing, typed fact-family routing, and explicit stay decisions

## Phase 7 — Normalize Prompt and Provider Architecture

### Goal

Make prompt layering and provider behavior consistent across backends.

### Work

- [x] define a provider-agnostic prompt/message envelope:
  - system
  - policy/developer instructions
  - structured investigation context
  - user intent
- [x] centralize provider message adaptation in `ProviderChatGateway` through additive normalized `prompt_envelope` passthrough and structured prompt metadata consumption
- [x] remove scattered prompt flattening behavior from orchestration code by plumbing normalized `prompt_envelope` and prompt metadata through `AgentLoop` orchestration into provider failover and provider-chat seams
- [x] align tool-use prompting across providers through additive provider-family tool prompting profiles in `ProviderChatGateway`
- [x] make follow-up explanation and direct-answer paths use the same layered prompt contract through additive summary/direct-answer prompt payload normalization in `PromptComposer`
- [x] add provider/prompt contract tests for layered summary/direct-answer prompt composition
- [x] add provider contract tests for:
  - tool decision mode
  - text generation mode
  - direct-answer chat mode
  - unavailable-provider fallback

### Phase 7 acceptance criteria

- [x] upstream prompt composition now exposes an additive provider-agnostic `prompt_envelope` regardless of provider while preserving legacy `system_prompt` / `messages` outputs
- [x] provider adapters now begin translating shared prompt structure instead of redefining it by consuming additive `prompt_envelope`, `prompt_mode`, and `structured_intent` metadata in `ProviderChatGateway`
- [x] tool-use consistency improves across supported providers through shared request metadata plumbing across `PromptComposer` -> `AgentLoop` -> `ProviderGateway` -> `ProviderChatGateway`

## Phase 8 — Runtime Hardening and Analyst Feedback Loop

### Goal

Prepare CABTA for real-world scale and iterative improvement without blocking earlier refactors.

### Work

- [x] introduce a queue-backed runtime design document
- [x] define resumable job model
- [x] define lease / cancel / retry semantics
- [x] define bounded concurrency policy
- [x] introduce analyst feedback data model for:
  - root cause correct / incorrect
  - entity link correct / incorrect
  - pivot useful / not useful
  - false positive chain
- [x] connect feedback storage to reasoning and governance surfaces
- [x] keep thread-per-session runtime as compatibility path until worker runtime is proven

### Phase 8 acceptance criteria

- [x] runtime migration path is explicit
- [x] analyst feedback loop exists as a first-class model
- [x] future queue/worker migration can proceed without redoing earlier reasoning refactors

## Verification Strategy

### Required focused tests

- [x] planner classification and capability-aware planning tests
- [x] typed fact normalization tests by tool family
- [x] entity canonicalization and relation semantics tests
- [x] hypothesis support / contradiction / missing-evidence tests
- [x] root-cause status and chain completeness tests
- [x] thread snapshot lifecycle tests
- [x] case accepted-memory tests
- [x] specialist routing tests
- [x] provider prompt adaptation tests
- [x] prompt/provider orchestration metadata plumbing tests
- [x] session response builder provider-mode and unavailable-fallback contract tests
- [x] follow-up restoration tests

Verification note:
- typed fact normalization coverage now includes focused contracts for:
  - log auth-event row normalization
  - correlation compatibility fallback for unknown payloads
  - typed network-event inference from correlation payloads
  - typed file-execution inference from log aggregate payloads
  - typed email-delivery envelope normalization
  - typed sandbox-behavior envelope normalization
  - IOC accepted-fact provenance enrichment
- entity / hypothesis / root-cause verification coverage already present includes focused contracts for:
  - entity canonicalization, co-observed safeguards, typed auth/process/email relation derivation
  - hypothesis support, contradiction, typed-topic relevance, explicit-relationship-aware missing evidence, and evidence-gap propagation
  - root-cause supported vs insufficient-evidence outcomes, explicit-relation causal chains, and gap-pressure handling
- thread snapshot lifecycle coverage now includes focused contracts for:
  - working vs accepted snapshot-state persistence
  - candidate lifecycle contract exposure
  - published lifecycle promotion for terminal published snapshots
  - lifecycle memory-layer mapping and snapshot contract metadata
  - new/legacy snapshot helper compatibility
- thread-store snapshot coverage now includes focused contracts for:
  - neutral `last_thread_snapshot` exposure alongside backward-compatible `last_accepted_snapshot`
  - lifecycle-aware latest snapshot authority metadata for published and accepted snapshot retrieval
- AgentLoop provider-health seam coverage now includes focused contracts for:
  - runtime-status fallback to legacy provider runtime metadata
  - cooldown-aware provider unavailability checks
  - runtime synchronization of primary/failover provider configuration into `ProviderHealthService`
  - evidence that current specialist ownership is retained when no stronger evidence-driven handoff signal exists
- follow-up memory restore coverage now includes focused contracts for:
  - published-over-accepted precedence for legacy `memory` envelopes
  - published memory-scope persistence in case-memory follow-up restore summaries
- case-memory authority coverage now includes focused contracts for:
  - published-session precedence over accepted-session candidates during authoritative case-memory selection
  - lifecycle-aware case-memory selection preserving published summary and thread ownership

### Verification commands

- command: `cd CABTA && pytest -q tests`
- command: `cd CABTA && pytest -q tests/test_agent* tests/test_web*`
- command: `cd CABTA && pytest -q tests -k "agent or reasoning or workflow or memory or thread or case"`
- command: `cd CABTA && python -m pytest -q`
- command: `cd CABTA && python -m pytest -q tests/test_session_context_service.py tests/test_thread_sync_service.py tests/test_case_sync_service.py tests/test_agentic_reasoning.py tests/test_specialist_router.py`
- command: `cd CABTA && python -m pytest -q tests/test_prompt_composer.py tests/test_provider_gateway.py tests/test_provider_health_service.py tests/test_provider_chat_gateway.py tests/test_specialist_router.py tests/test_session_context_service.py tests/test_agentic_reasoning.py`
- command: `cd CABTA && python -m pytest -q tests/test_governance_store.py tests/test_provider_health_service.py tests/test_provider_gateway.py tests/test_provider_chat_gateway.py tests/test_prompt_composer.py tests/test_agentic_reasoning.py`
- command: `cd CABTA && python -m pytest -q tests/test_agent.py tests/test_provider_health_service.py tests/test_provider_gateway.py tests/test_agent_loop_prompt_plumbing.py tests/test_session_response_builder.py`
- command: `cd CABTA && python -m pytest -q tests/test_session_context_service.py tests/test_thread_sync_service.py tests/test_case_sync_service.py tests/test_case_memory_service.py tests/test_agent.py`
- command: `cd CABTA && python -m pytest -q tests/test_case_memory_service.py tests/test_session_context_service.py tests/test_case_sync_service.py tests/test_thread_sync_service.py tests/test_agent.py`
- command: `cd CABTA && python -m pytest -q tests/test_thread_store.py tests/test_thread_sync_service.py tests/test_session_context_service.py tests/test_case_memory_service.py tests/test_case_sync_service.py tests/test_agent.py`

## Risks

- extracting too much from `AgentLoop` in one phase can break session behavior
- changing fact semantics too quickly can destabilize reasoning and follow-up flows
- memory lifecycle changes can cause subtle regressions in thread restoration
- stronger relation semantics may initially reduce apparent confidence until evidence handling improves
- provider normalization may expose hidden assumptions in individual backend adapters

## Rollout Guidance

### Start here first

The first executable implementation slice should be:

1. Phase 0 baseline tests
2. Phase 1 extraction of:
   - thread sync
   - case sync
   - prompt composition
   - provider chat gateway
3. focused regression verification
4. Phase 2 typed fact-plane improvements for log + IOC + email first

This order gives the best risk reduction without a rewrite.

### Explicitly do not do first

- do not rewrite `AgentLoop` and reasoning in one pass
- do not redesign worker runtime before fact/memory semantics are cleaner
- do not replace current hypothesis/root-cause logic before typed facts and relation quality improve
- do not hard-switch specialist routing until evidence-gap signals are available

## Immediate Next Implementation Slice

### Slice A — AgentLoop seam extraction
- [ ] add `thread_sync_service.py`
- [ ] add `case_sync_service.py`
- [ ] add `prompt_composer.py`
- [ ] add `provider_chat_gateway.py`
- [ ] move existing logic behind these service seams with minimal behavior change
- [ ] add regression tests for follow-up restore, snapshot sync, and provider chat calls

### Slice B — Fact-plane v1
- [x] define shared typed observation envelope
- [x] upgrade IOC/log/email normalization first
- [x] preserve compatibility payloads while introducing typed fields
- [x] update reasoning to prefer typed facts where available

### Slice C — Memory lifecycle v1
- [ ] rename internal thread snapshot semantics honestly
- [ ] add snapshot state field
- [ ] separate working snapshot from accepted snapshot retrieval logic

## Unresolved Questions

- whether accepted/published case memory should live purely in case events or also in dedicated structured storage
- whether provider normalization should target one common internal message schema or two schemas (tool mode vs text mode)
- whether specialist routing should remain stateless per turn or use explicit workflow-phase state
- whether alert lineage should be introduced in Phase 3 or deferred to Phase 8