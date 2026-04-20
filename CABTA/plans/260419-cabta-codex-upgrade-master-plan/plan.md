# CABTA Codex Upgrade Master Plan

**Date:** 2026-04-19
**Status:** Planning
**Type:** Feature

## Goal

Upgrade CABTA from a strong agentic investigation scaffold into a true agentic SOC investigator that can plan investigations, normalize evidence, reason across entities and causal chains, preserve deterministic verdict authority, and carry follow-up investigations without corrupting session state.

This plan is implementation-facing. It is intended for Codex or another code-writing agent operating directly in the CABTA repository. It should be treated as the primary working plan for the next major agentic-investigation upgrade.

## Source Of Truth

This plan is grounded in the current CABTA workspace code, not only product docs.

Primary implementation files:

- `src/agent/agent_loop.py`
- `src/agent/agent_state.py`
- `src/agent/agent_store.py`
- `src/agent/hypothesis_manager.py`
- `src/agent/entity_resolver.py`
- `src/agent/evidence_graph.py`
- `src/agent/tool_registry.py`
- `src/agent/mcp_client.py`
- `src/agent/playbook_engine.py`
- `src/agent/memory.py`
- `src/agent/specialist_supervisor.py`
- `src/agent/governance_store.py`
- `src/web/app.py`
- `src/web/routes/chat.py`
- `src/web/routes/agent.py`
- `src/web/case_store.py`
- `src/case_intelligence/service.py`
- `src/workflows/registry.py`
- `src/workflows/service.py`
- `src/models/analysis_result.py`
- `src/mcp_servers/splunk_tools.py`
- `src/utils/log_hunting_policy.py`
- `src/daemon/service.py`

Primary existing test files to extend:

- `tests/test_agent.py`
- `tests/test_agentic_reasoning.py`
- `tests/test_analyst_workflow_e2e.py`
- `tests/test_agent_chat_reasoning_ui.py`
- `tests/test_file_analysis_agentic_logic.py`
- `tests/test_playbook_log_demo.py`
- `tests/test_reasoning_mirror_ui.py`

## Scope

- in scope: investigation planning, observation normalization, stronger entity and evidence modeling, stronger hypothesis reasoning, root-cause assessment, thread memory groundwork, evidence-driven specialist routing, and log-first investigation improvements
- in scope: evolving the current session/store/case architecture without replacing CABTA's deterministic core
- in scope: additive schema and metadata changes in `AgentState`, `AgentStore`, `CaseStore`, and read-side services
- in scope: focused helper services that reduce `AgentLoop` overload without rewriting the runtime
- out of scope: replacing deterministic scoring with LLM reasoning
- out of scope: introducing a graph database or heavyweight new persistence system in the first major upgrade
- out of scope: dashboard-first redesign
- out of scope: a brand-new multi-agent swarm framework

## Current Code-Grounded Assessment

### What CABTA already has and must preserve

- `AgentLoop` is already a real asynchronous investigation runtime with THINK/ACT/OBSERVE-style looping, local and MCP tool execution, playbook dispatch, approval waits, provider failover, persistence hooks, and case sync.
- `AgentState` already carries `reasoning_state`, `entity_state`, `evidence_state`, `deterministic_decision`, and `agentic_explanation`.
- `ToolRegistry` already acts as a unified capability bus for local and MCP tools.
- `search_logs` is already productized with live/demo/manual modes, governance logging, approval boundaries, and SPL guardrails.
- `PlaybookEngine` is already a real background execution layer with conditional steps, approval pause/resume, interpolation, and tool execution.
- `GovernanceStore` already supports durable approvals and AI decision logging.
- `CaseIntelligenceService` already builds case-level graph, timeline, and reasoning summary views from stored sessions and case events.
- `HeadlessSOCDaemon` already exists as a queue-backed optional background automation scaffold.
- The deterministic vs agentic split already exists and must remain intact.

### What the current code is missing

The main bottleneck is not tool count. The main bottleneck is that tool outputs are not yet converted into sufficiently clean, typed, provenance-rich facts for investigator-grade reasoning.

Verified weaknesses in current code:

- there is no first-class `InvestigationPlan`; next action selection relies on heuristic helpers in `AgentLoop`
- `_think()` currently sends the large instruction block as a `user` message instead of a true system-role structure
- `AgentLoop._restore_follow_up_context()` deep-copies parent findings and structured state into a new session
- `HypothesisManager` still updates confidence largely via verdict/severity/score/keyword heuristics and fixed deltas
- `EntityResolver` is still mainly a thin session resolver with strong co-observation behavior
- `EvidenceGraph` is still lightweight explainability support, not yet a stronger causal reasoning substrate
- `InvestigationMemory` is still mostly IOC cache plus recurring pattern counters
- `AgentLoop` still mixes planning, provider transport, chat policy, tool orchestration, reasoning refresh, case sync, summary generation, and specialist sync
- specialist handoff is still mainly step-progress-driven
- naming drift still exists across `CABTA`, `AISA`, `AI Security Assistant`, and `.blue-team-assistant`

### Important correction to earlier analysis

The current workspace does include a meaningful `tests/` surface under `CABTA/tests/`. The next upgrade must extend and strengthen that surface instead of assuming it does not exist.

## Mission

The upgraded system must be able to:

- investigate across IOC, email, file, log, user, host, process, session, asset, and vulnerability context
- choose tools and playbooks based on active hypotheses and missing evidence, not only prompt heuristics
- normalize heterogeneous tool outputs into typed observations
- build evidence-backed timelines and causal chains
- reason explicitly about competing explanations
- produce a root-cause assessment with `supported`, `inconclusive`, or `insufficient_evidence` status
- preserve deterministic score, severity, verdict, and approval authority
- remain auditable, evidence-backed, and safe for analyst review

Target architecture:

- agentic-led for investigation control and reasoning
- evidence-governed for facts and explanation
- deterministic-core-governed for verdict, severity, policy, and approvals

## Non-Negotiable Rules

1. Do not move final numeric verdict authority into the LLM layer.
2. Do not rewrite the entire agent system.
3. Do not introduce a graph database or heavyweight new storage layer in the first upgrade.
4. Do not store opaque chain-of-thought.
5. Do not treat co-occurrence as truth.
6. Do not treat follow-up chat as a prompt-append problem.
7. Do not start with UI-first changes.
8. Do not add more tools before improving observation normalization and reasoning quality.
9. Do not weaken existing log-hunting guardrails.
10. Do not allow agentic explanation paths to silently overwrite deterministic decision ownership.

## Target End State

CABTA should evolve toward this operating model:

- the agent is the lead investigator
- tools, MCP servers, and playbooks are the capability plane
- normalized observations are the fact plane
- entities plus evidence graph are the reasoning substrate
- deterministic scoring is the verdict plane
- sessions, threads, and cases are the persistent investigative memory plane

In one investigation thread, the system should be able to:

1. understand the analyst goal
2. create an explicit investigation plan
3. seed multiple competing hypotheses
4. choose a tool or playbook step based on evidence needs
5. normalize results into typed observations
6. update entity state with confidence, provenance, and relation basis
7. revise hypotheses using richer evidence scoring
8. build or refine a causal chain
9. produce a root-cause assessment
10. distinguish deterministic decision from investigative explanation
11. say when evidence is insufficient
12. continue a follow-up investigation without cloning unbounded raw session state

## New Core Components To Add

### `src/agent/investigation_planner.py`

Purpose:

- turn a goal or analyst request into an explicit investigation plan

Responsibilities:

- classify investigation lane
- identify primary entities
- choose starting workflow or playbook
- seed intentional hypotheses
- define first pivots
- define stopping and escalation conditions

Required model:

```python
@dataclass
class InvestigationPlan:
    goal: str
    lane: str
    workflow_id: Optional[str]
    lead_profile: str
    primary_entities: List[str]
    initial_hypotheses: List[str]
    first_pivots: List[str]
    stopping_conditions: List[str]
    escalation_conditions: List[str]
    generated_at: str
```

### `src/agent/observation_normalizer.py`

Purpose:

- convert heterogeneous raw tool outputs into canonical structured observations

Responsibilities:

- normalize local tool outputs
- normalize MCP tool outputs
- normalize log hunting outputs
- classify event and observation types
- preserve provenance and source paths
- produce typed facts that downstream reasoning can trust

Minimum observation types:

- `ioc_enrichment`
- `email_delivery`
- `auth_event`
- `process_event`
- `network_event`
- `file_execution`
- `host_timeline_event`
- `vulnerability_exposure`
- `sandbox_behavior`
- `correlation_observation`

Required model:

```python
@dataclass
class Observation:
    observation_id: str
    tool_name: str
    observation_type: str
    timestamp: Optional[str]
    summary: str
    quality: float
    source_kind: str
    source_paths: List[str]
    entities: List[Dict[str, Any]]
    facts: Dict[str, Any]
    raw_ref: Dict[str, Any]
```

### `src/agent/root_cause_engine.py`

Purpose:

- convert hypothesis state plus normalized observations plus graph state into rigorous root-cause output

Responsibilities:

- rank hypotheses
- weigh contradiction
- enforce supported vs inconclusive vs insufficient-evidence outcomes
- build causal chains from strongest observations and relations
- produce structured case/session explanation output

Required model:

```python
@dataclass
class RootCauseAssessmentResult:
    status: str
    primary_root_cause: str
    confidence: float
    causal_chain: List[str]
    supporting_evidence_refs: List[Dict[str, Any]]
    alternative_hypotheses: List[str]
    missing_evidence: List[str]
    summary: str
    assessed_at: str
```

### `src/agent/thread_store.py`

Purpose:

- separate conversational thread memory from execution session state

Responsibilities:

- store thread messages
- store thread summary
- store last accepted reasoning snapshot
- store pinned entities and unresolved questions
- map thread to case and execution sessions

Required schema concepts:

- `thread_id`
- `case_id`
- `root_session_id`
- `last_session_id`
- `messages`
- `thread_summary`
- `last_accepted_snapshot`
- `pinned_entities`
- `pinned_questions`
- `status`

### `src/agent/chat_intent_router.py`

Purpose:

- classify follow-up requests before deciding whether a new execution session is needed

Minimum intents:

- `recap`
- `explain`
- `challenge_evidence`
- `new_pivot`
- `new_artifact`
- `scope_change`
- `review_or_approval`

### `src/agent/session_response_builder.py`

Purpose:

- keep final analyst-facing response shaping out of `AgentLoop`

Responsibilities:

- build evidence-backed final answers
- build chat-friendly answers from existing evidence
- keep wording separate from reasoning state generation

### `src/agent/log_query_planner.py`

Purpose:

- make log-first investigation planning explicit instead of embedding planning into `search_logs`

Responsibilities:

- choose query family
- choose pivot sequence
- choose window and result size
- decide when to pivot IP, user, host, session, process, or timeline next

### `src/agent/log_observation_normalizer.py`

Purpose:

- normalize Splunk and future SIEM outputs into auth, process, network, session, and host-timeline observations

## Data Contract Upgrades

### Upgrade `AgentState`

Add or strengthen:

- `investigation_plan`
- `session_snapshot_id`
- `thread_id`
- `active_observations`
- `accepted_facts`
- `unresolved_questions`
- `evidence_quality_summary`

### Upgrade `agent_sessions.metadata`

Persist:

- `investigation_plan`
- `normalized_observations`
- `reasoning_state`
- `entity_state`
- `evidence_state`
- `deterministic_decision`
- `agentic_explanation`
- `root_cause_assessment`
- `unresolved_questions`
- `accepted_facts_delta`

### Upgrade `EntityResolver`

Add:

```python
@dataclass
class EntityCandidate:
    type: str
    raw_value: str
    canonical_value: str
    label: str
    source_kind: str
    source_path: str
    extraction_method: str
    confidence: float
    attributes: Dict[str, Any] = field(default_factory=dict)
```

Expand `EntityRecord` with:

- `canonical_value`
- `confidence`
- `aliases`
- `attributes`
- `source_paths`
- `extraction_methods`
- `observation_count`
- `first_seen_at`
- `last_seen_at`

Relationship fields must include:

- `relation`
- `confidence`
- `basis`
- `source_paths`
- `evidence_refs`
- `explicit` or `relation_strength`

Required relation distinction:

- strong explicit: `authenticated_from`, `belongs_to`, `occurred_on`, `executed_on`, `connects_to`
- weak inferred: `associated_with`, `derived_from`
- weak co-observed: `co_observed`

Normalization requirements:

- validate IPs with `ipaddress`
- mark private, loopback, and reserved IPs in attributes
- normalize domains
- normalize session identifiers
- separate process basename from full path

### Upgrade `EvidenceRef`

Add:

- `observation_id`
- `source_kind`
- `source_path`
- `quality`
- `entity_ids`
- `extraction_method`
- `confidence`

### Upgrade `Hypothesis`

Add:

- `topics`
- `facets`
- `evidence_score`
- `contradiction_score`
- `last_updated_at`
- `priority`

Recommended structure:

```python
@dataclass
class Hypothesis:
    id: str
    statement: str
    status: str
    confidence: float
    topics: List[str]
    supporting_evidence_refs: List[Dict[str, Any]]
    contradicting_evidence_refs: List[Dict[str, Any]]
    open_questions: List[str]
    evidence_score: float = 0.0
    contradiction_score: float = 0.0
    last_updated_at: str = field(default_factory=_now_iso)
    priority: float = 0.0
```

## Reasoning Upgrade Requirements

### Upgrade `HypothesisManager`

Current issue:

- confidence shifts are still dominated by verdict labels, severity, score, keyword spotting, and fixed deltas

Required redesign:

- add an `ObservationAssessment` layer
- score by quality, reliability, topic relevance, explicitness, contradiction strength, entity coverage, causal relevance, and corroboration
- replace fixed delta math with diminishing-return support/contradiction updates
- add top-hypothesis margin logic so close competitions remain `inconclusive`
- make `insufficient_evidence` explicit when quality and entity coverage stay weak
- consume normalized observations plus entity/evidence state as real inputs, not optional context

Recommended model:

```python
@dataclass
class ObservationAssessment:
    stance: str
    evidence_strength: float
    evidence_quality: float
    tool_reliability: float
    entity_coverage: float
    causal_relevance: float
    tags: List[str]
    summary: str
    open_questions: List[str]
```

Recommended update shape:

```python
support_gain = weight * relevance * quality * reliability * causal_relevance
new_conf = old_conf + support_gain * (1 - old_conf)

contradiction_loss = weight * relevance * quality * reliability * causal_relevance
new_conf = old_conf - contradiction_loss * old_conf
```

Recommended margin rule:

- if `top1.confidence - top2.confidence < 0.12`, do not claim supported root cause yet

### Upgrade `EvidenceGraph`

Required changes:

- type observation nodes by event class
- add edge confidence and basis
- add explicit vs inferred distinction
- use canonical observation IDs everywhere
- keep the graph JSON-friendly and session-scoped

## Memory And Follow-Up Chat Redesign

### Working memory vs thread memory vs case memory

Working memory:

- live mutable investigation state in `AgentState`

Session snapshot:

- durable execution snapshot in `AgentStore`

Thread memory:

- analyst conversation continuity in `ThreadStore`

Case memory:

- accepted facts, accepted root cause, analyst corrections, and durable investigative memory at case level

### Required follow-up chat redesign

Current code clones too much parent session state.

New behavior:

1. classify follow-up intent first
2. if no fresh evidence is needed, answer from thread snapshot or case memory
3. if fresh evidence is needed, create a new execution session from accepted snapshot plus unresolved questions, not a full cloned findings list
4. if an execution session is still active, allow append-style commands or directives instead of only returning "still active"

## `AgentLoop` Factoring Strategy

Do not replace `AgentLoop`.

Do:

- keep it as orchestration shell
- move planning logic into `InvestigationPlanner`
- move normalization into `ObservationNormalizer`
- move root-cause ranking into `RootCauseEngine`
- move follow-up intent handling into `ChatIntentRouter`
- move analyst answer shaping into `SessionResponseBuilder`

`AgentLoop` should still own:

- session lifecycle
- state transitions
- execution sequencing
- approval waits
- high-level coordination

It should not remain the main home for:

- planning logic
- observation normalization logic
- thread-memory logic
- final response formatting logic

## Specialist Routing Upgrade

Current specialist routing is too progress-driven.

New routing must use:

- current investigation lane
- dominant hypothesis topics
- unresolved question types
- observation types seen so far
- missing evidence classes
- workflow phase completion

Examples:

- email delivery plus identity uncertainty -> phishing or identity specialist
- process execution plus file artifact -> malware specialist
- unresolved session attribution plus auth events -> identity or network specialist
- stable causal chain plus enough evidence -> correlation or reporting specialist

## Log Investigation Upgrade

CABTA already has a strong log-hunting base. The next step is to separate planning from execution while preserving safety controls.

Required additions:

- `LogQueryPlanner`
- `LogObservationNormalizer`
- optional `log_lane` facade only if it helps keep orchestration narrow

Keep intact:

- broad hunt approvals
- dangerous SPL blocking
- live/demo/manual branching

## Identity And Naming Cleanup

Current drift still exists across:

- `CABTA`
- `AISA`
- `AI Security Assistant`
- `.blue-team-assistant`

Required stance:

- keep naming cleanup as a dedicated pass
- do not mix large rename churn into the first reasoning slices
- prefer `CABTA` in new plan text, new docs, new logs, and new user-facing strings

Likely rename targets later:

- app titles
- template globals
- DB path defaults
- telemetry labels
- service labels
- residual user-facing legacy strings

## Delivery Phases

### Phase 0: Planning And Runtime Factoring

**Objective:** add explicit planning, thread scaffolding, and helper seams without destabilizing scoring or analyzers

Add:

- `src/agent/investigation_planner.py`
- `src/agent/observation_normalizer.py`
- `src/agent/root_cause_engine.py`
- `src/agent/thread_store.py`
- `src/agent/chat_intent_router.py`
- `src/agent/session_response_builder.py`

Modify:

- `src/agent/agent_state.py`
- `src/agent/agent_loop.py`
- `src/agent/agent_store.py`
- `src/web/routes/chat.py`

Do not change yet:

- `src/scoring/*`
- low-level analyzer implementations
- broad reporting surfaces

**Tests**

- `python -m pytest tests/test_agent.py tests/test_agentic_reasoning.py -q`

### Phase 1: Observation Normalization And Entity/Evidence Strengthening

**Objective:** create trustworthy normalized facts and stronger entity/evidence structures

Add:

- `src/agent/log_observation_normalizer.py`

Modify:

- `src/agent/entity_resolver.py`
- `src/agent/evidence_graph.py`
- `src/agent/agent_loop.py`
- `src/mcp_servers/splunk_tools.py` only if output shape changes are necessary

**Tests**

- `python -m pytest tests/test_agent.py tests/test_agentic_reasoning.py tests/test_playbook_log_demo.py -q`

### Phase 2: Hypothesis And Root-Cause Reasoning Upgrade

**Objective:** move from heuristic hypothesis shifts to stronger evidence-scored reasoning

Modify:

- `src/agent/hypothesis_manager.py`
- `src/agent/root_cause_engine.py`
- `src/agent/agent_loop.py`
- `src/agent/evidence_graph.py`
- `src/web/routes/agent.py`
- `src/web/routes/chat.py`
- `src/web/case_store.py`
- `src/case_intelligence/service.py`

**Tests**

- `python -m pytest tests/test_agentic_reasoning.py tests/test_analyst_workflow_e2e.py tests/test_reasoning_mirror_ui.py -q`

### Phase 3: Thread Memory And Case Memory

**Objective:** stop cloning unbounded raw session state and introduce accepted-snapshot based continuity

Add or modify:

- `src/agent/thread_store.py`
- `src/agent/agent_store.py`
- `src/web/routes/chat.py`
- `src/agent/memory.py`
- `src/agent/case_memory_service.py`
- `src/case_intelligence/service.py`

**Tests**

- `python -m pytest tests/test_agent.py tests/test_agentic_reasoning.py tests/test_analyst_workflow_e2e.py tests/test_agent_chat_reasoning_ui.py -q`

### Phase 4: Evidence-Driven Specialist Routing And Workflow Intelligence

**Objective:** move specialist and workflow progression from progress-based to evidence-driven

Modify:

- `src/agent/specialist_supervisor.py`
- `src/agent/agent_loop.py`
- `src/workflows/service.py`
- `src/workflows/registry.py`

**Tests**

- `python -m pytest tests/test_agent.py tests/test_analyst_workflow_e2e.py -q`

### Phase 5: Naming Cleanup And Hardening Pass

**Objective:** clean identity drift and tighten final contracts after reasoning architecture stabilizes

Modify:

- `src/web/app.py`
- template globals and user-facing labels
- store default paths and service labels
- residual legacy strings in touched runtime files

**Tests**

- `python -m pytest tests/test_web_api.py tests/test_agent.py tests/test_analyst_workflow_e2e.py -q`

## First Vertical Slice

If only one slice can be implemented first, implement:

**Lead Investigator Slice 1: planned log-first incident investigation**

Scope:

- explicit `InvestigationPlan`
- `ObservationNormalizer` for `search_logs` and one or two core local tools
- stronger `EntityResolver`
- upgraded `HypothesisManager`
- `RootCauseEngine`
- deterministic vs agentic split preserved
- thread snapshot groundwork for follow-up chat

Why this slice first:

- it proves planning, fact normalization, entity pivots, hypothesis revision, root-cause reasoning, and follow-up memory improvements without requiring a system rewrite

## Acceptance Criteria

- [ ] every meaningful investigation session gets an explicit `InvestigationPlan`
- [ ] tool results are normalized into typed observations before reasoning updates
- [ ] entity state includes confidence, provenance, and relation basis
- [ ] multiple competing hypotheses are maintained and revised through stronger evidence scoring
- [ ] root-cause state can be `supported`, `inconclusive`, or `insufficient_evidence`
- [ ] deterministic decision output remains separate from agentic explanation output
- [ ] follow-up chat can continue from thread snapshot instead of cloning unbounded raw session state
- [ ] specialist and workflow routing can consider evidence and unresolved questions, not only step progress
- [ ] local tools, MCP tools, playbook execution, and approvals remain intact
- [ ] log-hunting guardrails remain intact
- [ ] relevant docs are updated if contracts or operating expectations change
- [ ] relevant tests are added or updated alongside each phase

## Required Test Strategy

### Unit tests

Entity resolution:

- explicit auth-row relation yields strong relation with high confidence
- text-only co-observation yields only weak or co-observed relation
- IP normalization and validation work correctly
- provenance fields are present

Hypothesis reasoning:

- supporting evidence increases the correct hypothesis more than unrelated ones
- contradiction lowers confidence appropriately
- weak evidence does not over-amplify confidence
- close competing hypotheses remain `inconclusive`
- low-quality evidence can still result in `insufficient_evidence`

Observation normalization:

- Splunk/log result normalization produces auth/process/network/session observations
- local analyzer normalization produces canonical observation types

Root-cause engine:

- causal chain is built from strongest evidence
- contradiction margin is respected
- confident root cause is not invented when evidence is weak

### Integration tests

- session starts with explicit plan
- tool result -> normalized observation -> entity update -> hypothesis revision -> root-cause update
- deterministic decision remains unchanged when explanation changes
- follow-up chat uses thread snapshot instead of full finding clone
- case reasoning summary selects the strongest accepted explanation state

### End-to-end scenarios

Scenario 1: phishing-to-execution chain

- ingest email plus IOC plus process evidence
- identify likely phishing chain
- preserve uncertainty when user attribution is incomplete

Scenario 2: suspicious login with host timeline

- plan log investigation
- pivot IP -> session -> host -> process
- distinguish weak vs strong user linkage
- produce root-cause output with meaningful missing evidence when identity remains partial

Scenario 3: noisy or false-positive style case

- keep competing hypotheses alive
- lower malicious confidence when contradiction is stronger
- produce inconclusive or benign-leaning explanation without corrupting deterministic verdict logic

## Codex Working Rules

1. Inspect existing code paths before adding abstractions.
2. Prefer extension over replacement.
3. Keep new code narrow and composable.
4. Do not encode business truth in prompt strings alone.
5. Move intelligence into structured state and code-level contracts.
6. Avoid new global singletons.
7. Keep new state JSON-serializable unless there is a compelling reason not to.
8. Favor deterministic normalization before LLM interpretation.
9. Do not let web routes become reasoning engines.
10. Add tests alongside each new component.
11. Keep deterministic scoring untouched unless a later dedicated scoring plan explicitly requires otherwise.
12. Keep unsafe or broad log-hunting actions behind the current governance and approval model.

## Anti-Goals

Do not do these in the first major upgrade:

- build a graph database
- build a brand-new multi-agent swarm
- let the LLM control final verdicts or policy actions
- rewrite all analyzers to emit a new format before proving the normalizer layer
- couple thread memory directly to raw findings cloning
- start with dashboard redesign
- replace Splunk guardrails with looser free-form querying
- hide uncertainty to make the agent sound smarter

## Docs To Review

- `README.md`
- `docs/project-overview-pdr.md`
- `docs/system-design.md`
- `docs/codebase-summary.md`
- `docs/code-standards.md`
- `docs/feature-truth-matrix.md`
- `docs/agentic-lead-investigator-upgrade-plan.md`
- `docs/future-system-roadmap.md`
- `TEST-MANIFEST.md`

## Unresolved Questions

- should thread snapshots be implemented as a dedicated `thread_snapshots` table in `AgentStore` or as a separate `ThreadStore` SQLite file from day one
- should `AnalysisResult` become the direct lingua franca for some normalized observation types, or should `Observation` remain a separate contract with adapters from `AnalysisResult`
- should active-session follow-up directives be handled through a lightweight inbox queue in `AgentLoop`, or through persisted thread commands
