# CABTA Agentic Lead-Investigator Upgrade Plan

## Purpose

This document is the implementation-facing plan for upgrading CABTA's agentic layer from:

- tool router + summarizer

into:

- lead investigator + evidence-governed reasoner

This plan is grounded in the current CABTA codebase.
It is not a speculative redesign.

Use this file when implementing agentic upgrades so we preserve:

- deterministic verdict authority
- current analyzers and scoring
- existing tool and MCP integrations
- current session, case, and workflow lifecycle
- analyst trust and auditability

## Decision Summary

CABTA should not stay in its current form where the agent is mainly a tool coordinator.

CABTA also should not become a free-form agent that owns final scores, verdicts, or policy decisions.

The correct target architecture is:

- deterministic core for numeric score, severity, verdict, and policy gates
- agentic investigator for hypothesis-driven reasoning, evidence organization, pivots, root-cause explanation, and next-step guidance

In short:

- keep deterministic decision ownership
- upgrade agentic reasoning ownership

## Grounded Current Architecture

The plan below is based on the current repository structure and responsibilities.

### Current components that already exist

- `src/agent/agent_loop.py`
  - ReAct-style investigation loop
  - tool use
  - approval gate
  - playbook invocation
  - session lifecycle
  - specialist handoffs
  - summary generation
- `src/agent/agent_state.py`
  - live mutable state for one investigation session
  - findings, errors, pending approval, specialist metadata
- `src/agent/agent_store.py`
  - persistent agent sessions
  - persistent agent steps
  - flexible `metadata` JSON for new structured state
- `src/agent/tool_registry.py`
  - existing tools and current verdict-bearing helpers
  - case helpers already exist
- `src/agent/mcp_client.py`
  - MCP server discovery and tool transport
- `src/agent/playbook_engine.py`
  - workflow scaffolding and step execution
- `src/agent/memory.py`
  - cached IOC memory and recurring investigation patterns
- `src/agent/correlation.py`
  - correlation and entity graph style outputs from findings
- `src/web/app.py`
  - shared runtime wiring through `app.state`
- `src/web/routes/agent.py`
  - investigation session APIs
- `src/web/routes/chat.py`
  - chat entrypoint and follow-up flow
- `src/web/case_store.py`
  - case storage and case events
- `src/case_intelligence/service.py`
  - read-side graph and timeline reconstruction from stored artifacts
- `src/scoring/`
  - deterministic decision ownership

### What the current agent loop already does

The current `agent_loop.py` already provides real operational value.

It already:

- creates investigation sessions
- runs a ReAct-style think/act/observe loop
- calls local tools and MCP tools
- supports approval wait states
- invokes playbooks
- persists session steps and findings
- tracks specialist routing and handoffs
- produces an analyst-facing summary

This means CABTA does not need a new agent system.
It needs a structured reasoning layer on top of the current loop.

### What is currently missing

The current loop does not yet provide first-class structured investigation reasoning.

Missing pieces:

- explicit hypotheses
- explicit open questions
- supporting vs contradicting evidence tracking
- structured root-cause assessment
- explicit insufficient-evidence state
- entity-first normalization for pivots like `IP -> session -> host -> user`
- lightweight causal timeline built from structured evidence links
- clean split between deterministic decision output and agentic explanation output

## Architecture Direction

The target operating model is:

1. deterministic systems compute the authoritative numeric and policy-bearing decision
2. the agent maintains structured investigative reasoning
3. every important claim in agentic reasoning is linked to inspectable evidence
4. the system can stop honestly with:
   - sufficient evidence
   - insufficient evidence
   - approval wait
   - max steps reached

The agent should behave like a detective:

- form hypotheses
- gather evidence
- revise hypotheses
- build a causal explanation
- declare uncertainty honestly when evidence is insufficient

## Non-Negotiable Design Rules

### 1. Deterministic decision ownership stays intact

The following remain owned by the deterministic core:

- `score`
- `severity`
- `verdict`
- `policy flags`
- any allow/block/quarantine style policy output

The agent must not directly populate these unless they already come from deterministic code.

### 2. Agentic reasoning must be evidence-backed

The agent may not claim:

- root cause
- attribution
- user-to-IP linkage
- sequence of compromise

without linking those claims back to stored evidence references.

### 3. Reuse the current CABTA seams

Do not rewrite:

- the ReAct loop
- tool registry
- MCP client
- playbook engine
- analyzers
- scoring pipeline

Integrate by adding structured reasoning state into the existing session/store pattern.

### 4. No opaque chain-of-thought storage

Persist structured reasoning artifacts, not raw hidden free-form reasoning.

Allowed persisted artifacts:

- hypotheses
- evidence references
- root-cause assessment
- entity links
- causal chain records
- missing evidence list
- recommended next pivots

### 5. Graceful degradation still applies

If:

- a tool fails
- an MCP server is offline
- a data source is missing
- logs are incomplete

then the agent must degrade to:

- partial reasoning
- explicit open questions
- explicit insufficient evidence

It must not fake certainty.

## Target Reasoning Model

### Investigation session state

Every live investigation session should gain a structured reasoning state.

Initial home:

- in-memory: `AgentState`
- persisted: `agent_sessions.metadata`

Do not introduce a new database for Phase 1.

### Hypothesis

Each investigation may hold multiple hypotheses.

Minimum fields:

- `id`
- `statement`
- `status`
- `confidence`
- `supporting_evidence_refs`
- `contradicting_evidence_refs`
- `open_questions`

Recommended status values:

- `open`
- `supported`
- `contradicted`
- `inconclusive`
- `deprioritized`

### Evidence reference

Evidence references should point back to existing CABTA artifacts, not duplicate raw blobs.

Minimum fields:

- `session_id`
- `step_number`
- `tool_name`
- `finding_index`
- `summary`
- optional `result_path`

This preserves auditability and avoids storing the same tool result twice.

### RootCauseAssessment

Root cause must be separated from verdict.

Minimum fields:

- `primary_root_cause`
- `confidence`
- `causal_chain`
- `supporting_evidence_refs`
- `alternative_hypotheses`
- `missing_evidence`
- `summary`
- `assessed_at`

The root-cause object is explanatory only.
It must not override deterministic score or verdict.

## Output Contract

CABTA should expose two distinct outputs.

### 1. DeterministicDecisionOutput

Owned by the deterministic analysis and scoring path.

Fields:

- `score`
- `severity`
- `verdict`
- `confidence`
- `policy_flags`

### 2. AgenticExplanationOutput

Owned by the agentic reasoning layer.

Fields:

- `root_cause_assessment`
- `explanation_confidence`
- `causal_chain`
- `supporting_evidence_refs`
- `alternative_hypotheses`
- `missing_evidence`
- `recommended_next_pivots`
- `recommended_next_actions`

These outputs must not be merged into one ambiguous summary object.

## Where State Should Live

### Hypotheses

Primary location:

- `AgentState.reasoning_state`
- persisted under `agent_sessions.metadata.reasoning_state`

Why:

- matches current live session model
- survives across API calls
- avoids a migration in the first slice

### Evidence-backed reasoning state

Primary location:

- `agent_sessions.metadata.reasoning_state`

Evidence source of truth remains:

- `state.findings`
- `agent_steps`

### Root-cause assessment

Primary location:

- `agent_sessions.metadata.root_cause_assessment`

Optional mirror for case-level visibility:

- add a `case_event` in `CaseStore`

This keeps root-cause reasoning attached to the investigation while still making it visible in case history when needed.

### Entity-centric state

Primary location:

- `agent_sessions.metadata.entity_state`

Keep Phase 3 thin:

- normalized entities
- lightweight links
- source references

Do not introduce a heavy graph DB.

### Timeline / evidence links

Primary location:

- `agent_sessions.metadata.evidence_state`

The existing `CaseIntelligenceService` can remain the read-side consumer later.

## Recommended Upgrade Phases

## Phase 1: Structured hypothesis tracking

### Goal

Add structured hypothesis management to the existing agent system without rewriting it.

### Reuse

- `src/agent/agent_loop.py`
- `src/agent/agent_state.py`
- `src/agent/agent_store.py`
- existing tool findings and step records

### Add

- `src/agent/hypothesis_manager.py`

### Change first

- `src/agent/agent_state.py`
- `src/agent/agent_loop.py`
- new focused tests

### Behavior

- seed hypotheses at session start
- revise hypotheses after tool observations
- attach supporting and contradicting evidence refs
- carry forward open questions
- store all of this in structured session metadata

### Do not touch yet

- `src/scoring/*`
- `src/agent/tool_registry.py`
- `src/agent/mcp_client.py`
- `src/agent/playbook_engine.py`
- `src/web/analysis_manager.py`

### Acceptance criteria

- one session can hold multiple hypotheses
- each hypothesis persists across session reads
- tool observations can strengthen or weaken hypotheses
- deterministic verdict path remains unchanged

## Phase 2: RootCauseAssessment split from verdict

### Goal

Add a structured root-cause output without changing numeric scoring ownership.

### Reuse

- session metadata
- current case workflow
- current report/session APIs

### Add

- `src/agent/reasoning_models.py` or equivalent for shared structured models

### Change first

- `src/agent/agent_loop.py`
- `src/web/routes/agent.py`
- `src/web/routes/chat.py`
- optionally `src/web/case_store.py` for event mirroring

### Behavior

- the agent produces a structured root-cause assessment
- the root-cause object is stored with the investigation session
- when tied to a case, root-cause can optionally be mirrored as a case event
- deterministic verdict output remains separate

### Acceptance criteria

- root-cause assessment exists without touching `src/scoring/`
- a completed session returns both:
  - deterministic decision
  - agentic explanation

## Phase 3: Entity-first investigation

### Goal

Allow the agent to reason across normalized entities instead of isolated string observations.

### Reuse

- `src/agent/correlation.py`
- `src/case_intelligence/service.py`
- current tool outputs

### Add

- `src/agent/entity_resolver.py`

### Minimum entity types

- `user`
- `host`
- `ip`
- `process`
- `session`

### Behavior

- normalize observed values into entity records
- attach source evidence refs
- support pivots like:
  - which user is associated with this IP
  - what host did this session occur on
  - what process followed this login

### Acceptance criteria

- the agent can maintain a thin normalized entity state per session
- the entity layer does not require replacing current tool outputs

## Phase 4: Evidence links and causal timeline

### Goal

Add the minimum structured support needed for causal reasoning.

### Reuse

- current findings and steps
- `CaseIntelligenceService` as read-side consumer

### Add

- `src/agent/evidence_graph.py` or similarly narrow module

### Edge types

- `supports`
- `contradicts`
- `precedes`
- `linked_to`
- `derived_from`

### Behavior

- hypotheses can point to structured evidence links
- root-cause assessment can point to a causal chain
- the agent can build a minimal session-level timeline from stored observations

### Acceptance criteria

- causal claims are backed by structured references
- timeline is reconstructable from stored state
- still no generic graph platform or graph database

## Phase 5: UI and reporting exposure

### Goal

Make the new reasoning inspectable to analysts without confusing it with deterministic output.

### Change

- session detail APIs
- chat session response payloads
- case timeline and graph views
- reporting surfaces where useful

### UI principles

- deterministic decision is clearly labeled
- root cause is clearly labeled as investigative explanation
- alternative hypotheses are visible
- missing evidence is visible
- analyst can inspect evidence refs

## Smallest End-to-End Vertical Slice

The first proving slice should stay narrow.

### Scenario

Support one investigation session where the agent can:

1. receive a hypothesis-driven question
2. call existing tools
3. maintain multiple hypotheses
4. attach supporting and contradicting evidence
5. return:
   - deterministic decision output
   - agentic explanation output

### Example analyst question

Investigate whether `185.220.101.12` and `secure-payroll-check.com` are part of a phishing or command-and-control chain, and determine whether there is enough evidence to identify the affected host and user.

### Why this is the right first slice

It proves:

- structured hypothesis state
- evidence-backed reasoning
- honest insufficient-evidence handling
- clean coexistence with deterministic verdict logic

without needing:

- a new database
- a full graph subsystem
- a scoring rewrite
- a new tool stack

## Exact File Priorities

## Files to change first

Phase 1 priority:

- `src/agent/agent_state.py`
- `src/agent/agent_loop.py`
- `src/agent/agent_store.py` only if helper methods are needed for metadata ergonomics
- new `src/agent/hypothesis_manager.py`
- new focused tests under `tests/`

Phase 2 priority:

- `src/agent/agent_loop.py`
- `src/web/routes/agent.py`
- `src/web/routes/chat.py`
- optionally `src/web/case_store.py`

Phase 3 priority:

- new `src/agent/entity_resolver.py`
- `src/agent/agent_loop.py`
- optionally `src/case_intelligence/service.py` later, not first

Phase 4 priority:

- new `src/agent/evidence_graph.py`
- `src/agent/agent_loop.py`
- case or session serialization surfaces as needed

## Files not to touch yet

Until the first vertical slice proves itself, avoid changing:

- `src/scoring/*`
- `src/agent/tool_registry.py`
- `src/agent/mcp_client.py`
- `src/agent/playbook_engine.py`
- `src/web/analysis_manager.py`
- analyzer implementations unrelated to session reasoning

These are stable seams and should only be extended when the new reasoning layer proves its value.

## Proposed Data Shapes

These are the recommended minimum shapes for implementation.

### Hypothesis

```json
{
  "id": "hyp-001",
  "statement": "The domain is part of a phishing delivery chain.",
  "status": "open",
  "confidence": 0.35,
  "supporting_evidence_refs": [],
  "contradicting_evidence_refs": [],
  "open_questions": [
    "Which host contacted the domain?",
    "Is there process execution evidence after contact?"
  ]
}
```

### RootCauseAssessment

```json
{
  "primary_root_cause": "Likely phishing attachment leading to user execution on WS-12.",
  "confidence": 0.68,
  "causal_chain": [
    "Suspicious email delivered",
    "Attachment opened by user",
    "Process executed from roaming path",
    "Outbound connection to suspicious IP observed"
  ],
  "supporting_evidence_refs": [],
  "alternative_hypotheses": [
    "Benign admin tooling was misclassified",
    "The outbound IP was unrelated scanning noise"
  ],
  "missing_evidence": [
    "No authenticated session log tying the IP to a named user",
    "No process lineage event from EDR"
  ],
  "summary": "Most likely phishing-to-execution chain, but user attribution remains incomplete.",
  "assessed_at": "2026-04-17T00:00:00Z"
}
```

### Output split

```json
{
  "deterministic_decision": {
    "score": 87,
    "severity": "high",
    "verdict": "malicious",
    "confidence": 0.91,
    "policy_flags": ["needs_review"]
  },
  "agentic_explanation": {
    "root_cause_assessment": {},
    "explanation_confidence": 0.68,
    "causal_chain": [],
    "supporting_evidence_refs": [],
    "alternative_hypotheses": [],
    "missing_evidence": [],
    "recommended_next_pivots": [],
    "recommended_next_actions": []
  }
}
```

## Testing Strategy

Every phase must preserve trust.

### Required tests for Phase 1

- unit tests for `HypothesisManager`
- loop tests confirming hypotheses persist in session metadata
- regression tests confirming deterministic verdict ownership did not move

### Required tests for Phase 2

- route and serialization tests for output split
- tests proving root-cause assessment does not overwrite score/verdict

### Required tests for Phase 3

- unit tests for entity normalization
- end-to-end session tests for simple entity pivots

### Required tests for Phase 4

- evidence-link serialization tests
- timeline reconstruction tests
- contradiction/support edge tests

## Rollout Guidance

Implement this in order:

1. structured hypotheses
2. root-cause split from verdict
3. entity normalization
4. evidence links and timeline
5. UI/reporting exposure

Do not start with UI.
Do not start with a graph platform.
Do not start with scoring changes.

## Definition of Success

This upgrade is successful when CABTA can do all of the following in one investigation session:

- maintain multiple competing hypotheses
- revise them after tool observations
- explain why one root cause is more likely than another
- state clearly when evidence is insufficient
- pivot through normalized entities
- preserve deterministic verdict authority
- expose an auditable explanation trail to the analyst

## Immediate Next Step

Start with Phase 1 only.

That means:

- add `HypothesisManager`
- store hypothesis state in `AgentState` and `agent_sessions.metadata`
- revise hypotheses after tool observations inside the current `agent_loop.py`
- leave scoring, MCP transport, playbook engine, and analyzers untouched

This is the smallest slice that proves the new architecture without destabilizing CABTA.
