# AISA System Design

## Purpose

This document is the primary system-design source of truth for AISA.

Use it when vibe coding to decide:

- where a feature belongs
- which layer owns a change
- what should be adopted from Vigil-inspired ideas
- what must stay deterministic
- how AISA should evolve without breaking analyst trust

This file is intentionally operational and implementation-facing.

## Canonical Read Order

For most non-trivial work, read in this order:

1. `README.md`
2. `docs/project-overview-pdr.md`
3. this `docs/system-design.md`
4. `docs/vigil-main-integration-blueprint.md`
5. `docs/codebase-summary.md`
6. `docs/code-standards.md`
7. `docs/feature-truth-matrix.md`
8. `TEST-MANIFEST.md`
9. relevant `plans/` entry if one exists

## System Identity

- Canonical product name: `AISA`
- Expanded name: `AI Security Assistant`
- Historical aliases still present in some legacy docs/code: `CABTA`, `Blue Team Assistant`, `mcp-for-soc`
- Current repo/application path: `CABTA/`
- Primary product mode: `localhost web application`
- Secondary interfaces:
  - CLI
  - MCP server
  - Python import

When implementation and historical wording disagree, prefer:

- `AISA` for product, UI, architecture, and new documentation
- explicit legacy-name notes only where backward compatibility or historical context matters
- `CABTA/` for file layout and compatibility

## Product Thesis

AISA is a local-first AI SOC assistant platform with two tightly connected planes:

1. a deterministic analysis plane
2. an agentic investigation plane

The analysis plane provides trustworthy artifact analysis.
The investigation plane provides workflow, memory, correlation, governance, and orchestration.

The system should combine both without collapsing one into the other.

## Authoritative Integration Model

The integration model is asymmetric by design.

### AISA analysis core

AISA remains the authoritative owner of:

- evidence extraction
- enrichment normalization
- scoring
- verdict governance
- analyst-facing result contracts

This is the source of truth for verdict-bearing flows.

### Vigil-inspired orchestration plane

Vigil contributes patterns for:

- specialist agent roles
- multi-agent workflow orchestration
- playbook structure
- approval workflow
- optional headless daemon mode
- case-centered investigation coordination

This plane coordinates work around the analysis core.
It does not replace the analysis core.

### Hard boundary

If a workflow or agent needs evidence, it must obtain that evidence through:

- AISA tool orchestrators
- AISA analyzers and integrations
- approved MCP tools
- future case, graph, or timeline services built on real data

The model must not "guess" investigation results that should come from tools.

## Non-Negotiable Design Rules

### 1. Evidence first

Evidence must remain visible and inspectable in every analyst-facing flow.

### 2. Deterministic verdict authority

IOC, file, and email verdicts must remain grounded in:

- evidence extraction
- heuristics
- enrichment
- scoring
- explicit mapping rules

LLM output may interpret, summarize, and guide.
It must not silently become final verdict authority.

### 2b. Workflow and agent outputs are not verdict authority

Workflow phases may:

- gather evidence
- organize findings
- request pivots
- recommend actions
- summarize conclusions

They may not override AISA scoring as the final verdict source for analysis flows.

### 2c. LLM-first SOC request interpretation

Natural SOC chat can use an optional LLM-first request interpreter before objective/capability orchestration. The interpreter is an agentic planner/analyst for understanding only: it may split mixed objectives, identify entities, choose capability needs, surface missing inputs, propose candidate log-query intent, and mark approval needs. Its output is constrained to `SOCInterpretation` JSON, validated against local enums and `CapabilityOntology`, cross-checked by deterministic extractors, and recorded with parse/repair/fallback audit metadata. It cannot execute tools, approve destructive actions, or produce final IOC/file/email/log verdicts; execution still flows through `SOCTaskState`, `CapabilityAction`, `ParameterBinder`, `PreflightValidator`, `ClarificationGate`, governance approval, evidence collection, and `FinalAnswerGate`.

Feature modes are `disabled`, `shadow`, and `primary`. `disabled` preserves deterministic interpretation; `shadow` audits LLM interpretation while executing deterministic behavior; `primary` uses validated LLM interpretation and falls back or clarifies safely when invalid or unavailable.

### 2d. Objective/capability/evidence orchestration

Agent investigations now use an objective-first orchestration layer before legacy tool execution:

1. `RequestUnderstandingExtractor` parses the analyst request into intent, domain, entities, requested backends, timerange, safety flags, and required capabilities.
2. `ObjectiveModelBuilder` creates an additive `ObjectiveContract` with evidence requirements, success criteria, timerange policy, approval requirements, and final-answer requirements.
3. `CapabilityOntology` and `CapabilityResolver` map capability IDs such as `log.search`, `email.analyze`, `file.analyze.static`, `ioc.enrich`, `ir.approval.request`, and `config.capability.explain` to currently available AISA tools.
4. `NextActionPlanner` prefers capability-aware signals and bridges executable capabilities back to the legacy `ToolRegistry` tool names at the execution boundary.
5. `ReflectionEngine` checks observations against expected evidence and timerange coverage.
6. `FinalAnswerGate` blocks or downgrades unsupported final claims unless evidence gaps and degraded capabilities are stated explicitly.

This keeps planning portable across local tools and future MCP providers while preserving backward compatibility with existing tool execution. Missing integrations must resolve as degraded/unavailable capability decisions instead of silently falling back to unrelated IOC enrichment or malware analysis tools.

### 3. Local-first by default

Core analysis must remain usable:

- on localhost
- without paid APIs
- without mandatory cloud inference

### 4. Graceful degradation

Unavailable integrations, sandboxes, or external models must produce:

- partial results
- honest capability state
- manual fallback guidance

They must not fake success.

### 5. Workflow power without black-box behavior

As AISA adds Vigil-inspired workflow and agent power, it must remain:

- readable
- inspectable
- interruptible
- approval-aware

### 6. Stable contracts

Additive result changes are preferred.
Do not silently rewrite contracts used by:

- web routes
- reports
- history
- cases
- agents
- MCP surfaces

### 7. Integrate by seam, not by rewrite

Vigil-inspired ideas should enter AISA through explicit seams:

- new orchestration layers
- new case/intelligence layers
- new governance layers

Do not rewrite the analysis core just to imitate Vigil's structure.

## Product Operating Modes

### Mode A: Analyst-driven analysis

This is the current core path:

- submit IOC, file, or email
- run deterministic pipeline
- review evidence, score, verdict, and output artifacts

### Mode B: Agent-assisted investigation

This is the target expansion path:

- create or open a case
- run a workflow or specialist agent
- pivot across artifacts, cases, MCP tools, and prior findings
- capture decisions, approvals, graph links, and timeline outputs

### Mode C: Governed autonomous operations

This is a future optional path:

- background polling or hunt scheduling
- queued LLM reasoning
- confidence-scored action proposals
- mandatory approval policy where needed

This mode must never become mandatory for the main localhost analyst path.

## Canonical Product Surfaces

### Dashboard

Owns:

- system orientation
- recent analyses and investigations
- source health
- capability health
- workflow entrypoints

### IOC Investigation

Owns:

- single IOC triage
- enrichment
- score breakdown
- deterministic verdict
- exportable results

### File Analysis

Owns:

- upload/select file
- analyzer routing
- static and optional dynamic enrichment
- extracted evidence
- score and verdict

### Email Analysis

Owns:

- email parsing
- auth/header inspection
- phishing and BEC analysis
- attachment and URL pivots
- composite scoring

### History and Reports

Own:

- prior jobs
- report views
- export flows
- demo replay and audit visibility

### Cases

Own:

- grouping analyses
- notes
- investigation continuity
- attachments to workflows, decisions, graph, and timeline views

### Workflow Workspace

Owns:

- reusable investigation workflows
- specialist agent selection
- phase-by-phase execution state
- evidence-linked outputs

It does not own final artifact verdict logic.

### Agent Workspace

Owns:

- freeform AI-assisted investigation
- tool-driven reasoning
- guided pivots
- human-in-the-loop control

It does not own deterministic verdict mapping.

### Knowledge Views

Own:

- entity graph
- event timeline
- campaign/correlation summaries
- ATT&CK overlays

### Governance Views

Own:

- approval queue
- AI decision logs
- feedback
- capability truth
- action audit trails

### Settings and Integration Control

Own:

- configuration
- API keys and provider state
- MCP and external tool visibility
- health truth
- optional custom integration onboarding

## Target Architecture Summary

AISA should be treated as a web-first analyst platform built from two connected planes.

### Analysis Plane

Responsibilities:

- perform artifact-centric analysis
- produce evidence and deterministic verdicts
- generate stable analyst outputs

Primary code areas:

- `src/tools/*`
- `src/analyzers/*`
- `src/integrations/*`
- `src/scoring/*`
- `src/reporting/*`

### Investigation Plane

Responsibilities:

- orchestrate specialist agents and workflows
- manage case-centered context
- preserve decisions, graph links, and timelines
- govern actions and approvals
- expose richer SOC operating patterns

This plane is downstream of real evidence collection.
It should be tool-first and evidence-first.

Primary code areas today and future targets:

- `src/agent/*`
- `src/web/analysis_manager.py`
- `src/web/case_store.py`
- future workflow, graph, timeline, approval, and decision-log modules

## Layer Ownership

### 1. Presentation Layer

Files:

- `templates/*`
- `static/*`

Responsibilities:

- render UI states
- make evidence easy to scan
- expose workflow, case, and governance state clearly

Must not:

- compute verdicts
- hide important semantics in frontend-only logic

### 2. Web Routing Layer

Files:

- `src/web/app.py`
- `src/web/routes/*`

Responsibilities:

- receive requests
- validate inputs
- invoke orchestration layers
- shape API and page responses

Must not:

- own scoring
- bypass orchestrators
- invent product semantics not present in services

### 3. Job and Case Orchestration Layer

Files:

- `src/web/analysis_manager.py`
- `src/web/case_store.py`
- `src/web/runtime_refresh.py`

Responsibilities:

- track jobs
- persist status
- connect analyses to history and cases
- refresh runtime configuration safely

### 4. Core Analysis Orchestration Layer

Files:

- `src/tools/ioc_investigator.py`
- `src/tools/malware_analyzer.py`
- `src/tools/email_analyzer.py`

Responsibilities:

- coordinate end-to-end analysis flows
- invoke analyzers, integrations, scoring, and reporting
- preserve stable result contracts

This remains AISA's deterministic operational heart.
Workflow and agent layers should call into this layer instead of bypassing it.

### 5. Analyzer Layer

Files:

- `src/analyzers/*`
- `src/analyzers/deobfuscators/*`

Responsibilities:

- parse and inspect artifacts
- surface structured findings
- extract indicators and evidence

Must not:

- own final verdicts
- mutate job or case state

### 6. Enrichment and Provider Layer

Files:

- `src/integrations/*`

Responsibilities:

- threat intel
- sandbox lookup or submission
- LLM interpretation
- export/STIX/provider adapters

Must not:

- silently become final verdict authority

### 7. Scoring and Verdict Governance Layer

Files:

- `src/scoring/*`

Responsibilities:

- translate evidence into deterministic scores
- apply false-positive controls
- map score to verdict
- produce score breakdown

### 8. Reporting and Export Layer

Files:

- `src/reporting/*`
- `src/detection/*`

Responsibilities:

- analyst-readable output
- executive or technical summaries
- exportable formats
- detection content

### 9. Workflow Definition Layer

Files today:

- `workflows/*/WORKFLOW.md`
- `src/workflows/registry.py`
- `src/workflows/service.py`
- `src/web/routes/workflows.py`
- `templates/workflows.html`

Responsibilities:

- define reusable investigation workflows in readable text or markdown
- expose sequence, required roles, expected tools, and phase semantics
- declare where evidence must come from
- distinguish analysis steps from orchestration-only steps

This is one of the most valuable Vigil-inspired additions.

### 10. Specialist Agent Layer

Files today:

- `src/agent/*`
- `src/agent/profiles.py`

Responsibilities:

- role-specific system prompts and policies
- distinct methodologies for triage, hunt, correlation, response, reporting
- evidence-linked tool use
- planning and coordination around real tool output

Must not:

- bypass deterministic verdict logic in analysis flows
- fabricate unsupported investigation evidence

### 11. Knowledge and Correlation Layer

Files today:

- `src/case_intelligence/service.py`
- `src/web/routes/cases.py`

Responsibilities:

- entity mapping
- attack-path reconstruction
- timeline generation
- case-level correlation

### 12. Governance and Audit Layer

Files today:

- `src/agent/governance_store.py`
- `src/web/routes/governance.py`
- `templates/approvals.html`
- `templates/decisions.html`

Responsibilities:

- confidence-aware action gating
- approval queue
- decision logging
- human feedback capture
- safe automation boundaries

### 13. MCP and Integration Control Plane

Files today:

- `src/agent/mcp_client.py`
- `src/web/routes/mcp_management.py`
- `src/mcp_servers/*`

Responsibilities:

- manage integration connectivity
- expose tool availability
- govern tool registration and health
- eventually support richer capability catalogs and custom integration flows

### 14. Optional Background Automation Layer

Files today:

- `src/daemon/service.py`
- `src/daemon/__main__.py`

Responsibilities:

- scheduled hunts
- polling
- background enrichment
- queued reasoning

Must remain optional for the main localhost flow.

## Canonical Domain Model

The system should converge on the following concepts.

### AnalysisJob

A tracked execution unit for IOC, file, email, or future workflow tasks.

### EvidenceItem

The smallest analyst-consumable proof unit with:

- source
- confidence
- summary
- normalized data

### InvestigationCase

A container for related analyses, notes, graph links, timeline events, decisions, and approvals.

### WorkflowDefinition

A human-readable investigation recipe with:

- metadata
- ordered phases
- specialist agent roles
- recommended tools
- expected outputs

### AgentProfile

A named role with:

- specialization
- methodology
- tool constraints
- context rules

### ApprovalAction

A proposed response or privileged action with:

- action type
- target
- confidence
- reason
- evidence
- approval status

### AIDecisionLog

A stored record of meaningful AI decisions, including:

- context
- reasoning
- confidence
- recommended action
- human feedback

### TimelineEvent

A normalized event used for chronological case reconstruction.

### EntityGraph

A graph of hosts, users, IPs, domains, files, and relationships extracted from analysis and investigation outputs.

### CapabilityCatalog

A machine-readable view of:

- local tools
- MCP tools
- analyzers
- integrations
- workflows
- optional providers

## Runtime Contract Schemas

Runtime contracts are implementation-facing and additive. They describe what agent, workflow, web, and audit code must preserve when moving data between request understanding, capability resolution, tool execution, reflection, final-answer gating, and governance.

All runtime contracts must include:

- `schema_version`
- stable IDs for cross-reference
- evidence references where claims are made
- explicit degraded or unavailable state when runtime capability is missing
- additive fields instead of destructive reshaping of existing result payloads

### Natural SOC chat protocol contracts

Natural SOC chat now uses a canonical protocol before legacy tool execution:

1. `SOCTaskState` preserves the analyst request, entities, artifacts, timerange, requested backends, objective contract, capability actions, clarification/approval waits, observations, coverage, final-answer gate state, and progress events.
2. `CapabilityAction` represents a capability-first action such as `log.search`, `email.parse.inline`, `file.analyze.static`, `ioc.enrich`, `case.summarize`, or governed `ir.*.propose` before any legacy tool adapter is selected.
3. `ParameterBindingResult` binds typed params and blocks full-sentence leakage into scalar fields such as IOC values and file paths.
4. `PreflightDecision` validates required inputs, file existence/upload state, timerange/backend preservation, missing backend degradation, clarification needs, and approval requirements before execution.
5. Chat responses expose additive `soc_progress` metadata with task ID, objective, current capability, preflight state, coverage, pending clarification/approval, degraded capabilities, final-answer gate status, and progress events.

These contracts are additive. Legacy tool names remain execution adapters, not planning authority. Destructive incident-response actions are staged as approval-required proposals and are not executed silently.

### ObjectiveContract

`ObjectiveContract` is built by `src/agent/objective_model.py` from `RequestUnderstanding`. It is the investigation intent contract, not a verdict.

Minimum fields:

```yaml
schema_version: objective-contract/v1
contract_id: obj_20260428_001
objective_type: log_security_investigation
lane: network_log_hunt
summary: Investigate Fortigate deny events for repeated external source activity
analyst_objective: Determine whether the denied traffic indicates scanning or attempted exploitation
entities:
  - type: ip
    value: 203.0.113.10
requested_backends:
  - fortigate
  - splunk
timerange:
  requested: historical
  effective: historical
  source: analyst_request
  normalization_reason: none
evidence_requirements:
  - requirement_id: ev_log_events
    capability: log.search
    required_facets: [timestamp, source_ip, destination_ip, action, device, raw_event]
    blocking: true
    min_quality: typed_observation
success_criteria:
  - Blocking evidence requirements are covered or explicitly degraded.
  - Final claims cite visible evidence references or limitations.
approval_requirements: []
final_answer_requirements:
  - State timerange and backend coverage.
  - Do not claim compromise without supporting evidence.
degraded_allowed: true
```

Implementation rules:

- The contract must preserve explicit analyst timerange and backend requests.
- Defaults must include a reason and source.
- Missing backend capability must become a degraded contract or degraded capability resolution, not an unrelated fallback.
- Contract metadata may be stored in `reasoning_state`, chat envelopes, case memory, and decision logs, but deterministic analyzer outputs remain authoritative for artifact verdicts.

### CapabilityDescriptor and CapabilityResolution

`CapabilityDescriptor` belongs to `src/agent/capability_ontology.py`. `CapabilityResolution` belongs to `src/agent/capability_resolver.py`.

Descriptor minimum shape:

```yaml
schema_version: capability-descriptor/v1
capability_id: log.search
domains: [network_log_hunt, incident_response]
description: Search security logs within an explicit timerange and backend scope
required_inputs: [query_or_entities, timerange]
optional_inputs: [backend, index, sourcetype, limit]
output_facets: [timestamp, source_ip, destination_ip, action, raw_event, backend]
evidence_role: primary_observation
compatible_tools:
  - tool_name: search_logs
    provider: local
    supports_timerange: true
    requires_approval: false
```

Resolution minimum shape:

```yaml
schema_version: capability-resolution/v1
resolution_id: res_20260428_001
capability_id: log.search
selected_tool: search_logs
provider: local
availability: available
availability_reason: tool_registered
confidence: 0.86
params_template:
  timerange: historical
  backend: fortigate
degradation:
  status: none
  reason: ""
legacy_bridge:
  action: use_tool
  tool: search_logs
```

Implementation rules:

- Resolution chooses a provider based on objective, policy, runtime availability, and evidence need.
- `unavailable` and `degraded` are first-class outcomes.
- Legacy tool names are execution adapters only; planning and audit should retain capability IDs.
- A log/SIEM/firewall objective must not silently resolve to IOC enrichment because a log backend is missing.

### ReflectionResult

`ReflectionResult` belongs to `src/agent/reflection_engine.py`. It compares observations against `ObjectiveContract` evidence requirements and coverage state.

```yaml
schema_version: reflection-result/v1
reflection_id: refl_20260428_001
objective_ref: obj_20260428_001
status: needs_repair
covered_facets: [timestamp, source_ip, action]
missing_facets: [destination_ip, raw_event]
blocking_gaps:
  - requirement_id: ev_log_events
    missing: [destination_ip, raw_event]
repair_actions:
  - capability: log.search
    rationale: Query must request raw event fields and destination address.
degraded_reason: ""
max_repair_attempts_reached: false
```

Implementation rules:

- Reflection may request bounded repair, ask for missing input, or downgrade final-answer scope.
- Reflection does not create final verdicts.
- Repeated empty or equivalent repair actions must stop after configured retry limits.

### FinalAnswerGateResult

`FinalAnswerGateResult` belongs to `src/agent/final_answer_gate.py`. It is the mandatory gate before a final agent answer when an investigation made evidence-bearing claims.

```yaml
schema_version: final-answer-gate-result/v1
gate_id: gate_20260428_001
objective_ref: obj_20260428_001
allowed: false
status: blocked
verified_claims:
  - claim: Repeated denied Fortigate traffic was observed from 203.0.113.10.
    status: supported
    evidence_refs: [obs_log_001]
  - claim: The host is compromised.
    status: unsupported
    evidence_refs: []
    limitation: No endpoint, authentication, or successful connection evidence was collected.
blocking_reasons:
  - unsupported_compromise_claim
required_answer_constraints:
  - Remove or downgrade unsupported compromise claim.
  - State missing endpoint and raw event coverage.
```

Implementation rules:

- Claims must be `supported`, `contradicted`, `unsupported`, or `limitation`.
- Unsupported claims must be removed, downgraded, or explicitly framed as hypotheses.
- Degraded answers are allowed only when limitations are explicit and verdict claims are not overstated.

### ContextPackage and ContextLedger

`ContextPackage` is the model-call input contract. `ContextLedger` records what evidence was visible to the model at each call.

```yaml
schema_version: context-package/v1
package_id: ctx_20260428_001
objective_ref: obj_20260428_001
budget:
  max_tokens: 6000
  reserved_for_response: 1000
selection_policy:
  strategy: relevance_budgeted
  include_raw_history: false
sections:
  - name: objective
    refs: [obj_20260428_001]
  - name: evidence_summary
    refs: [obs_log_001, obs_log_002]
  - name: constraints
    refs: [do_not_claim_compromise_without_endpoint_evidence]
omitted_refs:
  - raw_chat_history_before_turn_3
```

```yaml
schema_version: context-ledger/v1
ledger_id: ledger_20260428_001
model_call_id: call_20260428_001
context_package_ref: ctx_20260428_001
visible_evidence_refs: [obs_log_001, obs_log_002]
visible_limitations:
  - Splunk backend unavailable; local demo backend used.
do_not_claim_constraints:
  - Do not claim confirmed compromise without successful access, endpoint, or malware evidence.
omitted_evidence_refs: []
```

Implementation rules:

- The model must not receive raw full history by default.
- Context packages must be built through relevance, recency, evidence priority, safety constraints, and token budget.
- Do-not-claim constraints must survive summarization and package rebuilds.
- Every model call that can affect analyst-facing conclusions must have a ledger recording evidence visible to that call.

### AIDecisionLog

`AIDecisionLog` records meaningful AI decisions and must connect AI reasoning to objective, context, evidence, policy, and human feedback.

```yaml
schema_version: ai-decision-log/v1
decision_id: dec_20260428_001
decision_type: final_answer_gate
objective_ref: obj_20260428_001
context_ledger_ref: ledger_20260428_001
input_refs: [obs_log_001, refl_20260428_001]
output_ref: gate_20260428_001
confidence: 0.72
policy_flags: [unsupported_claim_downgraded]
human_feedback:
  status: pending
```

Implementation rules:

- Decision logs must be sufficient to audit why a claim was allowed, blocked, downgraded, or routed for approval.
- Sensitive raw artifacts should be referenced by stable IDs instead of duplicated unless the storage policy explicitly permits duplication.

### CoverageMatrix

`CoverageMatrix` is the normalized record of evidence coverage against lane-specific requirements.

```yaml
schema_version: coverage-matrix/v1
coverage_id: cov_20260428_001
objective_ref: obj_20260428_001
lane: network_log_hunt
requirements:
  - requirement_id: ev_log_events
    required_facets: [timestamp, source_ip, destination_ip, action, raw_event]
    covered_facets: [timestamp, source_ip, action]
    status: partial
    evidence_refs: [obs_log_001]
blocking: true
overall_status: partial_blocking
retry_state:
  attempts: 1
  max_attempts: 2
```

Implementation rules:

- Coverage state is an orchestration signal, not verdict authority.
- Coverage must distinguish `covered`, `partial`, `degraded`, `unavailable`, and `not_applicable`.
- Final answers must state blocking coverage gaps or avoid claims requiring missing coverage.

## Context Management Policy

AISA must treat context as an explicit runtime resource, not an unbounded transcript dump.

- Raw full conversation history is not included in model calls by default.
- The context builder selects content by objective relevance, evidence priority, recency, safety constraints, and token budget.
- Evidence summaries must preserve stable references back to raw observations or artifacts.
- Do-not-claim constraints must be included whenever the answer could otherwise overstate findings.
- Context ledgers must record which evidence, limitations, and constraints were visible to each model call.
- If the model did not see a fact, it must not be treated as model-supported reasoning for that call.
- Summaries are cacheable only if they include source refs and invalidation criteria.

## Evidence Contract and Coverage Policy by Lane

Each lane has a minimum evidence contract. Missing required evidence does not automatically mean benign or malicious; it limits what AISA may claim.

| Lane | Primary evidence | Blocking coverage examples | Claims requiring caution |
|---|---|---|---|
| Identity | authentication events, user, source, target, action, MFA, geo/device, timestamp | user, source, outcome, timestamp, backend | account compromise, impossible travel, credential theft |
| Email | headers, sender, recipients, authentication results, URLs, attachments, body indicators, delivery path | parsed headers, sender identity, auth result, URL or attachment refs when cited | phishing verdict, BEC attribution, credential harvest claim |
| File/malware | file hash, file type, static indicators, strings/imports, signatures, packer/macros, sandbox status if used | file identity, analyzer route, extracted indicators, scoring basis | malware family, execution behavior, persistence, exfiltration |
| Network/log hunt | backend, query, timerange, raw event refs, source/destination, protocol/action, recurrence | timerange, backend, raw events or normalized event refs, fields used in conclusion | intrusion, scanning, lateral movement, exploit success |
| IOC | observable value/type, normalization, enrichment source, reputation result, timestamp, source confidence | normalized IOC, enrichment source status, score evidence | malicious infrastructure, campaign link, active compromise |

Implementation rules:

- Lane contracts live closest to orchestration coverage code and should be mirrored in tests.
- Evidence references must be stable enough for reports, case memory, and decision logs.
- If evidence is synthetic demo data, cached, stale, or unavailable, the answer must say so.
- Deterministic scoring remains authoritative for artifact verdicts even when agent coverage is complete.

## Hypothesis and Root-Cause Policy

Hypotheses help analysts reason, but they are not verdicts.

A hypothesis record should include:

```yaml
schema_version: hypothesis/v1
hypothesis_id: hyp_20260428_001
statement: Repeated denied inbound firewall events may indicate external scanning.
status: plausible
reason_codes: [repeated_denies, external_source, no_successful_connection_seen]
support_refs: [obs_log_001, obs_log_002]
contradict_refs: []
missing_refs: [endpoint_telemetry, successful_connection_events]
attack_stage_chain:
  - reconnaissance
  - attempted_initial_access
claim_limits:
  - Do not claim compromise without successful access or endpoint evidence.
```

Implementation rules:

- Hypothesis status must be one of `candidate`, `plausible`, `supported`, `contradicted`, `downgraded`, or `rejected`.
- Root-cause statements require reason codes and support references.
- Contradictory evidence must be preserved, not summarized away.
- Attack-stage chains must separate observed stages from inferred stages.
- Unsupported root-cause claims must be downgraded to hypotheses or removed by the final-answer gate.

## Calibration and Evaluation Policy

AISA thresholds and confidence behavior must be named, versioned, and testable.

- Scoring thresholds, final-answer gate thresholds, coverage thresholds, and confidence labels must be stored as named policy versions.
- No hidden policy magic numbers may be embedded in prompts or route handlers.
- Any profile, scoring, gating, coverage, or calibration change must run a scenario benchmark before merge.
- Confidence calibration must track at least false-positive rate, false-negative rate, unsupported-claim rate, degraded-answer correctness, and coverage-gap disclosure rate.
- Threshold changes must document rationale, affected lanes, expected behavior changes, and rollback path.
- LLM self-confidence is not calibrated confidence unless mapped through evaluation data and policy.

Example policy metadata:

```yaml
schema_version: calibration-policy/v1
policy_id: final_answer_gate_default
version: 2026-04-28.1
applies_to: [agent_workflow, network_log_hunt, email]
thresholds:
  min_supported_claim_ratio: 0.90
  max_unsupported_final_claims: 0
  min_blocking_coverage_status: covered_or_degraded_disclosed
metrics:
  - unsupported_claim_rate
  - degraded_answer_correctness
  - coverage_gap_disclosure_rate
```

## Scenario Evaluation Harness

Scenario tests are the regression harness for orchestration, coverage, calibration, and final-answer behavior.

Scenario schema:

```yaml
schema_version: scenario/v1
scenario_id: fortigate_historical_scan_001
lane: network_log_hunt
input:
  analyst_request: Investigate historical Fortigate denies from 203.0.113.10 in Splunk.
  runtime_capabilities:
    log.search: available
expected:
  objective:
    lane: network_log_hunt
    requested_backends: [fortigate, splunk]
    timerange: historical
  root_cause:
    allowed_statuses: [plausible, supported]
    forbidden_claims:
      - confirmed host compromise
      - malware execution observed
  evidence:
    required_facets: [timestamp, source_ip, destination_ip, action, backend]
  coverage:
    minimum_status: covered
  scorecard:
    route_correctness: pass
    timerange_preserved: pass
    unsupported_claims: 0
regression_gate:
  block_on:
    - wrong_lane
    - ioc_fallback_for_log_request
    - silent_24h_default
    - unsupported_final_verdict
```

Implementation rules:

- Scenario fixtures must include expected evidence, expected root cause or allowed hypotheses, forbidden claims, coverage expectations, and scorecard assertions.
- Scenario regressions must fail when routing, timerange, unsupported claims, or degraded-state disclosure breaks.
- Scenario benchmarks are required before changing scoring profiles, final-answer gate policy, capability routing, or lane coverage contracts.

## Sub-Investigation Policy

Sub-investigations are bounded child investigations opened to answer a specific evidence gap or pivot.

Open a child investigation when:

- a parent objective has a blocking evidence gap that needs a different lane or backend
- an extracted entity requires separate analysis, such as URL, attachment, hash, user, host, or IP
- a workflow phase explicitly requires a contained pivot
- approval or safety policy requires isolating a high-impact action proposal

Limits and merge rules:

- Child depth must be capped by policy; default maximum depth is `2` unless a workflow explicitly lowers it.
- Child count and tool budget must be capped per parent objective.
- Child investigations inherit parent do-not-claim constraints and add their own lane constraints.
- Child evidence may support or contradict parent hypotheses only after merge with evidence refs.
- A child investigation cannot set the final parent verdict.
- Parent final answers must distinguish parent evidence from child-derived evidence.
- Failed, degraded, or unavailable child investigations must merge as limitations, not disappear.

## Vigil-Inspired Capabilities to Adopt

### Adopt directly in spirit

- specialist agent roles
- markdown-readable workflows
- approval-based response actions
- timeline and graph views
- AI decision feedback logging
- capability truth and integration catalogs

### Adapt carefully

- autonomous daemon mode
- custom integration builder
- background LLM queues
- full case template and SLA systems

### Do not copy blindly

- Anthropic-specific assumptions
- Docker/Postgres/Redis as mandatory dependencies for core local use
- replacing deterministic analysis with agent-only reasoning
- vendor-style marketing abstractions that hide runtime truth

## AI Usage Policy

### LLMs may

- explain evidence
- summarize findings
- suggest next investigative steps
- assist workflow execution
- produce reports and detection drafts
- help orchestrate tool use within policy boundaries

### LLMs must not

- silently assign final artifact verdicts by themselves
- override deterministic scores without explicit product design change
- suppress contradictory evidence
- present missing integrations as successful results
- execute high-impact response actions without governance logic
- replace tool-backed investigation with unsupported model inference

## MCP and Integration Strategy

MCP remains the primary extensibility surface for AISA.

The long-term target is:

- core analysis works without MCP
- investigation power increases substantially with MCP
- workflows declare when they require, prefer, or optionally use MCP tools
- settings and health surfaces tell the truth about what is actually available

The best integration direction learned from Vigil is not "more MCP everywhere."
It is "clear integration control plane plus explicit workflow/tool expectations."

The best analysis direction remains:

- AISA tools produce evidence and verdicts
- workflow and agent layers consume and organize those outputs

## Implementation Lanes

Work in one lane at a time.

### Analysis core lane

- IOC
- file
- email
- scoring
- reporting

### Workflow lane

- workflow definitions
- workflow parser
- workflow execution state
- workflow UI

### Specialist agent lane

- agent profiles
- methodology prompts
- tool policy
- evidence-linked outputs

### Case intelligence lane

- cases
- graph
- timeline
- cross-analysis correlation

### Governance lane

- approval queue
- AI decision logs
- feedback
- action audit

### Integration control lane

- MCP
- custom integration metadata
- capability catalog
- source truth and health

### Background automation lane

- daemon
- scheduler
- queued reasoning
- polling and monitoring

## Definition of Done

A change is done only if:

- it fits an owning layer
- deterministic analysis semantics are preserved where applicable
- evidence remains visible
- degraded states are honest
- docs reflect the change
- relevant tests were updated or explicitly deferred
- new Vigil-inspired concepts do not weaken AISA's local-first and analyst-trust rules

## Open Design Decisions

These decisions are intentionally open and should be resolved through implementation plans, scenario benchmarks, and focused tests rather than prompt-only behavior.

- Where should persistent `ContextLedger` records live: governance store, case memory, investigation workdir, or a dedicated context store?
- Which fields are mandatory for `AIDecisionLog` persistence versus optional runtime-only metadata?
- What is the canonical policy registry location for named/versioned thresholds across scoring, coverage, final-answer gate, and confidence calibration?
- How should scenario benchmark results be stored and compared across local developer runs, CI, and demo datasets?
- What is the default child-investigation depth, child count, and tool budget for each lane?
- Which lane coverage requirements should be blocking by default versus warning-only during rollout?
- How should stale, cached, demo, and live evidence be labeled consistently across reports, chat, and case memory?
- What is the minimum context-ledger retention policy for local-first deployments with sensitive artifacts?
- Which root-cause reason codes become canonical enum values, and where should they be defined?
- When final-answer gate blocks a response, should the UI display the blocked draft internally for audit, or only the rewritten grounded answer?
