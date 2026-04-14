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
- Current repo/application path: `CABTA/`
- Primary product mode: `localhost web application`
- Secondary interfaces:
  - CLI
  - MCP server
  - Python import

When implementation and branding disagree, prefer:

- `AISA` for product/UI/docs
- `CABTA/` for current file layout and compatibility

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

They may not override CABTA/AISA scoring as the final verdict source for analysis flows.

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

## Unresolved Questions

- None.
