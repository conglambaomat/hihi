# CABTA Future System Roadmap

## Purpose

This roadmap describes how CABTA should evolve after studying `vigil-main`.

It is not a generic wishlist.
It is a phased implementation guide for turning CABTA from a strong local-first analysis platform into a stronger AI SOC assistant without breaking its current strengths.

Legacy naming note: older strategic material may still refer to the same product direction as `AISA` / `AI Security Assistant`. For implementation, architecture, UI, and new docs, treat `CABTA` as the canonical product name.

## Current Position

CABTA already has meaningful depth in:

- IOC investigation
- malware and file analysis
- email forensics
- reporting
- agent chat and playbooks
- MCP management
- local-first web delivery

The next step is not "add random AI features."
The next step is to make the platform more coherent and investigation-native.

## What Vigil Adds Strategically

The most useful lessons from Vigil are:

- specialist agent roles
- markdown-readable workflow definitions
- richer case-centered investigation model
- graph and timeline intelligence
- approval-driven action governance
- AI decision logging and feedback
- stronger integration control plane
- optional daemonized autonomous operations

These should be adapted into CABTA in phases.

## Integration Direction

The integration direction is:

- CABTA keeps the analysis core and verdict governance
- Vigil-inspired features provide the orchestration plane

That means:

- CABTA scoring remains the source of truth for verdicts
- workflows and specialist agents must call real tools for evidence
- approval and daemon capabilities wrap around the core instead of replacing it

## Non-Negotiable Direction

Future CABTA must remain:

- local-first
- evidence-first
- deterministic for verdict-bearing analysis flows
- usable with partial configuration
- transparent about degraded states

Future CABTA must avoid becoming:

- a cloud-required SOC product
- an LLM-only analyst replacement
- a workflow shell that weakens artifact-analysis quality
- a black-box autonomous responder

## Priority Themes

### 1. Preserve analysis truth while adding orchestration power

### 2. Make investigations first-class, not just individual analyses

### 3. Govern AI actions and recommendations more explicitly

### 4. Improve integration power without losing clarity

### 5. Package all of this into docs and contracts that AI coding can follow safely

## Recommended Phases

## Phase 0: Architectural Alignment and Contract Cleanup

**Goal:** prepare CABTA to absorb Vigil-inspired capabilities safely.

### Outcomes

- docs align on the two-plane model: analysis plane plus investigation plane
- CABTA identity is consistent in product docs
- core result contracts and capability states are explicit enough to support deeper orchestration

### Workstreams

- refresh system docs and roadmap
- normalize naming and contract language
- define what belongs to:
  - deterministic analysis
  - agentic workflow orchestration
  - governance
  - integration control

### Exit Criteria

- contributors can tell where a feature should live before coding
- docs are precise enough to support long multi-session implementation work

## Phase 1: Specialist Agent Foundation

**Goal:** move from generic agent behavior to explicit role-based agent profiles.

### Outcomes

- named agent profiles for:
  - triage
  - investigator
  - threat hunter
  - correlator
  - responder
  - reporter
  - MITRE analyst
  - malware analyst
  - network analyst
- each role has methodology, tool boundaries, and output expectations

### Workstreams

- agent profile library
- agent role selection UX
- role-specific prompt and policy structure
- output contract for specialist agent results

### Exit Criteria

- agent behavior is more predictable and reusable
- playbooks can target named roles instead of only generic freeform chat
- agent roles are explicitly prevented from becoming final verdict authority

## Phase 2: Workflow-First Investigation Engine

**Goal:** make workflows readable, inspectable, and first-class.

### Outcomes

- markdown or similarly human-readable workflow definitions
- workflow discovery, validation, and reload flow
- phase-by-phase execution state
- workflow run history linked to cases or sessions
- tool-first workflow execution semantics

### Workstreams

- workflow definition format
- workflow parser and registry
- workflow execution service
- workflow UI and API
- workflow-to-agent role mapping
- explicit evidence-source declarations for workflow steps
- enforcement that verdict-bearing steps route through CABTA analysis tools

### Exit Criteria

- analysts can inspect what a workflow does before running it
- developers can extend workflows without burying logic in Python only
- workflow runs use tool-backed evidence collection instead of model-only inference

## Phase 3: Case Intelligence, Graph, and Timeline

**Goal:** make CABTA investigations cumulative and navigable.

### Outcomes

- richer case model
- entity relationship graph
- event timeline reconstruction
- stronger cross-analysis pivoting
- finding and case similarity pivots
- recurring IOC and entity overlap visibility

### Workstreams

- case schema growth
- evidence linkage
- entity extraction normalization
- graph builder service
- timeline service
- ATT&CK overlays and correlation summaries
- related-case scoring via shared IOC and ATT&CK overlap
- optional embeddings-backed nearest-neighbor search for findings and cases
- shared-intelligence registry for recurring IOC and entity reuse across investigations

### Exit Criteria

- related IPs, hosts, users, hashes, domains, and findings can be explored from one investigation context
- CABTA supports "what happened and how is it connected?" better than isolated artifact screens
- CABTA can answer "have we seen something like this before?" with structured evidence

## Phase 4: Governance, Approval, and AI Decision Logging

**Goal:** make AI-assisted response and recommendation flows auditable and safe.

### Outcomes

- approval queue for privileged actions
- confidence-based response gating
- AI decision logs with reviewer feedback
- action audit trails

### Workstreams

- approval action model
- approval service
- AI decision logging schema
- decision feedback UI
- action policy thresholds

### Exit Criteria

- response actions are reviewable
- agent reasoning is not ephemeral
- analysts can audit and improve AI behavior over time
- governance layers operate on evidence-backed conclusions, not unsupported model guesses

## Phase 5: Integration Control Plane and Capability Catalog

**Goal:** make integrations easier to understand, safer to operate, and more useful to agents.

### Outcomes

- machine-readable capability catalog
- clearer MCP tool truth model
- integration health and readiness visibility
- groundwork for custom integration onboarding
- stronger config-to-runtime integration bridging
- honest test semantics for integrations and MCP-backed tools
- clearer secret handling for operational deployments

### Workstreams

- capability catalog generator
- MCP tool classification
- workflow dependency declarations
- source and tool readiness states
- custom integration metadata model
- integration bridge for config, env, and runtime application
- readiness/test states that distinguish configured from live-verified
- secret-resolution layer with explicit precedence
- telemetry and logging sanitization for keys, raw findings, prompts, and tool content

Partial implementation now in place:

- machine-readable capability catalog includes explicit readiness metadata for analysis core, tools, workflows, MCP, and daemon runtime
- orchestration/control-plane summary now distinguishes inventory presence from ready runtime state
- daemon worker supervision is exposed as part of runtime/control-plane truth instead of only queue counters

### Exit Criteria

- CABTA can say exactly which tools and integrations are available, optional, manual, degraded, or not configured
- agent and workflow selection improve because tool truth is explicit
- operational telemetry and logs do not casually leak sensitive material

## Phase 6: Detection and Hunt Intelligence Expansion

**Goal:** combine CABTA's artifact-analysis strengths with a stronger hunt and detection engineering layer.

### Outcomes

- richer threat-hunt workflows
- better detection-content generation
- stronger ATT&CK and coverage guidance
- optional log-query pivots through SIEM MCP servers
- hunt-to-detection feedback loops
- detection coverage and gap summaries around generated rules

### Workstreams

- hunt workflow improvements
- detection recommendation pipelines
- coverage and gap analysis concepts
- log-hunt tool interfaces for Splunk/Elastic/Sentinel via MCP
- similarity-assisted hunting pivots
- board-safe summaries of hunt outcomes and coverage posture

### Exit Criteria

- CABTA supports proactive hunt workflows better, not only reactive analysis
- detection engineering becomes a structured output, not only an afterthought

## Phase 7: Optional Daemon and Background Operations

**Goal:** add optional background autonomy without making it mandatory for normal product use.

### Outcomes

- optional daemon mode
- polling and scheduled hunts
- queued background reasoning
- monitored autonomous operations
- shared-intelligence memory across concurrent or recurring investigations
- investigation working sets for headless multi-step operations
- resumable queue jobs with explicit lease / retry / cancel transitions
- compatibility-preserving thread-per-session runtime during worker migration

### Workstreams

- background job model
- queueing or scheduler layer
- safe polling sources
- background notifications and metrics
- cross-investigation IOC/entity overlap tracking
- persistent working artifacts for daemon-led investigations
- approval-aware background orchestration
- resumable lease metadata:
  - lease expiry
  - resume token
  - last transition
- cancel / resume controls for queued daemon jobs
- bounded cycle concurrency and explicit runtime migration status

### Exit Criteria

- teams that want 24/7 monitoring can enable it
- localhost single-user mode remains simple and strong
- daemon mode improves investigations without becoming a required dependency
- runtime status clearly explains the current compatibility path and future worker migration target

## Phase 8: Productization and Operational Hardening

**Goal:** make the upgraded platform easier to test, run, and extend.

### Outcomes

- better CI and regression gates
- stronger packaging and deployment
- clearer extension contracts
- improved observability
- audience-specific reporting modes for analyst, executive, and board contexts

### Workstreams

- contract regression tests
- workflow and agent integration tests
- packaging and deployment cleanup
- performance and telemetry improvements
- executive and board-grade report templates backed by structured case data

### Exit Criteria

- future feature work lands with less risk
- the platform feels operational, not experimental
- reporting quality scales across technical and leadership audiences without hand-rewriting

## Highest-Value Candidate Epics

If work must be prioritized tightly, start here:

### Epic 1: specialist agent foundation

Why:

- unlocks clearer workflow orchestration
- improves agent predictability immediately

### Epic 2: workflow definition and execution engine

Why:

- highest leverage Vigil-inspired feature
- turns repeated investigation behavior into explicit reusable assets

### Epic 3: case intelligence with graph and timeline

Why:

- converts CABTA from analysis toolkit to investigation platform

### Epic 4: approval and AI decision logging

Why:

- adds trust, governance, and auditability

### Epic 5: capability catalog and integration control plane

Why:

- reduces drift between reality, UI, agent behavior, and developer docs

### Epic 6: case similarity and shared investigation memory

Why:

- gives agents and analysts a concrete way to pivot from one incident to similar prior evidence
- increases investigation quality without weakening verdict authority

### Epic 7: secrets, telemetry hygiene, and operational truth

Why:

- autonomy and integrations become dangerous without strong secret handling and honest status semantics

## Recommended Near-Term Sequence

The best practical order is:

1. Phase 0
2. Phase 1
3. Phase 2
4. partial Phase 5
5. Phase 3
6. Phase 4
7. partial Phase 6
8. partial Phase 7

This order gives CABTA the structure to absorb later complexity safely.

## Roadmap Guardrail

At every phase, preserve this rule:

- CABTA core decides verdicts
- Vigil-inspired orchestration coordinates workflows and actions

If a proposed feature weakens that separation, it should be redesigned before implementation.

## Unresolved Questions

- None.
