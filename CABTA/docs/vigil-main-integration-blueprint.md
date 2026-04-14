# Vigil Main Integration Blueprint for AISA

## Purpose

This document explains what `vigil-main` contributes conceptually and technically to AISA, what should be integrated, and how to do it without breaking AISA's architecture.

It is the bridge between:

- the `vigil-main/` repository
- AISA's current system
- implementation planning for future phases

## Scope of Review

The following Vigil areas were reviewed closely:

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/AGENTS.md`
- `docs/INTEGRATIONS.md`
- `docs/FEATURES.md`
- `workflows/*/WORKFLOW.md`
- `services/workflows_service.py`
- `services/investigation_workflow_service.py`
- `services/soc_agents.py`
- `services/approval_service.py`
- `services/mcp_registry.py`
- `services/mcp_service.py`
- `services/case_search_service.py`
- `services/database_data_service.py`
- `services/graph_builder_service.py`
- `services/timeline_service.py`
- `services/integration_bridge_service.py`
- `services/custom_integration_service.py`
- `backend/api/workflows.py`
- `backend/api/mcp.py`
- `backend/api/ai_decisions.py`
- `backend/api/case_search.py`
- `backend/api/graph.py`
- `backend/api/timeline.py`
- `services/llm_gateway.py`
- `daemon/main.py`
- `daemon/agent_runner.py`
- `daemon/shared_intel.py`
- `core/secrets.py`
- `core/telemetry_sanitizer.py`
- `data/taxonomy/capability-taxonomy.yaml`
- `mcp-config.json`

## Executive Conclusion

`vigil-main` is not just "another SOC app."
It contains a more mature investigation orchestration model than AISA currently has.

The most valuable contribution to AISA is not its vendor list or branding.
It is its structure:

- specialist AI roles
- readable workflow definitions
- richer investigation-state services
- governance around actions and AI decisions
- stronger integration control

These ideas fit AISA well if integrated carefully.

## Authoritative Integration Stance

The integration should follow this exact split:

### CABTA/AISA owns the analysis core

CABTA/AISA remains the authoritative owner of:

- tool orchestration for IOC, file, and email analysis
- analyzer execution
- integration normalization
- scoring
- verdict governance
- analyst-facing evidence contracts

This is the source of truth for verdict-bearing flows.

### Vigil-inspired features own the orchestration plane

Vigil contributes patterns for:

- specialist agent roles
- workflow and playbook orchestration
- approval workflow
- headless SOC daemon concepts
- richer case-linked investigation control

These components should sit above and around the AISA core.
They should not replace the AISA core.

### Tool-first investigation rule

If an agent or workflow needs evidence, it must obtain that evidence through:

- AISA analysis tools
- AISA integrations
- AISA scoring-aware services
- approved MCP tools

The orchestration layer may:

- request
- route
- summarize
- prioritize
- recommend

It may not fabricate investigative evidence or silently replace tool-backed analysis.

## High-Value Capabilities to Bring Into AISA

### 1. Specialist Agent Library

Vigil pattern:

- explicit `AgentProfile` objects in `services/soc_agents.py`
- role-specific methodologies for triage, investigation, hunt, response, reporting, and ATT&CK analysis

Why it matters for AISA:

- AISA already has agent tooling and playbooks
- explicit roles would make behavior more predictable
- workflows become easier to author when agent roles are named and bounded

Recommended AISA adaptation:

- create explicit role profiles for:
  - triage
  - investigator
  - threat hunter
  - correlator
  - responder
  - reporter
  - MITRE analyst
  - malware analyst
  - network analyst

Integrate into:

- `src/agent/*`
- playbook/workflow execution layer
- agent UI selection

### 2. Workflow Definitions as Readable Assets

Vigil pattern:

- `workflows/*/WORKFLOW.md`
- YAML frontmatter + markdown phases
- `services/workflows_service.py` for discovery and execution prompt assembly

Why it matters for AISA:

- AISA has playbooks today, but long-term reusable workflow structure can be clearer and more inspectable
- workflows are a better vehicle for repeatable SOC processes than hidden prompt logic

Recommended AISA adaptation:

- adopt a readable workflow definition format
- keep metadata explicit:
  - workflow id
  - description
  - specialist roles
  - required/preferred tools
  - expected outputs
- encode which steps are:
  - evidence-gathering
  - orchestration-only
  - approval-gated
- do not depend on raw LLM prompt concatenation alone; add execution state and contract awareness

Integrate into:

- future workflow definition directory
- workflow parser/registry
- web UI and case linkage

### 3. Case-Centered Investigation State

Vigil pattern:

- `services/investigation_workflow_service.py`
- `services/case_workflow_service.py`
- database-backed case objects, phases, tasks, templates, SLA concepts

Why it matters for AISA:

- AISA has cases, but they should evolve from passive grouping into active investigation containers

Recommended AISA adaptation:

- start with lightweight investigation-state evolution:
  - workflow attached to case
  - phase status
  - discovered entities
  - notes and pivots
- defer heavier template/SLA systems until later

### 4. Graph and Timeline Intelligence

Vigil pattern:

- `services/graph_builder_service.py`
- `services/timeline_service.py`

Why it matters for AISA:

- AISA already extracts many entities and findings from IOC/file/email flows
- graph and timeline views would turn those outputs into investigation-native artifacts

Recommended AISA adaptation:

- normalize entity extraction across existing analysis results
- build:
  - entity graph
  - attack path graph
  - timeline reconstruction
- link these to cases and reports

### 5. Approval-Driven Response Governance

Vigil pattern:

- `services/approval_service.py`
- confidence thresholds
- action typing
- audit-ready pending action model

Why it matters for AISA:

- AISA already has agent/playbook actions and sandbox approvals
- response workflows will need clearer governance as capability grows

Recommended AISA adaptation:

- create a first-class approval action model
- distinguish:
  - auto-allowed
  - approval-required
  - manual-only
  - monitor-only
- preserve current honesty around degraded and optional features
- only allow action proposals to be generated from evidence-backed workflow state

### 6. AI Decision Logging and Human Feedback

Vigil pattern:

- `backend/api/ai_decisions.py`
- stored reasoning, confidence, recommended action, human review, and outcome

Why it matters for AISA:

- AISA increasingly uses agent reasoning for workflow guidance and action suggestions
- ephemeral reasoning is hard to trust and impossible to improve

Recommended AISA adaptation:

- store high-value AI decisions only
- capture:
  - agent role
  - context
  - reasoning summary
  - confidence
  - recommendation
  - human agreement or correction

### 7. Stronger Integration Control Plane

Vigil pattern:

- `services/mcp_registry.py`
- `services/mcp_service.py`
- `backend/api/mcp.py`
- `mcp-config.json`

Why it matters for AISA:

- AISA already uses MCP heavily
- the next problem is not just more tools, but clearer tool truth and capability governance

Recommended AISA adaptation:

- keep AISA's current MCP foundation
- add:
  - capability catalog
  - dependency declarations for workflows
  - clearer enabled/connected/usable/manual/degraded states
  - richer metadata for tools and servers

### 8. Custom Integration Builder

Vigil pattern:

- `services/custom_integration_service.py`
- frontend builder UI
- AI-assisted server generation from docs

Why it matters for AISA:

- AISA's MCP-centric expansion model would benefit from easier onboarding of new tools

Recommended AISA adaptation:

- treat this as a later-phase feature
- first create a strong metadata model and validation path
- then consider guided integration scaffolding

### 9. Optional Daemon and Background Automation

Vigil pattern:

- `daemon/main.py`
- queueing, polling, orchestrator, metrics

Why it matters for AISA:

- opens future path for scheduled hunts and monitoring

Why it must be handled carefully:

- AISA must not make this mandatory for normal localhost use

Recommended AISA adaptation:

- keep daemon mode optional
- add only after workflow, governance, and capability truth are stronger

### 10. Capability Taxonomy

Vigil pattern:

- `data/taxonomy/capability-taxonomy.yaml`

Why it matters for AISA:

- helps describe what the platform can do in structured terms
- useful for docs, settings, MCP classification, and future planning

Recommended AISA adaptation:

- define capability catalog and taxonomy for:
  - analysis
  - workflow
  - investigation
  - governance
  - integration

## Additional High-Value Opportunities From Deeper Review

The sections above describe the main integration direction.

After a deeper pass through `vigil-main`, several additional ideas stand out as especially valuable for AISA.
These are not all equal.
Some are immediate leverage.
Some are later-stage hardening.
Some should only be adapted partially.

### 11. Similarity Search as an Investigation Primitive

Vigil pattern:

- `services/database_data_service.py`
- `nearest_neighbors`
- case search by shared IOC and shared MITRE overlap

Why it matters for AISA:

- AISA already has strong artifact analysis and growing case intelligence
- what it still lacks is a strong "show me similar things" pivot across prior investigations
- this is one of the best ways to make an agent feel more like an investigator and less like a summarizer

Recommended AISA adaptation:

- add finding and case similarity as first-class pivots
- keep the similarity layer evidence-oriented:
  - shared IOC overlap
  - shared ATT&CK overlap
  - shared entity overlap
  - optional embeddings-backed similarity where data quality justifies it
- expose this to:
  - workflows
  - agent tools
  - case views
  - related-case recommendations

Why this is high leverage:

- improves triage speed
- improves threat hunting
- improves case reuse and institutional memory
- does not weaken verdict authority

### 12. Cross-Investigation Shared Intelligence

Vigil pattern:

- `daemon/shared_intel.py`
- centralized IOC/entity tracker for overlap detection

Why it matters for AISA:

- AISA already runs IOC, file, and email analyses that discover entities
- today those outputs are still too isolated between sessions and cases
- a shared-intelligence layer would let AISA notice:
  - repeated infrastructure
  - overlapping hosts/users
  - recurring hash/domain clusters
  - cases that should probably be linked

Recommended AISA adaptation:

- build a shared entity and IOC registry around existing case intelligence
- start simple:
  - case-level overlap
  - workflow-level overlap
  - recurring IOC detection
- do not overfit to daemon mode; make the shared-intel layer usable from normal web flows too

### 13. Investigation Artifacts as Working Objects

Vigil pattern:

- `daemon/agent_runner.py`
- workdir files, plan state, per-investigation artifacts, completion signals

Why it matters for AISA:

- AISA already has session state, playbooks, workflows, governance logs, and case data
- what Vigil adds is a disciplined "working set" model for an investigation

Recommended AISA adaptation:

- introduce a lightweight investigation working set for agentic workflows:
  - objectives
  - collected evidence references
  - open questions
  - generated hunt queries
  - candidate actions
  - analyst feedback
- make these explicit artifacts, not only transient chat state

Important boundary:

- these working artifacts support orchestration
- they do not become a second verdict system

### 14. Integration Truth, Readiness, and Test Semantics

Vigil pattern:

- `services/integration_bridge_service.py`
- config-to-env mapping
- integration readiness/status APIs
- explicit distinction between configured, enabled, server available, and ready

Why it matters for AISA:

- AISA already has good MCP and settings improvements, but this is still an area where drift can happen
- strong integration semantics help both humans and agents know what is actually usable

Recommended AISA adaptation:

- push AISA further toward a capability-truth model:
  - configured
  - enabled
  - connected
  - usable
  - degraded
  - manual
  - not implemented
- keep test semantics honest:
  - "config is present" is not the same as "live query works"
  - "tool registered" is not the same as "tool is healthy"
- attach capability truth to:
  - settings
  - dashboard
  - agent tool selection
  - workflow dependency checks

### 15. Secure Secrets Resolution and Telemetry Sanitization

Vigil pattern:

- `core/secrets.py`
- `core/telemetry_sanitizer.py`

Why it matters for AISA:

- AISA is growing into a more operational platform
- it handles API keys, tool results, prompts, artifacts, and potentially log-hunting queries
- this creates new risk surfaces in:
  - config persistence
  - logs
  - telemetry
  - debugging

Recommended AISA adaptation:

- introduce a unified secret-resolution layer with explicit precedence:
  - runtime env
  - secure local secrets store
  - project config fallback
- add telemetry/log sanitization for:
  - API keys
  - tokens
  - raw findings
  - prompts/responses where needed
  - sensitive tool inputs/outputs

This is a high-value hardening feature.
It is not flashy, but it will matter more as AISA gets more autonomous.

### 16. Executive and Board-Grade Reporting

Vigil pattern:

- `docs/templates/board-brief.md`
- board brief flow in reporting agent

Why it matters for AISA:

- AISA already has reporting, executive outputs, and case summaries
- Vigil adds a stronger idea: reports for different audiences should be first-class products, not one summary rewritten three times

Recommended AISA adaptation:

- extend AISA reporting into audience-specific modes:
  - analyst technical report
  - incident summary
  - executive brief
  - board brief
- keep the board-grade output:
  - plain language
  - few metrics
  - evidence-backed
  - action-oriented
- do not let LLM improvise business metrics; all board/executive numbers must come from structured case and analysis data

### 17. Detection and Coverage Intelligence as a Separate Plane

Vigil pattern:

- detection engineering tools
- ATT&CK coverage analysis
- gap identification
- template generation

Why it matters for AISA:

- AISA already generates detection rules
- what it lacks is a stronger "coverage intelligence" layer around those rules

Recommended AISA adaptation:

- do not copy Vigil's detection stack wholesale
- instead add a dedicated AISA layer for:
  - ATT&CK coverage summaries
  - detection gap recommendations
  - hunt-to-detection feedback loops
  - analyst review of generated rules

This is especially valuable after live log hunting matures.

## Mapping Vigil Concepts to AISA

| Vigil concept | AISA equivalent target | Recommendation |
|---|---|---|
| Specialized agents | Agent profile library | Adopt early |
| WORKFLOW.md | Readable workflow definitions | Adopt early |
| Investigation workflow service | Case-linked workflow state | Adapt early |
| Graph builder | Entity graph / attack path | Add after entity normalization |
| Timeline service | Timeline view for cases and reports | Add after case-state growth |
| Approval service | Action governance layer | Add in governance phase |
| AI decision API | AI decision log + feedback | Add in governance phase |
| MCP registry/service | Capability truth model | Extend current AISA MCP model |
| Custom integration builder | Guided MCP integration onboarding | Later phase |
| Daemon | Optional background SOC mode | Late optional phase |

## What AISA Should Not Copy Directly

### 1. Anthropic-specific assumptions

Vigil is structurally tied to Claude-centric services in several places.
AISA should remain provider-flexible.

### 2. Mandatory infrastructure for core use

Vigil leans more naturally toward:

- PostgreSQL
- Redis
- Docker
- background services

AISA should not require these for core localhost analysis.

### 3. Backend-tool-first assumption for all workflows

Vigil's model assumes a strong findings/cases backend.
AISA's current strength is artifact-centric analysis.

Therefore AISA should:

- preserve artifact-first flows
- add workflow and case intelligence around them

### 4. Vendor-style feature sprawl

Vigil shows many integrations and features.
AISA should adopt the structure, not the sprawl.

### 5. Hard coupling to a single model vendor or agent runtime

Vigil makes strong use of Anthropic and Agent SDK assumptions.
AISA should keep:

- provider flexibility
- deterministic analysis independence
- workflow portability across providers

### 6. "Configured means working" semantics

Parts of Vigil's config and integration bridge are useful, but AISA should avoid treating:

- saved credentials
- enabled flags
- registered tools

as proof that a capability is actually live and healthy.

### 7. Purely confidence-driven response authority

Vigil's confidence-threshold model is useful for approvals, but AISA must not let response authority drift away from:

- evidence-backed workflow state
- deterministic analysis results
- explicit policy guardrails

Confidence helps govern actions.
It must not replace the CABTA/AISA verdict path.

## Recommended Integration Order

### First

- specialist agent profiles
- workflow definition model
- capability catalog groundwork
- explicit analysis-core versus orchestration-plane boundaries in code and docs

### Second

- case-linked workflow state
- graph and timeline foundations

### Third

- approval service
- AI decision logging

### Fourth

- custom integration builder
- optional daemon mode

## Highest-Value Additional Additions After Deeper Review

If AISA wants the best of Vigil without unnecessary sprawl, the strongest additions beyond the already planned agent/workflow/governance ideas are:

1. finding and case similarity pivots
2. shared-intelligence overlap tracking across investigations
3. richer integration readiness and test semantics
4. secret-resolution and telemetry-sanitization hardening
5. executive and board-grade reporting modes
6. coverage-intelligence around generated detections

These six items provide a lot of practical leverage without forcing AISA to become a clone of Vigil.

## Best Immediate Code Targets in AISA

When implementation begins, the most likely touch points are:

- `src/agent/*`
- `src/web/routes/*`
- `src/web/case_store.py`
- future workflow service modules
- future governance service modules
- MCP management and runtime capability layers
- future shared-intelligence and similarity services
- future secret-management and telemetry hygiene modules

## Best Documentation Set for Vibe Coding

When implementing Vigil-inspired upgrades in AISA, use these docs together:

1. `docs/project-overview-pdr.md`
2. `docs/system-design.md`
3. this `docs/vigil-main-integration-blueprint.md`
4. `docs/future-system-roadmap.md`
5. `docs/vibe-coding-operating-model.md`

## Final Assessment

The best way to combine Vigil with AISA is:

- keep AISA's deterministic analysis core
- add Vigil's investigation and orchestration strengths around it
- introduce governance before deeper automation
- improve capability truth before adding more integrations
- add similarity, shared-intelligence, and reporting intelligence as investigation multipliers

The two most important rules are:

1. CABTA/AISA scoring always remains the verdict source of truth.
2. Workflows must call tools to gather evidence instead of letting the model "guess" investigations.

That combination gives AISA a credible path toward becoming a stronger AI SOC assistant without losing the qualities that already make it useful.

## Unresolved Questions

- None.
