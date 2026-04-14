# AISA Project Overview

## Product Identity

- Canonical UI/product name: `AISA`
- Expanded name: `AI Security Assistant`
- Current repo/application path: `CABTA/`
- Primary product mode: `web-first localhost SOC and DFIR workbench`

For implementation, treat `AISA` as the product identity and `CABTA/` as the current repository and package location until an explicit migration is planned.

## Product Thesis

AISA should evolve from a strong local-first analysis toolkit into a local-first AI SOC assistant platform.

Its long-term value is not only:

- IOC triage
- suspicious file analysis
- email forensics

It is the combination of:

- deterministic artifact analysis
- case-centered investigation workflows
- specialist AI agents
- governed response actions
- extensible MCP-based tool connectivity
- evidence-linked reporting and recall

In short:

AISA should become an analyst-owned investigation platform, not just a set of analyzers and not a black-box AI SOC.

## Product Purpose

AISA helps defenders move from raw security inputs to trustworthy investigation outcomes.

It should turn alerts, artifacts, and hypotheses into:

- structured evidence
- deterministic verdicts where applicable
- explainable recommendations
- linked cases and investigation context
- repeatable workflows
- governed response proposals
- reusable reports and exports

## Strategic Direction

AISA should combine:

### AISA's existing strengths

- local-first operation
- broad IOC, file, and email analysis coverage
- deterministic scoring and verdict logic
- analyst-readable reporting
- MCP interoperability

### Vigil-inspired strengths

- specialist AI agent roles
- markdown-defined multi-agent workflows
- case workflow automation
- entity graph and timeline views
- approval-driven response governance
- AI decision logging and feedback loops
- richer integration control plane
- optional background autonomous operations

The goal is not to copy Vigil mechanically.

The goal is to adapt the best ideas into AISA's architecture while preserving AISA's strongest constraints:

- evidence first
- deterministic verdicts
- local-first usability
- graceful degradation

## Authoritative Integration Stance

The integration direction is intentionally asymmetric.

### AISA owns the analysis core

AISA remains the system of record for:

- artifact analysis
- evidence extraction
- enrichment normalization
- scoring
- verdict governance
- analyst-facing evidence outputs

That means verdict-bearing flows still belong to AISA's existing core:

- IOC investigation
- file analysis
- email analysis

### Vigil-inspired features own the orchestration plane

Vigil should be treated as the source of ideas and patterns for:

- specialist agent roles
- workflow and playbook orchestration
- approval-driven response flow
- optional headless SOC daemon behavior
- richer investigation coordination

These features should sit around the AISA core, not replace it.

### Tool-first integration rule

Workflow execution must gather evidence through real tools and services.

In practice, that means:

- workflows call AISA analyzers, orchestrators, integrations, scoring, and MCP tools
- agents summarize, organize, plan, and recommend
- agents do not invent investigative evidence
- workflows do not substitute model speculation for tool execution

### Verdict rule

For any flow that produces a security verdict, the final verdict must come from the AISA scoring and evidence path.

Agent outputs may:

- propose
- summarize
- prioritize
- explain
- recommend next steps

Agent outputs may not silently become the final verdict source of truth.

## Primary Users

- SOC analysts
- incident responders
- threat hunters
- malware analysts
- email security analysts
- security engineers building MCP-assisted security workflows
- team leads who need auditable, reusable investigation outputs

## Core User Problems

### 1. IOC, file, and email analysis are still too isolated

Analysts can get strong per-artifact results, but investigations often require richer case context, pivoting, and workflow continuity.

### 2. AI-assisted investigation often lacks governance

Many AI SOC products can summarize, but they do not provide enough:

- approval control
- evidence traceability
- confidence-aware actions
- auditability

### 3. Repeated investigation patterns are not first-class enough

Security teams repeat common workflows:

- alert triage
- phishing review
- incident response
- threat hunting
- malware deep dive

These should become explicit, editable workflows instead of ad hoc operator behavior.

### 4. Tool ecosystems are fragmented

Security operations require many external systems:

- TI providers
- sandboxes
- SIEMs
- EDR/XDR tools
- ticketing systems
- chatops systems

These need a clear extensibility model with runtime visibility and safe agent access.

### 5. Local-first users still need "platform power"

AISA should remain useful on a single analyst machine, but still grow toward:

- richer workflow orchestration
- case intelligence
- graph and timeline analysis
- governed automation

without turning cloud dependency into a requirement.

## Product Pillars

### Deterministic Analysis Core

Verdicts for IOC, file, and email workflows must remain driven by:

- extraction
- heuristics
- enrichment
- scoring
- explicit mapping logic

LLMs may explain and assist, but they do not replace final verdict authority.

### Evidence-Linked Investigation Plane

AISA should support longer-lived investigations through:

- cases
- workflows
- notes
- pivots
- timelines
- graph relationships

### Specialist AI Agents

AISA should move toward role-based assistants such as:

- triage
- investigator
- threat hunter
- correlator
- responder
- reporter
- MITRE analyst
- malware analyst
- network analyst

These should be explicit product concepts, not only hidden prompt variations.

### Workflow-First Operations

High-value workflows should be editable and inspectable.

Good targets include:

- incident response
- full investigation
- threat hunt
- phishing investigation
- malware deep dive
- case review and reporting

### Governance and Human Oversight

AI actions must be governed with:

- approval policies
- confidence thresholds
- audit history
- decision logging
- clear degraded or manual states

### MCP-First Extensibility

AISA should continue treating MCP as the main expansion surface for:

- SIEM
- EDR
- threat intel
- sandbox
- case export
- collaboration tools

### Local-First by Default

The main product path must remain useful:

- on localhost
- without paid APIs
- without mandatory cloud LLM
- under partial integration availability

## Capability Model

### Current strong capabilities

- IOC investigation
- file and malware analysis
- email analysis
- reporting
- dashboard and history
- cases
- agent and playbook foundations
- MCP server management

### Target platform capabilities

- specialist agent library
- markdown workflow orchestration
- richer case workflows and templates
- investigation graph and timeline intelligence
- governed response proposals
- AI decision audit and feedback loops
- integration catalog and health truth model
- optional daemonized background monitoring and hunting

## Non-Goals

AISA should not become:

- an LLM-only verdict engine
- a cloud-required SOC platform for basic use
- a black-box autonomous responder
- a generic agent shell with weak security semantics
- a product that hides evidence behind persuasive summaries

## Product Constraints

- local-first must remain true for the core analysis path
- scoring must remain deterministic for verdict-bearing analysis flows
- integrations must degrade honestly
- workflow automation must preserve analyst control
- new AI capabilities must improve trust, not reduce it

## What Effective Vibe Coding Needs

To build AISA effectively after learning from Vigil, the repo needs docs that keep five things explicit:

1. which layers own deterministic analysis versus agentic orchestration
2. which Vigil ideas should be adopted directly, adapted carefully, or avoided
3. how workflows, agents, MCP, cases, graph, and reporting fit together
4. what runtime and contract invariants must not break
5. what phased roadmap should guide implementation

That is why the most important docs for the next stage are:

- `docs/system-design.md`
- `docs/future-system-roadmap.md`
- `docs/vibe-coding-operating-model.md`
- `docs/vigil-main-integration-blueprint.md`

## Unresolved Questions

- None.
