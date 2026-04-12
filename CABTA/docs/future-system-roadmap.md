# CABTA Future System Roadmap

## Purpose

This roadmap describes how CABTA should evolve from a strong, broad prototype into a more coherent, scalable, and AI-native security analysis platform.

It is written for implementation planning, not marketing.

## Current Position

CABTA already has meaningful depth in:

- IOC investigation
- malware and file analysis
- email forensics
- analyst reporting
- web dashboard
- agent workflows
- MCP integration

The main constraint is no longer feature absence. It is system coherence.

The biggest current limits are:

- naming drift across old and new product identities
- mixed result contracts and backward-compat shims
- documentation drift versus current code reality
- test and verification flow not yet packaged as a strong delivery system
- broad capability spread without a strongly phased product direction

## Strategic Goal

Turn CABTA into a reliable local-first analyst platform with:

- clearer architecture contracts
- stronger correctness and verification
- better AI-assisted investigation workflows
- more composable integrations
- cleaner product identity

## Non-Negotiable Product Direction

Future CABTA should remain:

- local-first
- evidence-first
- deterministic in verdict path
- useful with partial configuration
- extensible without forcing a rewrite

Future CABTA should avoid becoming:

- an LLM-only verdict engine
- a pile of disconnected analyzers
- a dashboard with weak analyst workflows
- a cloud-required system for core analysis

## Priority Themes

### 1. Platform coherence

Unify naming, docs, result contracts, and subsystem responsibilities.

### 2. Analyst trust

Make findings, score provenance, and reasoning easier to audit.

### 3. Stronger execution model

Improve how CABTA moves from raw artifact -> enriched result -> case context -> action.

### 4. AI-native investigation workflows

Deepen agent and MCP usage as a workflow accelerator, not just a wrapper.

### 5. Product hardening

Improve testing, packaging, performance, and operational reliability.

## Recommended Phased Roadmap

## Phase 0: Stabilize the Foundation

**Goal:** Reduce ambiguity and drift before adding major new capabilities.

### Outcomes

- CABTA becomes the clear canonical name across new docs and newly touched surfaces.
- System design, codebase memory, and test manifest become the normal development entrypoint.
- Result contracts across IOC, file, and email become more explicit and less legacy-dependent.

### Workstreams

#### Identity and naming convergence

- standardize new docs and UI labels on `CABTA`
- inventory legacy names in code and docs
- preserve storage and backward-compat paths until migration is planned

#### Contract normalization

- document stable output keys for IOC, file, email, web, and MCP
- reduce multi-key fallback logic where possible
- introduce explicit versioning or compatibility notes where needed

#### Config cleanup

- unify config terminology across docs and code
- align `config.yaml.example` with current supported keys and behaviors
- document which keys are optional, deprecated, or planned

#### Documentation repair

- update install and usage docs that still reference `mcp-for-soc`
- align docs with current cache, web, and agent features
- make roadmap and system-design docs part of normal dev workflow

### Exit Criteria

- new contributor can understand the repo from docs without hitting naming confusion
- touched modules no longer add fresh naming drift
- output contracts are documented enough to support safe refactors

## Phase 1: Harden the Analysis Core

**Goal:** Make core analysis pipelines more reliable, explainable, and maintainable.

### Outcomes

- clearer score provenance
- easier debugging of verdict changes
- stronger confidence in analyzer and enrichment behavior

### Workstreams

#### Scoring transparency

- make score contribution breakdown first-class for all major analysis types
- normalize how evidence becomes points across layers
- improve false-positive reasoning visibility

#### Analyzer contract cleanup

- define expected analyzer return structures
- separate evidence extraction from verdict shaping more clearly
- reduce ad hoc per-analyzer result formatting

#### Enrichment reliability

- standardize timeout, retry, and failure semantics across TI sources
- improve caching strategy and cache observability
- make source freshness and partial-result status clearer

#### Sandbox and deep-analysis orchestration

- unify how sandbox results feed back into file analysis
- make beacon, ransomware, memory, and advanced signals easier to compose
- define when sandbox data should override or enrich static scoring

### Exit Criteria

- score changes can be tested and explained more easily
- analyzer additions require less custom glue
- partial enrichment failures are easier to diagnose

## Phase 2: Build a Strong Investigation Platform

**Goal:** Make CABTA more than separate analysis tools by strengthening case, correlation, and workflow.

### Outcomes

- better analysis-to-case linkage
- more useful cross-artifact pivoting
- stronger playbook execution model

### Workstreams

#### Case-centric workflows

- promote cases from passive storage to active investigation containers
- link IOC, file, email, and notes more richly
- add investigation summaries and timeline views

#### Correlation layer growth

- correlate repeated IOCs across analyses
- cluster related activity from email + attachment + IOC pivots
- surface campaign-level patterns

#### Playbooks as first-class workflow

- improve playbook authoring and visibility
- map playbooks to investigation stages
- allow playbooks to express recommended next steps, not only static templates

#### Better history and recall

- improve search across prior analyses
- promote cached findings into analyst-facing recall
- support "what have we already seen related to this?" workflows

### Exit Criteria

- CABTA supports investigations, not just isolated scans
- related artifacts can be pivoted from one surface
- playbooks become genuinely useful for repeatable analyst work

## Phase 3: Expand the AI-Native Layer

**Goal:** Make agent and MCP workflows a major differentiator while preserving analyst control.

### Outcomes

- better agent-guided investigations
- stronger MCP tool ecosystem
- richer human-in-the-loop workflows

### Workstreams

#### Agent orchestration maturation

- improve tool planning and execution boundaries
- add explicit reasoning checkpoints and analyst approval points
- support longer investigations without losing state quality

#### Investigation memory evolution

- move from cache-style recall to investigation-context memory
- preserve important decisions, pivots, and rationale
- support better rehydration for long-running cases

#### MCP ecosystem growth

- package CABTA capabilities into clearer MCP server profiles
- make external tool integration easier and more observable
- expose analyst-safe tool subsets for different environments

#### AI-assisted reporting

- improve executive and analyst summaries without hiding raw evidence
- generate clearer "next action" recommendations
- support structured briefings for SOC handoff

### Exit Criteria

- agent workflows materially reduce analyst toil
- MCP becomes a strong interoperability surface
- long-running investigations remain coherent across sessions

## Phase 4: Productize and Operationalize

**Goal:** Make CABTA easier to deploy, verify, and extend as a serious platform.

### Outcomes

- more reliable test and release flow
- stronger packaging and deployment
- clearer extension model for analyzers and integrations

### Workstreams

#### Test and CI maturity

- establish expected test lanes in automation
- add CI for focused suites and smoke checks
- track result contract regressions

#### Packaging and deployment

- improve local install story
- improve Docker and sandbox setup
- package web + CLI + MCP usage more cleanly

#### Extension architecture

- define plugin-like patterns for analyzers, sources, and playbooks
- reduce central wiring work for new modules
- document extension contracts thoroughly

#### Performance and observability

- add better timing and bottleneck visibility
- track external dependency latency and cache hit rates
- improve analysis progress reporting in web and agent surfaces

### Exit Criteria

- CABTA is easier to run, test, and extend
- future feature work lands with less coupling pain
- the platform feels operational, not just feature-rich

## High-Value Candidate Epics

These are the most useful roadmap epics to queue first.

### Epic 1: Naming and contract cleanup

Why:

- highest leverage for future AI-assisted work
- reduces confusion in docs, web labels, config, and reporting

### Epic 2: Score provenance and verdict auditability

Why:

- improves analyst trust
- reduces fear when adjusting scoring logic

### Epic 3: Case-centered investigation workflow

Why:

- transforms CABTA from analysis toolkit into investigation platform

### Epic 4: Agent and MCP workflow hardening

Why:

- likely the most differentiated future direction for CABTA

### Epic 5: Test and release hardening

Why:

- prevents future breadth from turning into unmanageable drift

## What to Avoid Right Now

These are attractive but lower-quality next steps if done too early:

- adding many more TI sources before contract cleanup
- adding more UI pages before case workflow becomes coherent
- over-investing in LLM polish before score provenance is clearer
- broad renames without compatibility planning
- large rewrites of analyzers without explicit return-contract strategy

## Suggested Near-Term Sequence

If the goal is "make CABTA stronger fast", the best near-term order is:

1. naming and docs convergence
2. result contract normalization
3. scoring transparency and auditability
4. case and correlation workflow strengthening
5. agent/MCP maturity
6. packaging and CI hardening

## Success Metrics

Use these metrics to judge roadmap progress:

### Developer metrics

- fewer files require manual compatibility shims
- feature work needs less exploratory reading
- higher percentage of tasks can be implemented from docs + plan only

### Analyst metrics

- clearer verdict explanations
- faster pivot from one artifact to related context
- stronger next-step recommendations from CABTA outputs

### System metrics

- lower breakage risk from scoring changes
- better cache hit rates and source resilience
- more predictable response time under partial dependency failures

## How to Use This Roadmap

- use it to decide what to build next
- use it to decide which work should be grouped into one plan
- use it to reject tempting but low-leverage side quests
- update it only when architecture direction genuinely changes

For implementation work, pair this file with:

- `docs/system-design.md`
- `docs/vibe-coding-operating-model.md`
- `TEST-MANIFEST.md`
- `plans/templates/*`

## Unresolved Questions

- Should naming convergence include migrating local storage paths from `~/.blue-team-assistant/` to a CABTA-branded path, or should that remain as a compatibility alias long-term?
- Should the long-term differentiation focus more on analyst workflows, or more on CABTA as an MCP-native security capability platform?
