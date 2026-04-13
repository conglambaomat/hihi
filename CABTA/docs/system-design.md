# CABTA System Design

## Purpose

This is the primary system-design document for CABTA.

Use it to answer:

- what CABTA is trying to optimize for
- which layer owns a change
- which files are the best entrypoints for a task
- what must not break when moving fast with AI assistance
- what "done" means for localhost web delivery

This file is intentionally shorter and sharper than older design docs.
If a detail belongs in deep technical reference, it should live in code, tests, or focused docs instead of bloating this file.

## Canonical Read Order

For most non-trivial tasks, read in this order:

1. `README.md`
2. `docs/project-overview-pdr.md`
3. this `docs/system-design.md`
4. `docs/codebase-summary.md`
5. `docs/code-standards.md`
6. `docs/feature-truth-matrix.md` for runtime-sensitive or demo-sensitive work
7. `TEST-MANIFEST.md`
8. relevant plan under `plans/` if one exists

## System Identity

- Canonical product name: `CABTA`
- Expanded name: `Cyan Agent Blue Team Assistant`
- Primary product mode: localhost web application
- Secondary interfaces:
  - CLI
  - MCP server
  - Python import

New docs, UI text, and newly touched code should prefer `CABTA`.
Legacy names may remain in older code paths until intentionally migrated, but new work should not add fresh naming drift.

## Product Goal

CABTA is a local-first analyst platform for SOC and DFIR work.

Its job is to turn raw security inputs into:

- visible evidence
- optional enrichment
- deterministic scores
- explainable verdicts
- actionable analyst recommendations
- reusable reports, cases, and exports

The main product is not "a pile of analyzers."
The main product is a decision-support workflow that remains trustworthy under partial configuration.

## Primary Product Mode

CABTA should be evolved as a web-first localhost product.

The browser path is the default demo and analyst experience:

- open app locally
- choose investigation path
- submit IOC, file, or email
- inspect evidence and verdict
- review history, cases, and reports

CLI and MCP still matter, but they are alternate interfaces into the same core analysis engine.
They are not separate products.

## Non-Negotiable Design Rules

### 1. Evidence first

Evidence must remain visible in analyst-facing results.
Do not hide core findings behind summary prose.

### 2. Deterministic verdict path

Final verdict authority belongs to deterministic logic:

- heuristics
- evidence extraction
- enrichment signals
- scoring
- explicit mapping rules

LLM output may interpret. It must not become the source of truth for verdicts.

### 3. Local-first by default

Core workflows must remain useful on localhost:

- without paid API keys
- without cloud-only dependencies
- with optional LLM support, not mandatory LLM support

### 4. Graceful degradation

Missing keys, offline services, or unavailable sandboxes should degrade results honestly, not fake success and not crash the main path.

### 5. Web-first, shared core

Web owns the main user journey.
CLI and MCP should reuse the same orchestration and scoring core instead of forking logic.

### 6. Stable result contracts

Additive changes are preferred over silent result-shape rewrites.
Reporting, web routes, and MCP surfaces depend on stable keys.

### 7. Narrow owning lane

Every change should clearly belong to one main lane:

- IOC
- File
- Email
- Dashboard/Web
- Case/History/Reports
- Agent/MCP

Cross-lane work should be planned before implementation.

## Canonical Product Surfaces

### Dashboard

Owns:

- system overview
- source health
- recent jobs
- quick actions
- demo-friendly orientation

### IOC Investigation

Owns:

- single IOC triage
- multi-source enrichment
- score breakdown
- verdict and recommendations
- rule and export generation

### File Analysis

Owns:

- upload/select file
- route by file type
- run static analysis and enrichment
- show extracted indicators, detections, MITRE context, and verdict

### Email Analysis

Owns:

- parse email artifacts
- inspect auth results and headers
- detect phishing and BEC signals
- pivot attachments and URLs into deeper analysis

### History

Owns:

- prior jobs
- result reopening
- demo replay

### Cases

Owns:

- grouping related analyses
- notes
- investigation context

### Reports

Owns:

- analyst-facing presentation
- exportable output

### Agent Workspace

Owns:

- AI-assisted investigation workflows
- tool-driven playbook execution
- evidence-linked agent activity

This is optional infrastructure, not the primary verdict authority.

### Settings and MCP Management

Own:

- local config
- API/LLM/source toggles
- optional integration visibility
- honest health and capability state

## Layer Ownership

### 1. Presentation Layer

Files:

- `templates/*`
- `static/*`

Responsibilities:

- render pages and components
- show evidence, scores, and status
- handle interaction and navigation

Must not:

- compute verdicts
- query integrations directly
- hide important business logic in frontend code

### 2. Web Routing Layer

Files:

- `src/web/app.py`
- `src/web/routes/*`

Responsibilities:

- receive requests
- validate input
- start jobs or invoke fast paths
- shape API/page responses

Must not:

- own analysis logic
- own scoring logic
- bypass orchestrators for convenience

### 3. Job and Case Orchestration Layer

Files:

- `src/web/analysis_manager.py`
- `src/web/case_store.py`
- `src/web/runtime_refresh.py`

Responsibilities:

- create and track jobs
- persist status
- connect results to history and cases
- keep the web workflow resumable and observable

### 4. Core Tool Orchestration Layer

Files:

- `src/tools/ioc_investigator.py`
- `src/tools/malware_analyzer.py`
- `src/tools/email_analyzer.py`

Responsibilities:

- coordinate full analysis flows
- call analyzers, integrations, scoring, and reporting
- preserve stable output contracts

This is CABTA's operational heart.

### 5. Analyzer Layer

Files:

- `src/analyzers/*`
- `src/analyzers/deobfuscators/*`

Responsibilities:

- parse artifact-specific formats
- extract evidence
- detect suspicious patterns
- surface structured findings

Must not:

- become the final verdict authority
- return UI-only shapes
- mutate job or case state

### 6. Enrichment and Integration Layer

Files:

- `src/integrations/*`

Responsibilities:

- call TI, LLM, sandbox, and export providers
- normalize third-party output
- report source quality and failure state honestly

Must not:

- silently define final verdict alone

### 7. Scoring and Verdict Governance Layer

Files:

- `src/scoring/*`

Responsibilities:

- convert evidence into deterministic score
- apply false-positive controls
- map score into verdict
- produce explainable breakdown

Changes here are product-behavior changes, not cosmetic refactors.

### 8. Reporting and Export Layer

Files:

- `src/reporting/*`
- `src/detection/*`

Responsibilities:

- render analyst-readable output
- generate HTML/markdown/export artifacts
- produce detection content

Must not:

- rewrite the underlying verdict
- hide evidence already produced upstream

### 9. Agent and MCP Layer

Files:

- `src/agent/*`
- `src/mcp_servers/*`
- `src/server.py`

Responsibilities:

- power tool-driven investigations
- manage memory and playbooks
- expose CABTA capabilities to external AI tooling

This layer is strategic and useful, but still secondary to core analyst trust.

### 10. Persistence and Configuration Layer

Files:

- `config.yaml`
- `config.yaml.example`
- `src/utils/config.py`
- cache and local state stores

Responsibilities:

- local-first config
- job/case persistence
- source toggles
- demo mode behavior

## High-Signal Entry Points By Lane

### IOC Lane

Start with:

- `src/tools/ioc_investigator.py`
- `src/integrations/threat_intel.py`
- `src/integrations/threat_intel_extended.py`
- `src/scoring/intelligent_scoring.py`
- `src/web/routes/analysis.py`

### File Lane

Start with:

- `src/tools/malware_analyzer.py`
- `src/analyzers/file_type_router.py`
- relevant file analyzer in `src/analyzers/`
- `src/scoring/tool_based_scoring.py`
- `src/reporting/*`

### Email Lane

Start with:

- `src/tools/email_analyzer.py`
- `src/analyzers/email_forensics.py`
- `src/analyzers/email_threat_indicators.py`
- `src/analyzers/bec_detector.py`
- `src/scoring/intelligent_scoring.py`

### Dashboard/Web Lane

Start with:

- `src/web/app.py`
- `src/web/routes/dashboard.py`
- relevant template in `templates/`
- relevant asset in `static/`

### Case and Report Lane

Start with:

- `src/web/case_store.py`
- `src/web/routes/cases.py`
- `src/web/routes/reports.py`
- `src/reporting/*`

### Agent and MCP Lane

Start with:

- `src/agent/*`
- `src/web/routes/agent.py`
- `src/web/routes/chat.py`
- `src/server.py`
- `src/mcp_servers/*`

## Stable Domain Nouns

These nouns should stay conceptually stable across web, reporting, and MCP work:

- `Artifact`: thing being analyzed
- `EvidenceItem`: structured finding worth showing to an analyst
- `EnrichmentResult`: normalized third-party or local provider output
- `ScoreBreakdown`: how evidence contributes to score
- `Verdict`: deterministic classification derived from scoring rules
- `AnalysisJob`: trackable work unit for web/history flows
- `Case`: container linking related jobs, notes, and follow-up context

If a new feature invents a new noun, justify it before spreading it across layers.

## Result Contract Expectations

### IOC Results

Should clearly include:

- normalized input
- source findings
- score or score breakdown
- final verdict
- recommendations
- optional exports or rules

### File Results

Should clearly include:

- file identity and hashes
- analyzer findings
- extracted IOCs or capabilities where relevant
- score breakdown
- final verdict
- reporting/export payloads

### Email Results

Should clearly include:

- auth and header findings
- phishing/BEC indicators
- extracted URLs, attachments, and pivots
- composite score or breakdown
- final verdict
- next analyst actions

### Cross-Surface Rule

Routes, reports, and MCP tools may add wrappers, but they should not silently destroy these core meanings.

## Verdict and LLM Policy

### Final authority

Final verdict authority belongs to deterministic logic in scoring/governance layers.

### LLM is allowed to

- explain evidence
- summarize findings
- suggest next steps
- improve analyst readability

### LLM is not allowed to

- replace scoring
- invent evidence
- silently override deterministic verdicts
- hide uncertainty behind polished language

### Fallback rule

If LLM is unavailable, CABTA must still produce a useful result from deterministic components.

## Localhost Demo Contract

A localhost CABTA demo is successful when:

- setup is reasonable
- the browser path is understandable without CLI knowledge
- IOC, file, and email flows are visible end to end
- zero-key mode still works in a useful degraded form
- evidence is visible
- unavailable capabilities are reported honestly

The demo should prefer truthful partial capability over fake "all green" messaging.

## Safe Extension Recipes

### Add a New TI Source

1. add integration under `src/integrations/`
2. normalize its output
3. wire it through the owning tool orchestrator
4. decide how it contributes to score
5. update tests
6. update docs if user-visible

### Add a New Analyzer

1. create analyzer with narrow responsibility
2. register it through routing/orchestration
3. expose structured findings
4. ensure reporting can consume the output
5. add focused tests

### Add a New Report or Export

1. consume stable upstream result contracts
2. do not alter verdict logic
3. keep evidence visible
4. add focused report tests if behavior matters

### Add a New Web Workflow

1. decide the owning lane
2. keep route thin
3. reuse existing orchestration where possible
4. verify templates, API shape, and history/case impact

## Test Obligations

### Scoring Change

Run focused scoring tests and any directly affected lane tests.

### Result Shape Change

Run API/report/model tests for every affected consumer.

### New TI Source

Test integration normalization and lane behavior under success and failure.

### New Analyzer

Test routing plus analyzer-specific behavior.

### UI Change

Test route behavior and any templates or API payloads it depends on.

### Agent or MCP Change

Test tool registration, route behavior, and any changed payload contracts.

Use `TEST-MANIFEST.md` to choose the smallest meaningful test slice first.

## Planning Rules

Create a plan before implementation if the task:

- spans multiple lanes
- changes scoring or verdict behavior
- changes both backend and UI
- adds a new analyzer or enrichment source
- changes persistence, cases, or history
- affects agent or MCP behavior
- lasts more than one session

Use `plans/templates/` instead of freehand planning when possible.

## Definition of Done

A CABTA change is done only if:

- it has a clear owning lane
- evidence remains visible
- deterministic verdict still works without LLM
- result contracts stay stable or are explicitly updated
- relevant tests were run or explicitly deferred
- docs impact was checked
- localhost demo behavior stays honest
- no forbidden shortcut was introduced across layers

## Related Docs

- `docs/project-overview-pdr.md` for product intent
- `docs/codebase-summary.md` for file-level orientation
- `docs/code-standards.md` for implementation rules
- `docs/feature-truth-matrix.md` for current verified reality
- `docs/future-system-roadmap.md` for longer-horizon direction
- `docs/vibe-coding-operating-model.md` for workflow discipline

## Unresolved Questions

- None.
