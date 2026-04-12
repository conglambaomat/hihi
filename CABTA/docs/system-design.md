# CABTA System Design

## Purpose

This document is the operational, AI-friendly source of truth for CABTA as a web-first localhost SOC triage and investigation platform.

Use this document when vibe coding to decide:

- where a feature belongs
- which layer owns a change
- how to extend CABTA without breaking verdict accuracy
- what must stay deterministic
- how the localhost demo should behave
- what tests, docs, and UI states must move with a change

This document is intentionally more product-operational than `docs/ARCHITECTURE.md`.

## System Identity

- Product name: `CABTA`
- Expanded name: `Cyan Agent Blue Team Assistant`
- Current product direction: local-first SOC analysis platform
- Primary operating mode for this design: localhost web application for demo and analyst workflows
- Secondary interfaces:
  - CLI
  - MCP server
  - internal Python import

New work should standardize on `CABTA` in UI, docs, and new code unless preserving backward compatibility.

## Product Goal

CABTA helps analysts make faster, safer triage and investigation decisions by turning raw security artifacts into:

- normalized evidence
- multi-source enrichment
- deterministic scores
- explainable verdicts
- analyst-ready recommendations
- optional detection content
- exportable case and report artifacts

CABTA is not just an analyzer collection.

It is a decision-support workbench.

## Current Reality vs Target Direction

### Current reality

The current repo already includes:

- a FastAPI web dashboard
- REST APIs
- HTML templates
- job tracking and history
- case workflows
- agent chat and playbooks
- MCP management
- CLI and MCP entrypoints
- local-first and optional-Ollama positioning

### Target direction

The system should now be designed and evolved as a web-first localhost product where the browser experience is the main demo and analyst path.

CLI and MCP remain important, but they are secondary interfaces into the same core.

## Primary Product Mode

### Web-first localhost mode

The default CABTA product experience is a browser-based application running on localhost.

This mode should provide a complete demo and analyst workflow without requiring the user to understand internal modules or CLI syntax.

### CLI and MCP remain supported

CLI and MCP should continue to use the same core orchestration and analysis engines.

They are not separate products.

They are alternate interfaces into the same analysis core.

## Demo Success Criteria

A localhost demo is successful when all of the following are true:

- a user can start CABTA locally with minimal setup
- the browser UI exposes all major analysis paths clearly
- IOC, file, and email workflows can be demonstrated end-to-end
- the app remains useful with zero paid API keys
- every verdict shows visible evidence and score reasoning
- UI output is understandable to a security analyst in under 30 seconds
- failures degrade gracefully and remain legible
- demo mode can showcase realistic results even when external services are unavailable
- reports, cases, and investigation history are viewable from the UI
- agent and MCP features do not become required dependencies for the main demo path

## Core Design Principles

### 1. Evidence first

CABTA is an analyst system.

Evidence must always remain visible and must never be hidden behind a narrative summary.

### 2. Deterministic verdict path

Threat verdicts come from deterministic scoring, source evidence, heuristics, and explicit rules.

LLM output may explain findings but must not become the final authority.

### 3. Local-first by default

Core workflows must remain usable on localhost with no mandatory cloud dependency.

Optional enrichments may improve results but must not be required to demonstrate the product.

### 4. Graceful degradation

Missing API keys, offline sources, sandbox failures, LLM unavailability, and unsupported artifact types must reduce enrichment quality, not collapse the workflow.

### 5. Web-first product, shared core engines

The browser app is the main product surface for demos and analyst use.

CLI and MCP must reuse the same orchestration and scoring core.

### 6. Explainability over theatrical AI

CABTA should prefer:

- evidence summaries
- source attribution
- score breakdowns
- analyst recommendations

over vague AI confidence language.

### 7. Safe extensibility

New analyzers, sources, playbooks, and reports must plug into stable contracts rather than inventing new result shapes ad hoc.

## Product Scope

CABTA supports the following primary investigation inputs:

- IP
- domain
- URL
- hash
- email address
- CVE identifier
- suspicious file sample
- suspicious email artifact
- IOC extracted from an alert or prior investigation

The platform should preserve these as first-class product capabilities:

- multi-source threat intelligence
- advanced malware analysis
- email forensics
- rule generation
- case management
- STIX export
- local LLM support

## Non-Goals

CABTA is not:

- a fully automated SOC decision engine
- a replacement for malware sandboxes or SIEMs
- a case management suite of record
- a full EDR or XDR platform
- a cloud-native multi-tenant SaaS in this design
- a system where LLM output replaces evidence review

## Primary User Personas

### 1. SOC Analyst

Needs fast triage, clear verdicts, visible evidence, and recommended next actions.

### 2. Incident Responder

Needs deeper artifact inspection, IOC pivoting, case notes, and exportable evidence.

### 3. Demo User or Evaluator

Needs a visually clear, low-friction walkthrough of CABTA's capabilities on localhost.

### 4. Power User or Integrator

Needs APIs, MCP, and reusable result contracts.

## System Context

CABTA exposes the same core logic through three interfaces:

- Web
  - primary interface for localhost demo and analyst workflows
  - entrypoint: `src/web/app.py`
- CLI
  - scriptable analyst path
  - entrypoint: `src/soc_agent.py`
- MCP
  - AI-tooling integration path
  - entrypoint: `src/server.py`

## System Architecture Summary

CABTA should be treated as a web application with a shared analysis core.

### Architecture layers

- presentation layer
- API and page routing layer
- analysis job orchestration layer
- core tool orchestration layer
- analyzer layer
- enrichment and integration layer
- scoring and verdict governance layer
- reporting and export layer
- agent and MCP orchestration layer
- local persistence and configuration layer

### Design direction

- Web owns user interaction.
- API owns request normalization and response formatting.
- Background jobs own long-running work.
- Tool orchestrators own workflow composition.
- Analyzers own artifact-specific extraction.
- Integrations own external lookups.
- Scoring owns verdict logic.
- Reporting owns human-readable and exportable output.
- Agent and MCP own AI-native workflows, not core verdict authority.

## Canonical Product Surfaces

### 1. Dashboard

Purpose:

- show system status
- show recent jobs
- provide quick actions
- provide demo-friendly overview
- surface lightweight telemetry

### 2. IOC Investigation

Purpose:

- single-input IOC triage
- enrichment across sources
- score breakdown
- verdict and analyst guidance
- rule and export generation

### 3. File Analysis

Purpose:

- upload or select file
- route by type
- run static analysis and enrichment
- show evidence, extracted IOCs, MITRE candidates, detections, and recommendations

### 4. Email Analysis

Purpose:

- parse mail artifact
- detect phishing and BEC signals
- analyze attachments and extracted URLs
- pivot to IOC and file workflows
- show composite verdict

### 5. History

Purpose:

- browse prior jobs
- reopen results
- compare analyses
- support demo replay

### 6. Cases

Purpose:

- group related analyses
- add notes
- preserve analyst workflow context

### 7. Reports

Purpose:

- render analyst-facing result views
- support JSON, HTML, and structured export

### 8. Agent Workspace

Purpose:

- interactive AI-assisted investigation
- tool-driven evidence gathering
- playbook execution
- MCP-connected workflows

### 9. Settings

Purpose:

- configure local behavior
- configure APIs, LLM, demo mode, sources, and limits

### 10. MCP Management

Purpose:

- show server connectivity
- enable or disable integrations
- keep AI tooling optional and visible

## Canonical Layer Ownership

### 1. Presentation Layer

Files:

- `templates/*`
- `static/*`

Responsibilities:

- analyst-facing HTML pages
- visual evidence rendering
- forms, tables, filters, and result navigation
- job progress visualization
- charting and timeline presentation

Must not:

- compute threat verdicts
- perform enrichment directly
- contain hidden business logic

### 2. API and Page Routing Layer

Files:

- `src/web/app.py`
- `src/web/routes/*`

Responsibilities:

- receive requests
- validate input shape
- create jobs or invoke fast paths
- expose APIs and page routes
- convert internal data into API or template response models

Must not:

- directly implement analysis logic
- bypass orchestrators for convenience
- own scoring logic

### 3. Analysis Job Orchestration Layer

Files:

- `src/web/analysis_manager.py`
- web background task helpers
- case and job linking utilities

Responsibilities:

- create analysis jobs
- track status
- persist progress
- retry, cancel, and finalize work
- preserve consistent job lifecycle
- support history and report retrieval

This layer is mandatory for a web-first CABTA because analysts and demo users need visible progress and resumable results.

### 4. Core Tool Orchestration Layer

Files:

- `src/tools/ioc_investigator.py`
- `src/tools/malware_analyzer.py`
- `src/tools/email_analyzer.py`

Responsibilities:

- coordinate complete workflows
- call analyzers, integrations, scoring, and reporting helpers
- preserve stable output contracts
- trigger pivots between artifact types

This layer is the operational heart of CABTA.

### 5. Analyzer Layer

Files:

- `src/analyzers/*`
- `src/analyzers/deobfuscators/*`

Responsibilities:

- artifact-specific parsing
- file and format-specific evidence extraction
- suspicious pattern detection
- IOC extraction
- MITRE candidate support

Must not:

- perform final verdict mapping
- emit UI-oriented output
- directly mutate case or job state

### 6. Enrichment and Integration Layer

Files:

- `src/integrations/*`

Responsibilities:

- query external or local intel, sandbox, LLM, and export providers
- normalize third-party responses
- express source reliability and source status
- return structured enrichment objects
- never decide final verdict alone

### 7. Scoring and Verdict Governance Layer

Files:

- `src/scoring/*`

Responsibilities:

- compute deterministic scores
- combine evidence and source signals
- apply false-positive reduction
- map score to verdict and confidence
- produce explainable breakdown

This layer is product-critical.

Changes here are behavior changes, not mere refactors.

### 8. Reporting and Export Layer

Files:

- `src/reporting/*`
- `src/detection/*`

Responsibilities:

- analyst-readable report generation
- JSON, HTML, and export views
- detection content generation
- result packaging for download or case attachment

Must not:

- change the underlying verdict
- hide evidence that the core pipeline produced

### 9. Agent and MCP Orchestration Layer

Files:

- `src/agent/*`
- `src/mcp_servers/*`
- `src/server.py`

Responsibilities:

- tool-driven investigations
- session and memory management
- playbook execution
- MCP bridging
- AI-assisted workflows

This is strategic growth infrastructure, not the source of truth for verdict logic.

### 10. Local Persistence and Configuration Layer

Files:

- `config.yaml`
- `config.yaml.example`
- local cache and state stores
- `src/utils/config.py`
- case and job stores

Responsibilities:

- local-first configuration
- cache and replay
- case persistence
- job persistence
- demo mode configuration
- source toggling
- local secrets handling

## Canonical Domain Model

CABTA should use a stable vocabulary.

### Observable

A single atomic indicator-like value.

Examples:

- IP
- domain
- URL
- hash
- email address
- CVE

Required fields:

- `type`
- `value`
- `normalized_value`

Optional:

- `tags`
- `source_context`
- `first_seen`
- `last_seen`

### Artifact

A submitted analysis object.

Examples:

- file sample
- email file
- pasted email headers
- uploaded document

Required:

- `artifact_id`
- `artifact_type`
- `source`
- `metadata`

### AnalysisJob

A tracked execution unit.

Required:

- `job_id`
- `job_type`
- `status`
- `created_at`
- `updated_at`
- `input_ref`
- `result_ref`

Statuses:

- `queued`
- `running`
- `partial`
- `completed`
- `failed`
- `cancelled`

### EvidenceItem

The smallest analyst-consumable proof unit.

Required:

- `id`
- `category`
- `title`
- `severity`
- `summary`
- `source`
- `confidence`

Optional:

- `raw_value`
- `normalized_value`
- `mitre_candidates`
- `related_observables`

### EnrichmentResult

Normalized output from a source or provider.

Required:

- `source_name`
- `status`
- `latency_ms`
- `summary`

Optional:

- `raw`
- `normalized`
- `flagged`
- `reliability`
- `error`

### ScoreBreakdown

Structured explanation of how score was built.

Required:

- `base_score`
- `adjustments`
- `caps`
- `final_score`
- `confidence`
- `reasoning`

### Verdict

Final analyst-facing risk classification.

Allowed values:

- `benign`
- `likely_benign`
- `suspicious`
- `malicious`
- `unknown`
- `error_partial`

### Recommendation

An analyst next-step suggestion.

Required:

- `priority`
- `action`
- `reason`

### Case

A container grouping related jobs, notes, and artifacts.

### PlaybookRun

A structured multi-step investigation run initiated by agent or user.

## Canonical Result Contracts

CABTA must treat result shapes as stable contracts.

### IOC Investigation Result

Required fields:

- `analysis_type: "ioc"`
- `input`
- `ioc_type`
- `normalized_value`
- `verdict`
- `score`
- `confidence`
- `score_breakdown`
- `evidence`
- `enrichment_sources`
- `recommendations`
- `detection_rules`
- `errors`
- `timings`

Optional:

- `llm_analysis`
- `mitre_candidates`
- `profiled_actor_candidates`
- `stix_bundle`

### File Analysis Result

Required fields:

- `analysis_type: "file"`
- `input`
- `file_metadata`
- `hashes`
- `file_type`
- `router_decision`
- `verdict`
- `score`
- `confidence`
- `score_breakdown`
- `evidence`
- `static_analysis`
- `extracted_iocs`
- `mitre_candidates`
- `recommendations`
- `detection_rules`
- `errors`
- `timings`

Optional:

- `sandbox_results`
- `llm_analysis`
- `stix_bundle`

### Email Analysis Result

Required fields:

- `analysis_type: "email"`
- `input`
- `email_metadata`
- `authentication_results`
- `header_findings`
- `phishing_indicators`
- `bec_indicators`
- `url_findings`
- `attachment_findings`
- `extracted_iocs`
- `verdict`
- `score`
- `confidence`
- `score_breakdown`
- `evidence`
- `recommendations`
- `detection_rules`
- `errors`
- `timings`

Optional:

- `llm_analysis`
- `related_jobs`
- `stix_bundle`

### Job Result Wrapper

Every web-visible result should be retrievable through a job wrapper:

- `job_id`
- `job_type`
- `status`
- `submitted_input`
- `started_at`
- `completed_at`
- `result`
- `warnings`
- `errors`
- `report_links`
- `case_links`

## Scoring and Verdict Governance

This section is mandatory for accurate vibe coding.

### Score authority

Only the scoring layer owns the final numeric score and verdict mapping.

No analyzer, integration, report generator, route, or LLM module may assign the final verdict as product truth.

### Score inputs

Allowed inputs to scoring:

- TI source results
- analyzer findings
- behavioral indicators
- false positive filters
- trusted infrastructure rules
- sandbox findings
- explicit heuristics
- correlation signals

### Score output

Every score calculation should return:

- numeric score
- confidence
- breakdown
- primary drivers
- mitigating factors
- final verdict

### Score precedence rules

- trusted infrastructure and known-good signals may reduce or suppress escalation
- known high-confidence malicious evidence may raise severity rapidly
- missing sources reduce confidence, not necessarily score
- contradictory evidence must remain visible in breakdown
- verdict must be reproducible without LLM help

### Confidence rules

Confidence is not score.

- score = estimated risk or severity
- confidence = certainty in result quality

Examples:

- high score plus low confidence is allowed
- medium score plus high confidence is allowed

### Verdict mapping

Recommended mapping:

- `0-19` -> `benign`
- `20-39` -> `likely_benign`
- `40-64` -> `suspicious`
- `65-100` -> `malicious`

`unknown` is used when there is insufficient valid evidence.

`error_partial` is used when execution partially failed but produced usable output.

### Mandatory explainability

Every non-benign verdict should show:

- top positive drivers
- top mitigating drivers
- affected sources
- analyst recommendation

## LLM Usage Policy

CABTA already positions LLM as interpretive, not authoritative.

The design must make that operational.

### LLM is allowed to:

- summarize findings
- explain score breakdown in human language
- suggest next analyst actions
- describe likely ATT&CK relevance
- produce executive summaries

### LLM is not allowed to:

- set final score
- override deterministic verdict
- suppress contradictory evidence
- invent unsupported source findings
- transform weak evidence into strong verdict claims
- hide uncertainty

### Fallback rule

If LLM is unavailable:

- verdict flow still completes
- UI still renders structured findings
- explanation section shows a clear degraded-state message

## Localhost Demo Mode

Demo mode is a target capability and should become explicit in the product.

### Demo mode goals

- make CABTA look complete on localhost
- allow deterministic walkthroughs
- prevent empty or broken screens when APIs are absent
- simulate realistic analyst workflow

### Demo mode capabilities

- seeded example IOC analyses
- seeded sample file and email jobs
- replayable canned TI responses
- fixture-backed timeline and history
- fake but clearly marked case data
- screenshot-friendly reports
- preloaded demo playbooks
- mock source health indicators

### Demo mode rules

- demo data must be clearly marked
- demo verdicts must remain deterministic
- demo mode must not be confused with live enrichment
- settings page should expose whether demo mode is enabled

### Demo mode architecture

Introduce a provider abstraction:

- live provider
- replay provider
- mock provider

Every enrichment source should be invocable through the same normalized interface so localhost demos remain visually complete even when live APIs are disabled.

## User Journey Flows

### 1. Dashboard-first flow

Flow:

- user lands on dashboard
- sees product health, source health, recent jobs, and quick actions
- chooses IOC, file, email, case, or agent workflow

Dashboard should show:

- counts by verdict
- recent analyses
- source availability
- demo or live mode banner
- quick links to all major workflows

### 2. IOC flow

Flow:

- user submits IOC
- system normalizes type
- job is created
- enrichment runs in parallel where possible
- score and verdict are computed
- result page shows evidence, source panels, score breakdown, ATT&CK, recommendations, and export options
- user may add job to a case

### 3. File flow

Flow:

- user uploads file
- metadata and hash calculation begin immediately
- file router selects analyzers
- enrichment and static analysis proceed

Result page should show tabs or sections for:

- summary
- indicators
- extracted IOCs
- MITRE
- detections
- raw details
- export

### 4. Email flow

Flow:

- user uploads email artifact or pasted headers and body
- parser extracts metadata, auth results, URLs, and attachments
- BEC and phishing logic run
- pivots to IOC and file workflows happen when enabled

Result page should show:

- summary
- auth
- indicators
- URLs
- attachments
- BEC
- evidence
- export

### 5. History and report flow

Flow:

- user opens history
- selects prior job
- opens report view
- optionally exports or attaches to a case

### 6. Case flow

Flow:

- user creates or opens case
- links jobs
- adds notes
- exports summary

### 7. Agent flow

Flow:

- user opens agent chat
- agent gathers evidence via tools
- agent may run playbooks
- agent output must always link back to evidence and jobs

## Web UX Rules

### Page design rules

- every analysis page must have a simple primary form
- every result page must have a top summary card
- evidence must be visible without opening raw JSON first
- long outputs must be tabbed or sectioned
- errors must be user-readable
- empty states must teach the user what to do next

### Result page structure

Top section:

- verdict
- score
- confidence
- key recommendation
- mode badge: live, demo, or partial

Middle section:

- evidence
- source enrichment panels
- score breakdown
- ATT&CK mapping
- detections

Bottom section:

- raw details
- exports
- debug metadata

### Visual severity rules

Severity color must be consistent across dashboard, tables, cards, reports, and case links.

## Dependency Rules

These rules prevent architecture drift.

### Allowed dependency direction

- Presentation -> API and view models only
- Routes -> analysis manager and tool orchestrators
- Analysis manager -> tools and persistence
- Tools -> analyzers, integrations, scoring, and reporting
- Analyzers -> parsing helpers only
- Integrations -> external clients and normalization helpers
- Scoring -> evidence inputs, source outputs, and policy constants
- Reporting -> read-only result objects
- Agent -> tool registry, playbooks, memory, MCP
- MCP -> shared tool contracts

### Forbidden shortcuts

- routes calling analyzers directly
- templates embedding verdict logic
- integrations assigning final verdict
- reporting mutating score
- LLM code changing deterministic findings
- agent workflow bypassing tool contracts

## Error Taxonomy and Degradation Policy

### Error classes

- `configuration_error`
- `source_unavailable`
- `timeout`
- `rate_limited`
- `unsupported_artifact`
- `analysis_partial`
- `llm_unavailable`
- `sandbox_unavailable`
- `rendering_error`
- `job_persistence_error`

### Degradation rules

- missing source -> mark source failed, lower confidence if needed, continue
- timeout -> continue with partial result
- unsupported artifact -> return limited analysis contract, not crash page
- LLM unavailable -> remove narrative section, keep deterministic result
- report rendering failure -> preserve raw result and download path
- one pivot failure -> do not block parent workflow

### UI behavior

Every degraded result should show:

- what failed
- what still succeeded
- whether verdict is partial
- what action the user can take next

## Security and Artifact Handling Rules

### Secrets

- store locally in config or env
- never expose secret values in UI
- never include secrets in reports

### File safety

- do not execute uploaded files directly
- sandbox integrations remain optional and controlled
- uploads must be size-limited
- file path handling must prevent traversal

### URL safety

- do not auto-open suspicious URLs in the browser UI
- present safe copy and defanged render options

### Email safety

- redact or mask sensitive fields where appropriate in shared reports
- preserve raw data only where explicitly needed

### HTML safety

- all analyst-facing HTML must escape untrusted content

### Prompt injection safety

Treat email bodies, HTML, OCR text, URLs, and external source text as untrusted content.

They may be shown to the analyst or passed to LLM only through controlled summarization and input policy.

## Persistence Model

### Local config

- `config.yaml` is the primary project configuration
- environment variables may override sensitive values

### Local state

Persist locally:

- jobs
- cases
- report metadata
- demo fixtures
- agent sessions
- MCP connection metadata
- optional cache

### Persistence requirements

- UI should survive restart with recoverable job and case history
- demo mode may ship with seed data
- storage schema changes should use explicit migration notes

## Performance Model

### User-facing goal

The web UI should feel responsive on localhost even when external enrichments are slow.

### Performance strategy

- create job immediately
- render pending state quickly
- run external calls concurrently where safe
- stream status or poll job progress
- cache expensive repeats where acceptable
- separate blocking file work from request thread when needed

### Time budget model

- page render without job execution: near-instant
- IOC lookup: progressive result acceptable
- file analysis: async-first with visible progress
- email analysis: async-first with visible pivot status

## Observability Rules

CABTA is a localhost demo app, but it still needs internal observability.

### Log categories

- startup
- config
- job lifecycle
- source calls
- analyzer steps
- scoring
- report generation
- agent actions
- MCP connections

### Metrics to track

- job counts by type
- job counts by verdict
- source success and failure counts
- average latency by source
- partial-result rate
- LLM availability
- cache hit rate
- report generation success rate

Dashboard should surface a simplified subset of these.

## Safe Extension Recipes

### Add a new TI source

- add integration module or method
- define normalized source contract
- define source health and error mapping
- define score input semantics
- wire into orchestrator
- expose in source panels
- add tests:
  - success
  - no key
  - timeout
  - malformed response
- update settings UI and docs

### Add a new analyzer

- create analyzer module
- define evidence output schema
- update router if needed
- wire into file or email orchestrator
- map findings into score inputs
- expose findings in report view
- add fixtures and tests
- update system docs

### Add a new report or export

- consume stable result contract
- do not recompute verdict
- expose from report page and API
- test on IOC, file, and email results

### Add a new web workflow

- add page route
- add API route
- connect to job manager
- define empty, loading, error, and result states
- update dashboard navigation
- add demo mode fixture if relevant

## Test Obligations Matrix

### Scoring change

Must include:

- unit tests
- regression fixtures
- verdict mapping checks
- docs update

### Result shape change

Must include:

- API response tests
- report rendering tests
- template compatibility tests
- agent and MCP compatibility review

### New TI source

Must include:

- mocked source tests
- timeout behavior
- no-key behavior
- normalization tests

### New analyzer

Must include:

- fixture-based parser tests
- routing tests
- evidence contract tests
- report visibility tests

### UI change

Must include:

- route test
- template render test
- empty, loading, and error state review
- demo mode compatibility check

### Agent or MCP change

Must include:

- tool contract tests
- session behavior tests
- graceful-failure tests

## File Read Order for New Tasks

For any meaningful implementation task, read in this order:

1. `README.md`
2. this `docs/system-design.md`
3. `docs/ARCHITECTURE.md`
4. `docs/project-overview-pdr.md`
5. `docs/codebase-summary.md`
6. `docs/code-standards.md`
7. relevant tests
8. relevant orchestrator file
9. relevant UI route or template

## Planning Rules

Create a plan before implementation if the task:

- changes scoring
- changes result contracts
- introduces a new analyzer
- introduces a new enrichment source
- changes both backend and UI
- changes case or history persistence
- affects agent or MCP behavior
- affects demo mode
- spans more than one product lane

## Product Lanes for Vibe Coding

### IOC lane

- IOC UI
- IOC API
- IOC orchestrator
- TI enrichment
- IOC scoring
- IOC reports

### File lane

- upload UI
- job handling
- file routing
- analyzers
- enrichment
- file scoring
- reports

### Email lane

- email UI
- parser
- phishing and BEC logic
- URL and attachment pivots
- composite scoring
- report visibility

### Dashboard lane

- metrics
- recent jobs
- source health
- navigation
- demo polish

### Case lane

- case store
- linking
- notes
- summary views
- exports

### Agent lane

- chat
- playbooks
- memory
- MCP
- evidence-linked outputs

## Definition of Done for Localhost Web CABTA

A change is done only if:

- it fits one owning layer
- result contracts remain stable or are explicitly versioned
- evidence remains visible
- deterministic verdict still works without LLM
- localhost demo mode remains usable
- affected pages have sane loading, error, and result states
- tests for the touched lane are added or updated
- docs reflect behavior changes
- no forbidden dependency shortcut was introduced

## Unresolved Questions

- None.
