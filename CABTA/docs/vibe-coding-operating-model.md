# AISA Vibe Coding Operating Model

## Why This Exists

AISA is no longer just a broad artifact-analysis repo.

After studying `vigil-main`, the repo direction now includes:

- deterministic analysis
- specialist agents
- workflow orchestration
- case intelligence
- governance
- MCP-driven expansion

Without a disciplined operating model, AI-assisted coding will create architecture drift very quickly.

## Core Thesis

Effective vibe coding for AISA means:

1. protect the deterministic analysis core
2. add new investigation power through explicit layers, not hacks
3. externalize decisions into docs and plans
4. integrate Vigil-inspired ideas by seam, not by imitation
5. verify behavior lane by lane before claiming progress

## Repo-Specific Rules

### 1. Product/UI/docs should say AISA

The repo path is still `CABTA/`, but product-facing work should prefer `AISA`.

### 2. Analysis truth and agent orchestration are different planes

Do not blur:

- artifact verdict logic
- agent reasoning
- workflow coordination
- response governance

### 3. LLM interprets, workflow coordinates, scoring decides

For verdict-bearing flows:

- analyzers extract
- integrations enrich
- scoring decides
- LLM explains
- workflows orchestrate

This separation is mandatory.

### 3b. Workflow must call tools for evidence

When implementing Vigil-inspired orchestration:

- use workflows and agents to coordinate
- use tools and services to investigate
- use scoring and evidence contracts to conclude

Never let a workflow "complete" an investigation step by pure model reasoning when AISA has a real tool path for that question.

### 4. Local-first remains mandatory

Do not make Vigil-inspired upgrades depend on:

- mandatory cloud inference
- mandatory Docker for core use
- mandatory Redis/Postgres just to use IOC/file/email analysis

### 5. Honest degradation matters more than flashy orchestration

If a workflow, MCP tool, or integration is unavailable:

- say so clearly
- return a useful partial state
- offer manual fallback where possible

### 6. Treat Vigil as a pattern library, not a transplant target

Adopt:

- ideas
- structures
- service boundaries
- workflow concepts

Do not blindly copy:

- naming
- storage assumptions
- provider lock-in
- deployment assumptions

### 7. Preserve the asymmetric integration model

Use this as the default architecture stance:

- AISA/CABTA owns analysis core and verdict governance
- Vigil-inspired features own orchestration, agent roles, approval, and optional daemon behavior

If a task blurs that boundary, stop and redesign before coding.

## Canonical Read Order

Before non-trivial implementation, read:

1. `README.md`
2. `AGENTS.md`
3. `docs/project-overview-pdr.md`
4. `docs/system-design.md`
5. `docs/vigil-main-integration-blueprint.md`
6. `docs/codebase-summary.md`
7. `docs/code-standards.md`
8. `docs/feature-truth-matrix.md`
9. `TEST-MANIFEST.md`
10. relevant plan under `plans/`

## Work Lanes

Use one lane at a time.

### Analysis core lane

Use for:

- IOC
- file
- email
- scoring
- reporting

### Workflow lane

Use for:

- workflow definition format
- workflow parser/registry
- workflow execution state
- workflow UI and API

### Specialist agent lane

Use for:

- agent profiles
- role prompts
- role methodologies
- tool boundaries

### Case intelligence lane

Use for:

- case schema
- entity graph
- timeline
- cross-analysis pivots

### Governance lane

Use for:

- approval queue
- AI decision logs
- feedback
- action auditing

### Integration control lane

Use for:

- MCP truth model
- capability catalog
- custom integration metadata
- settings and health semantics

### Background automation lane

Use for:

- daemon
- scheduler
- queued reasoning
- polling and monitoring

## Planning Rule

Create or update a plan if the task:

- crosses planes
- changes scoring or verdict behavior
- changes contracts used by web and agent surfaces
- introduces a new specialist agent
- introduces a new workflow system behavior
- affects cases, approvals, graph, or timeline logic
- affects MCP or integration control
- lasts more than one session

## Minimum Plan Structure

Every meaningful plan should include:

- goal
- owning lane
- affected planes
- impacted files
- contract risks
- acceptance criteria
- tests to run
- docs to update
- unresolved questions

## How To Integrate Vigil-Inspired Features Safely

For every feature inspired by Vigil, classify it first:

### Adopt directly

Good examples:

- specialist agent roles
- readable workflow definitions
- approval semantics
- timeline and graph concepts

### Adapt carefully

Good examples:

- AI decision logging
- queue-backed LLM gateway
- custom integration builder
- daemon mode

### Avoid direct import

Good examples:

- provider lock-in assumptions
- mandatory service dependencies for all users
- replacing deterministic analysis with agentic reasoning

Write this classification into the plan before coding.

Then answer two extra questions:

1. Does this feature call real AISA tools for evidence?
2. Does this feature preserve AISA scoring as verdict source of truth?

If either answer is "no", the design is not ready.

## Quality Gates

A task is not done until:

- the intended behavior is implemented
- touched lane behavior is verified
- degraded states remain honest
- docs were checked
- no architecture boundary was weakened
- unresolved questions are listed

## Test Discipline

### For analysis-core changes

Run:

- focused unit tests
- contract tests
- smoke web tests if UI is affected

### For workflow or agent changes

Run:

- workflow parsing or execution tests
- agent route tests
- session/progress regression tests

### For governance changes

Run:

- approval logic tests
- decision-log tests
- status/health rendering tests

### For integration control changes

Run:

- settings save/load tests
- MCP registration tests
- capability-state tests

## Documentation Discipline

When a change alters architecture, behavior, or operating assumptions, update at least one of:

- `docs/system-design.md`
- `docs/future-system-roadmap.md`
- `docs/vigil-main-integration-blueprint.md`
- plan file under `plans/`

Do not leave major architectural intent only in chat.

## Anti-Patterns

- using agent reasoning as verdict authority
- copying Vigil features wholesale without checking AISA constraints
- letting workflows infer verdicts without going through AISA evidence/scoring paths
- adding workflows with unclear ownership or no execution truth
- building graph/timeline features without normalized entities
- adding response automation without approval or audit semantics
- exposing tools to agents without capability-state truth
- doing multi-session architecture work without a plan

## Best Default for Large Features

1. write or update the plan
2. decide the lane and plane boundaries
3. implement the narrowest vertical slice
4. run focused tests
5. update docs
6. then move to the next phase

## Unresolved Questions

- None.
