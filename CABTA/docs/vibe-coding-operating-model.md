# CABTA Vibe Coding Operating Model

## Why This Exists

CABTA is already broad. It has IOC investigation, file analysis, email forensics, a web dashboard, agent workflows, MCP integration, scoring, reporting, and many specialized analyzers.

Without a stable operating model, AI-assisted development here will drift fast.

## Core Thesis

Effective vibe coding for CABTA means:

1. keep a written plan for non-trivial work
2. use the plan as persistent project memory
3. change one domain lane at a time
4. preserve evidence-first security logic
5. verify with focused tests before claiming completion

## Repo-Specific Rules

### 1. CABTA is the canonical name

Legacy names exist in the repo. New work should standardize around `CABTA`.

### 2. LLM interprets, scoring decides

CABTA's strongest architectural rule is that LLM output should support analysts, not replace deterministic verdict logic.

### 3. Local-first stays intact

Do not make external APIs or cloud LLMs mandatory for core analysis paths.

### 4. Graceful degradation matters

If a source, sandbox, or model is unavailable, the workflow should still return a useful partial result.

## Recommended Work Lanes

Use a narrow lane instead of mixing everything at once.

### IOC lane

- `src/tools/ioc_investigator.py`
- `src/integrations/threat_intel*.py`
- `src/utils/dga_detector.py`
- `src/utils/domain_age_checker.py`
- `src/scoring/intelligent_scoring.py`

### Malware lane

- `src/tools/malware_analyzer.py`
- relevant analyzer in `src/analyzers/`
- `src/scoring/tool_based_scoring.py`
- `src/reporting/`

### Email lane

- `src/tools/email_analyzer.py`
- email analyzers
- `src/scoring/intelligent_scoring.py`
- reporting and templates if needed

### Web lane

- `src/web/app.py`
- `src/web/routes/`
- `templates/`
- `static/`

### Agent/MCP lane

- `src/server.py`
- `src/agent/`
- `src/mcp_servers/`

## Planning Rule

Create a plan if the task:

- spans more than one subsystem
- changes scoring or verdict behavior
- affects both backend and dashboard
- introduces a new analyzer or TI source
- lasts more than one session

## Minimum Plan Structure

Every meaningful plan should include:

- goal
- scope
- impacted files
- acceptance criteria
- tests to run
- docs to update
- unresolved questions

Use `plans/templates/`.

## Context Discipline

### Read order

Before coding:

1. `README.md`
2. `AGENTS.md`
3. `docs/project-overview-pdr.md`
4. `docs/codebase-summary.md`
5. `docs/code-standards.md`
6. `TEST-MANIFEST.md`
7. task-specific plan

### Keep context small

- read the orchestrator before reading many leaf modules
- load only the relevant analyzer for the current change
- avoid dragging all docs into every session

### Externalize memory

Use files for:

- plans
- decision summaries
- test notes
- follow-up questions

Do not rely on chat history alone.

## Quality Gates

A CABTA task is not done until:

- the intended behavior is implemented
- relevant tests were run or explicitly deferred
- user-facing docs impact was checked
- naming drift was not made worse
- unresolved questions are listed

## Good Default for Large Features

1. create a feature plan
2. implement one phase
3. run focused tests
4. update docs if needed
5. move to the next phase

## Good Default for Bug Fixes

1. isolate failing behavior
2. identify the lowest layer causing it
3. fix there first
4. run focused tests
5. record any behavior contract that changed

## Anti-Patterns

- changing scoring without test coverage
- changing route payloads without checking templates or API consumers
- using LLM output as the only reason for a verdict
- mixing CABTA naming with new alternate names
- doing multi-session work without a plan file

## Unresolved Questions

- None.
