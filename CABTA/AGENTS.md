# AGENTS.md

This file gives agent-facing guidance for working on CABTA.

## Project Identity

- Canonical project name: `CABTA`
- Expanded name: `Cyan Agent Blue Team Assistant`
- Treat `Blue Team Assistant` and `mcp-for-soc` as legacy names still present in code/docs.
- Do not introduce new product names.

## Project Summary

CABTA is a local-first SOC platform for:

- IOC investigation
- malware and file analysis
- email forensics
- AI-assisted analyst workflows
- web dashboard and REST API
- MCP-based tool exposure

The system combines deterministic scoring, analyst-facing evidence, optional local LLM interpretation, and multiple threat-intelligence integrations.

## Mandatory Reading Before Work

Always read these first:

1. `README.md`
2. `docs/project-overview-pdr.md`
3. `docs/system-design.md`
4. `docs/codebase-summary.md`
5. `docs/code-standards.md`
6. `docs/feature-truth-matrix.md` for runtime-sensitive, demo-sensitive, or integration-sensitive work
7. `TEST-MANIFEST.md`
8. Relevant files under `plans/` if the task already has a plan

If the task is architecture-heavy, also read:

- `docs/future-system-roadmap.md`
- `docs/vibe-coding-operating-model.md`

Unless the task is explicitly UI-visual, do not spend time reading `docs/screenshots/`.
Treat screenshots as visual reference material, not architectural truth.

## Core Development Rules

### 1. Preserve CABTA's Security Model

- Keep CABTA local-first by default.
- Do not make cloud access mandatory for core workflows.
- Treat LLM output as interpretation, not as the primary threat verdict engine.
- Keep deterministic scoring and evidence visible.

### 2. Respect Graceful Degradation

- Missing API keys should reduce enrichment, not break the workflow.
- Missing optional tools should fail soft where possible.
- Preserve compatibility for offline and low-connectivity use.

### 3. Keep Names Consistent

- New docs and user-facing text should prefer `CABTA`.
- If old names are preserved for backward compatibility, note them explicitly.
- Avoid mixing multiple product names in the same new feature unless compatibility requires it.

### 4. Change Narrowly

- Prefer small, scoped changes over broad rewrites.
- If a task touches more than one subsystem, create a plan first.
- Keep feature work split by domain: `ioc`, `file`, `email`, `web`, `agent`, `mcp`, `reporting`, `scoring`.

### 5. Tests Are Part of Delivery

- Run the most relevant tests for the changed area.
- If no test exists for a changed behavior, add one when practical.
- Do not claim completion without stating what was verified.

## Recommended Workflow

### For small changes

1. Read affected module and tests
2. Make the smallest safe change
3. Run focused tests
4. Update docs if behavior changed

### For medium or large changes

1. Create or update a plan under `plans/`
2. List impacted files and acceptance criteria
3. Implement one phase at a time
4. Run focused tests per phase
5. Sync docs before closing the task

## CABTA Architecture Map

High-signal entrypoints:

- `src/soc_agent.py` - CLI entrypoint
- `src/server.py` - MCP server entrypoint
- `src/web/app.py` - FastAPI app factory

Core orchestration modules:

- `src/tools/ioc_investigator.py`
- `src/tools/malware_analyzer.py`
- `src/tools/email_analyzer.py`

Important supporting layers:

- `src/analyzers/` - specialized analysis engines
- `src/integrations/` - TI, LLM, sandbox, STIX integrations
- `src/scoring/` - verdict and weighting logic
- `src/detection/` - rule generation
- `src/reporting/` - analyst outputs and reports
- `src/agent/` - agent loop, memory, tool registry, playbooks, MCP client
- `src/web/routes/` - API and dashboard routes

## When to Create a Plan

Create a plan for:

- any feature crossing multiple directories
- any scoring or verdict change
- any web + backend combined work
- any new analyzer or TI source
- any MCP or agent workflow change
- any refactor expected to last more than one session

Use the templates in `plans/templates/`.

## Documentation Rules

Update docs when you change:

- architecture
- configuration
- API behavior
- analyst workflow
- scoring logic
- setup or test procedure

At minimum, review:

- `README.md`
- `docs/system-design.md`
- `docs/codebase-summary.md`
- `TEST-MANIFEST.md`

## Reporting Style

- Be concise.
- State what changed, what was verified, and what remains risky.
- List unresolved questions at the end, if any.

## Unresolved Questions

- None.
