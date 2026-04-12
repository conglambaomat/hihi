# CABTA Codebase Summary

## Overview

CABTA is a Python codebase with three main entry modes:

- CLI via `src/soc_agent.py`
- MCP server via `src/server.py`
- web app via `src/web/app.py`

The system is modular and already broad. The main challenge for future work is not missing capability, but keeping changes aligned across orchestration, analyzers, scoring, reporting, and docs.

## High-Signal Directory Map

### `src/tools/`

Top-level analysis orchestrators:

- `ioc_investigator.py`
- `malware_analyzer.py`
- `email_analyzer.py`

Use these first when changing end-to-end behavior.

### `src/analyzers/`

Specialized artifact analysis engines by type and domain:

- PE, ELF, Mach-O, Office, PDF, Script, APK, Archive, Memory, Text
- email-specific analyzers and deobfuscators

Use this layer when changing artifact parsing or domain-specific detection.

### `src/integrations/`

External enrichment and output integrations:

- threat intelligence
- LLM analysis
- sandbox connectors
- STIX generation
- threat actor profiling

Use this layer when adding external data sources or changing enrichment semantics.

### `src/scoring/`

Threat scoring and false-positive handling:

- `tool_based_scoring.py`
- `intelligent_scoring.py`
- `adaptive_scoring.py`
- `enhanced_scoring.py`
- `false_positive_filter.py`

Any change here can alter final verdicts across the product.

### `src/detection/`

Rule generation:

- YARA
- Sigma
- KQL
- SPL
- email security formats

Use this layer when changing operational outputs for defenders.

### `src/reporting/`

Human-facing outputs:

- HTML
- markdown
- executive summaries
- MITRE Navigator layers
- SOC formatter

Use this layer when changing analyst UX or export fidelity.

### `src/web/`

FastAPI dashboard and APIs:

- `app.py` initializes shared state and route wiring
- `routes/` contains API/page endpoints
- `analysis_manager.py` and `case_store.py` persist dashboard state

Use this layer for dashboard workflows, APIs, and web-facing orchestration.

### `src/agent/`

Agent and MCP orchestration:

- agent loop
- memory
- playbooks
- tool registry
- sandbox orchestration
- MCP client manager

This is a high-leverage area and a likely growth zone for future CABTA development.

### `tests/`

Focused test surface across:

- web API
- analyzers
- scoring
- caching
- email
- agent behavior

There are `21` test modules in the current repo snapshot.

## Entry Points and Their Roles

### `src/soc_agent.py`

- primary CLI entrypoint
- user-facing command execution
- report formatting
- high-volume legacy output logic

Changes here affect direct analyst workflows and CLI usability.

### `src/server.py`

- MCP server entrypoint
- exposes CABTA as tools to external MCP clients
- wires IOC, email, and file analysis as callable tools

Changes here affect AI-assisted interoperability.

### `src/web/app.py`

- FastAPI application factory
- initializes stateful services
- mounts routes and templates
- auto-connects configured MCP servers

Changes here affect the dashboard, APIs, and system startup behavior.

## Current Context Risks

### 1. Naming drift

The repo still contains multiple identities:

- `CABTA`
- `Blue Team Assistant`
- `mcp-for-soc`

When making new changes:

- use `CABTA` in new docs and user-facing design decisions
- preserve legacy names only where compatibility or historical references matter

### 2. Mixed maturity across docs

README is rich, but repo-wide development memory is incomplete. Some docs still point to older names or outdated install paths.

### 3. Cross-layer feature coupling

A single feature can easily touch:

- tools
- analyzers
- scoring
- reporting
- web routes
- tests

Planning is important for anything beyond a narrow fix.

## Recommended Change Lanes

### IOC work

Start in:

- `src/tools/ioc_investigator.py`
- `src/integrations/threat_intel*.py`
- `src/utils/dga_detector.py`
- `src/utils/domain_age_checker.py`
- `src/scoring/intelligent_scoring.py`

### Malware/file work

Start in:

- `src/tools/malware_analyzer.py`
- `src/analyzers/file_type_router.py`
- relevant analyzer in `src/analyzers/`
- `src/scoring/tool_based_scoring.py`
- `src/reporting/`

### Email work

Start in:

- `src/tools/email_analyzer.py`
- `src/analyzers/email_forensics.py`
- `src/analyzers/email_threat_indicators.py`
- `src/analyzers/bec_detector.py`
- `src/scoring/intelligent_scoring.py`

### Web/API work

Start in:

- `src/web/app.py`
- relevant file under `src/web/routes/`
- matching template under `templates/`
- related frontend asset under `static/`

### Agent/MCP work

Start in:

- `src/server.py`
- `src/agent/tool_registry.py`
- `src/agent/agent_loop.py`
- `src/agent/playbook_engine.py`
- `src/agent/mcp_client.py`

## Practical Development Advice

- Read the orchestrator first, not only the specialized analyzer.
- Check tests before changing result shapes.
- Treat scoring changes as product behavior changes.
- Keep docs updated when setup, outputs, or naming changes.
- Create a plan for any cross-layer work.

## Unresolved Questions

- None.
