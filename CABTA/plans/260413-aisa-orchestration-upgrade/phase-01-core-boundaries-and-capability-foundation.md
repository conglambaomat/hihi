# Phase 01: Core Boundaries and Capability Foundation

**Status:** Planning
**Objective:** lock the analysis-core versus orchestration-plane boundary in code, config, and runtime truth before adding major new workflow behavior.

## Scope

- establish explicit architectural seam between verdict core and orchestration plane
- add machine-readable capability truth for tools, MCP, integrations, and workflows
- harden result contracts and routing assumptions needed by later phases

## Tasks

1. [ ] Define `agent profile` and `workflow capability` domain models in new modules under `src/agent/` or `src/workflows/`
2. [ ] Add capability catalog generator or runtime registry for:
   - local tools
   - MCP tools
   - integrations
   - workflow definitions
   - specialist agents
3. [ ] Extend health/config APIs so they can express:
   - available
   - configured
   - manual
   - degraded
   - not_configured
   - verdict_authority_owner
4. [ ] Add explicit metadata or adapter layer that marks verdict-bearing results as owned by CABTA scoring
5. [ ] Add developer-facing contract docs or schemas for workflow-to-analysis routing
6. [ ] Add regression tests proving workflow layers cannot override artifact verdict authority

## Impacted Areas

- `src/agent/*`
- `src/web/routes/config_api.py`
- `src/web/data_provider.py`
- `src/web/runtime_refresh.py`
- future `src/workflows/*`
- `tests/test_web_api.py`
- `tests/test_agent.py`

## Acceptance Criteria

- [ ] capability truth is accessible at runtime
- [ ] specialist agents and workflows can be represented without changing verdict semantics
- [ ] health/config surfaces communicate who owns verdict authority
- [ ] no workflow or agent route can silently claim final verdict ownership

## Tests

- `python -m pytest tests/test_agent.py -q`
- `python -m pytest tests/test_web_api.py -q`
- `python -m pytest tests/test_web_data_provider.py -q`

## Unresolved Questions

- none yet
