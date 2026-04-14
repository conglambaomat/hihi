# Phase 05: Integration Control and Headless SOC

**Status:** Planning
**Objective:** strengthen integration governance and define the optional path to headless background SOC operations.

## Scope

- richer MCP and integration control plane
- workflow dependency declarations
- custom integration metadata groundwork
- optional daemon design and staged introduction

## Tasks

1. [ ] Extend MCP and integration metadata with:
   - capability class
   - risk class
   - workflow dependencies
   - evidence role
   - manual/degraded semantics
2. [ ] Surface capability truth in settings, workflow detail views, and health pages
3. [ ] Add workflow dependency validation before execution
4. [ ] Define custom integration metadata and validation path
5. [ ] Design optional daemon mode for:
   - scheduled hunts
   - polling
   - background enrichment
   - monitored autonomous operations
6. [ ] Ensure daemon path is optional and cannot become a dependency for core localhost analysis
7. [ ] Add observability and audit expectations for background operations

## Impacted Areas

- `src/web/routes/mcp_management.py`
- `src/web/routes/config_api.py`
- `src/agent/mcp_client.py`
- future capability catalog modules
- future daemon modules
- `templates/*`
- `tests/*`

## Acceptance Criteria

- [ ] integrations and tools expose truthful readiness and risk state
- [ ] workflows know what dependencies they need before running
- [ ] custom integration path has clear metadata and validation boundaries
- [ ] daemon mode is staged as optional, not mandatory

## Tests

- MCP and config regression tests
- capability-state tests
- future daemon smoke tests behind explicit feature flag
- `python -m pytest tests/test_web_api.py -q`

## Unresolved Questions

- none yet
