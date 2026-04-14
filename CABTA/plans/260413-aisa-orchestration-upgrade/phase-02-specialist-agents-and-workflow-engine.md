# Phase 02: Specialist Agents and Workflow Engine

**Status:** Planning
**Objective:** introduce named specialist agents and a readable workflow engine that coordinates CABTA analysis tools rather than replacing them.

## Scope

- explicit specialist agent profiles
- readable workflow definitions
- workflow parser, registry, execution service, and run tracking
- workflow execution routed through CABTA tools and approved MCP tools

## Tasks

1. [ ] Create agent profile library for:
   - triage
   - investigator
   - threat_hunter
   - correlator
   - responder
   - reporter
   - mitre_analyst
   - malware_analyst
   - network_analyst
2. [ ] Define workflow file format with:
   - metadata
   - roles
   - phases
   - required or preferred tools
   - evidence-source declarations
   - approval-gated steps
3. [ ] Build workflow discovery and reload service
4. [ ] Build workflow execution state model with resumable phase tracking
5. [ ] Route workflow evidence steps into CABTA tools:
   - IOC
   - file
   - email
   - search/correlation helpers
   - MCP tools where declared
6. [ ] Expose workflow list/detail/run/status APIs
7. [ ] Add workflow UI surface and session linkage in web app
8. [ ] Ensure verdict-bearing outputs in workflow results reuse CABTA scoring outputs rather than freeform agent claims

## Impacted Areas

- `src/agent/*`
- future `src/workflows/*`
- `src/web/app.py`
- `src/web/routes/*`
- `templates/*`
- `tests/test_agent.py`
- future workflow tests

## Acceptance Criteria

- [ ] specialist agents are selectable and have explicit methodologies
- [ ] workflow definitions are readable and reloadable
- [ ] workflow runs are observable phase by phase
- [ ] workflow steps gather evidence via real tools
- [ ] workflow summaries cannot overrule CABTA verdicts

## Tests

- `python -m pytest tests/test_agent.py -q`
- `python -m pytest tests/test_web_api.py -q`
- add new focused workflow parser and execution tests

## Unresolved Questions

- none yet
