# CABTA Agent Workflows

Use this rule for CABTA's investigation and orchestration planes.

## Scope

Primary areas:

- `CABTA/src/agent/`
- `CABTA/src/workflows/`
- `CABTA/src/web/routes/agent.py`
- `CABTA/src/web/routes/chat.py`
- `CABTA/src/web/routes/workflows.py`
- `CABTA/src/web/routes/governance.py`
- `CABTA/src/web/routes/mcp_management.py`
- `CABTA/workflows/`
- workflow, agent, governance, and MCP-related tests

## Architectural boundary

This lane coordinates investigations around the analysis core.

It may:

- gather evidence through CABTA tools and approved MCP tools
- organize reasoning, hypotheses, and case memory
- drive workflows, specialist routing, and approvals
- summarize findings and recommend next actions

It may not:

- invent unsupported findings instead of calling tools
- override deterministic CABTA scoring as the final verdict source
- hide degraded runtime capability behind fake success

## Important modules

Start with these high-signal files:

- `CABTA/src/agent/agent_loop.py`
- `CABTA/src/agent/tool_registry.py`
- `CABTA/src/agent/playbook_engine.py`
- `CABTA/src/agent/mcp_client.py`
- `CABTA/src/workflows/registry.py`
- `CABTA/src/workflows/service.py`

If workflow definitions are involved, inspect `CABTA/workflows/` frontmatter and body shape before editing runtime code.

## Workflow definition pattern

CABTA workflow definitions are markdown-backed contracts.

Preserve these conventions:

- one workflow directory per capability under `CABTA/workflows/`
- frontmatter for id, name, backend, tools, capabilities, approvals, and dependencies
- short body sections that explain the operating model and phase sequence
- honest dependency semantics through `required-tools`, `required-features`, and MCP server fields

## Plan triggers

Create or update a plan when the change:

- touches agent plus web surfaces
- changes workflow contracts or approval semantics
- affects case memory, thread state, or governance persistence
- modifies MCP capability exposure or runtime dependency status
- introduces new specialist roles or new workflows

## Delivery checklist

- verify the feature still uses real tools for evidence
- verify deterministic decisions remain distinct from agentic explanation
- test degraded states for missing providers, MCP servers, or playbooks
- update docs if workflow or runtime assumptions changed
