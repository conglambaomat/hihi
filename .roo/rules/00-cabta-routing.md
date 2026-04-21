# CABTA Routing and Onboarding

Apply this guidance for CABTA product work in this repository.

## When to use CABTA context

Use CABTA context when the task involves:

- any file under `CABTA/`
- IOC investigation
- malware or file analysis
- email forensics
- SOC workflows
- MCP servers
- the CABTA dashboard or API

If the task is ambiguous, default to `CABTA/`.

## Read order

Load the smallest useful CABTA context set in this order:

1. `CABTA/docs/ONBOARDING.md`
2. `CABTA/AGENTS.md`
3. `CABTA/README.md`
4. `CABTA/docs/system-design.md`
5. `CABTA/docs/codebase-summary.md`
6. `CABTA/docs/code-standards.md`
7. `CABTA/TEST-MANIFEST.md`

Load deeper docs only when the task requires them.

## CABTA lanes

Choose one primary lane before editing:

- `analysis-core` - deterministic IOC, file, email, scoring, detection, reporting
- `agent-workflow` - agent loop, playbooks, workflows, case memory, governance, MCP orchestration
- `web-surface` - FastAPI app, routes, templates, static assets, dashboard UX
- `integration-control` - provider health, capability status, runtime config, MCP management

If a task crosses more than one lane, create or update a plan under `CABTA/plans/` before coding.

## CABTA invariants

- `CABTA` is the canonical product name.
- CABTA is local-first by default.
- Deterministic analyzers, scoring, and evidence paths remain authoritative for verdicts and scores.
- LLMs may interpret, summarize, route, and assist, but must not silently become verdict authority.
- Missing integrations should degrade honestly and preserve partial utility.
- Treat `Blue Team Assistant`, `mcp-for-soc`, and similar names as legacy references only.

## Working note

Before implementation, state:

1. the chosen lane
2. the main files likely to change
3. whether a plan is required
4. which tests and docs are likely affected
