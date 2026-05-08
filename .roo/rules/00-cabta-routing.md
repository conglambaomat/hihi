# AISA Routing and Onboarding

Apply this guidance for CABTA product work in this repository.

## When to use CABTA context

Use CABTA context when the task involves:

- any file under `CABTA/`
- IOC investigation
- malware or file analysis
- email forensics
- SOC workflows
- MCP servers
- the AISA dashboard or API

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

## AISA lanes

Choose one primary lane before editing:

- `analysis-core` - deterministic IOC, file, email, scoring, detection, reporting
- `agent-workflow` - agent loop, playbooks, workflows, case memory, governance, MCP orchestration
- `web-surface` - FastAPI app, routes, templates, static assets, dashboard UX
- `integration-control` - provider health, capability status, runtime config, MCP management

If a task crosses more than one lane, create or update a plan under `CABTA/plans/` before coding.

## AISA invariants

- `AISA` is the canonical product name.
- AISA is local-first by default.
- Deterministic analyzers, scoring, and evidence paths remain authoritative for verdicts and scores.
- LLMs may interpret, summarize, route, and assist, but must not silently become verdict authority.
- Missing integrations should degrade honestly and preserve partial utility.
- Treat `AI Security Assistant`, `mcp-for-soc`, and similar names as legacy references only.

## GitNexus freshness

Before serious code tasks, check GitNexus index freshness when the GitNexus MCP server is available. Use the repo context or a safe read tool such as `list_repos`, `query`, or `context`. If any GitNexus response says the index is stale, run `npx gitnexus analyze` from the workspace root before relying on GitNexus for navigation, impact analysis, or implementation planning.

Do not block tiny local edits if GitNexus is unavailable. Do not auto-allow write-like GitNexus tools such as rename operations.

## Working note

Before implementation, state:

1. the chosen lane
2. the main files likely to change
3. whether GitNexus was checked or unavailable for a serious code task
4. whether a plan is required
5. which tests and docs are likely affected

## Completion hygiene

When ending a task, report the result only once.

- Do not send a long normal assistant message (`Roo said`) and then call `attempt_completion` or `Task Completed` with the same content.
- If `attempt_completion` is required, put the final result in that tool call and keep the preceding normal message absent, tool-only, or extremely short.
- Keep completions concise, non-duplicative, and focused on what changed, where it changed, and any verification performed.
- Prefer referencing created or modified artifacts by path instead of repeating long generated content.
