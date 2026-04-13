# AGENTS.md

This file routes agents to the correct project context in this repository.

## Workspace Identity

- Repository name: `hihi`
- Primary product: `CABTA/`
- Root `.claude/`, `plans/`, and root `docs/` contain shared agent tooling plus historical ClaudeKit-era material.
- Do not assume the root of this repo describes CABTA's runtime architecture unless the task explicitly targets root tooling.

## First Routing Decision

### Default path for almost all product work

If the task mentions any of the following, start in `CABTA/`:

- `CABTA`
- IOC investigation
- malware analysis
- email forensics
- SOC workflows
- MCP servers
- dashboard or API
- any file under `CABTA/`

Read these first:

1. `./CABTA/README.md`
2. `./CABTA/AGENTS.md`
3. `./CABTA/docs/system-design.md`
4. `./CABTA/docs/codebase-summary.md`
5. `./CABTA/docs/code-standards.md`
6. `./CABTA/TEST-MANIFEST.md`

If the task is ambiguous, default to `CABTA/`.

### Root tooling path

Only use root context first when the task explicitly targets:

- `.claude/`
- root `plans/`
- root `docs/`
- root release or packaging scripts
- workspace-level agent workflows

For those tasks, read:

1. `./README.md`
2. `./.claude/rules/development-rules.md`
3. the relevant root doc or script

## Hard Rules

- `CABTA` is the canonical product name for the security platform in this repo.
- Treat `Blue Team Assistant`, `mcp-for-soc`, `Claude Code Boilerplate`, and `claudekit-engineer` as legacy or historical references unless the task is explicitly about preserving that history.
- Do not copy root boilerplate identity into CABTA docs, UI, reports, or code comments.
- Prefer the nearest project-local instructions over root instructions.
- Keep reports concise and list unresolved questions at the end.

## Root Context Limits

- Root `README.md` is a workspace landing page, not the product README for CABTA.
- Root `docs/` are not the source of truth for CABTA runtime behavior.
- When working inside `CABTA/`, follow `CABTA/AGENTS.md` over this file.
