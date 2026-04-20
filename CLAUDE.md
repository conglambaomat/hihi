# CLAUDE.md

This file gives Claude Code root-level guidance for this repository.

## Context Routing

Before planning or implementing, route yourself to the correct project context.

### Default to CABTA

If the task is about the product, security analysis features, the dashboard, MCP exposure, or any path under `CABTA/`, read these first:

1. `./CABTA/docs/ONBOARDING.md` (what to read next by task — start here)
2. `./CABTA/README.md`
3. `./CABTA/AGENTS.md`
4. `./CABTA/docs/system-design.md`
5. `./CABTA/docs/codebase-summary.md`
6. `./CABTA/docs/code-standards.md`
7. `./CABTA/TEST-MANIFEST.md`

If the task is ambiguous, choose this path.

### Use root context only for workspace tooling

Use root context first only when the task explicitly targets:

- `.claude/` workflows, hooks, or settings (skill markdown lives under `.cursor/skills/`)
- root `plans/`
- root `docs/`
- release or packaging scripts at the repo root

For those tasks, read:

1. `./README.md`
2. `./.claude/rules/development-rules.md`
3. the relevant root file

## Naming Rules

- `CABTA` is the canonical product name.
- `Blue Team Assistant`, `mcp-for-soc`, `Claude Code Boilerplate`, and `claudekit-engineer` are legacy references and should not be reintroduced into new CABTA-facing work.
- Prefer the nearest local instructions when a deeper `AGENTS.md` or project doc exists.

## Root Notes

- The root `README.md` is a workspace index. It does not define CABTA's architecture.
- Root `docs/` mainly describe shared agent tooling and historical scaffolding. They are not CABTA's source of truth.
- When touching root tooling, follow `./.claude/rules/development-rules.md`.

## GitNexus (optional)

If GitNexus MCP is connected, prefer it for impact-aware refactors when appropriate. It is not mandatory for routine edits. Details: [`docs/gitnexus-workflow.md`](docs/gitnexus-workflow.md).
