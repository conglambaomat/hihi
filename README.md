# hihi Workspace

This repository is a workspace that currently hosts `CABTA` as the primary product, alongside shared agent tooling and some historical ClaudeKit-era scaffolding at the repo root.

## Start Here

### For CABTA work

Read these first:

1. `CABTA/README.md`
2. `CABTA/AGENTS.md`
3. `CABTA/docs/system-design.md`

`CABTA/` is the product application. If a task is ambiguous, assume the user means CABTA.

### For root tooling work

Use the root only when the task explicitly targets shared agent workflows, hooks, skills, plans, or packaging scripts.

Important files:

- `AGENTS.md`
- `CLAUDE.md`
- `.claude/rules/development-rules.md`

## What Lives In This Repo

- `CABTA/` - local-first SOC and DFIR platform for IOC investigation, file analysis, email forensics, reporting, and MCP exposure
- `.claude/` - shared agent workflows, hooks, skills, and repo automation
- `plans/` - plan templates and implementation memory
- `docs/` - root workspace and legacy reference docs

## Important Context Rule

The root README is a workspace landing page. It is not the runtime or architecture README for CABTA.

If you are developing the security product, do not anchor on root boilerplate text. Go straight to `CABTA/`.

## CABTA Quick Start

```bash
git clone https://github.com/conglambaomat/hihi.git
cd hihi/CABTA
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn src.web.app:create_app --factory --host 0.0.0.0 --port 3003
```

Then open `http://localhost:3003`.
