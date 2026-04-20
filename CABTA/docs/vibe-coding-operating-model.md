# CABTA — product operating model (vibe coding)

This file is **CABTA-only**: how the product balances deterministic analysis, agents, workflows, and governance.

**Workspace-wide** habits (plan / cook / fix / quality gates, progressive disclosure) live in the repo root: [`docs/vibe-coding-operating-model.md`](../../docs/vibe-coding-operating-model.md).

## Naming

- **Canonical product name:** `CABTA` (code, UI, new documentation). Expanded: Cyan Agent Blue Team Assistant.
- **`AISA`** may appear in older strategic docs (e.g. `project-overview-pdr.md`) as a historical or narrative alias for the same direction — **do not** introduce new “second product names” in code or user-facing strings. When in doubt, follow [`AGENTS.md`](../AGENTS.md).

## Why this exists

CABTA combines a deterministic analysis core with specialist agents, workflow orchestration, case intelligence, and MCP-driven expansion. Without clear lanes, AI-assisted coding drifts across boundaries.

## Core thesis

1. Protect the **deterministic analysis core** (IOC, file, email, scoring).
2. Add investigation power through **explicit layers** (agent, workflow, case store), not ad hoc shortcuts.
3. **Externalize** intent in plans and docs; avoid architecture-only-in-chat.
4. Integrate Vigil-inspired ideas **by seam**, not by copying another product wholesale.

## Planes (do not blur)

- Artifact **verdict** logic (analyzers + scoring)
- **Agent** reasoning and tool orchestration (explanatory; not final verdict authority)
- **Workflow** coordination
- **Response governance** (approvals, audit)

## Verdict-bearing flows

- Analyzers extract; integrations enrich; **scoring decides**; LLM explains; workflows orchestrate.
- Workflows must **call tools for evidence** when CABTA has a real tool path — do not “complete” an investigation step with pure model speculation.

## Local-first

Do not make core CABTA value depend on mandatory cloud inference, mandatory Docker for basic IOC/file/email analysis, or mandatory Redis/Postgres for those core paths.

## Honest degradation

If a workflow, MCP tool, or integration is unavailable: say so, return a useful partial state, offer manual fallback where possible.

## Vigil-inspired work

Treat Vigil as a **pattern library**. Adopt ideas and boundaries; avoid transplanting naming, storage assumptions, or provider lock-in blindly.

**Asymmetric model (default):**

- CABTA owns analysis core and verdict governance.
- Vigil-inspired layers own orchestration, specialist roles, approvals, optional daemon behavior.

## Work lanes (one at a time)

Use the lane that matches the task; see [`docs/ONBOARDING.md`](ONBOARDING.md) for what to read first.

- **Analysis core:** IOC, file, email, scoring, reporting.
- **Workflow:** definitions, registry, execution state, API/UI.
- **Specialist agent:** profiles, prompts, tool boundaries.
- **Case intelligence:** case schema, graph, timeline, pivots.
- **Governance:** approvals, AI decision logs, feedback, auditing.
- **Integration control:** MCP truth model, capability catalog, settings/health.
- **Background automation:** daemon, queue, optional headless dispatch.

## Planning rule

Create or update a plan when work crosses planes, changes scoring/verdict contracts, touches web + agent surfaces, adds specialists/workflows, affects cases/MCP, or spans multiple sessions. Use templates in [`plans/templates/`](../plans/templates/).

## Minimum plan shape

Goal, owning lane, affected planes, impacted files, contract risks, acceptance criteria, tests, docs to update, unresolved questions.

## Vigil feature checklist (before coding)

1. Does this call **real CABTA tools** for evidence where applicable?
2. Does it preserve **CABTA scoring** as verdict source of truth?

If either is “no”, redesign before merging.

## Quality gates

Done means: behavior implemented, lane verified, degraded paths honest, docs impact checked, boundaries intact, open questions listed.

## Test discipline (summary)

- **Analysis core:** unit + contract + web smoke if UI touched.
- **Workflow / agent:** workflow tests, agent routes, session regression.
- **Governance:** approval and decision-log tests.

## Documentation discipline

When architecture or operating assumptions change, update `docs/system-design.md`, `docs/future-system-roadmap.md`, or `docs/vigil-main-integration-blueprint.md` as appropriate — **link** to `system-design.md` instead of pasting full architecture into multiple files.

## Anti-patterns

- Using agent reasoning as **verdict authority**
- Workflows inferring verdicts without scoring/evidence paths
- Multi-session architecture work without a plan file
- Graph/timeline features without normalized entities where needed

## Unresolved questions

- None.
