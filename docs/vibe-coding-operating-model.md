# Vibe Coding Operating Model for Large Projects

**Status:** Recommended working model  
**Scope:** Workspace-wide delivery discipline in this repository (not CABTA product architecture — for that see `CABTA/docs/ONBOARDING.md` and `CABTA/docs/system-design.md`).

## Core Thesis

In this repo, "vibe coding" does **not** mean improvising with a chat window until something works.

It means:

1. Keep a **persistent written plan** as source of truth.
2. Use agents/skills/tasks as the **execution engine**.
3. Use hooks as **guardrails** for context, privacy, and performance.
4. Require **tests, review, and docs sync** before claiming completion.
5. Optimize for **token quality**, not raw context volume.

The repo's strongest idea is simple:

> Fast AI work is reliable only when orchestration, context control, and verification are built into the workflow.

## Non-Negotiables

- `plan` creates the persistent implementation shape.
- `cook` is the main implementation orchestrator.
- `fix` always starts with `debug`, not guesswork.
- `test` and `code-review` are gates, not optional polish.
- Plan files stay persistent; session tasks are temporary execution state.
- Docs updates are part of delivery, not post-work cleanup.
- Reports stay concise and end with unresolved questions if any.

## Large-Project Default Loop

### 1. Intake and Scoping

- Start with `README.md`, `docs/`, and relevant existing plans.
- Scout the codebase before changing anything substantial.
- Define the work as one plan directory, not a loose conversation.
- Split work into phases with explicit scope boundaries and file ownership.

### 2. Planning First

Use `plan` for:

- net-new features
- refactors crossing multiple modules
- work with 3+ meaningful steps
- anything likely to survive across sessions

Planning rules:

- Executive summary: short
- Context: link files/docs, do not paste everything
- Tasks: concrete, checkable, phase-scoped
- Success criteria: measurable
- Risks: explicit

### 3. Hydrate Work Into Tasks

Treat markdown plans as the durable layer and Claude Tasks as the session layer.

- Write `plan.md` plus phase files
- Hydrate unchecked items into tasks
- Track dependencies with blocked-by chains
- On resume, re-hydrate from remaining unchecked items
- On completion, sync tasks back to plan checkboxes

This is the key pattern that makes long work survivable across sessions.

### 4. Execute Through Narrow Lanes

Use a small set of stable lanes:

- Feature work: `plan` -> `cook`
- Bug work: `fix` -> `debug` -> `test` -> `code-review`
- Validation-only work: `test`
- Review-only work: `code-review`
- Docs lookup: `docs-seeker`
- Context health / optimization: `context-engineering`

Do not invent a custom workflow for every task.

### 5. Verification Before Completion

Completion requires:

- relevant tests passing
- code review performed
- docs impact checked
- plan/task sync complete
- unresolved questions listed

No "done" claim before evidence.

## Context Rules

### Progressive Disclosure

Load the minimum context needed to move the current step forward.

- skill metadata first
- `SKILL.md` second
- references only when needed
- avoid dumping large docs into active context

### Externalize State

Put durable state in:

- plan files
- reports
- docs
- `plans/reports/` (or optional `docs/journals/` if you recreate it) when lessons matter

Do not rely on chat history as the project memory.

### Compact Early

When context gets heavy:

- summarize current state
- write it to a file
- carry only active constraints forward

Target compaction before the session becomes noisy or confused.

### Guardrails Matter

Keep the hooks working for large-project discipline:

- `session-init.cjs` for environment/session context
- `dev-rules-reminder.cjs` for prompt-time rule injection
- `scout-block.cjs` for avoiding heavy low-signal directories
- `privacy-block.cjs` for sensitive file control
- `subagent-init.cjs` and team hooks for scoped delegation context
- `post-edit-simplify-reminder.cjs` for keeping implementation quality from drifting

## What persistent notes teach

Short reports under `plans/reports/` (or a revived `docs/journals/`) are valuable because they record failures, not just ideals.

### Anti-Patterns to Avoid

- research mistaken for execution
- ambitious multi-phase plans with no scheduled implementation
- giant skill/docs dumps that poison context
- internal optimization work without owner, milestone, or ship target
- claiming success before tests or verification
- spreading the same logic across many files "for now"

### Biases to Adopt

- boring shipping beats elegant stagnation
- smaller scoped phases beat grand master plans
- explicit ownership beats parallel chaos
- concise reports beat verbose status theater
- root-cause fixes beat symptom patching

## Runtime Adaptation Rule

If the current runtime supports subagents or teams, use them for bounded parallel work.

If the runtime does **not** support delegation, keep the **same artifacts and gates** but run them serially:

- still plan
- still hydrate or maintain checklist state
- still separate debug from fix
- still run tests
- still review
- still sync docs

Loss of delegation is **not** a reason to lose structure.

## Recommended Operating Policy for the Upcoming Large Project

### Work Unit

- One plan directory per feature/initiative
- One active phase at a time unless ownership is explicit
- Max 10 tasks per phase
- Prefer 1-3 day slices over week-long vague phases

### Command Discipline

- Start complex work with `plan`
- Execute with `cook`
- Route bugs through `fix`
- Route uncertainty through `research` or `docs-seeker`
- Route validation through `test`
- Route quality gates through `code-review`

### Documentation Discipline

- Update `docs/` when architecture, workflow, or standards change
- Keep summaries short and link deeper material
- Add short reports for painful lessons worth preserving

### Review Discipline

- Findings first
- Evidence over confidence
- Edge-case scouting before approval

### Done Criteria

A work item is done only when:

- implementation landed
- tests passed
- review issues resolved
- docs impact handled
- plan checkboxes synced
- remaining open questions called out

## Practical Default

For the next large project, the safest default is:

1. Plan everything non-trivial.
2. Keep plan files as system memory.
3. Execute in small phases.
4. Use strict verify/review/docs gates.
5. Prefer progressive disclosure over loading everything.
6. Treat written reports as feedback loops for workflow repair.

**CABTA product work:** use `CABTA/docs/ONBOARDING.md` for the short read order; use `CABTA/docs/vibe-coding-operating-model.md` for product lanes (analysis vs workflow vs governance). Do not paste long architecture here — link `CABTA/docs/system-design.md`.

That is the repo's real version of "vibe coding":

high-tempo AI execution with persistent structure, narrow context, and hard quality gates.

## Unresolved Questions

- None at this time.
