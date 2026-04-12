# CABTA Plan Template Usage Guide

## When to Use These Templates

Use a plan whenever the task is:

- multi-file
- cross-layer
- longer than one session
- likely to change scoring, APIs, or analyst workflow

## Template Selection

### Feature template

Use for:

- new analyzer
- new TI source
- new dashboard workflow
- new agent or MCP capability
- new reporting capability

### Bug-fix template

Use for:

- broken analysis behavior
- incorrect verdicts
- API regressions
- dashboard bugs
- config or integration failures

### Refactor template

Use for:

- cleanup without intended behavior change
- naming normalization
- result-shape cleanup
- moving logic across layers

## Context Discipline

Keep plans short and high-signal.

- link files instead of pasting large code blocks
- define acceptance criteria clearly
- keep each phase small
- list exact tests to run

## Naming Suggestion

Use:

```text
plans/YYMMDD-short-feature-name/
```

Example:

```text
plans/260330-email-bec-hardening/
```

## Minimum Files in a Plan Directory

- `plan.md`
- one or more `phase-XX-*.md` files

Optional:

- `research-notes.md`
- `test-notes.md`
- `open-questions.md`

## Unresolved Questions

- None.
