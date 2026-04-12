# CABTA Code Standards

## Purpose

These standards exist to make CABTA safer to evolve with AI-assisted development.

The goals are:

- preserve analytical correctness
- keep outputs explainable
- reduce context drift across long tasks
- make tests and docs part of delivery

## General Principles

### Prefer deterministic logic for verdicts

- LLMs may explain, summarize, or help interpret.
- LLMs should not become the sole source of threat verdicts.
- Scoring and evidence should stay inspectable.

### Fail soft

- missing API keys should reduce enrichment, not crash the workflow
- optional tools should degrade gracefully
- partial functionality is better than hard failure for analyst workflows

### Keep user-facing naming consistent

- prefer `CABTA` in new docs and UI copy
- preserve legacy names only where compatibility matters
- avoid adding fresh naming drift

### Small changes beat wide rewrites

- change the narrowest layer that solves the problem
- keep end-to-end behavior in mind, especially for scoring and reporting

## Python Standards

- Prefer explicit, readable Python over clever abstractions.
- Preserve type hints where present.
- Keep functions focused and short when practical.
- Use clear log messages with subsystem tags such as `[IOC]`, `[EMAIL]`, `[WEB]`, `[MALWARE]`.
- Avoid introducing hidden side effects in constructors.

## Async and I/O Standards

- Network-heavy operations should remain async-aware.
- Preserve timeout behavior.
- Avoid blocking calls in async paths unless there is no practical alternative.
- If you add a new external source, make timeout and error handling explicit.

## Result Shape Standards

When extending results:

- keep stable keys where existing callers may depend on them
- add new keys rather than silently replacing old ones
- preserve backward-compat aliases if needed during transitions
- keep analyst-facing outputs human-readable

Be especially careful in:

- `src/tools/`
- `src/reporting/`
- `src/web/routes/`
- MCP tool payloads

## Scoring Standards

Scoring changes are product behavior changes.

Before changing scoring:

1. identify all affected result paths
2. state the intended analyst outcome
3. update or add tests
4. document the change if user-visible

Touch these files carefully:

- `src/scoring/intelligent_scoring.py`
- `src/scoring/tool_based_scoring.py`
- `src/scoring/adaptive_scoring.py`
- `src/scoring/enhanced_scoring.py`
- `src/scoring/false_positive_filter.py`

## Web and API Standards

- Keep API routes thin where possible.
- Put analysis logic in tools/analyzers, not directly in routes.
- If a route changes payload shape, review templates and tests.
- Keep dashboard and API behavior aligned.

## Analyzer Standards

When adding or modifying analyzers:

- keep analyzer responsibility narrow
- return structured findings
- avoid burying scoring logic inside low-level analyzers unless already established
- surface evidence in a way reporting layers can reuse

If adding a new file type:

1. add analyzer
2. register through file type routing
3. connect orchestration path
4. add tests
5. update docs

## LLM Standards

- local LLM remains the preferred default
- prompts should focus on interpretation and explanation
- do not hide raw evidence behind LLM-only summaries
- if LLM fails, return a useful result anyway

## Testing Standards

- For changed behavior, run the smallest relevant test slice first.
- For cross-layer changes, run all directly affected tests.
- Add tests for bug fixes when practical.
- If you could not run tests, say so explicitly.

Use `TEST-MANIFEST.md` to choose the right test scope.

## Documentation Standards

Update docs when you change:

- setup
- configuration
- architecture
- API behavior
- scoring logic
- naming
- workflow expectations

At minimum, review:

- `README.md`
- `docs/project-overview-pdr.md`
- `docs/codebase-summary.md`
- `TEST-MANIFEST.md`

## Planning Standards

Create a plan when:

- the task spans multiple directories
- the work will continue across sessions
- the change alters architecture or scoring
- the work has more than 3 meaningful steps

Use the templates in `plans/templates/`.

## Completion Standard

Do not consider a task complete until:

- implementation is done
- relevant tests were run or explicitly deferred
- docs impact was checked
- unresolved questions are listed

## Unresolved Questions

- None.
