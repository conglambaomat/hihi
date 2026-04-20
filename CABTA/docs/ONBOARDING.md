# CABTA — agent onboarding (single read order)

Paths below are relative to the `CABTA/` directory unless noted.

## Start here (minimal)

1. [`README.md`](../README.md) — product scope and quick start  
2. [`AGENTS.md`](../AGENTS.md) — invariants, architecture map, when to plan  
3. **This file** — what to read next by task (avoid loading every doc every time)

## By task type

### Small fix (one module, clear scope)

- [`docs/code-standards.md`](code-standards.md)  
- [`TEST-MANIFEST.md`](../TEST-MANIFEST.md) — pick the right tests  

### Feature / API / integration work

- [`docs/system-design.md`](system-design.md) — architecture (authoritative for structure)  
- [`docs/codebase-summary.md`](codebase-summary.md) — directory map  

### Runtime, demo, or integration-sensitive work (required)

- [`docs/feature-truth-matrix.md`](feature-truth-matrix.md) — what is tested, wired, vs manual/optional  

### Scoring, verdicts, agent vs deterministic boundaries

- [`docs/feature-truth-matrix.md`](feature-truth-matrix.md)  
- [`docs/system-design.md`](system-design.md)  
- [`docs/project-overview-pdr.md`](project-overview-pdr.md) — strategic context (**naming note at top**; do not duplicate architecture here — use `system-design.md`)  

### Large or multi-session work

- Relevant files under [`plans/`](../plans/)  
- Repo root [`docs/vibe-coding-operating-model.md`](../../docs/vibe-coding-operating-model.md) — workspace discipline (plan / cook / fix / gates)  
- [`docs/vibe-coding-operating-model.md`](vibe-coding-operating-model.md) — **CABTA-only** product lanes (analysis core vs workflow vs governance)  

## Product invariants (non-negotiable)

- **Final verdicts and numeric scoring** are owned by deterministic CABTA analyzers and scoring — not by LLM text as the source of truth.  
- **LLMs** may interpret, summarize, route tools, and assist investigations; they do not replace scoring engines for authoritative verdict output.  

## Deeper reference (load on demand)

- [`docs/future-system-roadmap.md`](future-system-roadmap.md)  
- [`docs/vigil-main-integration-blueprint.md`](vigil-main-integration-blueprint.md)  
- Screenshots under `docs/screenshots/` — visual reference only, not architectural truth  
