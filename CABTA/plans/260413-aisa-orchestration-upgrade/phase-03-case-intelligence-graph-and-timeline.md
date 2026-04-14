# Phase 03: Case Intelligence, Graph, and Timeline

**Status:** Planning
**Objective:** upgrade AISA from isolated analysis views to case-centered investigation intelligence.

## Scope

- case-linked workflow state
- normalized entity extraction for graph and timeline features
- graph views and timeline reconstruction foundations
- cross-analysis pivoting across case context

## Tasks

1. [ ] Extend case model/store to attach:
   - workflow runs
   - entity references
   - timeline events
   - AI decisions
   - approval actions
2. [ ] Normalize entity extraction from IOC, file, email, and workflow results
3. [ ] Build graph builder service for:
   - entity graph
   - attack path graph
   - case-level relationship graph
4. [ ] Build timeline service for:
   - analysis jobs
   - email/file pivots
   - case events
   - workflow phase events
5. [ ] Add web/API surfaces for graph and timeline views
6. [ ] Link graph and timeline outputs into cases, reports, and workflow summaries

## Impacted Areas

- `src/web/case_store.py`
- `src/web/routes/cases.py`
- `src/tools/*`
- future graph and timeline modules
- `templates/*`
- `tests/*`

## Acceptance Criteria

- [ ] cases preserve investigation continuity beyond simple job grouping
- [ ] graph data comes from normalized entities, not UI-only reconstruction
- [ ] timeline data comes from real events and artifacts
- [ ] analysts can pivot through related entities inside a case context

## Tests

- add focused unit tests for graph and timeline builders
- `python -m pytest tests/test_web_api.py -q`
- add case-store and report linkage regression tests

## Unresolved Questions

- none yet
