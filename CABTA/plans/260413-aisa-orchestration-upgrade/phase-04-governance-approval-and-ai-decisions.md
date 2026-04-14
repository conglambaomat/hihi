# Phase 04: Governance, Approval, and AI Decisions

**Status:** Planning
**Objective:** make AI-assisted actions auditable, approval-aware, and feedback-driven.

## Scope

- approval action model
- approval queue and thresholds
- AI decision logging
- reviewer feedback and audit trail

## Tasks

1. [ ] Create approval action schema with:
   - action type
   - target
   - confidence
   - evidence references
   - rationale
   - approval state
2. [ ] Build approval service and persistence model
3. [ ] Integrate approval gating with:
   - workflow steps
   - agent actions
   - sandbox or response actions
4. [ ] Create AI decision log model for meaningful agent decisions
5. [ ] Add human feedback capture on AI decisions
6. [ ] Add web views for:
   - pending approvals
   - decision logs
   - reviewer feedback
7. [ ] Ensure all action proposals are evidence-backed and linked to real findings/jobs/cases

## Impacted Areas

- `src/agent/*`
- `src/web/routes/*`
- `src/web/case_store.py`
- future approval and decision-log modules
- `templates/*`
- `tests/*`

## Acceptance Criteria

- [ ] high-impact actions are governed by explicit policy
- [ ] approval state is visible in UI and APIs
- [ ] AI decisions can be reviewed after the fact
- [ ] feedback can improve trust and future tuning
- [ ] approval and decision services never become substitute verdict engines

## Tests

- add approval service unit tests
- add AI decision log API tests
- `python -m pytest tests/test_agent.py -q`
- `python -m pytest tests/test_web_api.py -q`

## Unresolved Questions

- none yet
