# AISA Orchestration Upgrade Plan

**Date:** 2026-04-13
**Status:** Planning
**Type:** Feature

## Goal

Upgrade AISA by keeping CABTA as the authoritative analysis core and verdict-governance layer, while adding a Vigil-inspired orchestration plane for specialist agents, readable workflows, approval-driven actions, richer case intelligence, and optional headless SOC automation.

The goal is not to replace CABTA logic. The goal is to wrap CABTA's deterministic analysis engine with stronger investigation orchestration that stays tool-first, evidence-first, and safe for long-term vibe coding.

## Scope

- in scope: specialist agent foundation
- in scope: workflow definition and execution engine
- in scope: workflow-to-tool evidence routing through CABTA analysis core
- in scope: capability catalog and integration truth model
- in scope: case-linked workflow state, graph, and timeline foundations
- in scope: approval and AI decision governance
- in scope: optional daemon design and staged implementation path
- out of scope: replacing CABTA scoring with agent reasoning
- out of scope: mandatory Redis/Postgres/Docker for core localhost analysis
- out of scope: direct transplant of Vigil architecture or branding

## Architecture Stance

### Source of truth

- CABTA/AISA scoring remains the source of truth for verdict-bearing flows.
- Agents may summarize, organize, prioritize, and recommend.
- Agents may not silently become verdict authority.

### Evidence rule

- Workflows must call real tools for evidence.
- Orchestration layers should route through CABTA tools, analyzers, integrations, scoring, reporting, and approved MCP tools.
- Model-only inference is not a valid substitute for investigation evidence.

### Integration model

- CABTA/AISA owns the analysis core.
- Vigil-inspired features own the orchestration plane.
- The orchestration plane coordinates around the core instead of replacing it.

## Impacted Areas

- `src/agent/*`
- `src/tools/*`
- `src/web/routes/*`
- `src/web/case_store.py`
- `src/web/analysis_manager.py`
- `src/web/runtime_refresh.py`
- `src/mcp_servers/*`
- `templates/*`
- `tests/*`
- `docs/*`
- future `workflows/*`
- future workflow, governance, graph, timeline, and capability modules

## Acceptance Criteria

- [ ] specialist agents are explicit product concepts with bounded roles and methods
- [ ] workflow definitions are readable, inspectable, and resumable
- [ ] workflow execution is tool-first and evidence-first
- [ ] verdict-bearing workflow results still resolve through CABTA scoring and evidence paths
- [ ] case-linked workflow state is persisted and visible in web UI and APIs
- [ ] graph and timeline foundations exist for case intelligence
- [ ] approval and AI decision logging exist for governed actions
- [ ] capability truth for local tools, MCP tools, workflows, and integrations is explicit
- [ ] optional daemon mode is designed and staged without becoming mandatory for core use
- [ ] docs reflect the new architecture and developers can implement against them safely

## Risks

- risk: orchestration features bypass analysis core and create conflicting verdict semantics
- mitigation: require every verdict-bearing flow to route through CABTA scoring and result contracts

- risk: workflow engine becomes prompt-only and hard to trust
- mitigation: encode explicit tool expectations, evidence sources, and execution state in workflow services

- risk: too much Vigil complexity lands before capability truth and governance
- mitigation: implement in phases and block advanced automation behind explicit readiness gates

- risk: local-first simplicity regresses
- mitigation: keep daemon, queues, and heavier infra optional and phase-gated

## Delivery Strategy

- Phase 1 builds the guardrails and metadata needed to integrate safely.
- Phase 2 makes specialist agents and workflows first-class.
- Phase 3 upgrades investigation state with cases, graph, and timeline.
- Phase 4 adds governance for actions and AI decisions.
- Phase 5 hardens integration control and defines the optional daemon path.

## Phase Files

- `phase-01-core-boundaries-and-capability-foundation.md`
- `phase-02-specialist-agents-and-workflow-engine.md`
- `phase-03-case-intelligence-graph-and-timeline.md`
- `phase-04-governance-approval-and-ai-decisions.md`
- `phase-05-integration-control-and-headless-soc.md`
- `research-notes.md`

## Docs To Review

- `README.md`
- `docs/project-overview-pdr.md`
- `docs/system-design.md`
- `docs/vigil-main-integration-blueprint.md`
- `docs/future-system-roadmap.md`
- `docs/vibe-coding-operating-model.md`
- `docs/codebase-summary.md`
- `docs/feature-truth-matrix.md`
- `TEST-MANIFEST.md`

## Unresolved Questions

- none yet
