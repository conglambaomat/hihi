# AISA Vibe SOC Agentic Platform Remediation Plan

Date: 2026-04-29

Plan file: `CABTA/plans/2026-04-29-vibe-soc-agentic-platform-remediation-plan.md`

## Chosen lanes and why this plan is required

Primary lanes:

- `agent-workflow`: the main remediation touches the agent loop, request interpretation, capability planning, tool execution boundaries, evidence graph, memory, governance, and feedback loop.
- `web-surface`: chat/API/WebSocket/UI currently expose agent state and deterministic decision panels, so verdict safety, compile/plan preview, workbench UX, and feedback capture require coordinated web changes.
- `analysis-core`: deterministic analyzers, scoring, parser outputs, evidence contracts, and verdict authority must remain authoritative as the agentic platform becomes more capable.
- `integration-control`: MCP and SIEM/backend degradation, tool capability availability, policy gates, and audit trails must be explicit and production-grade.

A plan is required because the remediation crosses source areas that currently evolve as additive layers rather than one enforced platform contract: `UniversalInputCompiler`, `SOCTaskState`, capability actions, the ReAct loop, tool registry, final gate, evidence graph, governance store, WebSocket events, and chat UI. The upgrade must avoid code changes in this step and give coding agents an implementation-ready sequence based on verified source behavior.

## Source-grounded target architecture

AISA should become a production-grade agentic Vibe SOC platform with these runtime components as enforced contracts, not just advisory metadata:

1. **Universal input compiler registry**
   - Replace the single hardcoded compiler path with a registry of typed compilers/parsers for natural requests, IOC lists, raw logs, inline email, local file references, alerts, JSON events, SIEM queries, case follow-ups, and response-action requests.
   - Every compiler emits a typed `CompiledInput` with artifact refs, normalized entities, objective hints, safety flags, parser confidence, and limitations.

2. **Canonical objective/evidence/capability contract**
   - Promote `CompiledInput`, `SOCTaskState`, objective contract, capability plan, evidence graph refs, and final-answer constraints into one stable `SOCTaskContract` passed through compile, plan, execute, observe, verify, and answer stages.
   - Preserve deterministic verdict authority and make unsupported claims impossible to surface as final verdicts.

3. **Compile/plan preview API**
   - Add non-executing API endpoints that let the UI preview compiled inputs, objective contract, capability plan, preflight result, required evidence, missing inputs, policy gates, and degraded providers before starting an investigation.

4. **Investigation DAG planner**
   - Replace mostly linear first-action planning with a DAG of typed tasks: parse, enrich, search, correlate, verify, decide, summarize, and propose response actions.
   - Each node has inputs, capability requirements, policy requirements, evidence outputs, retry/recovery rules, and status transitions.

5. **Mandatory capability execution boundary**
   - Enforce all tool execution through capability actions, parameter binding, preflight validation, tool policy, and observation normalization before calling legacy tools or MCP tools.
   - Prevent direct `use_tool` execution from bypassing the capability protocol for investigation claims.

6. **Tool policy engine**
   - Centralize tool allow/deny, dangerous action approval, live backend scope, query window limits, destructive action gating, local file safety, MCP availability, and demo/manual fallback policy.
   - Emit typed policy decisions to governance and UI.

7. **Typed artifact parsers and SOC ontology**
   - Add parser registry and SOC ontology for alert, email, log, endpoint, identity, network, cloud, vulnerability, malware, IOC, case, and response-action artifacts.
   - Normalize entities and observations into typed fact families that the evidence graph and claim verifier can reason about.

8. **Evidence graph, claim verification, and decision aggregation**
   - Harden the evidence graph into the central source for observation refs, entity links, contradictions, coverage, hypotheses, claims, and deterministic decision evidence.
   - Add a decision aggregator that combines deterministic tool outputs, coverage, contradiction handling, and claim verification into a structured final verdict contract.

9. **Typed failure/recovery workflow**
   - Classify failures as missing input, invalid params, policy blocked, approval required, provider unavailable, MCP unavailable, backend unavailable, parser low confidence, timeout, no results, partial coverage, contradiction, or unsafe action.
   - Provide deterministic recovery actions and UI-visible status.

10. **Observability/event-sourced audit trail**
    - Emit append-only events for compile, plan, policy, approval, tool call, observation, normalization, evidence graph update, claim verification, final gate, feedback, retry, and rollback.
    - Store events in governance/workdir/session metadata with stable refs.

11. **Structured analyst feedback loop**
    - Extend feedback from decision-level comments into structured per-claim, per-evidence, per-tool, per-parser, per-plan, and per-UI feedback events.
    - Use feedback for eval cases and regression tests without changing verdict authority silently.

12. **UI as SOC workbench**
    - Turn chat from a single send/status page into a workbench showing compile preview, plan DAG, capability status, evidence graph, claim verification, typed failures, pending approvals, feedback, and safe verdict badges.

## Source-code evidence matrix of current gaps

| Issue | Severity | Exact file/function evidence | Root cause | Impact | Remediation |
|---|---:|---|---|---|---|
| Universal input compiler is narrow and hardcoded | High | `CompiledInput` and `UniversalInputCompiler.compile()` in `CABTA/src/agent/universal_input_compiler.py:27` and `CABTA/src/agent/universal_input_compiler.py:59` use regex IP/domain extraction and one raw log parser path. | No parser/compiler registry; compiler decides lane with simple heuristics. | Many SOC artifacts become generic/IOC/log only; weak Vibe SOC breadth. | Add `InputCompilerRegistry`, typed compiler plugins, confidence ranking, parser limitations, and registry tests. |
| Raw log parsing covers useful network logs but not a broad SOC artifact ontology | High | `RawLogParser.NETWORK_HINTS` and `RawLogParser.looks_like_raw_log()` in `CABTA/src/agent/raw_log_parser.py:72` and `CABTA/src/agent/raw_log_parser.py:74`. | Single parser focused on KV/JSON/network hints. | Alerts, endpoint logs, cloud audit, EDR process trees, identity events, and email headers are not first-class artifacts. | Add parser modules and ontology types for log, alert, email, endpoint, identity, cloud, vulnerability, malware, IOC list, and response request. |
| Compile/plan preview does not exist as a first-class API | High | Chat directly calls `agent_loop.investigate()` in `send_message()` at `CABTA/src/web/routes/chat.py:390`; agent API starts investigation at `CABTA/src/web/routes/agent.py:225`. | Compile/plan occurs inside async investigation startup only. | Analyst cannot inspect intended tools, policy blocks, missing inputs, or degraded capability before execution. | Add `/api/agent/compile-preview`, `/api/agent/plan-preview`, and chat UI preview panel. |
| Capability plan exists but does not own execution | Critical | `CapabilityPlanBuilder.build()` creates actions in `CABTA/src/agent/capability_plan.py:43`, but `AgentLoop._run_loop()` still accepts direct `use_tool` at `CABTA/src/agent/agent_loop.py:1974`, and `_act()` executes by tool name at `CABTA/src/agent/agent_loop.py:3810`. | Capability protocol is a bridge, not the mandatory execution boundary. | LLM/heuristics can bypass typed binding/preflight/policy and execute legacy tools directly. | Route every investigation action through `CapabilityActionExecutor`; allow direct tools only for explicit compatibility flag or internal non-verdict utilities. |
| Tool registry performs broad parameter auto-mapping | High | `ToolRegistry.execute_local_tool()` maps arbitrary aliases and any remaining string at `CABTA/src/agent/tool_registry.py:229`. | Legacy safety net favors execution over typed binding. | Full analyst sentences can leak into scalar params; wrong tool may run with wrong target. | Move mapping behind typed `ParameterBinder`; strict mode denies arbitrary fallback unless compatibility flag enabled. |
| Preflight validator is useful but partial and only invoked for `use_capability` bridge | Critical | `PreflightValidator.validate()` in `CABTA/src/agent/preflight_validator.py:33`; invoked in `_bridge_capability_decision()` at `CABTA/src/agent/agent_loop.py:3730`. | Direct `use_tool` path does not require preflight. | File, IOC, log, response-action safety checks are inconsistent. | Make preflight mandatory before tool execution and log every preflight decision. |
| Tool policy is distributed instead of centralized | High | Log query approval/degrade policy is inside `_search_logs()` in `CABTA/src/agent/tool_registry.py:1249`; approval handling is also inside `AgentLoop._run_loop()` at `CABTA/src/agent/agent_loop.py:2002`. | Policy concerns live in tool wrappers, loop, and governance store. | Hard to reason about safety, rollout flags, live backend scopes, and failure modes. | Add `ToolPolicyEngine` used by preflight and tool execution for all local/MCP tools. |
| Final-answer gate is conservative but claim verification is sentence/keyword based | High | `ClaimVerifier.verify()` in `CABTA/src/agent/final_answer_gate.py:81` checks strong verdict words and only looks for tool evidence refs. | No typed claim extraction, contradiction handling, or evidence graph traversal. | Unsupported non-verdict claims may pass if any evidence exists; supported claims lack precise evidence refs. | Add typed `ClaimVerifier` backed by evidence graph facts, normalized observations, and decision aggregator. |
| Deterministic decision aggregation is “last useful result wins” | Critical | `_build_deterministic_decision_output()` in `CABTA/src/agent/agent_loop.py:961` scans reversed findings and picks verdict/severity/score. | No multi-source decision aggregator or contradiction semantics. | Final UI can over-trust whichever tool produced the latest verdict. | Implement `DecisionAggregator` with source authority, confidence, contradictions, coverage, and provenance. |
| Authoritative outcome resolution is shallow | High | `_resolve_authoritative_outcome()` in `CABTA/src/agent/agent_loop.py:3915` checks top-level `verdict` or `severity` only. | Deterministic outputs have varied shapes; nested structured verdicts are not aggregated. | Final-answer gate and summaries may miss authoritative or contradictory structured decisions. | Normalize decision outputs into `DecisionEvidence` and aggregate through one contract. |
| Evidence graph is session metadata, not yet authoritative evidence ledger | High | `EvidenceGraph.ingest_observation()` and `sync_reasoning()` in `CABTA/src/agent/evidence_graph.py:43` and `CABTA/src/agent/evidence_graph.py:155` maintain nodes/edges but mostly append metadata. | Evidence graph lacks append-only event refs, typed claim links, and strict provenance rules. | Hard to prove why a verdict/claim is supported or rejected. | Add immutable event IDs, observation schemas, claim-support edges, contradiction edges, and graph validation tests. |
| Investigation planner is not a DAG executor | High | `NextActionPlanner.reasoning_guided_next_action()` in `CABTA/src/agent/next_action_planner.py:69` returns one next action based on heuristics/signals. | Planning is next-step heuristic, not a typed graph of dependent work. | Complex SOC tasks behave like chat pivots rather than reliable investigations. | Add DAG planner/executor with node state, dependencies, retries, and completion proofs. |
| LLM request interpreter is optional/shadow by default and not unified with compiler registry | Medium | `LLMRequestInterpreter` modes in `CABTA/src/agent/llm_request_interpreter.py:59`; `SOCRequestInterpreter.interpret_async()` in `CABTA/src/agent/request_understanding.py:289`. | Two interpretation paths plus compiler are merged late. | Inconsistent objective/capability contracts across deterministic/LLM paths. | Make deterministic compiler registry primary, LLM interpreter advisory/augmenting, then reconcile into canonical contract. |
| Chat route launches execution immediately and hides preview/control boundary | High | New chat branch at `CABTA/src/web/routes/chat.py:387` calls `agent_loop.investigate()` directly. | UI treats send as execute. | Analyst cannot review plan, missing inputs, or risky policy decisions before runtime. | Add preview-first option and safe execution confirmation for non-trivial tasks. |
| WebSocket event stream lacks typed platform events | Medium | `agent_ws()` forwards messages from `AgentLoop._notify()` in `CABTA/src/web/websocket.py:73`; loop emits ad hoc messages at `CABTA/src/agent/agent_loop.py:1798`, `CABTA/src/agent/agent_loop.py:2123`, and `CABTA/src/agent/agent_loop.py:2320`. | Events are UI progress messages, not stable audit/event contracts. | UI and tests cannot reliably assert platform state transitions. | Define `AgentEvent` schema and emit event-sourced audit records. |
| UI displays deterministic decision but not compile/plan/policy/claim verification | High | `renderDeterministicDecisionPanel()` in `CABTA/templates/agent_chat.html:1771` and reasoning panels around `CABTA/templates/agent_chat.html:1736`. | Workbench panels exist but focus on final state, not execution contract. | Analyst sees outputs but not why execution path is safe/reliable. | Add compile preview, DAG, policy, claim verification, typed failure, and feedback panels. |
| Governance store has decisions and feedback but not full event-sourced audit | Medium | `log_ai_decision()` and `record_decision_feedback()` in `CABTA/src/agent/governance_store.py:167` and `CABTA/src/agent/governance_store.py:303`. | Governance is decision/approval/feedback centric, not every platform transition. | Auditing and production reliability are incomplete. | Add `agent_events` table/API and link events to sessions, cases, workdir artifacts, decisions, and feedback. |
| Analyst feedback is not structured enough for Vibe SOC evals | Medium | `record_decision_feedback()` captures decision-level feedback in `CABTA/src/agent/governance_store.py:303`. | No typed feedback target for claim, evidence, parser, plan node, or UI answer segment. | Cannot build strong regression/eval loop from analyst corrections. | Add feedback schema, UI feedback controls, eval materialization, and test fixtures. |
| Backward compatibility is implicit and scattered | Medium | Direct tool, auto-enrich, legacy tool wrappers, workdir mirror, and chat paths coexist in `CABTA/src/agent/agent_loop.py:2150`, `CABTA/src/agent/tool_registry.py:356`, and `CABTA/src/web/routes/agent.py:518`. | No explicit migration flags or rollback strategy. | Refactors can break existing chat/playbooks/tests. | Add feature flags, compatibility adapters, metrics, and staged rollout. |

## Phased implementation plan

### P0 — Execution boundary and UI verdict safety

**Goal:** stop unsafe over-claiming and direct execution bypasses before expanding platform features.

Files to create/modify:

- Create `CABTA/src/agent/capability_executor.py`.
- Create `CABTA/src/agent/tool_policy.py`.
- Modify `CABTA/src/agent/agent_loop.py`.
- Modify `CABTA/src/agent/tool_registry.py`.
- Modify `CABTA/src/agent/final_answer_gate.py`.
- Modify `CABTA/templates/agent_chat.html`.
- Add/update tests in `CABTA/tests/test_capability_execution_boundary.py`, `CABTA/tests/test_tool_policy_engine.py`, `CABTA/tests/test_final_answer_gate.py`, and `CABTA/tests/test_vibe_soc_natural_chat_scenarios.py`.

Implementation tasks:

1. Add `CapabilityActionExecutor` that accepts `SOCTaskState`, `CapabilityAction`, current `AgentState`, and execution context.
2. Move `ParameterBinder.bind()`, `PreflightValidator.validate()`, `CapabilityResolver.resolve()`, and `ToolPolicyEngine.evaluate()` into one mandatory path.
3. In `AgentLoop._run_loop()`, convert direct `use_tool` decisions into capability actions when possible before `_act()`.
4. Add `agent.execution.require_capability_boundary` feature flag defaulting to warn/shadow first, then enforce.
5. Add `agent.execution.allow_legacy_direct_tool_fallback` for rollback and tests.
6. Update `_act()` to require a validated execution envelope when enforcement is on.
7. Make `ToolRegistry.execute_local_tool()` strict when `_execution_context.capability_enforced` is true: no arbitrary string parameter mapping.
8. Update chat UI badges so verdict-like text from `final_answer` is clearly provisional unless backed by `structured_verdict.allowed_final` and deterministic authority.
9. Ensure `final_answer_gate` blocks strong verdict claims unless decision aggregator or deterministic evidence exists.

Desired behavior:

- No investigation tool executes without a capability, typed params, preflight, and policy decision.
- UI never renders a malicious/clean/suspicious badge from unsupported LLM text.
- Legacy direct tool calls remain available only behind rollback flag.

Completion criteria:

- Direct `use_tool` decisions are wrapped or blocked in enforced mode.
- Policy/preflight decisions appear in reasoning metadata and WebSocket events.
- Final answers with unsupported verdict-like claims produce a provisional evidence-gap response.

Risks to avoid:

- Do not block direct help/capability questions that make no investigation claims.
- Do not break playbook execution before compatibility wrapper exists.
- Do not silently fall back to IOC enrichment for raw logs or missing files.

Tests/validation:

- New tests prove raw log input executes `log.analyze.inline` and cannot fallback to `investigate_ioc`.
- New tests prove a fake LLM `final_answer` at step 0 is blocked for investigation artifacts.
- Existing `CABTA/tests/test_vibe_soc_natural_chat_scenarios.py` continues passing.

Proof of result:

- Test output shows enforced boundary paths, blocked unsupported verdicts, and safe UI structured verdict rendering.

### P1 — Compile/plan preview and canonical contract

**Goal:** make compile and plan visible, stable, and testable before execution.

Files to create/modify:

- Create `CABTA/src/agent/soc_task_contract.py`.
- Create `CABTA/src/agent/compile_preview_service.py`.
- Modify `CABTA/src/agent/universal_input_compiler.py`.
- Modify `CABTA/src/agent/soc_task_state.py`.
- Modify `CABTA/src/agent/capability_plan.py`.
- Modify `CABTA/src/web/routes/agent.py`.
- Modify `CABTA/src/web/routes/chat.py`.
- Modify `CABTA/templates/agent_chat.html`.
- Add/update `CABTA/tests/test_compile_plan_preview_api.py`, `CABTA/tests/test_universal_input_compiler.py`, and `CABTA/tests/test_capability_catalog_contracts.py`.

Implementation tasks:

1. Define `SOCTaskContract` containing compiled input, task state, objective contract, capability plan, preflight summary, policy summary, required evidence, missing inputs, approval needs, and execution readiness.
2. Add `CompilePreviewService.compile_and_plan(raw_input, metadata, execute=False)`.
3. Add `GET/POST /api/agent/compile-preview` and `POST /api/agent/plan-preview`.
4. Add `POST /api/chat/preview` or reuse agent preview route from chat UI.
5. Update chat send flow to optionally preview before execution for complex/high-risk tasks.
6. Add contract schema versioning and stable IDs.
7. Store preview refs in session metadata when execution starts from preview.

Desired behavior:

- Analyst can preview how AISA understands input and what capabilities/tools/policies will apply.
- Preview has no side effects except optional audit event.
- Execution can accept a preview ref and verify it matches raw input before using it.

Completion criteria:

- Preview endpoint returns deterministic contract for IOC, raw log, inline email, file path, generic help, and response-action samples.
- UI shows compile kind, lane, entities, artifact refs, capability plan, missing inputs, and policy blockers.

Risks to avoid:

- Do not let preview become a verdict or evidence source.
- Do not require preview for low-risk compatibility paths until rollout flag is enabled.

Tests/validation:

- API tests assert no session is created by preview.
- Snapshot tests assert schema fields and backward-compatible aliases.

Proof of result:

- Preview JSON and UI panel demonstrate exact planned action before execution.

### P2 — Parser registry and SOC artifact breadth

**Goal:** expand AISA from log/IOC/file/email heuristics into a true universal SOC input compiler.

Files to create/modify:

- Create `CABTA/src/agent/input_compilers/` package.
- Create `CABTA/src/agent/input_compilers/base.py`.
- Create parsers: `ioc_list.py`, `raw_log.py`, `email_artifact.py`, `alert_artifact.py`, `endpoint_event.py`, `identity_event.py`, `cloud_audit.py`, `file_reference.py`, `response_request.py`, `case_followup.py`.
- Create/modify `CABTA/src/agent/soc_ontology.py`.
- Modify `CABTA/src/agent/universal_input_compiler.py` into registry orchestrator.
- Modify `CABTA/src/agent/raw_log_parser.py` to become one registry plugin.
- Add/update `CABTA/tests/test_universal_input_compiler.py`, `CABTA/tests/test_raw_log_parser.py`, and new `CABTA/tests/test_soc_artifact_parsers.py`.

Implementation tasks:

1. Define `InputCompilerPlugin` interface: `matches()`, `compile()`, `confidence`, `artifact_types`, `limitations`.
2. Register deterministic plugins and choose highest-confidence or multi-artifact outputs.
3. Extend entities with roles: source, destination, user, host, process, url, domain, hash, file, session, alert, rule, cloud principal, mailbox.
4. Normalize artifacts with `artifact_id`, `artifact_type`, `source`, `confidence`, `raw_ref`, `parsed_fields`, and `limitations`.
5. Add explicit unknown/ambiguous result with clarification questions.
6. Preserve current `CompiledInput.to_dict()` shape for compatibility while adding fields.

Desired behavior:

- Pasted alert JSON, EDR process event, Windows logon event, cloud audit event, email header/body, IOC list, and response request compile to typed artifacts.
- Ambiguous/mixed input produces multiple artifact candidates and asks clarifying questions when necessary.

Completion criteria:

- At least eight SOC artifact families compile deterministically with tests.
- Raw network log tests retain current behavior.

Risks to avoid:

- Do not assign malicious/benign verdicts during parsing.
- Do not discard raw refs or limitations.

Tests/validation:

- Fixture-based tests for each parser family.
- Negative tests for prompt injection and “mark it malicious” text.

Proof of result:

- Compiler evidence matrix in test output shows artifact kind, entities, capability plan, and limitations for each fixture.

### P3 — Investigation DAG and decision aggregator

**Goal:** make investigations reliable workflows instead of linear next-action chat loops.

Files to create/modify:

- Create `CABTA/src/agent/investigation_dag.py`.
- Create `CABTA/src/agent/dag_executor.py`.
- Create `CABTA/src/agent/decision_aggregator.py`.
- Modify `CABTA/src/agent/next_action_planner.py`.
- Modify `CABTA/src/agent/agent_loop.py`.
- Modify `CABTA/src/agent/capability_plan.py`.
- Add/update `CABTA/tests/test_investigation_dag_planner.py`, `CABTA/tests/test_decision_aggregator.py`, and `CABTA/tests/test_query_coverage_retry.py`.

Implementation tasks:

1. Convert capability plan actions into DAG nodes with dependencies: parse -> primary evidence -> enrichment/search -> correlation -> claim verification -> decision aggregation -> answer.
2. Add node statuses: planned, ready, blocked, approval_required, running, succeeded, partial, failed_recoverable, failed_terminal, skipped, rolled_back.
3. Add `DecisionAggregator.aggregate(observations, tool_results, evidence_graph, coverage, objective)`.
4. Normalize verdict evidence from nested `structured_verdict`, `verdict`, `severity`, `score`, and coverage matrices.
5. Track contradictions and conservative outcomes.
6. Update final-answer gate to use aggregator output, not only `_resolve_authoritative_outcome()`.

Desired behavior:

- Complex investigations execute required nodes in order and do not skip correlation/verification.
- Final decision is aggregated from typed evidence with provenance and contradictions.

Completion criteria:

- `deterministic_decision_output` includes source refs, evidence refs, aggregation reason, contradiction status, and confidence.
- Tests show latest-tool verdict cannot override stronger contradictory deterministic evidence.

Risks to avoid:

- Do not make DAG executor too rigid for direct chat/help.
- Preserve current session status and WebSocket messages during transition.

Tests/validation:

- DAG planner tests for IOC, raw log, inline email, log hunt, response-action approval.
- Aggregator tests for conflicting tool verdicts, missing evidence, and inconclusive raw log.

Proof of result:

- Session metadata shows DAG nodes and final aggregate decision with refs.

### P4 — Claim verification and evidence graph hardening

**Goal:** ensure every significant claim is supported, contradicted, or marked as a limitation.

Files to create/modify:

- Create `CABTA/src/agent/claim_model.py`.
- Create/modify `CABTA/src/agent/claim_verifier.py` if present, otherwise split from `CABTA/src/agent/final_answer_gate.py`.
- Modify `CABTA/src/agent/evidence_graph.py`.
- Modify `CABTA/src/agent/observation_normalizer.py`.
- Modify `CABTA/src/agent/final_answer_gate.py`.
- Add/update `CABTA/tests/test_claim_verifier.py`, `CABTA/tests/test_evidence_graph.py`, and `CABTA/tests/test_session_response_builder.py`.

Implementation tasks:

1. Define typed claims: verdict, entity relationship, temporal sequence, root cause, scope, impact, recommended response, limitation, next action.
2. Extract claims from draft answer and agentic explanation.
3. Verify each claim by traversing evidence graph nodes/edges and accepted facts.
4. Add contradiction detection and unsupported claim downgrade.
5. Persist `claim_verification_result` in reasoning metadata and workdir.
6. Render claim verification summary in chat UI.

Desired behavior:

- Final answer can include only supported claims, explicitly provisional claims, or limitations.
- Evidence graph validates node/edge refs and supports reproducible proof.

Completion criteria:

- Final-answer gate output lists supported, unsupported, contradicted, and limitation claims.
- UI shows claim safety status.

Risks to avoid:

- Do not rely on LLM to verify claims.
- Do not require full graph support for direct help answers.

Tests/validation:

- Tests with draft answer containing unsupported malicious claim block it.
- Tests with supported IOC verdict allow it with evidence refs.
- Tests with contradictory evidence produce inconclusive/needs-review outcome.

Proof of result:

- Claim verification fixture outputs stable refs and blocked claim reasons.

### P5 — Typed failures, observability, and event-sourced audit

**Goal:** make production runtime behavior explainable and debuggable.

Files to create/modify:

- Create `CABTA/src/agent/events.py`.
- Create `CABTA/src/agent/failure_model.py`.
- Modify `CABTA/src/agent/governance_store.py`.
- Modify `CABTA/src/agent/agent_loop.py`.
- Modify `CABTA/src/web/websocket.py`.
- Modify `CABTA/src/web/routes/agent.py`.
- Modify `CABTA/src/agent/investigation_workdir.py`.
- Add/update `CABTA/tests/test_agent_event_stream.py`, `CABTA/tests/test_governance_store.py`, and `CABTA/tests/test_workdir_event_audit.py`.

Implementation tasks:

1. Define `AgentEvent` schema with event_id, session_id, case_id, task_id, dag_node_id, event_type, payload, severity, timestamp, refs, and authoritative flag.
2. Add `TypedFailure` schema and classifier.
3. Emit events for compile, plan, policy, preflight, approval, tool start/result/error, observation normalization, graph update, retry, claim verification, final gate, feedback, and rollback.
4. Add `agent_events` table to governance store.
5. Add `/api/agent/sessions/{session_id}/events` endpoint.
6. Stream typed events over WebSocket while preserving existing progress messages.
7. Mirror event log to workdir.

Desired behavior:

- Every production state transition has a typed event.
- Failures produce recovery instructions and UI state.

Completion criteria:

- Event log can reconstruct investigation timeline.
- WebSocket client receives typed events plus compatibility messages.

Risks to avoid:

- Avoid large unbounded event payloads.
- Do not store secrets/API keys/tool tokens in events.

Tests/validation:

- Event stream tests assert ordering and schema.
- Failure tests assert missing input/provider unavailable/backend unavailable/policy blocked statuses.

Proof of result:

- Governance API returns full event timeline for a test session.

### P6 — Analyst feedback and SOC workbench UX

**Goal:** make the UI a real SOC workbench and close the feedback loop.

Files to create/modify:

- Modify `CABTA/templates/agent_chat.html`.
- Modify `CABTA/src/web/routes/agent.py`.
- Modify `CABTA/src/agent/governance_store.py`.
- Create `CABTA/src/agent/feedback_model.py`.
- Add/update `CABTA/tests/test_agent_chat_reasoning_ui.py`, `CABTA/tests/test_analyst_feedback_api.py`, and `CABTA/tests/test_session_response_builder.py`.

Implementation tasks:

1. Add UI panels for compile preview, DAG execution, policy decisions, typed failures, claim verification, and event audit.
2. Add feedback buttons for claim useful/correct/incorrect, evidence relevance, missing pivot, parser correction, plan correction, and final answer quality.
3. Add structured feedback API and storage target fields.
4. Add “convert feedback to eval fixture” service output.
5. Display runtime capability/degraded state honestly.

Desired behavior:

- Analyst can see what AISA understood, what it plans, what executed, what failed, what claims are supported, and provide structured corrections.

Completion criteria:

- Feedback events are queryable and linked to claims/evidence/plan nodes.
- UI safely distinguishes deterministic decision, agentic explanation, and provisional claims.

Risks to avoid:

- Do not let feedback alter current verdict silently.
- Do not make UI imply disconnected tools are available.

Tests/validation:

- UI tests assert panels render with representative session payloads.
- API tests assert feedback targets and schema.

Proof of result:

- Example session has feedback events tied to a claim and evidence ref.

### P7 — Vibe SOC eval suite and production readiness

**Goal:** prove reliability with repeatable Vibe SOC scenarios and safe rollout controls.

Files to create/modify:

- Create `CABTA/tests/fixtures/vibe_soc/`.
- Create `CABTA/tests/test_vibe_soc_eval_suite.py`.
- Update `CABTA/tests/test_vibe_soc_natural_chat_scenarios.py`.
- Update `CABTA/tests/test_agent_loop_prompt_plumbing.py`.
- Update `CABTA/tests/test_thread_sync_service.py`.
- Update `CABTA/tests/test_case_memory_service.py`.
- Update `CABTA/TEST-MANIFEST.md` only after implementation.
- Add operational notes to a future docs update only after source behavior exists.

Implementation tasks:

1. Build eval fixtures for IOC, raw firewall log, Splunk stream log, Windows logon, endpoint process tree, inline phish email, malware file reference missing, alert JSON, cloud audit event, response-action approval, provider unavailable, SIEM unavailable, and contradictory evidence.
2. Add assertions for compile contract, plan DAG, policy outcome, execution boundary, evidence graph, claim verification, decision aggregation, UI payload, events, and feedback.
3. Add production readiness smoke tests for startup with missing optional providers.
4. Add rollback flag tests.
5. Add performance guardrails for event/log payload size and max DAG nodes.

Desired behavior:

- AISA reliably compiles, plans, executes, recovers, and answers SOC tasks with evidence-backed claims.

Completion criteria:

- Eval suite passes without live paid services using deterministic fixtures/demo backends.
- Live backend tests are optional and skip honestly when unavailable.

Risks to avoid:

- Do not depend on nondeterministic LLM outputs for core pass/fail.
- Do not require external MCP servers for baseline CI.

Proof of result:

- Test report shows every Vibe SOC scenario has compile/plan/execution/evidence/final-gate proof.

## Backward compatibility strategy

1. Preserve existing route shapes for `POST /api/chat`, `POST /api/agent/investigate`, `GET /api/agent/sessions/{session_id}`, and WebSocket messages.
2. Add new fields additively: `soc_task_contract`, `compile_preview`, `dag`, `policy_decisions`, `claim_verification`, `agent_events`.
3. Keep direct legacy tool execution behind `agent.execution.allow_legacy_direct_tool_fallback` until P7 passes.
4. Keep existing `CompiledInput.to_dict()`, `SOCTaskState.to_dict()`, capability plan, deterministic decision, and agentic explanation fields while adding versioned contracts.
5. Maintain current workdir artifacts and add new event/claim/DAG artifacts additively.
6. Keep direct help/capability chat short-circuit behavior, with explicit non-investigation answer mode.
7. For playbooks, add adapter from playbook step tools to capability envelopes before enforcing strict mode.

## Test strategy and exact test files

Add or update:

- `CABTA/tests/test_universal_input_compiler.py`: registry behavior, parser confidence, compatibility fields.
- `CABTA/tests/test_raw_log_parser.py`: raw log plugin parity and limitations.
- `CABTA/tests/test_soc_artifact_parsers.py`: alert/email/endpoint/identity/cloud/file/response/case parsers.
- `CABTA/tests/test_compile_plan_preview_api.py`: no-side-effect preview endpoints.
- `CABTA/tests/test_capability_execution_boundary.py`: no direct bypass; compatibility flag behavior.
- `CABTA/tests/test_tool_policy_engine.py`: approval, deny, demo/manual fallback, unsafe file, query window.
- `CABTA/tests/test_investigation_dag_planner.py`: DAG node creation and dependencies.
- `CABTA/tests/test_decision_aggregator.py`: multi-source verdict/conflict aggregation.
- `CABTA/tests/test_claim_verifier.py`: supported/unsupported/contradicted claims.
- `CABTA/tests/test_evidence_graph.py`: node/edge/provenance validation.
- `CABTA/tests/test_agent_event_stream.py`: typed event ordering and WebSocket compatibility.
- `CABTA/tests/test_governance_store.py`: event table, structured feedback, migration.
- `CABTA/tests/test_analyst_feedback_api.py`: feedback targets and eval materialization.
- `CABTA/tests/test_agent_chat_reasoning_ui.py`: workbench panel payload rendering.
- `CABTA/tests/test_vibe_soc_eval_suite.py`: end-to-end deterministic Vibe SOC scenario suite.
- Update existing `CABTA/tests/test_vibe_soc_natural_chat_scenarios.py`, `CABTA/tests/test_query_coverage_retry.py`, `CABTA/tests/test_agent_loop_prompt_plumbing.py`, `CABTA/tests/test_session_response_builder.py`, `CABTA/tests/test_thread_sync_service.py` as contracts change.

Validation command set for coding phases:

- Focused unit tests for each phase.
- Full affected lane tests before rollout flag defaults change.
- Production readiness smoke tests with no LLM key, no MCP, and no SIEM.

## Rollout flags and rollback strategy

Introduce flags under `agent` or dedicated `vibe_soc` config:

- `vibe_soc.compiler_registry_enabled`: default true after P2, false rollback to current compiler.
- `vibe_soc.preview_api_enabled`: default true after P1.
- `vibe_soc.require_preview_for_complex_tasks`: default false until P6.
- `vibe_soc.dag_planner_enabled`: default shadow in P3, enforce after evals.
- `vibe_soc.decision_aggregator_enabled`: default shadow then enforce.
- `vibe_soc.claim_verifier_v2_enabled`: default shadow then enforce.
- `vibe_soc.event_sourcing_enabled`: default true with payload caps.
- `vibe_soc.structured_feedback_enabled`: default true after P6.
- `agent.execution.require_capability_boundary`: default shadow/warn in P0, enforce after compatibility tests.
- `agent.execution.allow_legacy_direct_tool_fallback`: default true during migration, false after P7.
- `agent.tools.strict_parameter_binding`: default false, true after P0/P1 tests.

Rollback:

1. Disable DAG planner and use current next-action planner.
2. Disable compiler registry and use current `UniversalInputCompiler` compatibility adapter.
3. Re-enable legacy direct tool fallback.
4. Keep final-answer gate and UI verdict safety on unless a critical regression requires temporary rollback.
5. Preserve additive storage fields so old sessions remain readable.

## Definition of done

AISA is considered remediated into a strong production-grade agentic Vibe SOC platform when:

1. Every non-trivial SOC input compiles into a typed contract with explicit artifact type, entities, limitations, capabilities, and evidence requirements.
2. Analysts can preview compile/plan/policy outcomes before execution.
3. Every investigation tool execution passes through capability binding, preflight, and tool policy.
4. Complex investigations run as observable DAGs with typed node statuses and recoveries.
5. Deterministic decision aggregation is explicit, conservative, contradiction-aware, and provenance-backed.
6. Final answers include only supported claims, explicit limitations, or provisional statements.
7. Evidence graph stores reproducible support/contradiction/provenance for claims and decisions.
8. All important runtime transitions emit typed audit events.
9. UI exposes compile, plan, DAG, policy, evidence, claim verification, failures, feedback, and verdict authority clearly.
10. Structured analyst feedback links to claims/evidence/plans and can create eval fixtures.
11. Missing LLM/MCP/SIEM providers degrade honestly without fake success.
12. The Vibe SOC eval suite passes deterministically without external paid services.

## Measurable success criteria

- `compile_preview` tests cover at least eight SOC artifact families.
- Enforced capability boundary blocks direct investigation tool execution in tests.
- Final-answer gate blocks unsupported verdict-like claims in all artifact scenarios.
- Decision aggregator tests pass for conflicting, nested, and missing verdict evidence.
- Event stream contains typed compile, plan, policy, execute, observe, verify, and answer events for every eval session.
- UI tests prove deterministic decision and agentic explanation remain visually distinct.
- Feedback API stores per-claim and per-evidence feedback with stable target refs.
- No baseline eval requires live LLM, MCP, or SIEM connectivity.
- Existing chat/session/playbook compatibility tests continue passing with rollback flags.
