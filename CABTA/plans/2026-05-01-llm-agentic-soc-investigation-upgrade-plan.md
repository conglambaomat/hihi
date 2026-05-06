# Kế hoạch nâng cấp AISA/CABTA thành SOC Agentic Investigator

- **Date:** 2026-05-01
- **Status:** Draft plan - ready for RooCode implementation
- **Owner:** AISA/CABTA engineering team
- **Target:** RooCode implementation agent; runtime owners of `src/agent`, daemon runtime, web/session response, and tests
- **Scope:** Tạo lộ trình nâng cấp agent điều tra SOC để không dừng sớm sau verdict/next pivots, có vòng lặp planner-executor-reflector-reviewer, gate hoàn tất có bằng chứng, auto-pivot có kiểm soát, và daemon long-running.

## 1. Problem Statement

AISA/CABTA hiện có năng lực phân tích log và điều phối agent, nhưng luồng điều tra có xu hướng kết thúc quá sớm khi LLM sinh ra verdict hoặc câu trả lời cuối cùng, kể cả khi còn pivot rõ ràng trong log. Triệu chứng chính:

1. Agent nhìn thấy một chuỗi đáng ngờ, ví dụ Sysmon `stage2.exe -> powershell.exe`, đưa ra nhận định nguy hiểm, gợi ý pivot tiếp theo, rồi dừng.
2. Final-answer gate hiện tại chủ yếu kiểm soát hình thức và điều kiện tối thiểu, chưa đóng vai trò completeness gate cho điều tra SOC.
3. Raw log parser và universal input compiler đã nhận diện raw log/capability, nhưng tín hiệu này chưa ép runtime phải chạy investigation loop đến milestone đủ sâu.
4. Next action planner đang bị giới hạn theo hướng `search_logs`, chưa sinh tín hiệu typed/structured đủ mạnh để agent tự pivot qua parent/child process, network, registry, file writes, account/session, host timeline, và related indicators.
5. Daemon service có dispatch nền nhưng chưa được thiết kế như long-running investigation worker có budget, milestones, reviewer, resume, telemetry, và completion decision rõ ràng.

Hậu quả:

- Analyst nhận được verdict sớm nhưng thiếu bằng chứng theo chuỗi kill chain.
- Agent có thể nói “cần kiểm tra thêm” nhưng không tự thực hiện các pivot đó.
- Các case raw log bị xử lý như trả lời chat ngắn thay vì investigation job.
- Tính tin cậy của SOC workflow giảm vì thiếu determinism ở các điểm dừng.

## 2. Evidence Từ Phân Tích Code Hiện Tại

Các vị trí cần RooCode kiểm tra và dùng làm điểm móc triển khai:

| File | Lines | Evidence / Vấn đề |
| --- | ---: | --- |
| `CABTA/src/agent/agent_loop.py` | 1905-1964 | Final break trong agent loop: khi model/loop quyết định final, runtime có thể thoát trước khi hoàn tất các pivot SOC bắt buộc. Cần intercept final answer tại đây. |
| `CABTA/src/agent/agent_loop.py` | 2799-2818 | No findings guard: có logic xử lý không có finding, nhưng chưa phân biệt “không có finding sau khi đã pivot đủ” với “chưa tìm đủ”. Cần gắn completeness/evidence rubric. |
| `CABTA/src/agent/final_answer_gate.py` | 115-153 | Inline gate rules hiện chủ yếu kiểm tra điều kiện trả lời cuối; cần mở rộng thành structured completion decision. |
| `CABTA/src/agent/final_answer_gate.py` | 192-218 | Gate hiện chưa đủ deterministic để chặn final khi còn next pivots/milestones chưa đạt. |
| `CABTA/src/agent/raw_log_parser.py` | 231-240 | `allowed_final` cho raw log cần bị ràng buộc bởi investigation completeness, không chỉ parser-level permission. |
| `CABTA/src/agent/universal_input_compiler.py` | 136-150 | Raw log capability đã được nhận diện; cần chuyển capability này thành `InvestigationState.input_type=raw_log` và bật auto-pivot/gate. |
| `CABTA/src/agent/objective_model.py` | 180-186 | Objective model có log inline; cần bổ sung objective/milestone cho SOC investigation, đặc biệt raw Sysmon/process chain. |
| `CABTA/src/agent/next_action_planner.py` | 507-515 | Planner còn thiên về `search_logs` only; cần typed `NextActionSignal` đa pivot. |
| `CABTA/src/agent/prompt_composer.py` | 37-41 | Final rules trong prompt có thể cho phép final quá sớm; cần thay bằng policy “do not final until gate/reviewer approves”. |
| `CABTA/src/agent/prompt_composer.py` | 77-82 | Prompt rules cần bắt LLM trả về next actions có cấu trúc nếu chưa đủ bằng chứng. |
| `CABTA/src/daemon/service.py` | 301-349 | Dispatch service là điểm để biến investigation thành job long-running/resumable thay vì chat turn ngắn. |

## 3. Goals

1. Biến AISA/CABTA thành SOC agentic investigator: luôn lập kế hoạch, chạy tool/pivot, phản tư kết quả, review completeness, rồi mới final.
2. Chặn final sớm khi còn pivot bắt buộc hoặc tín hiệu next action chưa được thực thi.
3. Tạo deterministic safety/evidence/completeness gate độc lập với LLM.
4. Dùng LLM reviewer như lớp thứ hai để kiểm tra chất lượng investigation, nhưng không để reviewer bypass gate deterministic.
5. Chuẩn hóa `NextActionSignal` để chuyển “nên kiểm tra thêm” thành hành động runtime cụ thể.
6. Tạo investigation graph/milestones giúp theo dõi coverage, bằng chứng, khoảng trống, và lý do kết thúc.
7. Hỗ trợ daemon long-running cho raw log/case investigation có budget, resume, telemetry, và UI feedback.
8. Giữ compatibility với chat hiện tại bằng feature flags và rollout theo pha.

## 4. Non-goals

1. Không sửa code runtime trong task tạo plan này.
2. Không thay thế toàn bộ LLM provider/router.
3. Không yêu cầu tích hợp SIEM thật ngay trong phase đầu; demo log backend và existing tool registry phải đủ để test.
4. Không cho agent chạy vô hạn; mọi auto-pivot phải có budget, loop detection, và stop reason rõ ràng.
5. Không cho LLM tự bịa evidence; mọi conclusion phải trỏ về observed log/tool result hoặc đánh dấu hypothesis.
6. Không làm UI redesign lớn; chỉ bổ sung telemetry/progress nếu cần.

## 5. Architecture Target

### 5.1 LLM-first Planner-Executor-Reflector-Reviewer Loop

Target loop:

1. **Planner:** LLM phân tích objective/input, tạo investigation plan gồm milestones và next pivots có cấu trúc.
2. **Executor:** Runtime thực thi các tool/pivot được allowlist, ghi evidence vào `InvestigationState`.
3. **Reflector:** LLM hoặc deterministic reflector đọc kết quả, xác định findings, gaps, next actions.
4. **Completeness Gate:** Deterministic gate kiểm tra milestone/evidence/budget/safety trước khi cho final.
5. **Reviewer:** LLM reviewer độc lập đánh giá report candidate: đủ bằng chứng chưa, có hallucination không, còn pivot nào quan trọng không.
6. **Finalizer:** Chỉ xuất final khi gate pass và reviewer approve, hoặc khi budget exhausted với incomplete status minh bạch.

### 5.2 Deterministic Safety/Evidence/Completeness Gate

Gate phải quyết định bằng dữ liệu có cấu trúc, không dựa vào prose của LLM:

- Có raw log/process evidence chưa?
- Có parent/child process pivot chưa?
- Có command line/deobfuscation pivot chưa?
- Có network/file/registry/account pivots phù hợp chưa?
- Có timeline và scope host/user chưa?
- Có IoC extraction và enrichment tối thiểu chưa?
- Có unresolved high-priority next actions không?
- Có citation/evidence id cho mỗi conclusion không?
- Có loop/budget stop reason hợp lệ không?

### 5.3 Next Action Signals

Mọi đề xuất pivot phải thành `NextActionSignal` typed:

- `PROCESS_PARENT_LOOKUP`
- `PROCESS_CHILD_LOOKUP`
- `COMMAND_LINE_DEOBFUSCATE`
- `NETWORK_CONNECTION_LOOKUP`
- `FILE_WRITE_LOOKUP`
- `REGISTRY_LOOKUP`
- `USER_SESSION_LOOKUP`
- `HOST_TIMELINE_EXPAND`
- `IOC_EXTRACT_ENRICH`
- `RELATED_EVENT_SEARCH`
- `RULE_DETECTION_GENERATE`
- `REPORT_FINALIZE`

### 5.4 Investigation Graph/Milestones

Mỗi investigation duy trì graph:

- Nodes: events, processes, files, registry keys, network endpoints, users, hosts, hypotheses, findings.
- Edges: spawned, wrote, connected_to, loaded, modified, logged_on, same_host, same_user, derived_from.
- Milestones: triage, process tree, command analysis, network, file/registry, timeline, scope, verdict, containment recommendations.

### 5.5 Daemon Long-running

Raw log hoặc case lớn nên chạy qua daemon job:

- Dispatch nhận investigation request.
- Worker chạy loop theo budget.
- State được persist/resume.
- UI/session nhận progress events.
- Final response chỉ được build từ `CompletionDecision` đã approve.

## 6. Data Models / Interfaces

### 6.1 `InvestigationState`

```python
@dataclass
class InvestigationState:
    investigation_id: str
    session_id: str | None
    input_type: Literal["chat", "raw_log", "ioc", "case", "file", "email"]
    objective: str
    raw_input_ref: str | None
    normalized_events: list[NormalizedEvent]
    graph: InvestigationGraph
    milestones: list[SOCMilestone]
    evidence: list[EvidenceItem]
    findings: list[Finding]
    hypotheses: list[Hypothesis]
    next_actions: list[NextActionSignal]
    completed_actions: list[str]
    rejected_actions: list[RejectedAction]
    budgets: InvestigationBudget
    completion: CompletionDecision | None
    reviewer: ReviewerDecision | None
    created_at: datetime
    updated_at: datetime
```

Implementation notes:

- `InvestigationState` có thể đặt ở `CABTA/src/agent/investigation_state.py` hoặc module mới `CABTA/src/agent/investigation/`.
- Không nhét state vào prompt text only; runtime phải giữ object để gate/test deterministic.
- `evidence` cần stable IDs để final report cite được.

### 6.2 `InvestigationBudget`

```python
@dataclass
class InvestigationBudget:
    max_iterations: int = 12
    max_tool_calls: int = 30
    max_auto_pivots: int = 15
    max_wall_clock_seconds: int = 180
    max_same_action_retries: int = 2
    min_required_milestones_for_final: int = 5
    allow_incomplete_final_on_budget_exhaustion: bool = True
```

### 6.3 `NextActionSignal`

```python
@dataclass
class NextActionSignal:
    id: str
    type: NextActionType
    priority: Literal["critical", "high", "medium", "low"]
    rationale: str
    required: bool
    query: str | None
    target_entities: list[EntityRef]
    source_evidence_ids: list[str]
    expected_evidence: list[str]
    status: Literal["pending", "running", "done", "blocked", "skipped"]
    created_by: Literal["llm", "deterministic", "playbook", "reviewer"]
```

Rules:

- Final bị chặn nếu còn `required=True` và `status in pending/running` trừ khi budget exhausted hoặc action blocked có lý do.
- `priority=critical/high` phải được execute hoặc explicitly waived bởi gate với reason.

### 6.4 `CompletionDecision`

```python
@dataclass
class CompletionDecision:
    allowed: bool
    status: Literal["complete", "incomplete_budget_exhausted", "blocked", "needs_more_investigation"]
    reasons: list[str]
    missing_milestones: list[str]
    pending_required_actions: list[str]
    evidence_score: float
    hallucination_risk: Literal["low", "medium", "high"]
    final_answer_allowed: bool
    stop_reason: str | None
```

### 6.5 `ReviewerDecision`

```python
@dataclass
class ReviewerDecision:
    approved: bool
    confidence: Literal["low", "medium", "high"]
    issues: list[str]
    required_followups: list[NextActionSignal]
    hallucination_flags: list[str]
    report_quality_score: float
    rationale: str
```

### 6.6 `SOCMilestone`

```python
@dataclass
class SOCMilestone:
    id: str
    name: str
    required_for: list[str]
    status: Literal["not_started", "in_progress", "satisfied", "blocked", "not_applicable"]
    evidence_ids: list[str]
    completion_criteria: list[str]
    blocker_reason: str | None = None
```

Recommended default milestones for raw Sysmon/process chain:

1. `input_normalized`
2. `seed_event_identified`
3. `process_tree_reconstructed`
4. `command_line_analyzed`
5. `network_activity_checked`
6. `file_registry_activity_checked`
7. `user_host_scope_checked`
8. `timeline_expanded`
9. `ioc_extracted_enriched`
10. `verdict_evidence_mapped`
11. `containment_recommendations_ready`

### 6.7 `EvidenceRubric`

```python
@dataclass
class EvidenceRubric:
    min_evidence_items: int
    require_seed_event: bool
    require_process_tree: bool
    require_command_line: bool
    require_scope: bool
    require_citations_for_findings: bool
    allowed_inference_without_evidence: list[str]
    disallowed_claim_patterns: list[str]
```

Default raw log rubric:

- `min_evidence_items >= 4`
- Seed event required.
- Process tree required if process creation exists.
- Command line analysis required if command line contains PowerShell/cmd/wscript/mshta/rundll32/regsvr32.
- Network pivot required if process is script interpreter, downloader, or known LOLBin.
- Scope required for host/user.
- Every finding must cite at least one evidence ID.

## 7. Detailed Module Changes By File

### 7.1 `CABTA/src/agent/agent_loop.py`

Objectives:

- Intercept final break around lines 1905-1964.
- Replace direct final exit with `CompletionDecision` check.
- Integrate `InvestigationState` lifecycle in loop.
- Convert LLM “next pivots” into executable `NextActionSignal`.
- Update no-findings guard around lines 2799-2818 to require completed coverage before saying no findings.

Required changes:

1. Initialize investigation state when input compiler marks SOC/raw log/case investigation.
2. Before accepting any final answer:
   - Parse candidate final.
   - Run `investigation_completeness.evaluate(state, candidate_final)`.
   - If not allowed, append required next actions and continue loop.
   - If allowed and reviewer flag enabled, run reviewer.
3. When LLM emits next actions in prose, extract them using existing parser or new helper into structured `NextActionSignal`.
4. Execute pending actions by priority, respecting budget.
5. Record tool results as `EvidenceItem` and graph nodes/edges.
6. Emit telemetry events: `investigation.loop.iteration`, `investigation.final.blocked`, `investigation.action.executed`, `investigation.completed`.

Pseudo integration point:

```python
if candidate_final_answer:
    completion = completeness_gate.evaluate(state, candidate_final_answer)
    state.completion = completion
    if not completion.allowed:
        state.next_actions.extend(completion_to_next_actions(completion))
        add_system_message(build_continue_investigation_prompt(completion))
        continue

    if flags.llm_final_reviewer_enabled:
        reviewer = reviewer_service.review(state, candidate_final_answer)
        state.reviewer = reviewer
        if not reviewer.approved:
            state.next_actions.extend(reviewer.required_followups)
            add_system_message(build_reviewer_followup_prompt(reviewer))
            continue

    final_answer = candidate_final_answer
    break
```

No findings guard update:

- Current guard must not produce final “no findings” unless:
  - Required milestones are `satisfied` or `not_applicable`.
  - At least one negative evidence item exists per required pivot.
  - Budget exhaustion is explicitly reported if incomplete.

### 7.2 `CABTA/src/agent/final_answer_gate.py`

Objectives:

- Keep existing public behavior for non-SOC chat.
- Add structured SOC completion gate for investigations.
- Expose deterministic `CompletionDecision`.

Required changes:

1. Add function:

```python
def evaluate_investigation_final(
    state: InvestigationState,
    candidate_answer: str,
    rubric: EvidenceRubric | None = None,
) -> CompletionDecision:
    ...
```

2. Existing inline rules around 115-153 and 192-218 should call new gate when `state.input_type in {"raw_log", "case"}` or objective category is SOC investigation.
3. Gate checks:
   - pending required next actions;
   - missing milestones;
   - findings without citation;
   - candidate final contains claims not backed by evidence;
   - high-risk suspicious chain without network/file/scope pivots;
   - no-findings with incomplete coverage.
4. Return machine-readable reasons for prompt/telemetry/tests.

### 7.3 New `CABTA/src/agent/investigation_completeness.py`

Purpose:

- Central deterministic evaluator for readiness to final.
- Independent from prompt wording.

Core functions:

```python
def default_rubric_for_state(state: InvestigationState) -> EvidenceRubric: ...
def evaluate_milestones(state: InvestigationState) -> list[str]: ...
def evaluate_pending_actions(state: InvestigationState) -> list[str]: ...
def evaluate_evidence_coverage(state: InvestigationState, rubric: EvidenceRubric) -> EvidenceScore: ...
def evaluate_candidate_claims(candidate_answer: str, state: InvestigationState) -> list[str]: ...
def evaluate(state: InvestigationState, candidate_answer: str) -> CompletionDecision: ...
```

Rules:

- Deterministic first; no LLM calls.
- Treat raw Sysmon PowerShell chain as high-risk until required pivots complete.
- Allow incomplete final only if budget exhausted and answer clearly labels gaps.

### 7.4 New `CABTA/src/agent/final_investigation_reviewer.py`

Purpose:

- LLM reviewer pass after deterministic gate, before final response.
- Reviewer cannot approve if deterministic gate blocks.

Inputs:

- `InvestigationState`
- candidate final answer
- evidence summary with IDs
- completed/pending actions
- rubric

Output:

- `ReviewerDecision`

Prompt requirements:

- Return JSON only.
- Identify unsupported claims.
- Identify missing pivots.
- Propose structured `NextActionSignal` follow-ups.
- Approve only if report has evidence-backed verdict and clear gaps.

Failure mode:

- If reviewer call fails, fallback depends on flag:
  - default: deterministic gate alone may allow final;
  - strict mode: block final and produce incomplete status.

### 7.5 `CABTA/src/agent/next_action_planner.py`

Objectives:

- Expand beyond search_logs-only logic around lines 507-515.
- Produce typed, prioritized next action signals.

Required changes:

1. Add `NextActionType` enum and planner output schema.
2. Add deterministic heuristics:
   - PowerShell child process -> command deobfuscation, network lookup, file writes.
   - Unknown executable `stage2.exe` -> parent lookup, hash/path enrichment, file creation source.
   - Sysmon Event ID 1 -> process tree and timeline.
   - Sysmon Event ID 3 -> network enrichment.
   - Sysmon Event ID 11 -> file writes.
   - Sysmon Event ID 13/12/14 -> registry persistence.
3. Convert LLM natural language “next pivots” into structured actions.
4. Deduplicate actions by type + target + query.
5. Mark critical/high actions as required.

Expected API:

```python
def plan_next_actions(state: InvestigationState, observation: Observation) -> list[NextActionSignal]: ...
def extract_next_actions_from_text(text: str, state: InvestigationState) -> list[NextActionSignal]: ...
def select_actions_to_execute(state: InvestigationState) -> list[NextActionSignal]: ...
```

### 7.6 `CABTA/src/agent/universal_input_compiler.py`

Objectives:

- Use raw log capability around lines 136-150 to start investigation mode.

Required changes:

1. Add compiled fields:
   - `requires_agentic_investigation: bool`
   - `input_type: raw_log | case | chat | ...`
   - `recommended_milestones: list[str]`
   - `evidence_rubric_id`
2. If raw log contains Sysmon/process creation/security events:
   - set `requires_agentic_investigation=True`;
   - attach parsed seed entities;
   - disable direct final unless gate approves.
3. Preserve compatibility for simple chat by leaving flags false.

### 7.7 `CABTA/src/agent/raw_log_parser.py`

Objectives:

- Reinterpret `allowed_final` around lines 231-240.

Required changes:

1. `allowed_final` must mean “parser found enough normalized input to attempt analysis”, not “runtime may finalize”.
2. Add fields:
   - `seed_events`
   - `suspicious_chains`
   - `required_pivots`
   - `raw_log_confidence`
3. For Sysmon process creation:
   - identify `Image`, `ParentImage`, `CommandLine`, `User`, `Computer`, `UtcTime`, `ProcessGuid`, `ParentProcessGuid`.
4. For `stage2.exe -> powershell.exe`:
   - generate required pivots listed in section 9.

### 7.8 `CABTA/src/agent/prompt_composer.py`

Objectives:

- Update final rules around 37-41 and 77-82.
- Prompt LLM to continue investigation until gate allows final.

Required prompt policy:

```text
You must not provide a final answer merely because you have a preliminary verdict.
If important pivots remain, output NEXT_ACTIONS with structured targets.
Only produce FINAL when the runtime completion gate has approved finalization.
Every finding must cite evidence IDs supplied by the runtime.
If budget is exhausted, label the report INCOMPLETE and list unexecuted pivots.
```

Changes:

1. Add investigation state summary to prompt.
2. Add completed/pending milestones.
3. Add evidence IDs.
4. Ask for JSON block for next actions when not final.

### 7.9 `CABTA/src/agent/session_response_builder.py`

Objectives:

- Ensure user-facing response reflects completion status.

Required changes:

1. Include `completion.status`, `missing_milestones`, and `pending_required_actions` in response metadata.
2. If incomplete due to budget, show “Incomplete investigation - budget exhausted” and gaps.
3. Avoid presenting preliminary verdict as final confirmed incident without evidence.
4. Surface citations/evidence IDs in SOC report.

### 7.10 `CABTA/src/agent/tool_registry.py`

Objectives:

- Map `NextActionSignal` to executable tools.

Required changes:

1. Add registry metadata:
   - action type supported;
   - input schema;
   - output evidence mapping;
   - safe/unsafe classification;
   - max calls per investigation.
2. Provide fallback for demo/no SIEM environment:
   - search demo logs;
   - inspect current raw log batch;
   - run local parser/deobfuscator;
   - generate detection rule from evidence.
3. Tool outputs must include `evidence_id` and normalized entities.

### 7.11 `CABTA/src/agent/query_planning/*` và `CABTA/src/agent/retry/*`

Objectives:

- Tie query coverage retry to investigation completeness.

Required changes:

1. Query planner should accept `NextActionSignal` and emit query variants.
2. Query result evaluator should mark action `done`, `blocked`, or `needs_retry`.
3. Retry logic should not retry indefinitely; use budget and same-action retry limit.
4. Coverage retry should create negative evidence when no result after sufficient queries.

Recommended files:

- `query_planning/query_model.py`
- `query_planning/query_validator.py`
- `query_planning/query_rewriter.py`
- `query_planning/query_result_evaluator.py`
- `retry/__init__.py` or specific retry service modules.

### 7.12 `CABTA/src/daemon/service.py`

Objectives:

- Extend dispatch around lines 301-349 into long-running investigation worker path.

Required changes:

1. Detect requests with `requires_agentic_investigation=True`.
2. Enqueue as investigation job with `InvestigationState`.
3. Persist state after each iteration/action.
4. Emit progress events:
   - `queued`
   - `planning`
   - `executing_action`
   - `reflecting`
   - `reviewing`
   - `completed`
   - `blocked`
5. Support resume after daemon restart.
6. Provide safe cancellation and budget exhaustion.

### 7.13 UI / Telemetry

Relevant if current UI displays chat/investigations:

1. Add progress panel for investigation milestones.
2. Show pending/complete pivots.
3. Show evidence count and citations.
4. Show completion status badge:
   - `Complete`
   - `Incomplete - budget exhausted`
   - `Blocked - needs connector/tool`
   - `Needs more investigation`
5. Telemetry metrics:
   - `investigation_final_blocked_total`
   - `investigation_auto_pivots_total`
   - `investigation_completion_status_total`
   - `investigation_reviewer_reject_total`
   - `investigation_budget_exhausted_total`
   - `investigation_loop_iterations`
   - `investigation_evidence_items_total`

## 8. Pseudocode

### 8.1 Final Answer Interception

```python
def maybe_accept_final(state: InvestigationState, candidate: str, flags: RuntimeFlags) -> FinalizationResult:
    if not flags.agentic_investigation_gate_enabled:
        return FinalizationResult(accepted=True, answer=candidate, reason="gate_disabled")

    completion = investigation_completeness.evaluate(state, candidate)
    state.completion = completion

    if not completion.allowed:
        followups = completion_to_next_actions(completion, state)
        state.next_actions = merge_next_actions(state.next_actions, followups)
        return FinalizationResult(
            accepted=False,
            reason="completion_gate_blocked",
            next_actions=followups,
            message=build_gate_block_message(completion),
        )

    if flags.llm_final_reviewer_enabled:
        reviewer = final_investigation_reviewer.review(state, candidate)
        state.reviewer = reviewer
        if not reviewer.approved:
            state.next_actions = merge_next_actions(state.next_actions, reviewer.required_followups)
            return FinalizationResult(
                accepted=False,
                reason="reviewer_rejected",
                next_actions=reviewer.required_followups,
                message=build_reviewer_block_message(reviewer),
            )

    return FinalizationResult(accepted=True, answer=candidate, reason="approved")
```

### 8.2 Reviewer Loop

```python
def investigation_loop(request):
    state = initialize_state(request)

    while not state.budgets.exhausted():
        planner_actions = next_action_planner.plan_next_actions(state, latest_observation(state))
        state.next_actions = merge_next_actions(state.next_actions, planner_actions)

        executable = next_action_planner.select_actions_to_execute(state)
        if executable:
            for action in executable:
                result = tool_executor.execute(action)
                evidence = evidence_mapper.from_tool_result(action, result)
                state.evidence.extend(evidence)
                state.graph.merge(evidence_to_graph(evidence))
                mark_action_status(action, result)
            continue

        candidate = llm_generate_candidate_report(state)
        finalization = maybe_accept_final(state, candidate, flags)
        if finalization.accepted:
            return build_final_response(state, candidate)

        if not finalization.next_actions:
            if state.budgets.can_continue_without_action():
                state.next_actions.extend(default_gap_actions(state))
                continue
            break

    incomplete_candidate = llm_generate_incomplete_report(state)
    state.completion = CompletionDecision(
        allowed=True,
        status="incomplete_budget_exhausted",
        reasons=["Investigation budget exhausted before all required pivots completed"],
        missing_milestones=missing_milestones(state),
        pending_required_actions=pending_required_actions(state),
        evidence_score=score_evidence(state),
        hallucination_risk="medium",
        final_answer_allowed=True,
        stop_reason="budget_exhausted",
    )
    return build_final_response(state, incomplete_candidate)
```

## 9. Strategy Cho Pasted Sysmon `stage2.exe -> powershell.exe`

### 9.1 Input Pattern

Nếu user paste raw Sysmon log có chuỗi:

- `Image` hoặc process name: `stage2.exe`
- child process: `powershell.exe`
- command line đáng ngờ: encoded command, download cradle, bypass, hidden window, no profile, execution policy bypass
- fields như `ParentImage`, `CommandLine`, `ProcessGuid`, `ParentProcessGuid`, `User`, `Computer`, `UtcTime`

Runtime phải coi đây là high-risk process chain, không được final sau verdict sơ bộ.

### 9.2 Required Pivots

Required actions tối thiểu:

1. `PROCESS_PARENT_LOOKUP`
   - Mục tiêu: tìm parent của `stage2.exe`.
   - Evidence kỳ vọng: parent process, command line, user, timestamp.
2. `PROCESS_CHILD_LOOKUP`
   - Mục tiêu: tìm tất cả child của `stage2.exe` và `powershell.exe`.
   - Evidence kỳ vọng: process tree đầy đủ.
3. `COMMAND_LINE_DEOBFUSCATE`
   - Mục tiêu: decode PowerShell command, Base64, escaped strings.
   - Evidence kỳ vọng: decoded command và intent.
4. `NETWORK_CONNECTION_LOOKUP`
   - Mục tiêu: tìm Sysmon Event ID 3 hoặc network logs liên quan PowerShell/stage2.
   - Evidence kỳ vọng: destination IP/domain/port, timestamp.
5. `FILE_WRITE_LOOKUP`
   - Mục tiêu: tìm Sysmon Event ID 11/file writes của chain.
   - Evidence kỳ vọng: dropped files, paths, hashes nếu có.
6. `REGISTRY_LOOKUP`
   - Mục tiêu: persistence via Run keys/services/WMI/script policies nếu PowerShell nghi ngờ persistence.
   - Evidence kỳ vọng: modified keys/values.
7. `USER_SESSION_LOOKUP`
   - Mục tiêu: xác định user context và logon session.
   - Evidence kỳ vọng: user, logon id, privilege hints.
8. `HOST_TIMELINE_EXPAND`
   - Mục tiêu: ±15-30 phút quanh seed event.
   - Evidence kỳ vọng: timeline trước/sau.
9. `IOC_EXTRACT_ENRICH`
   - Mục tiêu: extract hash/path/domain/IP/URL/command indicators.
   - Evidence kỳ vọng: IoC list và enrichment status.
10. `RULE_DETECTION_GENERATE`
   - Mục tiêu: sinh Sigma/YARA/EDR query nếu đủ evidence.
   - Evidence kỳ vọng: detection logic dựa trên chain.

### 9.3 Expected Behavior

Expected runtime behavior:

1. User paste log.
2. Universal input compiler marks `requires_agentic_investigation=True`.
3. Raw log parser extracts seed event and suspicious chain.
4. Agent loop creates milestones and required `NextActionSignal` list.
5. LLM may state preliminary hypothesis internally, but final is blocked.
6. Executor runs available local/demo pivots.
7. Missing connector pivots become `blocked` with reason, not silently ignored.
8. Completion gate allows final only when required evidence exists or budget exhausted with explicit gaps.
9. Final report includes:
   - verdict with confidence;
   - evidence table with IDs;
   - process tree;
   - decoded command analysis;
   - network/file/registry/user/timeline findings or negative evidence;
   - remaining gaps;
   - containment and detection recommendations.

## 10. Phased Implementation

## Phase 0 - Baseline Characterization

### Objectives

- Reproduce early final issue.
- Capture current behavior before changes.
- Establish tests that fail under current runtime.

### Code Changes

- No production logic change except optional test fixtures.
- Add fixtures for Sysmon `stage2.exe -> powershell.exe` raw log.
- Add snapshot helpers for final response metadata if not existing.

### Tests

Create/update:

- `CABTA/tests/fixtures/sysmon_stage2_powershell_raw.log`
- `CABTA/tests/test_agent_loop_prevents_early_final.py`
- `CABTA/tests/test_raw_log_parser_stage2_chain.py`
- `CABTA/tests/test_universal_input_compiler_investigation_mode.py`

Test assertions:

- Current runtime finalizes too early or lacks required pivot metadata.
- Parser extracts process names, command line, user, host, timestamp.
- Compiler recognizes raw log and investigation requirement.

### Acceptance Criteria

- Failing tests demonstrate early final gap.
- Evidence references line locations listed in section 2 are validated by code reading.
- Fixture is deterministic and small enough for CI.

### Risks / Rollback

- Risk: tests may be brittle due to LLM variability.
- Mitigation: use mocked LLM/tool outputs.
- Rollback: remove new failing tests if blocking unrelated release; keep fixture.

## Phase 1 - Block Early Final

### Objectives

- Prevent final answer when required pivots remain.
- Add feature flag `agentic_investigation_gate_enabled` default false initially, then true after tests pass.

### Code Changes

- Add `InvestigationState`, `InvestigationBudget`, `SOCMilestone`, `EvidenceRubric` minimal dataclasses.
- Add `investigation_completeness.py` with deterministic pending-action/milestone checks.
- Update `final_answer_gate.py` to call completeness gate for investigation state.
- Intercept final break in `agent_loop.py`.
- Update no-findings guard to require coverage.

### Tests

Create/update:

- `CABTA/tests/test_investigation_completeness_gate.py`
- `CABTA/tests/test_final_answer_gate_investigation.py`
- `CABTA/tests/test_agent_loop_prevents_early_final.py`

Concrete cases:

1. Candidate verdict says malicious but `NETWORK_CONNECTION_LOOKUP` pending -> blocked.
2. Candidate says no findings but process tree milestone missing -> blocked.
3. Budget exhausted with explicit incomplete report -> allowed with status `incomplete_budget_exhausted`.

### Acceptance Criteria

- Final break cannot occur for raw log investigation with pending required actions.
- Blocking reason is visible in telemetry/test state.
- Existing non-SOC chat tests pass unchanged.

### Risks / Rollback

- Risk: over-blocking simple chat.
- Mitigation: gate only active when compiler/objective marks investigation.
- Rollback: disable `agentic_investigation_gate_enabled`.

## Phase 2 - Next Action Signals / Auto-pivot

### Objectives

- Convert next pivots into structured executable actions.
- Expand planner beyond `search_logs` only.

### Code Changes

- Add `NextActionSignal` and `NextActionType`.
- Update `next_action_planner.py` heuristics and LLM text extraction.
- Update `tool_registry.py` to map action types to tools.
- Update query planning/retry to execute action-specific queries.
- Add dedupe and priority selection.

### Tests

Create/update:

- `CABTA/tests/test_next_action_planner_soc_pivots.py`
- `CABTA/tests/test_tool_registry_next_action_mapping.py`
- `CABTA/tests/test_query_coverage_retry_investigation_actions.py`

Concrete cases:

- `stage2.exe -> powershell.exe` generates parent, child, deobfuscate, network, file, timeline, IoC actions.
- Duplicate prose pivots are merged.
- Blocked connector produces blocked action with reason.

### Acceptance Criteria

- Planner emits typed actions for Sysmon process chain.
- Agent loop executes available actions before final.
- Action status transitions are deterministic.

### Risks / Rollback

- Risk: auto-pivot increases latency.
- Mitigation: budget defaults conservative; auto-pivot flag.
- Rollback: disable `auto_pivot_enabled` while keeping gate.

## Phase 3 - Completeness Gate

### Objectives

- Strengthen evidence and milestone scoring.
- Support negative evidence and blocked/not-applicable pivots.

### Code Changes

- Expand `investigation_completeness.py` rubric checks.
- Add claim-to-evidence lightweight validation.
- Add milestone evaluator and evidence score.
- Update `session_response_builder.py` to expose completion status/gaps.

### Tests

Create/update:

- `CABTA/tests/test_investigation_completeness_rubric.py`
- `CABTA/tests/test_session_response_builder_completion_status.py`
- `CABTA/tests/test_no_findings_requires_coverage.py`

Concrete cases:

- Finding without evidence citation -> blocked.
- Missing command line analysis for PowerShell -> blocked.
- Network lookup no results after adequate query -> negative evidence counts.

### Acceptance Criteria

- Gate decisions are explainable with reasons.
- No-findings final requires completed coverage or incomplete label.
- Response metadata includes missing milestones and pending actions.

### Risks / Rollback

- Risk: claim validation false positives.
- Mitigation: start with simple citation/keyword checks; avoid semantic overreach.
- Rollback: relax claim validation while retaining milestone checks.

## Phase 4 - LLM Reviewer

### Objectives

- Add independent final review pass.
- Catch unsupported claims and missing pivots missed by deterministic gate.

### Code Changes

- Add `final_investigation_reviewer.py`.
- Add reviewer prompt and JSON parser.
- Wire into `agent_loop.py` after deterministic gate.
- Add flag `llm_final_reviewer_enabled` default false for rollout.

### Tests

Create/update:

- `CABTA/tests/test_final_investigation_reviewer.py`
- `CABTA/tests/test_agent_loop_reviewer_followups.py`
- `CABTA/tests/test_reviewer_json_schema_contract.py`

Concrete cases:

- Mock reviewer rejects final and returns required network pivot.
- Mock reviewer approves final with evidence-backed findings.
- Invalid reviewer JSON fails closed or follows configured fallback.

### Acceptance Criteria

- Reviewer cannot override deterministic block.
- Reviewer followups are converted into `NextActionSignal`.
- Reviewer failures are observable and do not crash investigation.

### Risks / Rollback

- Risk: reviewer adds LLM cost/latency.
- Mitigation: flag, provider timeout, skip for low-risk/simple cases.
- Rollback: disable `llm_final_reviewer_enabled`.

## Phase 5 - Planner-Executor-Reflector Loop

### Objectives

- Formalize loop instead of ad-hoc tool/final sequencing.
- Add reflection step and investigation state persistence within session.

### Code Changes

- Refactor `agent_loop.py` into explicit phases or helper service:
  - `plan_next_actions`
  - `execute_actions`
  - `reflect_on_results`
  - `attempt_final`
- Add graph updates from evidence.
- Add reflection prompt for unresolved gaps.
- Ensure budgets control iterations/tool calls.

### Tests

Create/update:

- `CABTA/tests/test_agentic_investigation_loop.py`
- `CABTA/tests/test_investigation_budget_loop_prevention.py`
- `CABTA/tests/test_investigation_graph_updates.py`

Concrete cases:

- Loop executes multiple actions then finalizes.
- Same action retry capped.
- Graph contains process parent/child edges.

### Acceptance Criteria

- Investigation progresses through plan/execute/reflect/final phases.
- Loop cannot run beyond configured budget.
- State is inspectable in tests.

### Risks / Rollback

- Risk: large refactor destabilizes agent loop.
- Mitigation: extract helpers incrementally; keep old path for non-investigation.
- Rollback: route investigation back to Phase 3 gate-only path.

## Phase 6 - Graph / Playbook / Daemon

### Objectives

- Make investigations long-running and resumable.
- Encode SOC playbook milestones.
- Persist graph/state across daemon jobs.

### Code Changes

- Extend `daemon/service.py` dispatch path.
- Add state store or reuse existing workdir/case memory services.
- Add playbook definitions for raw Sysmon/process investigation.
- Add resume/cancel APIs if absent.
- Update UI to show progress if relevant.

### Tests

Create/update:

- `CABTA/tests/test_daemon_investigation_dispatch.py`
- `CABTA/tests/test_daemon_investigation_resume.py`
- `CABTA/tests/test_soc_playbook_milestones.py`
- `CABTA/tests/test_investigation_workdir_service.py` updates if workdir persistence reused.

Concrete cases:

- Dispatch raw log creates investigation job.
- Restart/resume continues from persisted state.
- Cancel marks job stopped safely.

### Acceptance Criteria

- Daemon can run raw log investigation beyond single chat turn.
- Progress events emitted in expected order.
- State persists after each action.

### Risks / Rollback

- Risk: persistence schema complexity.
- Mitigation: start JSON state per workdir/case before DB migration.
- Rollback: keep daemon dispatch disabled behind flag.

## Phase 7 - Observability And UI

### Objectives

- Make agentic investigation transparent to analyst.
- Track quality and loop behavior.

### Code Changes

- Add telemetry events/metrics listed in section 7.13.
- Add session response fields for milestones/actions/evidence.
- UI badges and progress panel if templates support it.
- Add debug export for investigation state.

### Tests

Create/update:

- `CABTA/tests/test_investigation_telemetry.py`
- `CABTA/tests/test_agent_chat_reasoning_ui.py`
- `CABTA/tests/test_reasoning_mirror_ui.py`
- `CABTA/tests/test_vibe_soc_hardening_runtime_ui.py`

Concrete cases:

- Final blocked event emitted.
- UI receives completion status and pending actions.
- Evidence citations displayed or serialized.

### Acceptance Criteria

- Analysts can see why final was delayed or incomplete.
- Metrics allow detecting infinite loops/over-blocking.
- Existing UI tests pass.

### Risks / Rollback

- Risk: UI noise.
- Mitigation: collapse details behind “Investigation progress”.
- Rollback: keep telemetry only, hide UI panel.

## 11. Test Plan

### 11.1 Unit Tests

Recommended files:

- `CABTA/tests/test_investigation_completeness_gate.py`
- `CABTA/tests/test_investigation_completeness_rubric.py`
- `CABTA/tests/test_final_answer_gate_investigation.py`
- `CABTA/tests/test_final_investigation_reviewer.py`
- `CABTA/tests/test_next_action_planner_soc_pivots.py`
- `CABTA/tests/test_raw_log_parser_stage2_chain.py`
- `CABTA/tests/test_universal_input_compiler_investigation_mode.py`
- `CABTA/tests/test_tool_registry_next_action_mapping.py`

Core unit cases:

1. Pending required action blocks final.
2. Missing milestone blocks final.
3. Finding without evidence ID blocks final.
4. Budget exhausted permits incomplete final with gaps.
5. Reviewer rejection creates follow-up actions.
6. Sysmon parser extracts chain entities.
7. Planner emits expected action types.

### 11.2 Integration Tests

Recommended files:

- `CABTA/tests/test_agent_loop_prevents_early_final.py`
- `CABTA/tests/test_agentic_investigation_loop.py`
- `CABTA/tests/test_agent_loop_reviewer_followups.py`
- `CABTA/tests/test_query_coverage_retry_investigation_actions.py`
- `CABTA/tests/test_session_response_builder_completion_status.py`

Core integration cases:

1. Mock LLM tries to final early; loop blocks and executes pivots.
2. Mock LLM says “no findings”; gate blocks until coverage complete.
3. Tool returns no network hits; negative evidence recorded.
4. Reviewer demands file-write pivot; loop executes it.
5. Final response includes completion status, evidence IDs, and gaps.

### 11.3 E2E Tests

Recommended files:

- `CABTA/tests/test_sysmon_stage2_agentic_e2e.py`
- `CABTA/tests/test_daemon_investigation_dispatch.py`
- `CABTA/tests/test_daemon_investigation_resume.py`
- `CABTA/tests/test_analyst_workflow_e2e.py` updates

Core E2E cases:

1. User pastes Sysmon `stage2.exe -> powershell.exe`; final not emitted until pivots complete.
2. Daemon job processes raw log, emits progress, persists state, returns final report.
3. Resume after simulated restart continues pending action.
4. UI/session shows complete/incomplete status correctly.

### 11.4 Security Tests

Recommended files:

- `CABTA/tests/test_investigation_hallucination_controls.py`
- `CABTA/tests/test_investigation_tool_safety.py`
- `CABTA/tests/test_investigation_prompt_injection_resistance.py`

Core security cases:

1. Raw log contains prompt injection text “ignore previous instructions”; prompt composer treats it as evidence, not instruction.
2. LLM claims external enrichment not present in evidence; gate flags unsupported claim.
3. Tool registry refuses unsafe action not allowlisted.
4. Reviewer cannot approve deterministic block.

### 11.5 Regression Tests

Recommended files to keep green:

- `CABTA/tests/test_agent_loop_prompt_plumbing.py`
- `CABTA/tests/test_prompt_composer.py`
- `CABTA/tests/test_raw_log_parser.py`
- `CABTA/tests/test_universal_input_compiler.py`
- `CABTA/tests/test_session_response_builder.py`
- `CABTA/tests/test_query_coverage_retry.py`
- `CABTA/tests/test_headless_soc_daemon.py`
- `CABTA/tests/test_vibe_soc_natural_chat_scenarios.py`

Regression expectations:

- Non-SOC chat does not enter investigation loop.
- Existing raw log parsing still works.
- Existing prompt composition tests updated only for new final policy.
- Daemon legacy dispatch remains compatible.

## 12. Security And Hallucination Controls

1. Treat user-pasted logs as data, never as prompt instructions.
2. Every finding must cite `evidence_id`.
3. Claims about VirusTotal, reputation, geoIP, domain age, or external intel must require actual tool result evidence.
4. LLM reviewer output must be schema-validated JSON.
5. Deterministic gate has final authority over required pivots.
6. Tool execution must use allowlist from `tool_registry.py`.
7. Block or require approval for tools that can mutate systems.
8. Store raw and normalized evidence separately; do not let decoded command execute.
9. Mark unsupported hypotheses as hypotheses, not confirmed findings.
10. Redact secrets in telemetry and UI.

## 13. Loop Prevention / Budget Controls

Required controls:

1. `max_iterations`
2. `max_tool_calls`
3. `max_auto_pivots`
4. `max_wall_clock_seconds`
5. `max_same_action_retries`
6. action dedupe by semantic key
7. cycle detection in investigation graph
8. stop reason enum:
   - `completed`
   - `budget_exhausted`
   - `blocked_missing_tool`
   - `cancelled`
   - `error`
   - `gate_disabled`
9. incomplete final only with explicit gaps.

Budget policy:

- Critical pivots first.
- If budget low, prefer breadth across required milestones over repeated variants of same query.
- If connector missing, mark action blocked and proceed to other pivots.
- Never spin on same empty query more than retry limit.

## 14. Observability Events And Metrics

### Events

Emit structured events:

- `investigation.created`
- `investigation.loop.iteration_started`
- `investigation.plan.actions_created`
- `investigation.action.started`
- `investigation.action.completed`
- `investigation.action.blocked`
- `investigation.evidence.added`
- `investigation.milestone.satisfied`
- `investigation.final.blocked`
- `investigation.reviewer.started`
- `investigation.reviewer.rejected`
- `investigation.reviewer.approved`
- `investigation.completed`
- `investigation.budget_exhausted`

### Metrics

- `investigation_final_blocked_total{reason}`
- `investigation_completion_total{status}`
- `investigation_auto_pivots_total{type}`
- `investigation_action_blocked_total{type,reason}`
- `investigation_reviewer_reject_total`
- `investigation_budget_exhausted_total`
- `investigation_loop_iterations_histogram`
- `investigation_tool_calls_histogram`
- `investigation_evidence_items_histogram`
- `investigation_duration_seconds`

### Logs

Each log line should include:

- `investigation_id`
- `session_id`
- `iteration`
- `action_id`
- `milestone_id`
- `completion_status`
- `stop_reason`

## 15. Migration Flags And Compatibility

### Flags

1. `agentic_investigation_gate_enabled`
   - Default Phase 1: false in production, true in tests/dev.
   - Default after Phase 3: true for raw log/case investigations.
2. `llm_final_reviewer_enabled`
   - Default Phase 4: false.
   - Enable gradually for raw log high-risk cases.
3. `auto_pivot_enabled`
   - Default Phase 2: false in production, true in tests/dev.
   - Enable with conservative budgets.

### Compatibility Requirements

- Non-SOC chat should behave like current flow.
- Existing API response fields remain stable; add metadata fields without removing old ones.
- Existing daemon dispatch continues to work for non-investigation jobs.
- Existing tests should only need updates where final prompt policy intentionally changes.
- If flags are disabled, runtime should fall back to existing behavior.

### Suggested Config Shape

```yaml
agentic_investigation:
  gate_enabled: true
  auto_pivot_enabled: true
  llm_final_reviewer_enabled: false
  max_iterations: 12
  max_tool_calls: 30
  max_auto_pivots: 15
  max_wall_clock_seconds: 180
  strict_reviewer_failure: false
```

## 16. Definition Of Done

Implementation is done when:

1. Pasted Sysmon `stage2.exe -> powershell.exe` raw log no longer finalizes after preliminary verdict.
2. Agent creates structured required pivots and executes all available pivots before final.
3. Final answer is blocked by deterministic gate when required milestones/actions are missing.
4. Budget exhaustion produces explicit incomplete report with gaps, not a confident final.
5. Reviewer can reject a candidate final and force follow-up actions when enabled.
6. Findings in final report cite evidence IDs.
7. No-findings answer requires completed coverage or incomplete label.
8. Daemon can run/resume long-running investigation jobs when enabled.
9. Telemetry shows final blocked/completed/budget exhausted states.
10. Unit, integration, E2E, security, and regression tests listed in section 11 pass.
11. Feature flags allow safe rollback to previous behavior.
12. Documentation or comments explain how to add new pivot/action types.

## 17. Recommended Implementation Order

1. Add Phase 0 failing tests and Sysmon fixture.
2. Add data models with no runtime behavior change.
3. Implement deterministic `investigation_completeness.py`.
4. Wire `final_answer_gate.py` and `agent_loop.py` final interception behind `agentic_investigation_gate_enabled`.
5. Update raw log parser and universal input compiler to start investigation mode.
6. Expand `next_action_planner.py` to emit typed `NextActionSignal`.
7. Map actions to tools and query planning/retry.
8. Add session response completion metadata.
9. Add LLM reviewer behind `llm_final_reviewer_enabled`.
10. Refactor loop into planner-executor-reflector structure.
11. Add daemon long-running/resume support.
12. Add telemetry/UI progress.
13. Enable flags gradually: tests/dev first, then raw log high-risk, then broader SOC cases.

## 18. RooCode Implementation Notes

- Work in small PR-sized slices by phase.
- Keep flags default-safe until tests prove behavior.
- Prefer deterministic tests with mocked LLM/provider responses.
- Avoid broad rewrites of `agent_loop.py` in Phase 1; intercept final first, refactor later.
- Preserve user changes in dirty worktree; do not revert unrelated files.
- After each phase, run focused tests first, then relevant regression tests.
- Treat every new model/interface as typed and schema-testable.

## 19. Expected Final Report Shape

A successful SOC final should look like:

```text
Verdict: Suspicious / likely malicious PowerShell execution spawned by stage2.exe
Confidence: High/Medium with reason
Completion status: Complete or Incomplete - budget exhausted

Evidence:
- E1: Sysmon process creation stage2.exe -> powershell.exe ...
- E2: Decoded PowerShell command ...
- E3: Network lookup result ...
- E4: File write or negative evidence ...

Investigation coverage:
- Process tree: complete
- Command line: complete
- Network: complete/no hits with query evidence
- File/registry: complete/no hits with query evidence
- User/host scope: complete
- Timeline: complete

Findings:
- Finding 1 with evidence IDs
- Finding 2 with evidence IDs

Gaps:
- Any blocked connector or budget-limited pivot

Recommendations:
- Containment
- Detection query/rule
- Follow-up hunts
```

This shape ensures the analyst receives an investigation result, not only a premature verdict.
