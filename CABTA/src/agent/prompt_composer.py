"""Prompt composition helpers for AISA agent investigations."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

_SYSTEM_PROMPT = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Investigation goal: {goal}

Previous findings:
{findings_block}

{response_style_block}

{chat_decision_block}

Current structured reasoning state:
{reasoning_block}

{provider_context_block}

{profile_block}

{workflow_block}

{playbooks_block}

INSTRUCTIONS:
1. When the analyst needs fresh evidence, you MUST use tools before drawing conclusions. Never answer from memory alone for investigation claims.
2. Choose the next action by objective, required capability, and missing evidence first; treat tool names as adapters to collect that evidence.
3. For log/SIEM/firewall hunts, prioritize log evidence collection (for example search_logs) and preserve the requested timerange before IOC enrichment.
4. For observable reputation questions, use IOC/threat-intel enrichment; for file artifacts use file analysis; for email artifacts use email analysis.
5. After gathering sufficient evidence, call correlate_findings when available to correlate evidence before the final verdict.
6. Only write a final text answer (no tool call) AFTER you have gathered real evidence or have explicitly stated degraded/missing capability limits.
7. When calling a tool, ONLY pass the tool's own parameters (e.g. {{"ioc": "8.8.8.8"}}). Do NOT include extra keys like "action", "reasoning", or "tool" in the arguments.
8. Use DIFFERENT tools each step. Never call the same tool with the same parameters twice.
9. For quick analyst chat questions, prefer the highest-value evidence pivot first and stop honestly once the evidence is sufficient. Avoid low-value manual or auth-required pivots unless the current evidence is still insufficient.

FINALIZATION CONTRACT:
- Do not produce a final answer unless deterministic completeness is complete and the final reviewer has passed or is explicitly unavailable with a safe degraded-status explanation.
- If completeness or reviewer status is missing/failed, output the next action instead of a final. In JSON mode use: {{"action":"use_tool","tool":"tool_name","params":{{...}},"reasoning":"gap analysis","gap_analysis":["missing evidence"],"next_actions":[{{"action_type":"collect_evidence","query_focus":"..."}}]}}.
- If all tool paths are blocked or budget is exhausted, produce a partial_safe_stop/final_investigation_report shape with limitations and pending_actions; do not claim a malicious/clean verdict as final.

If previous findings are "(none yet)" and the analyst gave you a concrete IOC, file, email, URL, hash, log artifact, or alert to investigate, you MUST call a tool now. Do NOT skip to a conclusion in that case.

RULES:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use the tools provided. Do NOT invent tool names.
"""

_SYSTEM_PROMPT_NO_TOOLS = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Available tools:
{tools_block}

{response_style_block}

{chat_decision_block}

{profile_block}

{workflow_block}

{playbooks_block}

Investigation goal: {goal}

Previous findings:
{findings_block}

Current structured reasoning state:
{reasoning_block}

{provider_context_block}

Decide your next action. Respond in JSON (no markdown, no extra text):
{{"action": "use_tool", "tool": "tool_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "run_playbook", "playbook_id": "playbook_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "final_answer", "answer": "investigation summary", "verdict": "MALICIOUS/SUSPICIOUS/CLEAN", "reasoning": "why"}}

FINALIZATION CONTRACT:
- Do not choose final_answer unless deterministic completeness is complete and reviewer status is passed or explicitly unavailable with safe degradation.
- If incomplete, return use_tool/run_playbook with gap_analysis and next_actions fields.
- If no more safe progress is possible, final_answer must contain final_investigation_report with required sections or partial_safe_stop with limitations and pending_actions.

IMPORTANT:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Actions marked as requiring approval will pause for analyst review.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use tools that are listed above. Do NOT invent tool names.
- If a playbook matches the investigation goal, prefer running the playbook for structured analysis.
- Always include the "action" key in your JSON response.
"""

_CHAT_DIRECT_ANSWER_PROMPT = """\
You are a Blue Team Security Agent continuing an analyst conversation.

Investigation goal: {goal}

Previous findings:
{findings_block}

{response_style_block}

Current structured reasoning state:
{reasoning_block}

{provider_context_block}

{profile_block}

Answer the analyst directly in natural language using only the evidence that is already available.
Do not output JSON.
Do not request or call more tools in this response.
Do not propose a playbook, workflow step, or next tool unless you are explicitly stating what evidence is still missing.
If the evidence is still insufficient, say that clearly and explain what is missing.
"""

_SUMMARY_PROMPT = """\
You are a Blue Team Security Agent. Summarise the following investigation
in 3-5 sentences suitable for a SOC ticket.  Include the verdict
(MALICIOUS / SUSPICIOUS / CLEAN), key evidence, and recommended next steps.

{response_style_block}

Goal: {goal}

Current structured reasoning state:
{reasoning_block}

{provider_context_block}

Steps taken: {step_count}

Findings:
{findings_json}

Respond in plain text (no JSON).
"""


class PromptComposer:
    """Compose model-facing prompts from normalized investigation context."""

    @staticmethod
    def _truncate(value: str, limit: int = 200) -> str:
        if len(value) <= limit:
            return value
        return value[: limit - 3] + "..."

    @staticmethod
    def _section_excerpt(section_text: str, limit: int = 3) -> str:
        parts: List[str] = []
        for raw_line in section_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("- "):
                parts.append(line[2:].strip())
            elif re.match(r"^\d+\.\s+", line):
                parts.append(re.sub(r"^\d+\.\s+", "", line))
            elif not parts:
                parts.append(line)
            if len(parts) >= limit:
                break
        return " | ".join(parts[:limit])

    def build_tools_block(self, tool_descriptors: List[Any]) -> str:
        """Format registered tools into a readable list for the prompt."""
        lines = []
        for td in tool_descriptors:
            approval_tag = " [REQUIRES APPROVAL]" if td.requires_approval else ""
            params_desc = ", ".join(
                f"{k}: {v.get('type', 'any')}"
                for k, v in td.parameters.get("properties", {}).items()
            )
            lines.append(f"- {td.name}({params_desc}){approval_tag}: {td.description}")
        return "\n".join(lines) if lines else "(no tools registered)"

    def build_playbooks_block(self, playbooks: List[Dict[str, Any]]) -> str:
        """Format available playbooks into a readable list for the prompt."""
        if not playbooks:
            return ""
        lines = ["Available playbooks (use run_playbook action to execute):"]
        for pb in playbooks:
            step_count = pb.get("step_count", 0)
            desc = str(pb.get("description", "") or "")
            if len(desc) > 120:
                desc = desc[:120] + "..."
            lines.append(f"- {pb['id']} ({step_count} steps): {desc}")
        return "\n".join(lines)

    def build_profile_block(
        self,
        state: Any,
        *,
        profile_prompt_block: str = "",
    ) -> str:
        """Return specialist-agent guidance for the current session."""
        lines = []
        if profile_prompt_block:
            lines.append("Specialist profile guidance:\n" + profile_prompt_block)
        specialist_team = getattr(state, "specialist_team", None)
        if specialist_team:
            lines.append("Active specialist team: " + " -> ".join(specialist_team))
            lines.append(
                f"Current active specialist: {getattr(state, 'active_specialist', None) or getattr(state, 'agent_profile_id', None) or 'workflow_controller'}"
            )
        return "\n".join(line for line in lines if line)

    def build_workflow_block(
        self,
        state: Any,
        *,
        workflow: Dict[str, Any] | None = None,
        latest_handoff: Dict[str, Any] | None = None,
    ) -> str:
        """Return workflow guardrails for the current session."""
        if not workflow:
            return ""

        lines = [
            f"Workflow context: {workflow.get('name', getattr(state, 'workflow_id', ''))}",
            f"Workflow backend: {workflow.get('execution_backend', 'agent')}",
        ]
        if workflow.get("description"):
            lines.append("Workflow intent: " + str(workflow["description"]))
        if workflow.get("use_case"):
            lines.append("Workflow use case: " + str(workflow["use_case"]))
        if workflow.get("agents"):
            lines.append(
                "Suggested specialist sequence: "
                + ", ".join(str(agent) for agent in workflow["agents"])
            )
        if latest_handoff:
            lines.append(
                "Latest specialist handoff: "
                f"{latest_handoff.get('from_profile') or 'unassigned'} -> {latest_handoff.get('to_profile')}"
            )
        if workflow.get("tools_used"):
            lines.append(
                "Expected evidence tools: "
                + ", ".join(str(tool) for tool in workflow["tools_used"])
            )
        sections = workflow.get("sections") or {}
        operating_model = sections.get("operating_model")
        if operating_model:
            excerpt = self._section_excerpt(operating_model)
            if excerpt:
                lines.append("Workflow operating model: " + excerpt)
        phase_sequence = sections.get("phase_sequence") or sections.get("phases")
        if phase_sequence:
            excerpt = self._section_excerpt(phase_sequence)
            if excerpt:
                lines.append("Workflow phases: " + excerpt)
        lines.append(
            "Workflow guardrail: follow the tool-backed workflow path and never "
            "invent unsupported evidence."
        )
        return "\n".join(lines)

    def build_findings_block(
        self,
        state: Any,
        *,
        is_chat_session: bool,
        chat_prompt_findings_limit: int,
        describe_fallback_evidence,
    ) -> str:
        """Summarise findings so far (capped to keep context manageable)."""
        findings = getattr(state, "findings", None) or []
        if not findings:
            return "(none yet)"

        max_findings = chat_prompt_findings_limit if is_chat_session else 8
        recent = findings[-max_findings:]
        parts = []
        for i, finding in enumerate(recent):
            step = finding.get("step", i)
            finding_type = str(finding.get("type") or "finding")
            if finding_type == "tool_result":
                tool_name = str(finding.get("tool") or "tool_result")
                summary = describe_fallback_evidence(tool_name, finding.get("result"))
                if not summary:
                    payload = finding.get("result")
                    preview = self._truncate(json.dumps(payload, default=str), 220)
                    summary = f"{tool_name} returned {preview}"
                parts.append(f"[{step}] {summary}")
            elif finding_type == "final_answer":
                answer = self._truncate(str(finding.get("answer") or ""), 220)
                parts.append(f"[{step}] final_answer: {answer}")
            else:
                preview = self._truncate(json.dumps(finding, default=str), 220)
                parts.append(f"[{step}] {preview}")
        return "\n".join(parts)

    def build_reasoning_block(
        self,
        state: Any,
        *,
        is_chat_session: bool,
    ) -> str:
        """Return a compact structured reasoning snapshot for the prompt."""
        reasoning_state = (
            state.reasoning_state if isinstance(getattr(state, "reasoning_state", None), dict) else {}
        )
        hypotheses = reasoning_state.get("hypotheses", []) if isinstance(reasoning_state, dict) else []
        lines: List[str] = []
        plan = (
            state.investigation_plan
            if isinstance(getattr(state, "investigation_plan", None), dict)
            else {}
        )
        if plan:
            lines.append(
                "Investigation plan: "
                f"lane={plan.get('lane')}, lead_profile={plan.get('lead_profile')}, "
                f"primary_entities={', '.join(plan.get('primary_entities', [])[:5]) or '(none)'}"
            )
            if plan.get("first_pivots"):
                lines.append("Planned first pivots:")
                for pivot in list(plan.get("first_pivots", []))[:3]:
                    lines.append(f"- {pivot}")
        if not hypotheses:
            lines.append("(no structured hypotheses yet)")
            return "\n".join(lines)

        status = str(reasoning_state.get("status") or "collecting_evidence")
        lines.append(f"Reasoning status: {status}")
        active_observations = getattr(state, "active_observations", None)
        if active_observations:
            lines.append(f"Normalized observations: {len(active_observations)}")
        evidence_quality_summary = (
            state.evidence_quality_summary
            if isinstance(getattr(state, "evidence_quality_summary", None), dict)
            else {}
        )
        if evidence_quality_summary:
            avg_quality = evidence_quality_summary.get("average_quality")
            obs_count = evidence_quality_summary.get("observation_count")
            lines.append(f"Evidence quality: avg={avg_quality}, observations={obs_count}")

        coverage_matrix = reasoning_state.get("coverage_matrix", {}) if isinstance(reasoning_state, dict) else {}
        if isinstance(coverage_matrix, dict) and coverage_matrix:
            status = coverage_matrix.get("overall_status") or coverage_matrix.get("coverage_status")
            score = coverage_matrix.get("overall_score")
            lines.append(f"Coverage matrix: status={status}, score={score}")
            gaps = coverage_matrix.get("blocking_gaps", []) if isinstance(coverage_matrix.get("blocking_gaps", []), list) else []
            if gaps:
                lines.append("Top coverage gaps:")
                for gap in gaps[:3]:
                    if isinstance(gap, dict):
                        lines.append(f"- {gap.get('facet')} ({gap.get('status')}, basis={gap.get('basis')})")
            hypothesis_cells = [
                cell for cell in (coverage_matrix.get("cells") or [])
                if isinstance(cell, dict) and (cell.get("metadata") or {}).get("cell_type") == "hypothesis_required_evidence"
            ]
            if hypothesis_cells:
                lines.append("Hypothesis evidence requirement coverage:")
                for cell in hypothesis_cells[:3]:
                    meta = cell.get("metadata") or {}
                    missing = ",".join(str(item) for item in (cell.get("missing_fields") or [])[:4]) or "none"
                    relation_basis = meta.get("strongest_relation_basis") or "missing"
                    lines.append(f"- {meta.get('hypothesis_type') or cell.get('facet')} status={cell.get('status')} missing={missing} relation_basis={relation_basis}")

        query_attempts = reasoning_state.get("query_attempts", []) if isinstance(reasoning_state, dict) else []
        if isinstance(query_attempts, list) and query_attempts:
            latest_attempt = query_attempts[-1] if isinstance(query_attempts[-1], dict) else {}
            lines.append(
                "Latest query attempt: "
                f"class={latest_attempt.get('result_class')}, "
                f"covered={','.join(str(item) for item in (latest_attempt.get('covered_cells') or [])[:4]) or 'none'}, "
                f"remaining={','.join(str(item) for item in (latest_attempt.get('remaining_gaps') or [])[:4]) or 'none'}"
            )
            coverage_delta = latest_attempt.get("coverage_delta") if isinstance(latest_attempt.get("coverage_delta"), dict) else {}
            if coverage_delta:
                lines.append(
                    "Latest query coverage delta: "
                    f"new={','.join(str(item) for item in (coverage_delta.get('newly_covered_facets') or [])[:4]) or 'none'}, "
                    f"still_missing={','.join(str(item) for item in (coverage_delta.get('still_missing_facets') or [])[:4]) or 'none'}, "
                    f"score_delta={coverage_delta.get('score_delta')}"
                )
            diagnosis = latest_attempt.get("diagnosis") if isinstance(latest_attempt.get("diagnosis"), dict) else {}
            if diagnosis:
                lines.append(
                    "Latest query diagnosis: "
                    f"{diagnosis.get('diagnosis')} ({self._truncate(str(diagnosis.get('reason') or ''), 120)})"
                )
        retry_state = reasoning_state.get("retry_state", {}) if isinstance(reasoning_state, dict) else {}
        if isinstance(retry_state, dict) and retry_state:
            stop_reason = retry_state.get("stop_reason")
            last_decision = retry_state.get("last_decision") if isinstance(retry_state.get("last_decision"), dict) else {}
            if stop_reason or last_decision:
                lines.append(
                    "Retry state: "
                    f"decision={last_decision.get('action') or retry_state.get('action') or 'tracked'}, "
                    f"stop_reason={stop_reason or last_decision.get('stop_reason') or 'none'}"
                )
            if str(stop_reason or last_decision.get("stop_reason") or "").endswith("retry_budget_exhausted"):
                lines.append("Retry status: budget exhausted; remaining coverage gaps are telemetry limitations, not verdict authority.")
            degraded = retry_state.get("degraded_status") or retry_state.get("last_result_class")
            if degraded in {"manual_required", "approval_required", "blocked_by_policy", "backend_unavailable"}:
                lines.append(f"Retry degraded status: {degraded}; do not present missing coverage as successful evidence.")
            last_diagnosis = retry_state.get("last_diagnosis") if isinstance(retry_state.get("last_diagnosis"), dict) else {}
            if last_diagnosis:
                lines.append(f"Retry diagnosis: {last_diagnosis.get('diagnosis')} confidence={last_diagnosis.get('diagnosis_confidence') or 'low'} - {self._truncate(str(last_diagnosis.get('reason') or ''), 120)}")
            last_delta = retry_state.get("last_coverage_delta") if isinstance(retry_state.get("last_coverage_delta"), dict) else {}
            if last_delta:
                lines.append(
                    "Retry coverage delta: "
                    f"new={','.join(str(item) for item in (last_delta.get('newly_covered_facets') or [])[:4]) or 'none'}, "
                    f"still_missing={','.join(str(item) for item in (last_delta.get('still_missing_facets') or [])[:4]) or 'none'}"
                )
        query_eval = reasoning_state.get("last_query_result_evaluation", {}) if isinstance(reasoning_state, dict) else {}
        if isinstance(query_eval, dict) and query_eval:
            lines.append(
                "Query result evaluation: "
                f"class={query_eval.get('result_class')}, "
                f"remaining={','.join(str(item) for item in (query_eval.get('remaining_facets') or [])[:4]) or 'none'}"
            )

        agentic_explanation = (
            state.agentic_explanation
            if isinstance(getattr(state, "agentic_explanation", None), dict)
            else {}
        )
        root_cause = agentic_explanation.get("root_cause_assessment", {})
        if isinstance(root_cause, dict) and root_cause.get("summary"):
            lines.append(
                f"Root cause assessment: {self._truncate(str(root_cause.get('summary')), 220)}"
            )

        entity_state = (
            state.entity_state if isinstance(getattr(state, "entity_state", None), dict) else {}
        )
        entities = entity_state.get("entities", {}) if isinstance(entity_state.get("entities"), dict) else {}
        if entities:
            entity_summaries = []
            for entity in list(entities.values())[:5]:
                if not isinstance(entity, dict):
                    continue
                entity_summaries.append(f"{entity.get('type')}={entity.get('value')}")
            if entity_summaries:
                lines.append("Tracked entities: " + ", ".join(entity_summaries))

        open_questions = reasoning_state.get("open_questions", [])
        if isinstance(open_questions, list) and open_questions:
            lines.append("Open questions:")
            question_limit = 2 if is_chat_session and status == "sufficient_evidence" else 4
            for question in open_questions[:question_limit]:
                lines.append(f"- {question}")
        else:
            unresolved_questions = getattr(state, "unresolved_questions", None) or []
            if unresolved_questions:
                lines.append("Open questions:")
                for question in unresolved_questions[:4]:
                    lines.append(f"- {question}")

        lines.append("Hypotheses:")
        for raw_hypothesis in hypotheses[:3]:
            if not isinstance(raw_hypothesis, dict):
                continue
            statement = str(raw_hypothesis.get("statement") or "Unspecified hypothesis")
            confidence = float(raw_hypothesis.get("confidence", 0.0) or 0.0)
            status = str(raw_hypothesis.get("status") or "open")
            support_count = len(raw_hypothesis.get("supporting_evidence_refs", []) or [])
            contradict_count = len(raw_hypothesis.get("contradicting_evidence_refs", []) or [])
            origin = str(raw_hypothesis.get("origin") or "")
            hyp_type = str(raw_hypothesis.get("hypothesis_type") or raw_hypothesis.get("type") or "")
            reason_codes = ",".join(str(item) for item in (raw_hypothesis.get("reason_codes", []) or [])[:3])
            suffix = f", origin={origin}, type={hyp_type}" if origin or hyp_type else ""
            if reason_codes:
                suffix += f", reasons={reason_codes}"
            lines.append(
                f"- {statement} "
                f"(status={status}, confidence={confidence:.2f}, support={support_count}, contradict={contradict_count}{suffix})"
            )

        candidates = reasoning_state.get("candidate_hypotheses", []) if isinstance(reasoning_state, dict) else []
        if candidates:
            lines.append("Staged candidate hypotheses (non-authoritative; evidence gates decide promotion):")
            for candidate in candidates[:3]:
                if not isinstance(candidate, dict):
                    continue
                statement = self._truncate(str(candidate.get("statement") or "Candidate hypothesis"), 180)
                status = str(candidate.get("promotion_status") or (candidate.get("verification", {}) or {}).get("status") or "staged")
                required = []
                for contract in candidate.get("required_evidence", []) or []:
                    if isinstance(contract, dict):
                        required.extend(str(item) for item in contract.get("required_observation_types", []) or [])
                reason_codes = ",".join(str(item) for item in (candidate.get("reason_codes", []) or [])[:3])
                lines.append(f"- {statement} (status={status}, required={','.join(required[:3]) or 'fresh evidence'}, reasons={reason_codes or 'none'})")
        events = reasoning_state.get("hypothesis_events", []) if isinstance(reasoning_state, dict) else []
        if events:
            latest = events[-1]
            if isinstance(latest, dict):
                lines.append("Latest hypothesis event: " + self._truncate(str(latest.get("summary") or latest.get("event_type") or ""), 180))
        return "\n".join(lines)

    def _provider_context_data(self, state: Any) -> Dict[str, str]:
        investigation_plan = getattr(state, "investigation_plan", {}) if isinstance(getattr(state, "investigation_plan", {}), dict) else {}
        agentic_explanation = getattr(state, "agentic_explanation", {}) if isinstance(getattr(state, "agentic_explanation", {}), dict) else {}
        missing_evidence = [str(item) for item in agentic_explanation.get("missing_evidence", []) if str(item).strip()]
        return {
            "active_specialist": str(getattr(state, "active_specialist", "") or getattr(state, "agent_profile_id", "") or "").strip(),
            "investigation_lane": str(investigation_plan.get("lane") or "").strip(),
            "incident_type": str(investigation_plan.get("incident_type") or "").strip(),
            "memory_scope": str(
                getattr(state, "chat_context_restored_memory_scope", None)
                or getattr(state, "restored_memory_scope", None)
                or ""
            ).strip(),
            "top_evidence_gap": missing_evidence[0] if missing_evidence else "",
        }

    def _provider_context_block(self, state: Any) -> str:
        provider_context = self._provider_context_data(state)

        lines: List[str] = []
        if provider_context["active_specialist"]:
            lines.append(f"Active specialist: {provider_context['active_specialist']}")
        if provider_context["investigation_lane"]:
            lines.append(f"Investigation lane: {provider_context['investigation_lane']}")
        if provider_context["incident_type"]:
            lines.append(f"Incident type: {provider_context['incident_type']}")
        if provider_context["memory_scope"]:
            lines.append(f"Restored memory scope: {provider_context['memory_scope']}")
        if provider_context["top_evidence_gap"]:
            lines.append(f"Top evidence gap: {provider_context['top_evidence_gap']}")
        return "\n".join(lines) if lines else "(no additional provider context)"

    def build_findings_block_from_context_pack(self, context_pack: Dict[str, Any]) -> str:
        sections = context_pack.get("sections", {}) if isinstance(context_pack, dict) else {}
        briefs = sections.get("evidence_briefs", []) if isinstance(sections, dict) else []
        findings = sections.get("selected_findings", []) if isinstance(sections, dict) else []
        lines = ["Context pack selected evidence (non-authoritative orchestration metadata):"]
        for brief in briefs[:10] if isinstance(briefs, list) else []:
            if not isinstance(brief, dict):
                continue
            ref = brief.get("evidence_ref", {}) if isinstance(brief.get("evidence_ref"), dict) else {}
            tool = ref.get("tool_name") or brief.get("authority") or "context"
            reason = brief.get("selected_reason") or brief.get("reason") or "selected"
            lines.append(f"- {tool}: {self._truncate(str(brief.get('summary') or ''), 220)} (reason={self._truncate(str(reason), 100)}, authority={brief.get('authority')})")
        if len(lines) == 1:
            for finding in findings[:8] if isinstance(findings, list) else []:
                if isinstance(finding, dict):
                    lines.append(f"- {self._truncate(str(finding.get('summary') or finding.get('tool') or finding.get('type') or 'finding'), 220)}")
        return "\n".join(lines) if len(lines) > 1 else "(none yet)"

    def build_reasoning_block_from_context_pack(self, context_pack: Dict[str, Any], *, legacy_reasoning_block: str = "") -> str:
        sections = context_pack.get("sections", {}) if isinstance(context_pack, dict) else {}
        budget = context_pack.get("budget_report", {}) if isinstance(context_pack, dict) else {}
        ledger_id = context_pack.get("ledger_id") if isinstance(context_pack, dict) else ""
        lines = [
            "AISA context orchestration pack:",
            "- Authority policy: deterministic evidence, scoring, and root-cause gates remain authoritative; context summaries are orchestration metadata.",
            f"- Context ledger: {ledger_id or 'none'}; estimated_tokens={budget.get('estimated_total')}; over_budget={budget.get('over_budget')}",
        ]
        decision = sections.get("deterministic_decision", {}) if isinstance(sections, dict) else {}
        if isinstance(decision, dict) and decision:
            lines.append(f"- Deterministic decision snapshot: verdict={decision.get('verdict')}, score={decision.get('score')}, severity={decision.get('severity')}, source={decision.get('source')}")
        root_cause = sections.get("root_cause", {}) if isinstance(sections, dict) else {}
        if isinstance(root_cause, dict) and root_cause:
            lines.append(f"- Root-cause context (non-authoritative explanation): status={root_cause.get('status')}, summary={self._truncate(str(root_cause.get('summary') or root_cause.get('primary_root_cause') or ''), 220)}")
        gaps = sections.get("coverage_gaps", []) if isinstance(sections, dict) else []
        if gaps:
            lines.append("Top coverage/missing-evidence gaps:")
            for gap in gaps[:4]:
                if isinstance(gap, dict):
                    lines.append(f"- {gap.get('facet') or gap.get('summary')} status={gap.get('status')} basis={gap.get('basis')}")
        hypotheses = sections.get("hypotheses", []) if isinstance(sections, dict) else []
        if hypotheses:
            lines.append("Top hypotheses with evidence refs/reason codes:")
            for hyp in hypotheses[:4]:
                if not isinstance(hyp, dict):
                    continue
                refs = len(hyp.get("evidence_refs", []) or hyp.get("supporting_evidence_refs", []) or [])
                contrad = len(hyp.get("contradiction_refs", []) or hyp.get("contradicting_evidence_refs", []) or [])
                reasons = ",".join(str(item) for item in (hyp.get("reason_codes", []) or [])[:4]) or "none"
                lines.append(f"- {self._truncate(str(hyp.get('statement') or hyp.get('label') or hyp.get('id')), 180)} (status={hyp.get('status')}, confidence={hyp.get('confidence')}, refs={refs}, contradict={contrad}, reasons={reasons}, authority={hyp.get('authority')})")
        entities = sections.get("entities", []) if isinstance(sections, dict) else []
        if entities:
            lines.append("Selected entities: " + ", ".join(str(item.get("id") or item.get("label") or item.get("value")) for item in entities[:8] if isinstance(item, dict)))
        if legacy_reasoning_block:
            lines.append("Legacy reasoning fallback excerpt:")
            lines.append(self._truncate(legacy_reasoning_block, 1200))
        return "\n".join(lines)

    def build_think_payload(
        self,
        *,
        state: Any,
        tools_block: str,
        findings_block: str,
        response_style_block: str,
        chat_decision_block: str,
        reasoning_block: str,
        profile_block: str,
        workflow_block: str,
        playbooks_block: str,
        model_only_chat: bool,
        has_native_tools: bool,
        context_pack: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        provider_context = self._provider_context_data(state)
        provider_context_block = self._provider_context_block(state)
        rendered_context_pack = context_pack if isinstance(context_pack, dict) else None
        if rendered_context_pack:
            findings_block = self.build_findings_block_from_context_pack(rendered_context_pack)
            reasoning_block = self.build_reasoning_block_from_context_pack(rendered_context_pack, legacy_reasoning_block=reasoning_block)

        if model_only_chat:
            system_prompt = _CHAT_DIRECT_ANSWER_PROMPT.format(
                goal=state.goal,
                findings_block=findings_block,
                response_style_block=response_style_block,
                chat_decision_block=chat_decision_block,
                reasoning_block=reasoning_block,
                provider_context_block=provider_context_block,
                profile_block=profile_block,
                workflow_block=workflow_block,
                playbooks_block=playbooks_block,
            )
        elif has_native_tools:
            system_prompt = _SYSTEM_PROMPT.format(
                goal=state.goal,
                findings_block=findings_block,
                response_style_block=response_style_block,
                chat_decision_block=chat_decision_block,
                reasoning_block=reasoning_block,
                provider_context_block=provider_context_block,
                profile_block=profile_block,
                workflow_block=workflow_block,
                playbooks_block=playbooks_block,
            )
        else:
            system_prompt = _SYSTEM_PROMPT_NO_TOOLS.format(
                tools_block=tools_block,
                goal=state.goal,
                findings_block=findings_block,
                response_style_block=response_style_block,
                chat_decision_block=chat_decision_block,
                reasoning_block=reasoning_block,
                provider_context_block=provider_context_block,
                profile_block=profile_block,
                workflow_block=workflow_block,
                playbooks_block=playbooks_block,
            )

        prompt_mode = (
            "direct_answer"
            if model_only_chat
            else ("native_tooling" if has_native_tools else "json_tool_decision")
        )
        user_prompt = (
            "Continue the AISA investigation and decide the next best action."
            if not model_only_chat
            else "Answer the analyst directly from the current structured investigation context."
        )
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        context_pack_summary = None
        if rendered_context_pack and isinstance(rendered_context_pack.get("summary"), dict):
            context_pack_summary = rendered_context_pack.get("summary")
        if rendered_context_pack and context_pack_summary is None:
            context_pack_summary = {
                "pack_id": rendered_context_pack.get("pack_id"),
                "ledger_id": rendered_context_pack.get("ledger_id"),
                "objective": rendered_context_pack.get("objective"),
                "authority_policy": rendered_context_pack.get("authority_policy"),
                "token_estimate": rendered_context_pack.get("token_estimate"),
                "authoritative_for_verdict": False,
            }
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "messages": messages,
            "prompt_mode": prompt_mode,
            "provider_context_block": provider_context_block,
            "uses_native_tools": bool(has_native_tools and not model_only_chat),
            "model_only_chat": bool(model_only_chat),
            "prompt_envelope": {
                "system_instructions": (
                    "You are a Blue Team Security Agent. You investigate security threats autonomously."
                ),
                "policy_instructions": {
                    "response_style": response_style_block,
                    "chat_decision": chat_decision_block,
                    "profile_guidance": profile_block,
                    "workflow_guidance": workflow_block,
                    "playbooks_guidance": playbooks_block,
                    "tooling_mode": "native_tools" if has_native_tools else ("direct_answer" if model_only_chat else "json_tools"),
                },
                "investigation_context": {
                    "goal": str(getattr(state, "goal", "") or ""),
                    "findings": findings_block,
                    "reasoning": reasoning_block,
                    "provider_context": provider_context,
                    "provider_context_block": provider_context_block,
                    "tools_block": tools_block,
                    "prompt_mode": prompt_mode,
                    "context_pack_summary": context_pack_summary,
                    "context_ledger_id": rendered_context_pack.get("ledger_id") if rendered_context_pack else None,
                    "context_budget_summary": rendered_context_pack.get("budget_report") if rendered_context_pack else None,
                    "context_authority_policy": rendered_context_pack.get("authority_policy") if rendered_context_pack else None,
                },
                "user_intent": {
                    "prompt": user_prompt,
                    "mode": prompt_mode,
                },
            },
            "context_pack": rendered_context_pack,
            "context_pack_summary": context_pack_summary,
            "context_ledger": rendered_context_pack.get("ledger") if rendered_context_pack else None,
            "context_ledger_id": rendered_context_pack.get("ledger_id") if rendered_context_pack else None,
            "context_budget_summary": rendered_context_pack.get("budget_report") if rendered_context_pack else None,
        }

    def build_summary_payload(
        self,
        *,
        state: Any,
        response_style_block: str,
        reasoning_block: str,
        step_count: int,
        findings_json: str,
        context_pack: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        provider_context = self._provider_context_data(state)
        provider_context_block = self._provider_context_block(state)
        prompt_mode = "summary_explanation"
        rendered_context_pack = context_pack if isinstance(context_pack, dict) else None
        context_pack_summary = None
        if rendered_context_pack:
            compact_reasoning = self.build_reasoning_block_from_context_pack(
                rendered_context_pack,
                legacy_reasoning_block=reasoning_block,
            )
            compact_findings = self.build_findings_block_from_context_pack(rendered_context_pack)
            context_pack_summary = rendered_context_pack.get("summary") if isinstance(rendered_context_pack.get("summary"), dict) else {
                "pack_id": rendered_context_pack.get("pack_id"),
                "ledger_id": rendered_context_pack.get("ledger_id"),
                "objective": rendered_context_pack.get("objective"),
                "authority_policy": rendered_context_pack.get("authority_policy"),
                "token_estimate": rendered_context_pack.get("token_estimate"),
                "authoritative_for_verdict": False,
            }
            summary_notice = "\n".join([
                "Summary context pack constraints:",
                "- Treat context ledger, retrieval scores, sub-investigation summaries, and compressed context as non-authoritative orchestration metadata.",
                "- Preserve evidence refs, do-not-forget constraints, coverage gaps, retry status, and hypothesis essentials from the context pack when available.",
                "- deterministic AISA evidence, scoring, and root-cause gates remain authoritative; do not promote context summaries into verdict authority.",
                f"- Context ledger: {rendered_context_pack.get('ledger_id') or 'none'}; budget={rendered_context_pack.get('budget_report', {})}",
            ])
            reasoning_block = compact_reasoning + "\n" + summary_notice
            findings_json = compact_findings + "\n\nCompact selected context pack summary:\n" + json.dumps(context_pack_summary, default=str)
        prompt = _SUMMARY_PROMPT.format(
            goal=str(getattr(state, "goal", "") or ""),
            response_style_block=response_style_block,
            reasoning_block=reasoning_block,
            provider_context_block=provider_context_block,
            step_count=step_count,
            findings_json=findings_json[:4000],
        )
        return {
            "prompt": prompt,
            "prompt_mode": prompt_mode,
            "provider_context_block": provider_context_block,
            "prompt_envelope": {
                "system_instructions": (
                    "You are a Blue Team Security Agent. Summarise investigation results for analyst consumption."
                ),
                "policy_instructions": {
                    "response_style": response_style_block,
                    "tooling_mode": "summary_explanation",
                },
                "investigation_context": {
                    "goal": str(getattr(state, "goal", "") or ""),
                    "reasoning": reasoning_block,
                    "provider_context": provider_context,
                    "provider_context_block": provider_context_block,
                    "step_count": int(step_count),
                    "findings_json": findings_json[:4000],
                    "prompt_mode": prompt_mode,
                    "context_pack_summary": context_pack_summary,
                    "context_ledger_id": rendered_context_pack.get("ledger_id") if rendered_context_pack else None,
                    "context_budget_summary": rendered_context_pack.get("budget_report") if rendered_context_pack else None,
                    "context_authority_policy": rendered_context_pack.get("authority_policy") if rendered_context_pack else None,
                },
                "user_intent": {
                    "prompt": "Summarize the investigation for the analyst using the current structured evidence.",
                    "mode": prompt_mode,
                },
            },
            "context_pack": rendered_context_pack,
            "context_pack_summary": context_pack_summary,
            "context_ledger": rendered_context_pack.get("ledger") if rendered_context_pack else None,
            "context_ledger_id": rendered_context_pack.get("ledger_id") if rendered_context_pack else None,
            "context_budget_summary": rendered_context_pack.get("budget_report") if rendered_context_pack else None,
        }

    def build_summary_prompt(
        self,
        *,
        goal: str,
        response_style_block: str,
        reasoning_block: str,
        step_count: int,
        findings_json: str,
        provider_context_block: str = "(no additional provider context)",
    ) -> str:
        state = type(
            "SummaryPromptState",
            (),
            {
                "goal": goal,
                "active_specialist": "",
                "agent_profile_id": "",
                "investigation_plan": {},
                "agentic_explanation": {},
                "chat_context_restored_memory_scope": "",
                "restored_memory_scope": "",
            },
        )()
        payload = self.build_summary_payload(
            state=state,
            response_style_block=response_style_block,
            reasoning_block=reasoning_block,
            step_count=step_count,
            findings_json=findings_json,
        )
        if provider_context_block != "(no additional provider context)":
            return _SUMMARY_PROMPT.format(
                goal=goal,
                response_style_block=response_style_block,
                reasoning_block=reasoning_block,
                provider_context_block=provider_context_block,
                step_count=step_count,
                findings_json=findings_json[:4000],
            )
        return str(payload["prompt"])
