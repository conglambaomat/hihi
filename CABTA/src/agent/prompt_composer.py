"""Prompt composition helpers for CABTA agent investigations."""

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
2. For IOC investigations: call investigate_ioc first, then use MCP tools like osint-tools.whois_lookup, network-analysis.geoip_lookup, threat-intel-free.threatfox_ioc_lookup for deeper analysis.
3. For file analysis: call analyze_malware first, then use MCP tools like remnux.pe_analyze, flare.strings_analysis, remnux.yara_scan, forensics-tools.file_metadata for deeper analysis.
4. For email analysis: call analyze_email first, then use MCP tools like osint-tools.email_security_check, free-osint.openphish_lookup for deeper analysis.
5. After gathering evidence, call correlate_findings to produce the final verdict.
6. Only write a final text answer (no tool call) AFTER you have gathered real evidence from at least 2 tools.
7. When calling a tool, ONLY pass the tool's own parameters (e.g. {{"ioc": "8.8.8.8"}}). Do NOT include extra keys like "action", "reasoning", or "tool" in the arguments.
8. Use DIFFERENT tools each step. Never call the same tool with the same parameters twice.
9. For quick analyst chat questions, prefer the highest-value pivots first and stop honestly once the evidence is sufficient. Avoid low-value manual or auth-required pivots unless the current evidence is still insufficient.

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
            lines.append(
                f"- {statement} "
                f"(status={status}, confidence={confidence:.2f}, support={support_count}, contradict={contradict_count})"
            )
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
    ) -> Dict[str, Any]:
        provider_context = self._provider_context_data(state)
        provider_context_block = self._provider_context_block(state)

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
            "Continue the CABTA investigation and decide the next best action."
            if not model_only_chat
            else "Answer the analyst directly from the current structured investigation context."
        )
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
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
                },
                "user_intent": {
                    "prompt": user_prompt,
                    "mode": prompt_mode,
                },
            },
        }

    def build_summary_payload(
        self,
        *,
        state: Any,
        response_style_block: str,
        reasoning_block: str,
        step_count: int,
        findings_json: str,
    ) -> Dict[str, Any]:
        provider_context = self._provider_context_data(state)
        provider_context_block = self._provider_context_block(state)
        prompt_mode = "summary_explanation"
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
                },
                "user_intent": {
                    "prompt": "Summarize the investigation for the analyst using the current structured evidence.",
                    "mode": prompt_mode,
                },
            },
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
