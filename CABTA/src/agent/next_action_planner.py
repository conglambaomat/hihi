"""Reasoning-guided next-action planning for CABTA agent sessions."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


class NextActionPlanner:
    """Plan additive, reasoning-guided next actions without owning AgentLoop state."""

    def __init__(
        self,
        *,
        get_tool: Callable[[str], Any],
        has_tool_result: Callable[[Any, str], bool],
        guess_first_tool: Callable[[str], str],
        guess_tool_params: Callable[[str], Dict[str, Any]],
        latest_analyst_message: Callable[[Any], str],
        latest_focus_candidate: Callable[[Any], Optional[str]],
        resolve_authoritative_outcome: Callable[[Any], Optional[Dict[str, Any]]],
        simple_chat_has_strong_evidence: Callable[[Any], bool],
        looks_like_artifact_submission: Callable[[Optional[str]], bool],
        build_reasoning_search_request: Callable[[Any, List[str]], Dict[str, Any]],
    ) -> None:
        self._get_tool = get_tool
        self._has_tool_result = has_tool_result
        self._guess_first_tool = guess_first_tool
        self._guess_tool_params = guess_tool_params
        self._latest_analyst_message = latest_analyst_message
        self._latest_focus_candidate = latest_focus_candidate
        self._resolve_authoritative_outcome = resolve_authoritative_outcome
        self._simple_chat_has_strong_evidence = simple_chat_has_strong_evidence
        self._looks_like_artifact_submission = looks_like_artifact_submission
        self._build_reasoning_search_request = build_reasoning_search_request

    def reasoning_guided_next_action(
        self,
        state: Any,
        *,
        exclude_tools: Optional[set] = None,
    ) -> Optional[Dict[str, Any]]:
        excluded = {str(item) for item in (exclude_tools or set())}
        investigation_plan = state.investigation_plan if isinstance(state.investigation_plan, dict) else {}
        plan_lane = str(investigation_plan.get("lane") or "").strip().lower()
        reasoning_state = state.reasoning_state if isinstance(state.reasoning_state, dict) else {}
        agentic_explanation = state.agentic_explanation if isinstance(state.agentic_explanation, dict) else {}
        reasoning_status = str(reasoning_state.get("status") or "")
        latest_message = self._latest_analyst_message(state)
        focus = self._latest_focus_candidate(state)
        open_questions = [
            str(item).strip()
            for item in reasoning_state.get("open_questions", [])
            if str(item).strip()
        ]
        missing_evidence = [
            str(item).strip()
            for item in agentic_explanation.get("missing_evidence", []) or reasoning_state.get("missing_evidence", [])
            if str(item).strip()
        ]
        question_bundle = [*open_questions, *missing_evidence]
        authoritative_outcome = self._resolve_authoritative_outcome(state)

        def _with_meta(payload: Dict[str, Any], decision_source: str) -> Dict[str, Any]:
            return {
                **payload,
                "decision_source": decision_source,
                "plan_lane": plan_lane,
                "focus": focus,
                "question_bundle": list(question_bundle),
            }

        if not state.findings:
            if plan_lane == "log_identity" and "search_logs" not in excluded and self._get_tool("search_logs") is not None:
                log_request = self._build_reasoning_search_request(state, question_bundle)
                return _with_meta(
                    {
                        "action": "use_tool",
                        "tool": "search_logs",
                        "params": {
                            "query": log_request["query"],
                            "timerange": log_request["timerange"],
                        },
                        "reasoning": "Plan-guided bootstrap: begin with a focused log hunt for identity or session evidence. "
                        + log_request["reasoning"],
                    },
                    "plan_bootstrap_log_identity",
                )
            if plan_lane == "email" and "analyze_email" not in excluded and self._get_tool("analyze_email") is not None:
                guessed = self._guess_tool_params(latest_message or state.goal)
                file_path = str(guessed.get("file_path") or guessed.get("ioc") or "").strip()
                if file_path:
                    return _with_meta(
                        {
                            "action": "use_tool",
                            "tool": "analyze_email",
                            "params": {"file_path": file_path},
                            "reasoning": "Plan-guided bootstrap: analyze the submitted email artifact before deeper pivots.",
                        },
                        "plan_bootstrap_email",
                    )
            if plan_lane == "file" and "analyze_malware" not in excluded and self._get_tool("analyze_malware") is not None:
                guessed = self._guess_tool_params(latest_message or state.goal)
                file_path = str(guessed.get("file_path") or guessed.get("ioc") or "").strip()
                if file_path:
                    return _with_meta(
                        {
                            "action": "use_tool",
                            "tool": "analyze_malware",
                            "params": {"file_path": file_path},
                            "reasoning": "Plan-guided bootstrap: analyze the submitted file or sample before enrichment.",
                        },
                        "plan_bootstrap_file",
                    )

        if (
            state.findings
            and "correlate_findings" not in excluded
            and self._get_tool("correlate_findings") is not None
            and not self._has_tool_result(state, "correlate_findings")
            and (
                reasoning_status == "sufficient_evidence"
                or authoritative_outcome is not None
                or self._simple_chat_has_strong_evidence(state)
            )
        ):
            return _with_meta(
                {
                    "action": "use_tool",
                    "tool": "correlate_findings",
                    "params": {"findings": state.findings[-10:]},
                    "reasoning": "Reasoning-guided pivot: enough evidence exists to correlate before answering.",
                },
                "correlate_before_answer",
            )

        guessed_tool = self._guess_first_tool(latest_message or state.goal)
        guessed_params = self._guess_tool_params(latest_message or state.goal)
        if (
            guessed_tool == "investigate_ioc"
            and "investigate_ioc" not in excluded
            and self._get_tool("investigate_ioc") is not None
            and not self._has_tool_result(state, "investigate_ioc")
            and focus
        ):
            return _with_meta(
                {
                    "action": "use_tool",
                    "tool": "investigate_ioc",
                    "params": {"ioc": focus},
                    "reasoning": "Reasoning-guided pivot: start from the primary observable tracked in the reasoning state.",
                },
                "focus_first_ioc",
            )

        if guessed_tool in {"analyze_email", "analyze_malware"} and guessed_tool not in excluded:
            if self._get_tool(guessed_tool) is not None:
                file_path = str(guessed_params.get("file_path") or guessed_params.get("ioc") or "").strip()
                if file_path:
                    return _with_meta(
                        {
                            "action": "use_tool",
                            "tool": guessed_tool,
                            "params": {"file_path": file_path},
                            "reasoning": "Reasoning-guided pivot: analyze the primary submitted artifact before enrichment.",
                        },
                        "artifact_first_analysis",
                    )

        needs_log_pivot = any(
            any(keyword in question.lower() for keyword in ("host", "user", "session", "process", "telemetry", "endpoint", "log"))
            for question in question_bundle
        )
        if (
            state.findings
            and needs_log_pivot
            and "search_logs" not in excluded
            and self._get_tool("search_logs") is not None
            and not self._has_tool_result(state, "search_logs")
        ):
            log_request = self._build_reasoning_search_request(state, question_bundle)
            return _with_meta(
                {
                    "action": "use_tool",
                    "tool": "search_logs",
                    "params": {
                        "query": log_request["query"],
                        "timerange": log_request["timerange"],
                    },
                    "reasoning": "Reasoning-guided pivot: open questions point to host/user/session telemetry. "
                    + log_request["reasoning"],
                },
                "telemetry_gap_log_pivot",
            )

        if (
            self._looks_like_artifact_submission(latest_message)
            and "extract_iocs" not in excluded
            and self._get_tool("extract_iocs") is not None
            and not self._has_tool_result(state, "extract_iocs")
        ):
            return _with_meta(
                {
                    "action": "use_tool",
                    "tool": "extract_iocs",
                    "params": {"text": latest_message},
                    "reasoning": "Reasoning-guided pivot: extract observables from the submitted artifact before deeper pivots.",
                },
                "artifact_observable_extraction",
            )

        return None