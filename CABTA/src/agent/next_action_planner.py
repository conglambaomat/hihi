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
        resume_strategy = str(investigation_plan.get("resume_strategy") or "").strip().lower()
        resume_signals = investigation_plan.get("resume_signals", []) if isinstance(investigation_plan, dict) else []
        latest_resume_signal = resume_signals[-1] if isinstance(resume_signals, list) and resume_signals else {}
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
        triage_contract_questions = self._triage_contract_questions(investigation_plan)
        question_bundle = [*open_questions, *missing_evidence, *triage_contract_questions]
        contract_gate = self._triage_contract_gate(investigation_plan, state)
        if contract_gate:
            question_bundle = [*question_bundle, *contract_gate["question_bundle"]]
        plan_signals = self._plan_signals(investigation_plan)
        authoritative_outcome = self._resolve_authoritative_outcome(state)

        def _with_meta(payload: Dict[str, Any], decision_source: str) -> Dict[str, Any]:
            meta = {
                **payload,
                "decision_source": decision_source,
                "plan_lane": plan_lane,
                "focus": focus,
                "question_bundle": list(question_bundle),
                "resume_strategy": resume_strategy or None,
                "resume_signal": latest_resume_signal if isinstance(latest_resume_signal, dict) else {},
            }
            if contract_gate:
                meta["contract_gate"] = dict(contract_gate)
            return meta

        if not state.findings:
            signaled_bootstrap = self._decision_from_plan_signal(
                state,
                plan_signals,
                excluded=excluded,
                latest_message=latest_message,
                focus=focus,
                question_bundle=question_bundle,
                require_no_findings=True,
            )
            if signaled_bootstrap is not None:
                return _with_meta(signaled_bootstrap["payload"], signaled_bootstrap["decision_source"])

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
            and resume_strategy != "fresh_evidence"
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

        if contract_gate is not None:
            gating_signal = self._decision_from_plan_signal(
                state,
                plan_signals,
                excluded=excluded,
                latest_message=latest_message,
                focus=focus,
                question_bundle=question_bundle,
                require_no_findings=False,
                resume_strategy=resume_strategy,
                signal_types=set(contract_gate.get("signal_types", [])),
            )
            if gating_signal is not None:
                return _with_meta(gating_signal["payload"], f"contract_gate_{contract_gate.get('contract_id', 'generic')}")
            return None

        signaled_follow_up = self._decision_from_plan_signal(
            state,
            plan_signals,
            excluded=excluded,
            latest_message=latest_message,
            focus=focus,
            question_bundle=question_bundle,
            require_no_findings=False,
            resume_strategy=resume_strategy,
        )
        if signaled_follow_up is not None:
            return _with_meta(signaled_follow_up["payload"], signaled_follow_up["decision_source"])

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

    def _triage_contract_questions(self, investigation_plan: Dict[str, Any]) -> List[str]:
        contracts = investigation_plan.get("triage_contracts", []) if isinstance(investigation_plan, dict) else []
        questions: List[str] = []
        seen = set()
        for contract in contracts:
            if not isinstance(contract, dict):
                continue
            for item in contract.get("analyst_questions", []):
                question = str(item).strip()
                if not question:
                    continue
                key = question.lower()
                if key in seen:
                    continue
                seen.add(key)
                questions.append(question)
        return questions[:6]

    def _plan_signals(self, investigation_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        signals = investigation_plan.get("next_action_signals", []) if isinstance(investigation_plan, dict) else []
        normalized: List[Dict[str, Any]] = []
        for item in signals:
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool") or "").strip()
            reason = str(item.get("reason") or "").strip()
            if not tool or not reason:
                continue
            try:
                priority = int(item.get("priority", 0))
            except (TypeError, ValueError):
                priority = 0
            normalized.append(
                {
                    "tool": tool,
                    "reason": reason,
                    "priority": priority,
                    "signal_type": str(item.get("signal_type") or "generic").strip() or "generic",
                }
            )
        normalized.sort(key=lambda item: (-item["priority"], item["tool"], item["reason"]))
        return normalized

    def _decision_from_plan_signal(
        self,
        state: Any,
        plan_signals: List[Dict[str, Any]],
        *,
        excluded: set,
        latest_message: str,
        focus: Optional[str],
        question_bundle: List[str],
        require_no_findings: bool,
        resume_strategy: str = "",
        signal_types: Optional[set] = None,
    ) -> Optional[Dict[str, Any]]:
        if require_no_findings and state.findings:
            return None
        allowed_signal_types = {str(item).strip() for item in (signal_types or set()) if str(item).strip()}
        for signal in plan_signals:
            tool = str(signal.get("tool") or "").strip()
            if allowed_signal_types and str(signal.get("signal_type") or "").strip() not in allowed_signal_types:
                continue
            if not tool or tool in excluded or self._get_tool(tool) is None or self._has_tool_result(state, tool):
                continue
            if resume_strategy == "fresh_evidence" and tool == "correlate_findings":
                continue
            payload = self._payload_for_signaled_tool(
                state,
                tool=tool,
                signal=signal,
                latest_message=latest_message,
                focus=focus,
                question_bundle=question_bundle,
            )
            if payload is None:
                continue
            return {
                "payload": payload,
                "decision_source": f"plan_signal_{signal.get('signal_type', 'generic')}",
            }
        return None

    def _payload_for_signaled_tool(
        self,
        state: Any,
        *,
        tool: str,
        signal: Dict[str, Any],
        latest_message: str,
        focus: Optional[str],
        question_bundle: List[str],
    ) -> Optional[Dict[str, Any]]:
        reason = f"Plan-guided next action: {signal.get('reason')}"
        if tool == "search_logs":
            log_request = self._build_reasoning_search_request(state, question_bundle)
            return {
                "action": "use_tool",
                "tool": tool,
                "params": {
                    "query": log_request["query"],
                    "timerange": log_request["timerange"],
                },
                "reasoning": reason + " " + str(log_request.get("reasoning") or "").strip(),
            }
        if tool == "investigate_ioc":
            resolved_focus = str(focus or "").strip()
            if not resolved_focus:
                guessed = self._guess_tool_params(latest_message or state.goal)
                resolved_focus = str(guessed.get("ioc") or guessed.get("file_path") or "").strip()
            if not resolved_focus:
                return None
            return {
                "action": "use_tool",
                "tool": tool,
                "params": {"ioc": resolved_focus},
                "reasoning": reason,
            }
        if tool in {"analyze_email", "analyze_malware"}:
            guessed = self._guess_tool_params(latest_message or state.goal)
            file_path = str(guessed.get("file_path") or guessed.get("ioc") or "").strip()
            if not file_path:
                return None
            return {
                "action": "use_tool",
                "tool": tool,
                "params": {"file_path": file_path},
                "reasoning": reason,
            }
        return None

    def _triage_contract_gate(self, investigation_plan: Dict[str, Any], state: Any) -> Optional[Dict[str, Any]]:
        contracts = investigation_plan.get("triage_contracts", []) if isinstance(investigation_plan, dict) else []
        findings = state.findings if isinstance(getattr(state, "findings", []), list) else []
        latest_tools = {
            str(item.get("tool") or "").strip()
            for item in findings
            if isinstance(item, dict) and item.get("type") == "tool_result"
        }
        for contract in contracts:
            if not isinstance(contract, dict):
                continue
            contract_id = str(contract.get("contract_id") or "").strip()
            if contract_id == "fortigate_outbound_monitoring" and "search_logs" not in latest_tools:
                return {
                    "contract_id": contract_id,
                    "signal_types": {"fortigate_outbound", "evidence_gap", "entity_linkage"},
                    "question_bundle": list(contract.get("analyst_questions", []))[:3],
                }
            if contract_id == "windows_logon_monitoring" and "search_logs" not in latest_tools:
                return {
                    "contract_id": contract_id,
                    "signal_types": {"windows_logon", "evidence_gap", "entity_linkage"},
                    "question_bundle": list(contract.get("analyst_questions", []))[:3],
                }
            if contract_id == "phishing_email_triage" and "analyze_email" not in latest_tools:
                return {
                    "contract_id": contract_id,
                    "signal_types": {"evidence_gap", "hypothesis"},
                    "question_bundle": list(contract.get("analyst_questions", []))[:3],
                }
            if contract_id == "ioc_triage" and "investigate_ioc" not in latest_tools:
                return {
                    "contract_id": contract_id,
                    "signal_types": {"plan_pivot", "evidence_gap", "hypothesis"},
                    "question_bundle": list(contract.get("analyst_questions", []))[:3],
                }
        return None