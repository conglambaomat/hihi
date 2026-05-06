"""Reasoning-guided next-action planning for AISA agent sessions."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .capability_resolver import CapabilityResolver
from .log_query_coverage import build_query_fingerprint
from .retry import BacktrackingEngine, RetryPolicy, ToolResultClassifier


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
        retry_policy: Optional[RetryPolicy] = None,
        backtracking_engine: Optional[BacktrackingEngine] = None,
        tool_result_classifier: Optional[ToolResultClassifier] = None,
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
        self._retry_policy = retry_policy or RetryPolicy()
        self._backtracking_engine = backtracking_engine or BacktrackingEngine()
        self._tool_result_classifier = tool_result_classifier or ToolResultClassifier()
        self._capability_resolver = CapabilityResolver(get_tool=get_tool)

    def _forbidden_fallbacks(self, reasoning_state: Dict[str, Any]) -> set:
        if not isinstance(reasoning_state, dict):
            return set()
        soc_task = reasoning_state.get("soc_task_state", {}) if isinstance(reasoning_state.get("soc_task_state"), dict) else {}
        plan = soc_task.get("capability_plan", {}) if isinstance(soc_task.get("capability_plan"), dict) else reasoning_state.get("capability_plan", {})
        forbidden = list(plan.get("forbidden_fallbacks", []) if isinstance(plan, dict) else [])
        compiled = soc_task.get("compiled_input", {}) if isinstance(soc_task.get("compiled_input"), dict) else reasoning_state.get("compiled_input", {})
        if isinstance(compiled, dict) and compiled.get("input_kind") == "soc_alert_text":
            forbidden.extend(["file.analyze.static", "email.analyze", "email.parse.inline"])
        tool_to_cap = {"analyze_malware": "file.analyze.static", "analyze_email": "email.analyze"}
        return {str(item) for item in forbidden if str(item)} | {tool for tool, cap in tool_to_cap.items() if cap in forbidden}

    def _is_forbidden(self, capability: str = "", tool: str = "", forbidden: Optional[set] = None) -> bool:
        forbidden = forbidden or set()
        return bool((capability and capability in forbidden) or (tool and tool in forbidden))

    def _decision_from_soc_task_state(self, reasoning_state: Dict[str, Any], *, excluded: set) -> Optional[Dict[str, Any]]:
        soc_task = reasoning_state.get("soc_task_state", {}) if isinstance(reasoning_state, dict) else {}
        actions = soc_task.get("actions", []) if isinstance(soc_task, dict) else []
        forbidden = self._forbidden_fallbacks(reasoning_state)
        for action in actions or []:
            if not isinstance(action, dict):
                continue
            status = str(action.get("status") or "planned")
            capability = str(action.get("capability_id") or action.get("capability") or "").strip()
            if not capability or status not in {"planned", "binding_failed", "preflight_failed"}:
                continue
            tool_hint = str(action.get("legacy_tool_hint") or "").strip()
            if self._is_forbidden(capability, tool_hint, forbidden):
                continue
            if tool_hint and tool_hint in excluded:
                continue
            return {
                "action": "use_capability",
                "capability": capability,
                "capability_id": capability,
                "params": dict(action.get("bound_params") or {}),
                "reasoning": str(action.get("rationale") or "SOCTaskState capability action is authoritative for the next safe step."),
            }
        return None

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
        forbidden_fallbacks = self._forbidden_fallbacks(reasoning_state)
        agentic_explanation = state.agentic_explanation if isinstance(state.agentic_explanation, dict) else {}
        reasoning_status = str(reasoning_state.get("status") or "")
        latest_message = self._latest_analyst_message(state)
        focus = self._latest_focus_candidate(state)
        resume_strategy = str(investigation_plan.get("resume_strategy") or "").strip().lower()
        resume_signals = investigation_plan.get("resume_signals", []) if isinstance(investigation_plan, dict) else []
        latest_resume_signal = resume_signals[-1] if isinstance(resume_signals, list) and resume_signals else {}
        coverage_matrix = reasoning_state.get("coverage_matrix", {}) if isinstance(reasoning_state, dict) else {}
        coverage_gap_questions: List[str] = []
        if isinstance(coverage_matrix, dict):
            for gap in coverage_matrix.get("blocking_gaps", []) or []:
                if isinstance(gap, dict) and gap.get("facet"):
                    coverage_gap_questions.append(f"Missing required coverage facet: {gap.get('facet')}")
            if not coverage_gap_questions:
                for facet in coverage_matrix.get("missing_facets", []) or []:
                    coverage_gap_questions.append(f"Missing required coverage facet: {facet}")
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
        question_bundle = [*coverage_gap_questions, *open_questions, *missing_evidence, *triage_contract_questions]
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

        protocol_decision = self._decision_from_soc_task_state(reasoning_state, excluded=excluded)
        if protocol_decision is not None:
            return _with_meta(protocol_decision, "soc_task_state_capability_action")

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
            if plan_lane == "email" and "analyze_email" not in excluded and "analyze_email" not in forbidden_fallbacks and self._get_tool("analyze_email") is not None:
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
            if plan_lane == "file" and "analyze_malware" not in excluded and "analyze_malware" not in forbidden_fallbacks and self._get_tool("analyze_malware") is not None:
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
            guessed_tool == "search_logs"
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
                    "reasoning": "Reasoning-guided pivot: explicit Splunk/SIEM/log-hunt request requires log evidence before IOC enrichment. "
                    + str(log_request.get("reasoning") or "").strip(),
                },
                "explicit_log_hunt_request",
            )
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

        if guessed_tool in {"analyze_email", "analyze_malware"} and guessed_tool not in excluded and guessed_tool not in forbidden_fallbacks:
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

        retry_log_pivot = self._retry_log_pivot_decision(state, excluded, question_bundle)
        if retry_log_pivot is not None:
            return _with_meta(retry_log_pivot, "log_coverage_retry")

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
            capability = str(item.get("capability") or item.get("capability_id") or "").strip()
            tool = str(item.get("tool") or "").strip()
            reason = str(item.get("reason") or "").strip()
            if not reason or (not tool and not capability):
                continue
            try:
                priority = int(item.get("priority", 0))
            except (TypeError, ValueError):
                priority = 0
            normalized.append(
                {
                    "tool": tool,
                    "capability": capability,
                    "capability_id": capability,
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
            capability = str(signal.get("capability") or signal.get("capability_id") or "").strip()
            tool = str(signal.get("tool") or "").strip()
            if allowed_signal_types and str(signal.get("signal_type") or "").strip() not in allowed_signal_types:
                continue
            if self._is_forbidden(capability, tool, self._forbidden_fallbacks(getattr(state, "reasoning_state", {}) if isinstance(getattr(state, "reasoning_state", {}), dict) else {})):
                continue
            if capability:
                objective = (getattr(state, "reasoning_state", {}) or {}).get("objective_contract", {}) if isinstance(getattr(state, "reasoning_state", {}), dict) else {}
                resolution = self._capability_resolver.resolve(capability, objective=objective, state=state)
                if resolution.availability != "available" or not resolution.selected_tool:
                    return {
                        "payload": {
                            "action": "use_capability",
                            "capability": capability,
                            "capability_id": capability,
                            "params": {},
                            "reasoning": f"Plan-guided capability resolution degraded: {resolution.degradation_reason}",
                        },
                        "decision_source": f"plan_signal_{signal.get('signal_type', 'generic')}",
                    }
                tool = tool or resolution.selected_tool
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
            query_payload = log_request["query"]
            if isinstance(query_payload, dict):
                query_payload = "\n".join(
                    str(item)
                    for bucket in query_payload.values()
                    if isinstance(bucket, list)
                    for item in bucket[:1]
                    if str(item).strip()
                ) or str(query_payload)
            return {
                "action": "use_capability" if signal.get("capability") or signal.get("capability_id") else "use_tool",
                "capability": signal.get("capability") or signal.get("capability_id"),
                "capability_id": signal.get("capability") or signal.get("capability_id"),
                "tool": tool,
                "params": {
                    "query": query_payload,
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

    def _retry_log_pivot_decision(
        self,
        state: Any,
        excluded: set,
        question_bundle: List[str],
    ) -> Optional[Dict[str, Any]]:
        if "search_logs" in excluded or self._get_tool("search_logs") is None:
            return None
        attempts = [
            finding
            for finding in getattr(state, "findings", [])
            if isinstance(finding, dict)
            and finding.get("type") == "tool_result"
            and finding.get("tool") == "search_logs"
        ]
        if not attempts:
            return None
        latest = attempts[-1]
        result = latest.get("result") if isinstance(latest.get("result"), dict) else {}
        coverage = result.get("coverage_matrix") if isinstance(result, dict) else None
        reasoning_state = getattr(state, "reasoning_state", None) if isinstance(getattr(state, "reasoning_state", None), dict) else {}
        if not isinstance(coverage, dict) or not coverage.get("retry_recommended"):
            return None
        missing = [str(item) for item in coverage.get("missing_facets", []) if str(item).strip()]
        if not missing:
            return None
        result_class = str((reasoning_state.get("last_query_result_evaluation") or {}).get("result_class") or self._tool_result_classifier.classify(result))
        focus = str((reasoning_state.get("last_investigation_query_plan") or {}).get("focus") or self._latest_focus_candidate(state) or "")
        objective = str((reasoning_state.get("last_investigation_query_plan") or {}).get("objective") or "log_hunt")
        retry_state = dict(reasoning_state.get("retry_state") or {})
        backtrack_plan = self._backtracking_engine.plan_next(
            result=result,
            coverage_matrix=coverage,
            focus=focus,
            objective=objective,
            retry_state=retry_state,
        )
        policy_decision = self._retry_policy.decide(
            result_class=result_class,
            gap=missing[0],
            objective=objective,
            retry_state=retry_state,
        )
        if backtrack_plan.get("action") != "retry" or policy_decision.get("action") != "retry":
            stop_decision = {
                "action": "stop",
                "stop_reason": backtrack_plan.get("stop_reason") or policy_decision.get("stop_reason") or result_class,
                "result_class": result_class,
                "remaining_gaps": missing,
                "policy_decision": policy_decision,
                "backtrack_plan": backtrack_plan,
            }
            if isinstance(reasoning_state, dict):
                reasoning_state["last_log_retry_plan"] = stop_decision
                retry_state.update(stop_decision)
                reasoning_state["retry_state"] = retry_state
                history = reasoning_state.setdefault("log_hunt_attempts", [])
                if isinstance(history, list):
                    history.append(stop_decision)
            return None

        prior_fingerprints = {
            build_query_fingerprint((finding.get("result") or {}).get("queries", {}))
            for finding in attempts
            if isinstance(finding.get("result"), dict)
        }
        log_request = self._build_reasoning_search_request(
            state,
            [
                *question_bundle,
                "Retry log coverage for missing facets: " + ", ".join(missing[:4]),
            ],
        )
        if isinstance(backtrack_plan.get("query_variant"), dict) and backtrack_plan["query_variant"].get("query"):
            log_request["query"] = {"splunk": [backtrack_plan["query_variant"]["query"]]}
        new_fingerprint = build_query_fingerprint(log_request.get("query"))
        if new_fingerprint in prior_fingerprints and str(result.get("mode")) == "query_generation_only":
            stop_decision = {
                "action": "stop",
                "stop_reason": "manual_required_no_executable_fallback",
                "result_class": result_class,
                "remaining_gaps": missing,
                "policy_decision": policy_decision,
                "backtrack_plan": backtrack_plan,
            }
            if isinstance(reasoning_state, dict):
                reasoning_state["last_log_retry_plan"] = stop_decision
                retry_state.update(stop_decision)
                reasoning_state["retry_state"] = retry_state
            return None
        retry_plan = {
            "attempt": len(attempts) + 1,
            "max_attempts": getattr(self._retry_policy, "max_attempts_per_objective", None),
            "strategy": "policy_backtracking",
            "focus": str(log_request.get("plan", {}).get("focus") or focus),
            "target_facets": missing[:4],
            "query_bundle": log_request.get("query"),
            "reason": coverage.get("retry_reason") or backtrack_plan.get("retry_reason") or policy_decision.get("retry_reason"),
            "result_class": result_class,
            "policy_decision": policy_decision,
            "backtrack_plan": backtrack_plan,
        }
        if isinstance(reasoning_state, dict):
            history = reasoning_state.setdefault("log_hunt_attempts", [])
            if isinstance(history, list):
                history.append(
                    {
                        "attempt": retry_plan["attempt"],
                        "coverage_matrix": coverage,
                        "retry_plan": retry_plan,
                        "query_fingerprint": new_fingerprint,
                    }
                )
            reasoning_state["last_log_retry_plan"] = retry_plan
            retry_state["last_retry_plan"] = retry_plan
            retry_state["last_decision"] = policy_decision
            reasoning_state["retry_state"] = retry_state
        return {
            "action": "use_tool",
            "tool": "search_logs",
            "params": {
                "query": log_request["query"],
                "timerange": log_request["timerange"],
            },
            "reasoning": (
                "Coverage-guided retry: policy and backtracking selected a bounded log pivot for uncovered facets "
                f"({', '.join(missing[:4])}). "
                + str(retry_plan.get("reason") or "").strip()
            ),
            "retry_plan": retry_plan,
        }

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