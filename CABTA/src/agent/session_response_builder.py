"""Follow-up session prompt assembly and deterministic response shaping."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


class SessionResponseBuilder:
    """Build compact prompts and evidence-backed responses for CABTA sessions."""

    def chat_prefers_direct_response(
        self,
        *,
        is_chat_session: bool,
        has_findings: bool,
        focused_goal: str,
        goal_has_observable: Callable[[str], bool],
        looks_like_artifact_submission: Callable[[str], bool],
    ) -> bool:
        if not is_chat_session or has_findings:
            return False
        clean_goal = str(focused_goal or "").strip()
        if not clean_goal:
            return True
        if goal_has_observable(clean_goal):
            return False
        if looks_like_artifact_submission(clean_goal):
            return False
        return True

    def chat_follow_up_can_answer_from_context(
        self,
        *,
        is_chat_session: bool,
        metadata: Dict[str, Any],
        requires_fresh_evidence: bool,
        has_context_state: bool,
        latest_message: str,
        goal_has_observable: Callable[[str], bool],
    ) -> bool:
        if not is_chat_session:
            return False
        if not metadata.get("chat_context_restored"):
            return False
        if requires_fresh_evidence:
            return False
        if not has_context_state:
            return False

        message = str(latest_message or "").lower()
        answer_from_context_patterns = (
            "why",
            "how did",
            "what evidence",
            "summarize",
            "summary",
            "recap",
            "explain",
            "because",
            "tai sao",
            "vi sao",
            "giai thich",
            "tom tat",
            "bang chung",
            "what did you find",
        )
        if any(pattern in message for pattern in answer_from_context_patterns):
            return True
        return not goal_has_observable(message)

    def build_direct_chat_opening_answer(
        self,
        *,
        prefers_direct_response: bool,
        latest_message: str,
    ) -> str:
        if not prefers_direct_response:
            return ""

        message = str(latest_message or "").lower()
        if any(
            token in message
            for token in (
                "what can you do",
                "help me investigate",
                "how can you help",
                "how would you investigate",
                "what would you do",
                "soc workflow",
                "capabilities",
                "hello",
                "hi",
                "xin chao",
                "chao",
            )
        ):
            return (
                "I can investigate IPs, domains, URLs, hashes, suspicious files, email artifacts, "
                "and log snippets. Share a concrete artifact and I will start with the highest-value "
                "pivots, explain what the evidence shows, and tell you what to check next."
            )

        return (
            "Share a concrete IOC, file path, email artifact, or log snippet and I will start the "
            "investigation, gather evidence with the relevant tools, and explain the result clearly."
        )

    def build_initial_chat_tool_decision(
        self,
        *,
        is_chat_session: bool,
        has_findings: bool,
        prefers_direct_response: bool,
        latest_message: str,
        goal_has_observable: Callable[[str], bool],
        looks_like_artifact_submission: Callable[[str], bool],
        build_next_action_from_context: Callable[[Any], Dict[str, Any]],
        state: Any,
    ) -> Optional[Dict[str, Any]]:
        if not is_chat_session or has_findings or prefers_direct_response:
            return None

        message = str(latest_message or "")
        if not (
            goal_has_observable(message)
            or looks_like_artifact_submission(message)
        ):
            return None

        decision = build_next_action_from_context(state)
        primary_tools = {"investigate_ioc", "analyze_email", "analyze_malware", "extract_iocs"}
        if decision.get("action") != "use_tool" or decision.get("tool") not in primary_tools:
            return None

        decision["reasoning"] = (
            "Chat bootstrap: start with the submitted observable or artifact before waiting on an LLM planning turn."
        )
        return decision

    def build_follow_up_goal(
        self,
        *,
        previous_goal: str,
        thread_summary: str,
        snapshot: Dict[str, Any],
        message: str,
        intent: str,
        requires_fresh_evidence: bool,
    ) -> str:
        blocks: List[str] = ["Continue the same analyst thread for the ongoing CABTA investigation."]
        clean_goal = str(previous_goal or "").strip()
        if clean_goal:
            blocks.append(f"Original investigation goal:\n{clean_goal}")
        if thread_summary:
            blocks.append(f"Thread summary:\n{thread_summary}")

        root_cause = snapshot.get("root_cause_assessment", {}) if isinstance(snapshot, dict) else {}
        if isinstance(root_cause, dict) and root_cause.get("summary"):
            blocks.append(f"Latest root-cause state:\n{root_cause.get('summary')}")

        accepted_facts = snapshot.get("accepted_facts", []) if isinstance(snapshot, dict) else []
        if isinstance(accepted_facts, list) and accepted_facts:
            fact_lines = [f"- {item.get('summary')}" for item in accepted_facts[-4:] if isinstance(item, dict) and item.get("summary")]
            if fact_lines:
                blocks.append("Accepted facts:\n" + "\n".join(fact_lines))

        unresolved = snapshot.get("unresolved_questions", []) if isinstance(snapshot, dict) else []
        if isinstance(unresolved, list) and unresolved:
            unresolved_lines = [f"- {str(item)}" for item in unresolved[:4] if str(item).strip()]
            if unresolved_lines:
                blocks.append("Unresolved questions:\n" + "\n".join(unresolved_lines))

        blocks.append(f"Follow-up analyst request ({intent}):\n{str(message or '').strip()}")
        if requires_fresh_evidence:
            blocks.append(
                "Use the thread snapshot as working context, then collect fresh evidence only where it materially reduces uncertainty for this new pivot."
            )
        else:
            blocks.append(
                "Answer from the accepted snapshot and structured reasoning state unless the available evidence is clearly insufficient."
            )
        return "\n\n".join(blocks)

    def build_evidence_backed_answer(
        self,
        *,
        state: Any,
        authoritative_outcome: Optional[Dict[str, str]],
        include_runtime_notice: bool,
        llm_unavailable_notice: Callable[[], str],
        build_chat_specific_fallback: Callable[[Any], str],
        fallback_evidence_points: Callable[[Any], List[str]],
    ) -> str:
        sentences: List[str] = []
        if include_runtime_notice:
            sentences.append(llm_unavailable_notice())
        chat_specific = build_chat_specific_fallback(state)
        if chat_specific:
            sentences.append(chat_specific)

        if include_runtime_notice and getattr(state, "step_count", 0):
            sentences.append(
                f"The investigation completed {state.step_count} steps before switching to a deterministic fallback summary."
            )

        if authoritative_outcome:
            prefix = "Evidence-backed outcome" if include_runtime_notice else "Current evidence-backed outcome"
            sentences.append(f"{prefix}: {authoritative_outcome['label']}.")
        else:
            sentences.append(
                "The investigation collected evidence, but no authoritative verdict was finalized."
                if include_runtime_notice
                else "The current evidence does not support a finalized verdict yet."
            )

        evidence_points = fallback_evidence_points(state)
        if evidence_points:
            sentences.append("Key evidence: " + " ".join(evidence_points))

        agentic_explanation = state.agentic_explanation if isinstance(getattr(state, "agentic_explanation", None), dict) else {}
        root_cause = agentic_explanation.get("root_cause_assessment", {}) if isinstance(agentic_explanation, dict) else {}
        root_cause_summary = str(root_cause.get("summary") or "").strip()
        if root_cause_summary:
            sentences.append(f"Current investigative explanation: {root_cause_summary}")

        missing_evidence = agentic_explanation.get("missing_evidence", []) if isinstance(agentic_explanation, dict) else []
        if isinstance(missing_evidence, list) and missing_evidence:
            sentences.append(f"Main evidence gap: {str(missing_evidence[0])}")

        if include_runtime_notice:
            sentences.append(
                "This summary was generated directly from the collected evidence so the analyst can continue without losing context."
            )
        elif not chat_specific:
            sentences.append(
                "I can keep pivoting from this evidence if you want a deeper investigation."
            )
        return " ".join(sentences)[:2000]

    def provider_display_name(self, provider: Optional[str]) -> str:
        provider_name = str(provider or "").strip().lower()
        if provider_name == "nvidia":
            return "NVIDIA Build"
        return provider_name.capitalize() if provider_name else "Provider"

    def provider_runtime_error_excerpt(
        self,
        *,
        status: Dict[str, Any],
        provider_display_name: Callable[[Optional[str]], str],
    ) -> str:
        if not status or status.get("available", True):
            return ""

        raw_error = str(status.get("error") or status.get("message") or "").strip()
        if not raw_error:
            return ""

        lowered = raw_error.lower()
        provider_name = provider_display_name(status.get("provider"))
        if "429" in raw_error and ("quota" in lowered or "rate limit" in lowered or "too many requests" in lowered):
            return f"{provider_name} HTTP 429 rate limit reached for the current API key."
        if "403" in raw_error and ("authorization failed" in lowered or "forbidden" in lowered):
            return f"{provider_name} HTTP 403 authorization failed; verify the API key, model access, and any required terms acceptance."
        if "503" in raw_error and ("high demand" in lowered or "overloaded" in lowered):
            return f"{provider_name} HTTP 503 service overloaded."

        compact = " ".join(raw_error.split())
        if len(compact) > 180:
            compact = compact[:177] + "..."
        return compact

    def llm_unavailable_notice(
        self,
        *,
        status: Dict[str, Any],
        provider_name: Optional[str],
        active_model_name: Callable[[Optional[str]], str],
        provider_display_name: Callable[[Optional[str]], str],
        provider_runtime_error_excerpt: Callable[[], str],
    ) -> str:
        effective_provider = str(status.get("provider") or provider_name or "").strip() or provider_name
        model_name = str(status.get("model") or active_model_name(effective_provider)).strip() or active_model_name(effective_provider)
        provider_excerpt = provider_runtime_error_excerpt()
        if provider_excerpt:
            return (
                f"{provider_display_name(effective_provider)} model {model_name} is currently unavailable "
                f"({provider_excerpt}). CABTA did not fall back to another model."
            )
        return (
            f"{provider_display_name(effective_provider)} model {model_name} is currently unavailable. "
            "CABTA did not fall back to another model."
        )

    def provider_failure_message(
        self,
        *,
        provider: str,
        groq_endpoint: str,
        groq_model: str,
        anthropic_model: str,
        gemini_endpoint: str,
        gemini_model: str,
        nvidia_endpoint: str,
        nvidia_model: str,
        openrouter_endpoint: str,
        openrouter_model: str,
        ollama_endpoint: str,
        ollama_model: str,
    ) -> str:
        if provider == "groq":
            return (
                "LLM returned no decision. Verify the Groq API key is configured, "
                f"the endpoint '{groq_endpoint}' is reachable, and model "
                f"'{groq_model}' is available."
            )
        if provider == "anthropic":
            return (
                "LLM returned no decision. Verify the Anthropic API key is configured "
                f"and model '{anthropic_model}' is available."
            )
        if provider == "gemini":
            return (
                "LLM returned no decision. Verify the Gemini API key is configured, "
                f"the endpoint '{gemini_endpoint}' is reachable, and model "
                f"'{gemini_model}' is available."
            )
        if provider == "nvidia":
            return (
                "LLM returned no decision. Verify the NVIDIA Build API key is configured, "
                f"the endpoint '{nvidia_endpoint}' is reachable, and model "
                f"'{nvidia_model}' is available."
            )
        if provider == "openrouter":
            return (
                "LLM returned no decision. Verify the OpenRouter API key is configured, "
                f"the endpoint '{openrouter_endpoint}' is reachable, and model "
                f"'{openrouter_model}' is available."
            )
        return (
            "LLM returned no decision. Verify Ollama is running "
            f"({ollama_endpoint}) and model '{ollama_model}' "
            "is pulled. Run: ollama pull " + ollama_model
        )

    def build_direct_chat_fallback_answer(
        self,
        *,
        llm_unavailable_notice: str,
    ) -> str:
        return (
            f"{llm_unavailable_notice} "
            "Please share a concrete IOC, file path, email artifact, or log snippet if you want me to run the available investigation tools."
        )

    def build_chat_model_unavailable_answer(
        self,
        *,
        state: Any,
        build_direct_chat_fallback_answer: Callable[[str], str],
        goal: str,
        authoritative_outcome: Optional[Dict[str, str]],
        fallback_evidence_points: Callable[[Any, int], List[str]],
        build_fallback_answer: Callable[[Any, Optional[Dict[str, str]]], str],
        llm_unavailable_notice: str,
    ) -> str:
        if not getattr(state, "findings", None):
            return build_direct_chat_fallback_answer(goal)

        if authoritative_outcome is not None or fallback_evidence_points(state, 1):
            return build_fallback_answer(state, authoritative_outcome)

        return (
            f"{llm_unavailable_notice} "
            "CABTA preserved the collected tool outputs in this session and did not synthesize a fallback narrative answer while the model was unavailable. "
            "Review the tool results above or retry once the model is available again."
        )

    def build_planned_next_step_summary(
        self,
        *,
        decision: Optional[Dict[str, Any]],
    ) -> str:
        if not isinstance(decision, dict):
            return ""

        tool = str(decision.get("tool") or "").strip()
        action = str(decision.get("action") or "").strip()
        if action and action != "use_tool":
            return ""
        if not tool:
            return ""

        parts = [f"Next planned step: {tool}."]

        decision_source = str(decision.get("decision_source") or "").strip()
        if decision_source:
            parts.append(f"Source: {decision_source}.")

        plan_lane = str(decision.get("plan_lane") or "").strip()
        if plan_lane:
            parts.append(f"Lane: {plan_lane}.")

        focus = str(decision.get("focus") or "").strip()
        if focus:
            parts.append(f"Focus: {focus}.")

        question_bundle = decision.get("question_bundle", [])
        if isinstance(question_bundle, list):
            first_question = next((str(item).strip() for item in question_bundle if str(item).strip()), "")
            if first_question:
                parts.append(f"Open question: {first_question}")

        return " ".join(parts)

    def build_fallback_decision_without_llm(
        self,
        *,
        state: Any,
        chat_prefers_direct_response: bool,
        build_direct_chat_fallback_answer: Callable[[str], str],
        goal: str,
        build_next_action_from_context: Callable[[Any], Dict[str, Any]],
        has_tool: Callable[[str], bool],
        resolve_authoritative_outcome: Callable[[Any], Optional[Dict[str, str]]],
        is_chat_session: Callable[[Any], bool],
        provider_is_currently_unavailable: Callable[[Optional[str]], bool],
        provider_name: Optional[str],
        build_chat_model_unavailable_answer: Callable[[Any], str],
        build_fallback_answer: Callable[[Any, Optional[Dict[str, str]]], str],
    ) -> Dict[str, Any]:
        findings = getattr(state, "findings", []) or []
        if not findings:
            if chat_prefers_direct_response:
                return {
                    "action": "final_answer",
                    "answer": build_direct_chat_fallback_answer(goal),
                    "verdict": "UNKNOWN",
                    "reasoning": "Fallback: direct analyst chat response without tool use.",
                }
            decision = build_next_action_from_context(state)
            decision["reasoning"] = (
                "Fallback: LLM returned no decision. "
                + str(decision.get("reasoning") or "")
            ).strip()
            return decision

        last_tool = ""
        for finding in reversed(findings):
            if finding.get("type") == "tool_result":
                last_tool = str(finding.get("tool") or "")
                break

        if last_tool != "correlate_findings" and has_tool("correlate_findings"):
            return {
                "action": "use_tool",
                "tool": "correlate_findings",
                "params": {"findings": findings[-10:]},
                "reasoning": "Fallback: LLM returned no decision, so correlate the accumulated evidence.",
            }

        authoritative_outcome = resolve_authoritative_outcome(state)
        verdict = authoritative_outcome["label"] if authoritative_outcome else "UNKNOWN"
        if is_chat_session(state) and provider_is_currently_unavailable(provider_name):
            return {
                "action": "final_answer",
                "answer": build_chat_model_unavailable_answer(state),
                "verdict": verdict,
                "reasoning": (
                    "Fallback: the configured chat model is unavailable, so preserve the investigation state "
                    "without generating a deterministic narrative answer."
                ),
            }
        answer = build_fallback_answer(state, authoritative_outcome)
        return {
            "action": "final_answer",
            "answer": answer,
            "verdict": verdict,
            "reasoning": "Fallback: end the investigation with an evidence-preserving summary.",
        }

    def build_fallback_answer(
        self,
        *,
        state: Any,
        authoritative_outcome: Optional[Dict[str, str]],
        build_evidence_backed_answer: Callable[..., str],
    ) -> str:
        return build_evidence_backed_answer(
            state=state,
            authoritative_outcome=authoritative_outcome,
            include_runtime_notice=True,
        )

    async def generate_summary(
        self,
        *,
        state: Any,
        authoritative_outcome: Optional[Dict[str, str]],
        prompt: str,
        call_llm_text: Callable[[str], Any],
        is_chat_session: Callable[[Any], bool],
        provider_is_currently_unavailable: Callable[[Optional[str]], bool],
        provider_name: Optional[str],
        build_chat_model_unavailable_answer: Callable[[Any], str],
        build_fallback_answer: Callable[[Any, Optional[Dict[str, str]]], str],
    ) -> str:
        findings = getattr(state, "findings", []) or []
        errors = getattr(state, "errors", []) or []

        if not findings and errors:
            return (
                "Investigation failed before evidence collection. "
                + " ".join(str(err) for err in errors[:2])
            )[:2000]

        for finding in reversed(findings):
            if finding.get("type") != "final_answer":
                continue
            answer = finding.get("answer", "")
            if not answer:
                continue
            if authoritative_outcome and "did not fall back to another model" not in str(answer).lower():
                return f"[{authoritative_outcome['label']}] {answer}"
            return answer

        try:
            raw = await call_llm_text(prompt)
            if raw:
                return str(raw)[:2000]
        except Exception:
            pass

        if is_chat_session(state) and provider_is_currently_unavailable(provider_name):
            return build_chat_model_unavailable_answer(state)
        return build_fallback_answer(state, authoritative_outcome)