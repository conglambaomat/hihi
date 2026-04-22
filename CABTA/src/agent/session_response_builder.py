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

    def message_requests_fresh_evidence(self, message: str) -> bool:
        text = str(message or "").strip().lower()
        if not text:
            return False

        explanation_patterns = (
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
            "dua tren",
            "what did you find",
        )
        if any(pattern in text for pattern in explanation_patterns):
            return False

        investigation_patterns = (
            "investigate",
            "pivot",
            "check",
            "analyze",
            "lookup",
            "look up",
            "search",
            "hunt",
            "query",
            "scan",
            "enrich",
            "triage",
            "verify",
            "confirm",
            "correlate",
            "find related",
            "pull",
            "dieu tra",
            "kiem tra",
            "phan tich",
            "tra cuu",
            "xac minh",
            "tim them",
            "san",
            "quet",
        )
        if any(pattern in text for pattern in investigation_patterns):
            return True

        registrar_and_related_terms = (
            "registrar",
            "infrastructure",
            "related host",
            "related hosts",
            "related domain",
            "related domains",
        )
        return "pivot" in text or any(term in text for term in registrar_and_related_terms)

    def build_legacy_follow_up_goal(
        self,
        *,
        previous_goal: str,
        previous_summary: str,
        evidence_snapshot: str,
        message: str,
    ) -> str:
        clean_goal = str(previous_goal or "").strip()
        if clean_goal.lower().startswith("(follow-up to previous investigation:"):
            _, _, remainder = clean_goal.partition("\n")
            clean_goal = remainder.strip() or clean_goal
        needs_fresh_evidence = self.message_requests_fresh_evidence(message)

        blocks = ["Continue the previous analyst conversation about the security investigation."]
        if clean_goal:
            blocks.append(f"Previous investigation goal:\n{clean_goal}")
        if previous_summary:
            blocks.append(f"Previous investigation summary:\n{previous_summary}")
        if evidence_snapshot:
            blocks.append(f"Previous evidence snapshot:\n{evidence_snapshot}")
        blocks.append(f"New analyst request:\n{str(message or '').strip()}")
        if needs_fresh_evidence:
            blocks.append(
                "Carry forward the existing findings, reasoning state, and tracked entities from the previous session. "
                "Gather fresh evidence with tools if the analyst is asking for a new pivot or if the carried-over evidence is still insufficient."
            )
        else:
            blocks.append(
                "Carry forward the existing findings, reasoning state, and tracked entities from the previous session. "
                "If the analyst is asking for explanation, recap, or judgment from the current evidence, answer directly from that carried-over context. "
                "Only use tools if the current evidence is insufficient."
            )
        return "\n\n".join(blocks)

    def build_follow_up_goal(
        self,
        *,
        previous_goal: str,
        thread_summary: str,
        snapshot: Dict[str, Any],
        message: str,
        intent: str,
        requires_fresh_evidence: bool,
        memory_scope: Optional[str] = None,
    ) -> str:
        blocks: List[str] = ["Continue the same analyst thread for the ongoing CABTA investigation."]
        clean_goal = str(previous_goal or "").strip()
        if clean_goal:
            blocks.append(f"Original investigation goal:\n{clean_goal}")
        if thread_summary:
            blocks.append(f"Thread summary:\n{thread_summary}")

        scope = str(memory_scope or "").strip().lower()
        if scope not in {"working", "candidate", "accepted", "published"}:
            scope = "accepted"
        snapshot_label = {
            "working": "working session context",
            "candidate": "candidate session context",
            "accepted": "accepted case memory",
            "published": "published case memory",
        }[scope]
        scope_noun = {
            "working": "context",
            "candidate": "candidate context",
            "accepted": "accepted case truth",
            "published": "published case truth",
        }[scope]

        root_cause = snapshot.get("root_cause_assessment", {}) if isinstance(snapshot, dict) else {}
        if isinstance(root_cause, dict) and root_cause.get("summary"):
            blocks.append(f"Latest root-cause state:\n{root_cause.get('summary')}")

        accepted_facts = snapshot.get("accepted_facts", []) if isinstance(snapshot, dict) else []
        if isinstance(accepted_facts, list) and accepted_facts:
            fact_lines = [f"- {item.get('summary')}" for item in accepted_facts[-4:] if isinstance(item, dict) and item.get("summary")]
            if fact_lines:
                fact_heading = (
                    f"{snapshot_label.capitalize()} facts"
                    if scope in {"accepted", "published"}
                    else f"{snapshot_label.capitalize()} observations and candidate facts"
                )
                blocks.append(f"{fact_heading}:\n" + "\n".join(fact_lines))

        unresolved = snapshot.get("unresolved_questions", []) if isinstance(snapshot, dict) else []
        if isinstance(unresolved, list) and unresolved:
            unresolved_lines = [f"- {str(item)}" for item in unresolved[:4] if str(item).strip()]
            if unresolved_lines:
                blocks.append("Unresolved questions:\n" + "\n".join(unresolved_lines))

        blocks.append(f"Follow-up analyst request ({intent}):\n{str(message or '').strip()}")
        if requires_fresh_evidence:
            blocks.append(
                f"Use the {snapshot_label} as bounded {scope_noun}, then collect fresh evidence only where it materially reduces uncertainty for this new pivot."
            )
        else:
            blocks.append(
                f"Answer from the {snapshot_label} and structured reasoning state unless the available evidence is clearly insufficient. Do not overstate {scope_noun} beyond its lifecycle."
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
        return " ".join(
            self.build_evidence_backed_answer_sentences(
                state=state,
                authoritative_outcome=authoritative_outcome,
                include_runtime_notice=include_runtime_notice,
                llm_unavailable_notice=llm_unavailable_notice,
                build_chat_specific_fallback=build_chat_specific_fallback,
                fallback_evidence_points=fallback_evidence_points,
            )
        )[:2000]

    def build_evidence_backed_answer_sentences(
        self,
        *,
        state: Any,
        authoritative_outcome: Optional[Dict[str, str]],
        include_runtime_notice: bool,
        llm_unavailable_notice: Callable[[], str],
        build_chat_specific_fallback: Callable[[Any], str],
        fallback_evidence_points: Callable[[Any], List[str]],
    ) -> List[str]:
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
        return sentences

    def build_chat_specific_fallback(
        self,
        *,
        is_chat_session: bool,
        focused_goal: str,
        findings: List[Dict[str, Any]],
        reasoning_state: Optional[Dict[str, Any]],
    ) -> str:
        if not is_chat_session:
            return ""

        normalized_goal = str(focused_goal or "").lower()
        wants_org = any(
            phrase in normalized_goal
            for phrase in ("what organization", "which organization", "who owns this ip")
        )
        wants_host = any(
            phrase in normalized_goal
            for phrase in ("what hostname", "what host name", "hostname", "host name")
        )
        if not wants_org and not wants_host:
            return ""

        organization = ""
        hostname = ""
        for finding in reversed(findings or []):
            if not isinstance(finding, dict) or finding.get("type") != "tool_result":
                continue
            result = finding.get("result")
            payload = result.get("result") if isinstance(result, dict) and isinstance(result.get("result"), dict) else result
            if not isinstance(payload, dict):
                continue
            if not organization:
                organization = str(
                    payload.get("organization")
                    or payload.get("org_name")
                    or payload.get("registrant_org")
                    or ""
                ).strip()
                parsed_fields = payload.get("parsed_fields", {}) if isinstance(payload.get("parsed_fields"), dict) else {}
                if not organization:
                    registrant_org = parsed_fields.get("registrant_org")
                    if isinstance(registrant_org, list) and registrant_org:
                        organization = str(registrant_org[0]).strip()
                    elif registrant_org:
                        organization = str(registrant_org).strip()
            if not hostname:
                hostnames = payload.get("hostnames")
                if isinstance(hostnames, list) and hostnames:
                    hostname = str(hostnames[0]).strip()
                elif payload.get("reverse_dns"):
                    hostname = str(payload.get("reverse_dns")).strip()
                elif payload.get("hostname"):
                    hostname = str(payload.get("hostname")).strip()
            if organization and hostname:
                break

        if not organization and not hostname:
            return ""

        subject = ""
        if isinstance(reasoning_state, dict):
            subject = str(reasoning_state.get("goal_focus") or "").strip()
        subject = subject or "the investigation target"

        details: List[str] = []
        if wants_org and organization:
            details.append(f"organization {organization}")
        if wants_host and hostname:
            details.append(f"hostname {hostname}")
        if not details:
            return ""
        if len(details) == 1:
            return f"For {subject}, the strongest current mapping is {details[0]}."
        return f"For {subject}, the strongest current mapping is {details[0]} and {details[1]}."

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

    def build_provider_timeout_error(
        self,
        *,
        provider: Optional[str],
        timeout_seconds: float,
        provider_display_name: Callable[[Optional[str]], str],
    ) -> str:
        return (
            f"{provider_display_name(provider)} direct chat request timed out "
            f"after {timeout_seconds:.0f}s"
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

    def build_unavailable_model_preserved_outputs_answer(
        self,
        *,
        llm_unavailable_notice: str,
    ) -> str:
        return (
            f"{llm_unavailable_notice} "
            "CABTA preserved the collected tool outputs in this session and did not synthesize a fallback narrative answer while the model was unavailable. "
            "Review the tool results above or retry once the model is available again."
        )

    def build_chat_model_unavailable_answer(
        self,
        *,
        state: Any,
        build_direct_chat_fallback_answer: Callable[[str], str],
        goal: str,
        authoritative_outcome: Optional[Dict[str, str]],
        fallback_evidence_points: Callable[[Any, int], List[str]],
        build_fallback_answer: Callable[[Any, Optional[Dict[str, str]], bool], str],
        llm_unavailable_notice: str,
    ) -> str:
        if not getattr(state, "findings", None):
            return build_direct_chat_fallback_answer(goal)

        if authoritative_outcome is not None or fallback_evidence_points(state, 1):
            return build_fallback_answer(state, authoritative_outcome, True)

        return self.build_unavailable_model_preserved_outputs_answer(
            llm_unavailable_notice=llm_unavailable_notice,
        )

    def build_provider_runtime_fallback_context(
        self,
        *,
        provider_runtime_status: Any,
        provider_name: Optional[str],
        normalize_provider: Callable[[Optional[str]], str],
        active_model_name: Callable[[Optional[str]], str],
    ) -> Dict[str, Any]:
        normalized_provider = normalize_provider(provider_name)
        status = provider_runtime_status if isinstance(provider_runtime_status, dict) else {}
        return {
            "provider_name": normalized_provider,
            "status": status,
            "active_model_name": active_model_name(normalized_provider),
        }

    def build_runtime_fallback_artifacts(
        self,
        *,
        provider_runtime_status: Any,
        provider_name: Optional[str],
        normalize_provider: Callable[[Optional[str]], str],
        active_model_name: Callable[[Optional[str]], str],
        provider_display_name: Callable[[Optional[str]], str],
        provider_runtime_error_excerpt: Callable[..., str],
    ) -> Dict[str, Any]:
        fallback_context = self.build_provider_runtime_fallback_context(
            provider_runtime_status=provider_runtime_status,
            provider_name=provider_name,
            normalize_provider=normalize_provider,
            active_model_name=active_model_name,
        )
        unavailable_notice = self.llm_unavailable_notice_from_context(
            fallback_context=fallback_context,
            provider_display_name=provider_display_name,
            provider_runtime_error_excerpt=provider_runtime_error_excerpt,
        )
        return {
            "fallback_context": fallback_context,
            "llm_unavailable_notice": unavailable_notice,
        }

    def build_runtime_unavailable_notice(
        self,
        *,
        provider_runtime_status: Any,
        provider_name: Optional[str],
        normalize_provider: Callable[[Optional[str]], str],
        active_model_name: Callable[[Optional[str]], str],
        provider_display_name: Callable[[Optional[str]], str],
        provider_runtime_error_excerpt: Callable[..., str],
    ) -> str:
        return str(
            self.build_runtime_fallback_artifacts(
                provider_runtime_status=provider_runtime_status,
                provider_name=provider_name,
                normalize_provider=normalize_provider,
                active_model_name=active_model_name,
                provider_display_name=provider_display_name,
                provider_runtime_error_excerpt=provider_runtime_error_excerpt,
            ).get("llm_unavailable_notice")
            or ""
        )

    def build_direct_chat_fallback_answer_with_runtime_status(
        self,
        *,
        provider_runtime_status: Any,
        provider_name: Optional[str],
        normalize_provider: Callable[[Optional[str]], str],
        active_model_name: Callable[[Optional[str]], str],
        provider_display_name: Callable[[Optional[str]], str],
        provider_runtime_error_excerpt: Callable[..., str],
    ) -> str:
        artifacts = self.build_runtime_fallback_artifacts(
            provider_runtime_status=provider_runtime_status,
            provider_name=provider_name,
            normalize_provider=normalize_provider,
            active_model_name=active_model_name,
            provider_display_name=provider_display_name,
            provider_runtime_error_excerpt=provider_runtime_error_excerpt,
        )
        return self.build_direct_chat_fallback_answer(
            llm_unavailable_notice=str(artifacts.get("llm_unavailable_notice") or "")
        )

    def build_chat_model_unavailable_answer_with_runtime_status(
        self,
        *,
        state: Any,
        provider_runtime_status: Any,
        provider_name: Optional[str],
        normalize_provider: Callable[[Optional[str]], str],
        active_model_name: Callable[[Optional[str]], str],
        build_direct_chat_fallback_answer: Callable[[str], str],
        goal: str,
        authoritative_outcome: Optional[Dict[str, str]],
        fallback_evidence_points: Callable[[Any, int], List[str]],
        build_chat_specific_fallback: Callable[[Any], str],
        provider_display_name: Callable[[Optional[str]], str],
        provider_runtime_error_excerpt: Callable[..., str],
    ) -> str:
        artifacts = self.build_runtime_fallback_artifacts(
            provider_runtime_status=provider_runtime_status,
            provider_name=provider_name,
            normalize_provider=normalize_provider,
            active_model_name=active_model_name,
            provider_display_name=provider_display_name,
            provider_runtime_error_excerpt=provider_runtime_error_excerpt,
        )
        return self.build_chat_model_unavailable_answer_from_context(
            state=state,
            fallback_context=dict(artifacts.get("fallback_context") or {}),
            build_direct_chat_fallback_answer=build_direct_chat_fallback_answer,
            goal=goal,
            authoritative_outcome=authoritative_outcome,
            fallback_evidence_points=fallback_evidence_points,
            build_chat_specific_fallback=build_chat_specific_fallback,
            provider_display_name=provider_display_name,
            provider_runtime_error_excerpt=provider_runtime_error_excerpt,
            llm_unavailable_notice=str(artifacts.get("llm_unavailable_notice") or ""),
        )

    def build_provider_timeout_runtime_status(
        self,
        *,
        provider: Optional[str],
        timeout_seconds: float,
        provider_display_name: Callable[[Optional[str]], str],
    ) -> Dict[str, Any]:
        normalized_provider = str(provider or "").strip().lower()
        return {
            "provider": normalized_provider,
            "available": False,
            "error": self.build_provider_timeout_error(
                provider=normalized_provider,
                timeout_seconds=timeout_seconds,
                provider_display_name=provider_display_name,
            ),
        }

    def build_fallback_response_context(
        self,
        *,
        provider_runtime_status: Any,
        provider_name: Optional[str],
        normalize_provider: Callable[[Optional[str]], str],
        active_model_name: Callable[[Optional[str]], str],
    ) -> Dict[str, Any]:
        return self.build_provider_runtime_fallback_context(
            provider_runtime_status=provider_runtime_status,
            provider_name=provider_name,
            normalize_provider=normalize_provider,
            active_model_name=active_model_name,
        )

    def llm_unavailable_notice_with_runtime_status(
        self,
        *,
        provider_runtime_status: Any,
        provider_name: Optional[str],
        normalize_provider: Callable[[Optional[str]], str],
        active_model_name: Callable[[Optional[str]], str],
        provider_display_name: Callable[[Optional[str]], str],
        provider_runtime_error_excerpt: Callable[..., str],
    ) -> str:
        return self.build_runtime_unavailable_notice(
            provider_runtime_status=provider_runtime_status,
            provider_name=provider_name,
            normalize_provider=normalize_provider,
            active_model_name=active_model_name,
            provider_display_name=provider_display_name,
            provider_runtime_error_excerpt=provider_runtime_error_excerpt,
        )

    def llm_unavailable_notice_from_context(
        self,
        *,
        fallback_context: Dict[str, Any],
        provider_display_name: Callable[[Optional[str]], str],
        provider_runtime_error_excerpt: Callable[..., str],
    ) -> str:
        return self.llm_unavailable_notice(
            status=fallback_context.get("status", {}),
            provider_name=fallback_context.get("provider_name"),
            active_model_name=lambda _provider: str(fallback_context.get("active_model_name") or ""),
            provider_display_name=provider_display_name,
            provider_runtime_error_excerpt=lambda: provider_runtime_error_excerpt(
                status=fallback_context.get("status", {}),
                provider_display_name=provider_display_name,
            ),
        )

    def build_chat_model_unavailable_answer_from_context(
        self,
        *,
        state: Any,
        fallback_context: Dict[str, Any],
        build_direct_chat_fallback_answer: Callable[[str], str],
        goal: str,
        authoritative_outcome: Optional[Dict[str, str]],
        fallback_evidence_points: Callable[[Any, int], List[str]],
        build_chat_specific_fallback: Callable[[Any], str],
        provider_display_name: Callable[[Optional[str]], str],
        provider_runtime_error_excerpt: Callable[..., str],
        llm_unavailable_notice: Optional[str] = None,
    ) -> str:
        unavailable_notice = str(llm_unavailable_notice or "").strip() or self.llm_unavailable_notice_from_context(
            fallback_context=fallback_context,
            provider_display_name=provider_display_name,
            provider_runtime_error_excerpt=provider_runtime_error_excerpt,
        )
        return self.build_chat_model_unavailable_answer(
            state=state,
            build_direct_chat_fallback_answer=build_direct_chat_fallback_answer,
            goal=goal,
            authoritative_outcome=authoritative_outcome,
            fallback_evidence_points=fallback_evidence_points,
            build_fallback_answer=lambda current_state, current_outcome, include_runtime_notice: self.build_fallback_answer(
                state=current_state,
                authoritative_outcome=current_outcome,
                include_runtime_notice=include_runtime_notice,
                build_evidence_backed_answer=lambda **kwargs: self.build_evidence_backed_answer(
                    **kwargs,
                    llm_unavailable_notice=lambda: unavailable_notice,
                    build_chat_specific_fallback=build_chat_specific_fallback,
                    fallback_evidence_points=lambda answer_state: fallback_evidence_points(answer_state, 3),
                ),
            ),
            llm_unavailable_notice=unavailable_notice,
        )

    def chat_evidence_allows_answer_without_tools(
        self,
        *,
        reasoning_status: str,
        root_cause: Dict[str, Any],
        has_strong_evidence: bool,
        require_supported_root_cause_refs: bool = True,
    ) -> bool:
        supported_root_cause = (
            isinstance(root_cause, dict)
            and root_cause.get("status") == "supported"
            and (
                not require_supported_root_cause_refs
                or bool(root_cause.get("supporting_evidence_refs"))
            )
        )
        return bool(
            reasoning_status == "sufficient_evidence"
            or supported_root_cause
            or has_strong_evidence
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

    def build_think_request_metadata(
        self,
        *,
        prompt_payload: Dict[str, Any],
        planned_decision: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return {
            "prompt_mode": prompt_payload.get("prompt_mode"),
            "provider_context_block": prompt_payload.get("provider_context_block"),
            "prompt_envelope": prompt_payload.get("prompt_envelope"),
            "model_only_chat": prompt_payload.get("model_only_chat"),
            "uses_native_tools": prompt_payload.get("uses_native_tools"),
            "planned_next_step_summary": self.build_planned_next_step_summary(
                decision=planned_decision
            ),
        }

    def build_approval_context(
        self,
        *,
        session_id: str,
        state: Any,
        tool_name: str,
        params: Dict[str, Any],
        approval_id: Optional[str],
        case_id: Optional[str],
        execution_guidance: Dict[str, Any],
    ) -> Dict[str, Any]:
        reasoning_state = getattr(state, "reasoning_state", {})
        investigation_plan = getattr(state, "investigation_plan", {}) or {}
        return {
            "tool": tool_name,
            "params": dict(params or {}),
            "approval_id": approval_id,
            "case_id": case_id,
            "workflow_id": getattr(state, "workflow_id", None),
            "specialist": getattr(state, "active_specialist", None),
            "session_id": session_id,
            "step": getattr(state, "step_count", 0),
            "reasoning_status": (
                str(reasoning_state.get("status") or "")
                if isinstance(reasoning_state, dict)
                else ""
            ),
            "stop_conditions": list(investigation_plan.get("stopping_conditions", []))[:4],
            "escalation_conditions": list(investigation_plan.get("escalation_conditions", []))[:4],
            "execution_guidance": dict(execution_guidance or {}),
        }

    def build_approval_required_event(
        self,
        *,
        tool_name: str,
        params: Dict[str, Any],
        reason: str,
        approval_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "type": "approval_required",
            "tool": tool_name,
            "params": dict(params or {}),
            "reason": reason,
            "context": dict(approval_context or {}),
        }

    def apply_approval_review(
        self,
        *,
        state: Any,
        approved: bool,
        reviewed_at: str,
    ) -> bool:
        pending_approval = getattr(state, "pending_approval", None)
        if not isinstance(pending_approval, dict):
            return False
        pending_approval["approved"] = bool(approved)
        pending_approval["status"] = "approved" if approved else "rejected"
        pending_approval["reviewed_at"] = reviewed_at
        return True

    def build_approval_pending_payload(
        self,
        *,
        decision: Dict[str, Any],
        approval_id: Optional[str],
    ) -> Dict[str, Any]:
        return {
            **dict(decision or {}),
            "approval_id": approval_id,
        }

    def build_approval_rejection_finding(
        self,
        *,
        tool_name: str,
        approval_outcome: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        outcome = dict(approval_outcome or {})
        rejection_context = dict(outcome.get("context", {}))
        rejection_status = "timed_out" if outcome.get("status") == "timed_out" else "rejected"
        return {
            "type": "approval_rejected",
            "tool": tool_name,
            "status": rejection_status,
            "approval_context": rejection_context,
            "execution_guidance": rejection_context.get("execution_guidance", {}),
        }

    def build_approval_rejection_transition(
        self,
        *,
        tool_name: str,
        approval_outcome: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        rejection_finding = self.build_approval_rejection_finding(
            tool_name=tool_name,
            approval_outcome=approval_outcome,
        )
        return {
            "finding": rejection_finding,
            "blocker_status": rejection_finding["status"],
            "approval_context": rejection_finding["approval_context"],
        }

    def build_chat_prompt_policy(
        self,
        *,
        is_chat_session: bool,
        chat_context_restored: bool,
        requires_fresh_evidence: bool = False,
        restored_memory_scope: str = "",
        restored_memory_is_authoritative: bool = False,
    ) -> Dict[str, str]:
        response_style_block = ""
        chat_decision_block = ""
        if not is_chat_session:
            return {
                "response_style_block": response_style_block,
                "chat_decision_block": chat_decision_block,
            }

        response_style_block = (
            "Response style for analyst chat:\n"
            "- When you have enough evidence, answer the analyst's question directly in the first sentence.\n"
            "- Use plain, practical SOC language instead of stiff report boilerplate.\n"
            "- After the direct answer, briefly explain the evidence and why it matters.\n"
            "- End with concrete next steps only if they add value."
        )
        chat_decision_block = (
            "Chat decision policy:\n"
            "- If the analyst is greeting you, asking what you can do, asking how you would investigate, or has not provided a concrete IOC/file/email/log artifact yet, answer directly in conversation and ask for the missing input instead of forcing a tool call.\n"
            "- If the analyst's question can already be answered from the current findings, reason over those findings and answer directly.\n"
            "- Use tools when the analyst asks for fresh investigation, new evidence collection, or when the current findings are insufficient."
        )
        if chat_context_restored:
            response_style_block += "\n- Treat carried-over findings as live investigation context, not as a stale summary."
            scope_label = restored_memory_scope.replace("_", " ").strip()
            if scope_label:
                if restored_memory_is_authoritative:
                    response_style_block += (
                        f"\n- The restored {scope_label} memory is authoritative case truth within its lifecycle boundary."
                    )
                else:
                    response_style_block += (
                        f"\n- The restored {scope_label} memory is bounded working context, not finalized case truth."
                    )

            scope_phrase_label = scope_label or "restored"
            if restored_memory_is_authoritative:
                scope_phrase = f"the restored {scope_phrase_label} case truth"
            else:
                scope_phrase = f"the restored {scope_phrase_label} working context"
            if requires_fresh_evidence:
                chat_decision_block += (
                    f"\n- This is a follow-up chat turn with carried-over findings. Continue from {scope_phrase} and gather fresh evidence only for the new pivot the analyst requested."
                )
            else:
                chat_decision_block += (
                    f"\n- This is a follow-up chat turn with carried-over findings. Prefer answering from {scope_phrase} before starting new tool calls."
                )

        return {
            "response_style_block": response_style_block,
            "chat_decision_block": chat_decision_block,
        }

    def build_chat_response_style_block(
        self,
        *,
        is_chat_session: bool,
        chat_context_restored: bool,
        restored_memory_scope: str = "",
        restored_memory_is_authoritative: bool = False,
    ) -> str:
        return str(
            self.build_chat_prompt_policy(
                is_chat_session=is_chat_session,
                chat_context_restored=chat_context_restored,
                restored_memory_scope=restored_memory_scope,
                restored_memory_is_authoritative=restored_memory_is_authoritative,
            ).get("response_style_block")
            or ""
        )

    def build_chat_decision_block(
        self,
        *,
        is_chat_session: bool,
        chat_context_restored: bool,
        requires_fresh_evidence: bool,
        restored_memory_scope: str = "",
        restored_memory_is_authoritative: bool = False,
    ) -> str:
        return str(
            self.build_chat_prompt_policy(
                is_chat_session=is_chat_session,
                chat_context_restored=chat_context_restored,
                requires_fresh_evidence=requires_fresh_evidence,
                restored_memory_scope=restored_memory_scope,
                restored_memory_is_authoritative=restored_memory_is_authoritative,
            ).get("chat_decision_block")
            or ""
        )

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
        include_runtime_notice: bool = True,
    ) -> str:
        return build_evidence_backed_answer(
            state=state,
            authoritative_outcome=authoritative_outcome,
            include_runtime_notice=include_runtime_notice,
        )

    def build_fallback_evidence_points(
        self,
        *,
        findings: List[Dict[str, Any]],
        describe_fallback_evidence: Callable[[str, Any], str],
        limit: int = 3,
    ) -> List[str]:
        evidence: List[str] = []
        for finding in findings:
            if not isinstance(finding, dict) or finding.get("type") != "tool_result":
                continue
            tool_name = str(finding.get("tool") or "tool_result")
            point = describe_fallback_evidence(tool_name, finding.get("result"))
            if point and point not in evidence:
                evidence.append(point)
            if len(evidence) >= limit:
                break
        return evidence[:limit]

    def describe_fallback_evidence(self, *, tool_name: str, result: Any) -> str:
        if not isinstance(result, dict):
            return ""

        payload = result.get("result") if isinstance(result.get("result"), dict) else result
        if not isinstance(payload, dict):
            return ""

        error = payload.get("error")
        if error:
            return f"{tool_name} reported error={str(error)[:120]}."
        if payload.get("timed_out"):
            return f"{tool_name} timed out while gathering enrichment."

        if tool_name == "investigate_ioc":
            ioc = str(payload.get("ioc") or "IOC")
            verdict = str(payload.get("verdict") or "UNKNOWN").upper()
            threat_score = payload.get("threat_score")
            domain_enrichment = payload.get("domain_enrichment", {})
            domain_age = domain_enrichment.get("domain_age", {}) if isinstance(domain_enrichment, dict) else {}
            if isinstance(domain_age, dict) and domain_age.get("is_newly_registered"):
                age_days = domain_age.get("age_days")
                return (
                    f"{ioc} classified as {verdict} with threat_score={threat_score}; "
                    f"domain age is {age_days} days."
                )
            return f"{ioc} classified as {verdict} with threat_score={threat_score}."

        if tool_name.endswith("whois_lookup"):
            target = str(payload.get("target") or "domain")
            creation_date = str(payload.get("creation_date") or "").strip()
            registrar = payload.get("registrar")
            registrar_name = ""
            if isinstance(registrar, list) and registrar:
                registrar_name = str(registrar[0]).strip()
            elif registrar:
                registrar_name = str(registrar).strip()
            details = ", ".join(
                part
                for part in [
                    f"created={creation_date}" if creation_date else "",
                    f"registrar={registrar_name}" if registrar_name else "",
                ]
                if part
            )
            if details:
                return f"WHOIS for {target}: {details}."
            return f"WHOIS data collected for {target}."

        if tool_name.endswith("dns_resolve"):
            domain = str(payload.get("domain") or "domain")
            records = payload.get("records", {}) if isinstance(payload.get("records"), dict) else {}
            a_records = records.get("A") if isinstance(records.get("A"), list) else []
            if a_records:
                return f"DNS for {domain} resolved to {', '.join(str(ip) for ip in a_records[:3])}."
            return f"DNS data collected for {domain}."

        if tool_name.endswith("ssl_certificate_info"):
            host = str(payload.get("host") or "host")
            issuer = payload.get("issuer", {}) if isinstance(payload.get("issuer"), dict) else {}
            issuer_cn = str(issuer.get("commonName") or "").strip()
            not_after = str(payload.get("not_after") or "").strip()
            details = ", ".join(
                part
                for part in [
                    f"issuer={issuer_cn}" if issuer_cn else "",
                    f"expires={not_after}" if not_after else "",
                ]
                if part
            )
            if details:
                return f"TLS certificate for {host}: {details}."
            return f"TLS certificate metadata collected for {host}."

        if tool_name == "correlate_findings":
            severity = str(payload.get("severity") or "").upper()
            stats = payload.get("statistics", {}) if isinstance(payload.get("statistics"), dict) else {}
            unique_iocs = stats.get("unique_iocs")
            if severity:
                return f"Correlation rated the case severity={severity} across {unique_iocs or 0} unique IOCs."
            return "Correlation completed across collected findings."

        verdict = payload.get("verdict")
        if verdict:
            return f"{tool_name} reported verdict={str(verdict).upper()}."

        severity = payload.get("severity")
        if severity:
            return f"{tool_name} reported severity={str(severity).upper()}."

        return ""

    def mark_approval_timeout(
        self,
        *,
        state: Any,
        reviewed_at: str,
    ) -> None:
        errors = getattr(state, "errors", None)
        if isinstance(errors, list):
            errors.append("Approval timed out (30 min)")
        pending_approval = getattr(state, "pending_approval", None)
        if isinstance(pending_approval, dict):
            pending_approval["approved"] = False
            pending_approval["status"] = "timed_out"
            pending_approval["reviewed_at"] = reviewed_at

    def consume_approval_outcome(self, *, state: Any) -> Optional[Dict[str, Any]]:
        clear_approval = getattr(state, "clear_approval", None)
        if not callable(clear_approval):
            return None
        approval = clear_approval()
        if approval is None:
            return None
        setattr(state, "last_approval_outcome", approval)
        return approval

    def build_terminal_status_payload(
        self,
        *,
        state: Any,
        summary: str,
    ) -> Dict[str, Any]:
        findings = getattr(state, "findings", []) or []
        has_final_answer = any(
            isinstance(finding, dict) and finding.get("type") == "final_answer"
            for finding in findings
        )
        return {
            "status": "completed" if getattr(state, "phase", None) == "completed" else "failed",
            "summary": summary,
            "steps": int(getattr(state, "step_count", 0) or 0),
            "record_thread_message": bool(summary) and not has_final_answer,
        }

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
        build_fallback_answer: Callable[[Any, Optional[Dict[str, str]], bool], str],
    ) -> str:
        findings = getattr(state, "findings", []) or []
        errors = getattr(state, "errors", []) or []

        if not findings and errors:
            return (
                "Investigation failed before evidence collection. "
                + " ".join(str(err) for err in errors[:2])
            )[:2000]

        existing_answer = self.summary_from_final_answer(
            findings=findings,
            authoritative_outcome=authoritative_outcome,
        )
        if existing_answer:
            return existing_answer

        try:
            raw = await call_llm_text(prompt)
            if raw:
                return str(raw)[:2000]
        except Exception:
            pass

        return self.build_summary_fallback_answer(
            state=state,
            authoritative_outcome=authoritative_outcome,
            is_chat_session=is_chat_session,
            provider_is_currently_unavailable=provider_is_currently_unavailable,
            provider_name=provider_name,
            build_chat_model_unavailable_answer=build_chat_model_unavailable_answer,
            build_fallback_answer=build_fallback_answer,
        )

    def build_summary_fallback_answer(
        self,
        *,
        state: Any,
        authoritative_outcome: Optional[Dict[str, str]],
        is_chat_session: Callable[[Any], bool],
        provider_is_currently_unavailable: Callable[[Optional[str]], bool],
        provider_name: Optional[str],
        build_chat_model_unavailable_answer: Callable[[Any], str],
        build_fallback_answer: Callable[[Any, Optional[Dict[str, str]], bool], str],
    ) -> str:
        if is_chat_session(state) and provider_is_currently_unavailable(provider_name):
            return build_chat_model_unavailable_answer(state)
        return build_fallback_answer(state, authoritative_outcome, True)

    async def generate_summary_with_runtime_fallback(
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
        build_fallback_answer: Callable[[Any, Optional[Dict[str, str]], bool], str],
    ) -> str:
        try:
            return await self.generate_summary(
                state=state,
                authoritative_outcome=authoritative_outcome,
                prompt=prompt,
                call_llm_text=call_llm_text,
                is_chat_session=is_chat_session,
                provider_is_currently_unavailable=provider_is_currently_unavailable,
                provider_name=provider_name,
                build_chat_model_unavailable_answer=build_chat_model_unavailable_answer,
                build_fallback_answer=build_fallback_answer,
            )
        except Exception:
            return self.build_summary_fallback_answer(
                state=state,
                authoritative_outcome=authoritative_outcome,
                is_chat_session=is_chat_session,
                provider_is_currently_unavailable=provider_is_currently_unavailable,
                provider_name=provider_name,
                build_chat_model_unavailable_answer=build_chat_model_unavailable_answer,
                build_fallback_answer=build_fallback_answer,
            )

    def summary_from_final_answer(
        self,
        *,
        findings: List[Dict[str, Any]],
        authoritative_outcome: Optional[Dict[str, str]],
    ) -> str:
        for finding in reversed(findings):
            if not isinstance(finding, dict) or finding.get("type") != "final_answer":
                continue
            answer = finding.get("answer", "")
            if not answer:
                continue
            if authoritative_outcome and "did not fall back to another model" not in str(answer).lower():
                return f"[{authoritative_outcome['label']}] {answer}"
            return str(answer)
        return ""