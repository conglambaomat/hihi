"""Route specialist-team ownership and handoffs for CABTA investigation sessions."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional


class SpecialistRouter:
    """Own specialist team resolution and evidence-driven routing decisions."""

    def __init__(
        self,
        *,
        workflow_registry: Any = None,
        agent_profiles: Any = None,
        notify: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        log_decision: Optional[Callable[..., None]] = None,
    ) -> None:
        self.workflow_registry = workflow_registry
        self.agent_profiles = agent_profiles
        self.notify = notify
        self.log_decision = log_decision

    def resolve_specialist_team(self, metadata: Optional[Dict[str, Any]] = None) -> List[str]:
        """Resolve the ordered specialist team for a session."""
        metadata = dict(metadata or {})
        requested_team = metadata.get("specialist_team")
        workflow_id = metadata.get("workflow_id")
        workflow_team: List[str] = []
        if workflow_id and self.workflow_registry is not None:
            workflow = self.workflow_registry.get_workflow(workflow_id) or {}
            workflow_team = [str(item).strip() for item in workflow.get("agents", []) if str(item).strip()]

        candidates: List[str] = []
        if isinstance(requested_team, list):
            candidates.extend(str(item).strip() for item in requested_team if str(item).strip())
        candidates.extend(workflow_team)

        requested_profile = str(metadata.get("agent_profile_id") or "").strip()
        if requested_profile and requested_profile not in candidates:
            candidates.insert(0, requested_profile)

        if not candidates:
            candidates = [requested_profile or "workflow_controller"]

        resolved: List[str] = []
        for profile_id in candidates:
            if not profile_id or profile_id in resolved:
                continue
            if self.agent_profiles is not None and self.agent_profiles.get_profile(profile_id) is None:
                continue
            resolved.append(profile_id)
        return resolved or ["workflow_controller"]

    def assess_specialist_routing(self, state: Any) -> Dict[str, Any]:
        if not getattr(state, "specialist_team", None):
            return {
                "selected_index": None,
                "selected_profile": None,
                "reason": "no_specialist_team",
                "scores": {},
                "ranked_candidates": [],
                "winning_score": 0,
                "tie_detected": False,
                "signals": {},
            }

        profiles = list(state.specialist_team)
        active_observations = [
            item for item in getattr(state, "active_observations", [])[-8:]
            if isinstance(item, dict)
        ]
        observation_types = {
            str(item.get("observation_type") or "").strip().lower()
            for item in active_observations
        }
        fact_families = {
            str(
                item.get("fact_family")
                or ((item.get("typed_fact") or {}).get("family") if isinstance(item.get("typed_fact"), dict) else "")
                or ""
            ).strip().lower()
            for item in active_observations
            if isinstance(item, dict)
        }
        fact_families.discard("")
        agentic_explanation = getattr(state, "agentic_explanation", {}) if isinstance(getattr(state, "agentic_explanation", {}), dict) else {}
        missing_evidence = [
            *getattr(state, "unresolved_questions", []),
            *(agentic_explanation.get("missing_evidence", []) if isinstance(agentic_explanation, dict) else []),
        ]
        missing_text = " ".join(str(item) for item in missing_evidence).lower()
        top_gap = str(missing_evidence[0] if missing_evidence else "").lower()
        investigation_plan = getattr(state, "investigation_plan", {}) if isinstance(getattr(state, "investigation_plan", {}), dict) else {}
        reasoning_state = getattr(state, "reasoning_state", {}) if isinstance(getattr(state, "reasoning_state", {}), dict) else {}
        lane = str(
            investigation_plan.get("lane")
            or reasoning_state.get("investigation_lane")
            or ""
        ).lower()
        root_cause = agentic_explanation.get("root_cause_assessment", {}) if isinstance(agentic_explanation, dict) else {}
        entity_state = getattr(state, "entity_state", {}) if isinstance(getattr(state, "entity_state", {}), dict) else {}
        entity_types = {
            str(entity.get("type") or "").strip().lower()
            for entity in list((entity_state.get("entities", {}) or {}).values())
            if isinstance(entity, dict)
        }
        relationships = [
            item for item in (entity_state.get("relationships", []) or [])
            if isinstance(item, dict)
        ]
        explicit_relations = {
            str(item.get("relation") or "").strip().lower()
            for item in relationships
            if str(item.get("relation_strength") or "").strip().lower() == "explicit"
        }
        inferred_relations = {
            str(item.get("relation") or "").strip().lower()
            for item in relationships
            if str(item.get("relation_strength") or "").strip().lower() == "inferred"
        }
        co_observed_only = bool(relationships) and not explicit_relations and not inferred_relations
        recent_fact_text = " ".join(
            str(item.get("summary") or "")
            for item in getattr(state, "accepted_facts", [])[-6:]
            if isinstance(item, dict)
        ).lower()
        memory_scope = str(
            getattr(state, "chat_context_restored_memory_scope", None)
            or getattr(state, "restored_memory_scope", None)
            or ""
        ).lower()
        ranked_hypotheses = [
            item for item in (reasoning_state.get("hypotheses", []) or [])
            if isinstance(item, dict)
        ]
        active_hypothesis = ranked_hypotheses[0] if ranked_hypotheses else {}
        active_hypothesis_topics = {
            str(item).strip().lower()
            for item in active_hypothesis.get("topics", [])
            if str(item).strip()
        }
        active_hypothesis_text = " ".join(
            [
                str(active_hypothesis.get("statement") or ""),
                " ".join(str(item) for item in active_hypothesis.get("open_questions", []) if str(item).strip()),
            ]
        ).lower()

        def _find_index(*tokens: str) -> Optional[int]:
            for idx, profile in enumerate(profiles):
                lowered = str(profile or "").lower()
                if any(token in lowered for token in tokens):
                    return idx
            return None

        signals = {
            "lane": lane,
            "observation_types": sorted(observation_types),
            "fact_families": sorted(fact_families),
            "entity_types": sorted(entity_types),
            "explicit_relations": sorted(explicit_relations),
            "inferred_relations": sorted(inferred_relations),
            "co_observed_only": co_observed_only,
            "top_gap": top_gap,
            "memory_scope": memory_scope,
            "root_cause_status": str(root_cause.get("status") or "").lower(),
            "active_hypothesis_status": str(active_hypothesis.get("status") or "").lower(),
            "active_hypothesis_topics": sorted(active_hypothesis_topics),
        }

        if root_cause.get("status") == "supported":
            selected_index = _find_index("correl", "report", "investigator")
            selected_profile = profiles[selected_index] if selected_index is not None else None
            ranked_candidates = (
                [{"profile": selected_profile, "score": 1, "reasons": ["supported_root_cause"]}]
                if selected_profile is not None
                else []
            )
            return {
                "selected_index": selected_index,
                "selected_profile": selected_profile,
                "reason": "supported_root_cause",
                "scores": {},
                "ranked_candidates": ranked_candidates,
                "winning_score": 1 if selected_profile is not None else 0,
                "tie_detected": False,
                "signals": signals,
            }

        scores: Dict[int, int] = {}
        score_reasons: Dict[int, List[str]] = {}

        def _score(match_tokens: List[str], points: int, reason: str) -> None:
            for idx, profile in enumerate(profiles):
                lowered = str(profile or "").lower()
                if any(token in lowered for token in match_tokens):
                    scores[idx] = scores.get(idx, 0) + points
                    score_reasons.setdefault(idx, []).append(reason)

        if (
            lane in {"email"}
            or "email_delivery" in observation_types
            or "email" in fact_families
            or {"email", "sender", "recipient"} & entity_types
            or {"email", "phishing", "delivery", "attachment"} & active_hypothesis_topics
            or any(token in active_hypothesis_text for token in ("phish", "email", "sender", "recipient", "attachment"))
        ):
            _score(["phish", "email"], 5, "email_lane_or_entities")
        if (
            {"file_execution", "process_event", "sandbox_behavior"} & observation_types
            or "file" in fact_families
            or {"file", "hash", "process"} & entity_types
            or {"malware", "process", "payload", "sandbox", "execution"} & active_hypothesis_topics
            or any(token in active_hypothesis_text for token in ("payload", "malware", "process", "sandbox", "execution"))
        ):
            _score(["malware", "endpoint"], 5, "malware_execution_signals")
        if (
            lane == "log_identity"
            or "auth_event" in observation_types
            or "log" in fact_families
            or {"user", "session"} & entity_types
            or {"identity", "credential", "session", "user", "account", "logon"} & active_hypothesis_topics
            or any(token in active_hypothesis_text for token in ("credential", "identity", "session", "account", "logon"))
        ):
            _score(["identity", "investigator"], 4, "identity_signals")
        if (
            "network_event" in observation_types
            or {"network", "ioc"} & fact_families
            or {"ip", "domain", "url"} & entity_types
            or {"network", "beacon", "c2", "infrastructure", "domain", "ip"} & active_hypothesis_topics
            or any(token in active_hypothesis_text for token in ("network", "beacon", "c2", "domain", "ip", "infrastructure"))
        ):
            _score(["network", "forensics"], 4, "network_signals")
        if "vulnerability" in fact_families or lane == "vulnerability":
            _score(["vuln", "exposure", "investigator", "correl"], 4, "vulnerability_signals")

        if {"received_from", "received_attachment"} & explicit_relations or "email_delivery" in observation_types:
            _score(["phish", "email"], 4, "explicit_email_delivery_relations")
        if {"spawned_process", "executed_on"} & explicit_relations or {"derived_from"} & inferred_relations:
            _score(["malware", "endpoint"], 4, "process_or_payload_relations")
        if {"belongs_to", "authenticated_from", "occurred_on"} & explicit_relations:
            _score(["identity", "investigator"], 4, "explicit_identity_relations")
        if {"connects_to", "originates_from"} & explicit_relations:
            _score(["network", "forensics"], 4, "explicit_network_relations")

        if any(token in missing_text for token in ("identity", "user", "account", "session", "logon")):
            _score(["identity", "investigator"], 3, "missing_identity_evidence")
        if any(token in missing_text for token in ("process", "binary", "command line", "execution", "malware")):
            _score(["malware", "endpoint"], 3, "missing_process_evidence")
        if any(token in missing_text for token in ("network", "destination", "beacon", "registrar", "infrastructure", "domain")):
            _score(["network", "forensics", "investigator"], 3, "missing_network_evidence")
        if any(token in recent_fact_text for token in ("phishing", "sender", "attachment", "delivery")):
            _score(["phish", "email"], 2, "recent_email_facts")
        if any(token in recent_fact_text for token in ("powershell", "process", "payload", "sandbox")):
            _score(["malware", "endpoint"], 2, "recent_malware_facts")
        if any(token in recent_fact_text for token in ("login", "session", "credential", "account")):
            _score(["identity", "investigator"], 2, "recent_identity_facts")
        if any(token in recent_fact_text for token in ("c2", "beacon", "dns", "domain", "ip")):
            _score(["network", "forensics"], 2, "recent_network_facts")

        if any(token in top_gap for token in ("sender", "recipient", "attachment", "delivery")):
            _score(["phish", "email"], 4, "top_gap_email_delivery")
        if any(token in top_gap for token in ("process", "execution", "payload", "sandbox")):
            _score(["malware", "endpoint"], 4, "top_gap_process_execution")
        if any(token in top_gap for token in ("identity", "user", "session", "host", "logon")):
            _score(["identity", "investigator"], 4, "top_gap_identity")
        if any(token in top_gap for token in ("network", "destination", "domain", "ip", "infrastructure", "beacon")):
            _score(["network", "forensics"], 4, "top_gap_network")

        if co_observed_only:
            _score(["investigator", "triage"], 2, "co_observed_only")
        if memory_scope == "accepted":
            _score(["investigator", "correl"], 1, "accepted_memory_scope_bias")

        if not scores:
            current_index = getattr(state, "specialist_index", None)
            current_profile = getattr(state, "active_specialist", None)
            current_profile_valid = (
                isinstance(current_index, int)
                and 0 <= current_index < len(profiles)
                and current_profile == profiles[current_index]
            )
            if current_profile_valid:
                return {
                    "selected_index": current_index,
                    "selected_profile": current_profile,
                    "reason": "stay_with_current_specialist",
                    "scores": {},
                    "ranked_candidates": [
                        {
                            "profile": current_profile,
                            "score": 0,
                            "reasons": ["stay_with_current_specialist"],
                        }
                    ],
                    "winning_score": 0,
                    "tie_detected": False,
                    "signals": signals,
                }
            return {
                "selected_index": None,
                "selected_profile": None,
                "reason": "no_evidence_signal",
                "scores": {},
                "ranked_candidates": [],
                "winning_score": 0,
                "tie_detected": False,
                "signals": signals,
            }

        ranked_candidates = sorted(
            [
                {
                    "profile": profiles[idx],
                    "score": score,
                    "reasons": score_reasons.get(idx, []),
                }
                for idx, score in scores.items()
            ],
            key=lambda item: (-int(item["score"]), str(item["profile"])),
        )
        best_index, best_score = max(scores.items(), key=lambda item: item[1])
        tie_detected = sum(1 for score in scores.values() if score == best_score) > 1
        return {
            "selected_index": best_index if best_score > 0 else None,
            "selected_profile": profiles[best_index] if best_score > 0 else None,
            "reason": "evidence_signal_match" if best_score > 0 else "no_positive_score",
            "scores": {
                profiles[idx]: {
                    "score": score,
                    "reasons": score_reasons.get(idx, []),
                }
                for idx, score in scores.items()
            },
            "ranked_candidates": ranked_candidates,
            "winning_score": best_score if best_score > 0 else 0,
            "tie_detected": tie_detected if best_score > 0 else False,
            "signals": signals,
        }

    def specialist_index_from_evidence(self, state: Any) -> Optional[int]:
        return self.assess_specialist_routing(state).get("selected_index")

    def sync_specialist_progress(
        self,
        *,
        session_id: str,
        state: Any,
        store: Any,
        persist_specialist_metadata: Callable[..., None],
        reason: str = "",
    ) -> None:
        """Rotate the active specialist based on evidence and workflow progress."""
        if not getattr(state, "specialist_team", None):
            return

        if len(state.specialist_team) == 1:
            state.active_specialist = state.specialist_team[0]
            state.agent_profile_id = state.specialist_team[0]
            state.specialist_index = 0
            persist_specialist_metadata(session_id, state, reason=reason)
            return

        max_steps = max(getattr(state, "max_steps", 0), len(state.specialist_team), 1)
        current_index = getattr(state, "specialist_index", 0)
        current_profile = getattr(state, "active_specialist", None)
        assessment = self.assess_specialist_routing(state)
        desired_index = assessment.get("selected_index")
        routing_reason = reason or str(assessment.get("reason") or "")

        if desired_index is None:
            current_profile_valid = (
                isinstance(current_index, int)
                and 0 <= current_index < len(state.specialist_team)
                and current_profile == state.specialist_team[current_index]
            )
            if current_profile_valid:
                desired_index = current_index
                routing_reason = reason or "No stronger evidence-based handoff signal; keeping current specialist ownership"
            else:
                desired_index = min(
                    int((max(getattr(state, "step_count", 0), 0) / max_steps) * len(state.specialist_team)),
                    len(state.specialist_team) - 1,
                )
                routing_reason = reason or f"Workflow progression moved ownership to specialist phase {desired_index + 1}"

        if desired_index != current_index:
            from_profile = current_profile
            to_profile = state.specialist_team[desired_index]
            handoff_reason = routing_reason or f"Workflow progression moved ownership to specialist phase {desired_index + 1}"
            handoff = state.record_specialist_handoff(from_profile, to_profile, handoff_reason)
            store.add_step(
                session_id,
                getattr(state, "step_count", 0),
                "specialist_handoff",
                json.dumps(handoff, default=str),
            )
            if self.notify is not None:
                self.notify(
                    session_id,
                    {
                        "type": "specialist_handoff",
                        "step": getattr(state, "step_count", 0),
                        "from_profile": from_profile,
                        "to_profile": to_profile,
                        "reason": handoff_reason,
                    },
                )
            if self.log_decision is not None:
                self.log_decision(
                    session_id,
                    state,
                    decision_type="specialist_handoff",
                    summary=f"Handoff from {from_profile or 'unassigned'} to {to_profile}",
                    rationale=handoff_reason,
                    metadata=handoff,
                )

        persist_specialist_metadata(session_id, state, reason=routing_reason or reason)
