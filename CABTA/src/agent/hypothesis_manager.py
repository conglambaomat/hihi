"""Structured hypothesis tracking for agentic investigations.

This module keeps reasoning artifacts JSON-serializable so they can live in
``AgentState`` and ``agent_sessions.metadata`` without a schema migration.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceRef:
    session_id: str
    step_number: int
    finding_index: int
    tool_name: str
    summary: str
    result_path: Optional[str] = None
    stance: str = "neutral"
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Hypothesis:
    id: str
    statement: str
    status: str = "open"
    confidence: float = 0.25
    supporting_evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    contradicting_evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    open_questions: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(float(payload.get("confidence", 0.0)), 3)
        return payload


@dataclass
class RootCauseAssessment:
    primary_root_cause: str
    confidence: float
    causal_chain: List[str]
    supporting_evidence_refs: List[Dict[str, Any]]
    alternative_hypotheses: List[str]
    missing_evidence: List[str]
    summary: str
    assessed_at: str = field(default_factory=_now_iso)
    status: str = "inconclusive"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(float(payload.get("confidence", 0.0)), 3)
        return payload


class HypothesisManager:
    """Owns structured reasoning state for one investigation session."""

    SCHEMA_VERSION = 1

    _IOC_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")

    def bootstrap(self, goal: str, session_id: str, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if isinstance(existing, dict) and existing.get("hypotheses"):
            state = self._normalize_reasoning_state(existing, session_id=session_id, goal=goal)
            state["last_updated_at"] = _now_iso()
            return state

        goal_text = str(goal or "").strip()
        focus = self._extract_focus(goal_text)
        hypotheses = [
            Hypothesis(
                id=self._new_hypothesis_id(),
                statement=f"The activity under investigation involving {focus} reflects a real malicious security incident.",
                confidence=0.35,
                open_questions=[
                    "What evidence directly supports malicious intent?",
                    "Which entities are involved in the observed activity?",
                ],
            ),
            Hypothesis(
                id=self._new_hypothesis_id(),
                statement=f"The observed activity around {focus} is benign, noisy, or lacks enough context to confirm maliciousness.",
                confidence=0.2,
                open_questions=[
                    "What contradictory evidence would show the activity is benign?",
                    "Which missing logs or pivots would reduce uncertainty?",
                ],
            ),
        ]

        domain_specific = self._domain_hypothesis(goal_text)
        if domain_specific is not None:
            hypotheses.append(domain_specific)

        session_questions = [
            f"What is the most likely root cause affecting {focus}?",
            "Which host, user, IP, process, or session is directly involved?",
            "Is the available evidence sufficient to reach a reliable conclusion?",
        ]

        return {
            "schema_version": self.SCHEMA_VERSION,
            "session_id": session_id,
            "status": "collecting_evidence",
            "goal_focus": focus,
            "hypotheses": [hypothesis.to_dict() for hypothesis in hypotheses],
            "open_questions": session_questions,
            "missing_evidence": [],
            "recent_evidence_refs": [],
            "created_at": _now_iso(),
            "last_updated_at": _now_iso(),
        }

    def revise(
        self,
        reasoning_state: Optional[Dict[str, Any]],
        *,
        goal: str,
        session_id: str,
        tool_name: str,
        params: Optional[Dict[str, Any]],
        result: Any,
        finding_index: int,
        step_number: int,
    ) -> Dict[str, Any]:
        state = self.bootstrap(goal, session_id, existing=reasoning_state)
        hypotheses = [self._normalize_hypothesis(item) for item in state.get("hypotheses", [])]
        support_idx, benign_idx = self._base_hypothesis_indexes(hypotheses)

        stance, delta, summary, derived_questions = self._classify_observation(tool_name, params or {}, result)
        evidence = EvidenceRef(
            session_id=session_id,
            step_number=step_number,
            finding_index=finding_index,
            tool_name=tool_name,
            summary=summary,
            stance=stance,
        ).to_dict()

        if support_idx is not None and benign_idx is not None:
            if stance == "supports":
                self._apply_support(hypotheses[support_idx], evidence, delta)
                self._apply_contradiction(hypotheses[benign_idx], evidence, delta)
            elif stance == "contradicts":
                self._apply_contradiction(hypotheses[support_idx], evidence, delta)
                self._apply_support(hypotheses[benign_idx], evidence, delta)

        domain_idx = self._specialized_hypothesis_index(hypotheses)
        if domain_idx is not None and stance in {"supports", "contradicts"}:
            if self._tool_supports_specialized_hypothesis(hypotheses[domain_idx].statement, tool_name, result):
                if stance == "supports":
                    self._apply_support(hypotheses[domain_idx], evidence, max(delta, 0.12))
                else:
                    self._apply_contradiction(hypotheses[domain_idx], evidence, max(delta, 0.12))

        self._merge_questions_into_hypotheses(hypotheses, derived_questions)

        state["hypotheses"] = [hypothesis.to_dict() for hypothesis in hypotheses]
        recent_refs = list(state.get("recent_evidence_refs", []))
        recent_refs.append(evidence)
        state["recent_evidence_refs"] = recent_refs[-10:]
        state["open_questions"] = self._dedupe(
            [*state.get("open_questions", []), *derived_questions]
        )[:8]
        state["missing_evidence"] = self._derive_missing_evidence(hypotheses)
        state["status"] = self._derive_state_status(hypotheses, state["missing_evidence"])
        state["last_updated_at"] = _now_iso()
        return state

    def build_agentic_explanation(
        self,
        reasoning_state: Optional[Dict[str, Any]],
        *,
        goal: str,
        deterministic_decision: Optional[Dict[str, Any]] = None,
        entity_state: Optional[Dict[str, Any]] = None,
        evidence_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        deterministic_decision = deterministic_decision or {}
        state = self.bootstrap(goal, str((reasoning_state or {}).get("session_id") or "session"), existing=reasoning_state)
        hypotheses = [self._normalize_hypothesis(item) for item in state.get("hypotheses", [])]
        ranked = sorted(hypotheses, key=lambda item: item.confidence, reverse=True)
        primary = ranked[0] if ranked else None
        alternatives = [item.statement for item in ranked[1:3]]
        missing = self._dedupe([*state.get("missing_evidence", []), *state.get("open_questions", [])])[:6]
        causal_chain = self._build_causal_chain(
            primary,
            deterministic_decision,
            state.get("recent_evidence_refs", []),
            evidence_state=evidence_state,
        )

        if primary is None:
            assessment = RootCauseAssessment(
                primary_root_cause="Insufficient evidence to determine root cause.",
                confidence=0.0,
                causal_chain=[],
                supporting_evidence_refs=[],
                alternative_hypotheses=[],
                missing_evidence=missing,
                summary="No structured hypotheses are available yet.",
                status="insufficient_evidence",
            )
        else:
            sufficient = primary.status in {"supported", "open"} and bool(primary.supporting_evidence_refs)
            primary_cause = primary.statement if sufficient else "Insufficient evidence to determine root cause confidently."
            status = "supported" if sufficient and primary.status == "supported" else "insufficient_evidence" if not sufficient else "inconclusive"
            summary = (
                f"Primary investigative hypothesis: {primary.statement}"
                if sufficient
                else "The investigation collected some evidence, but root cause is still provisional."
            )
            assessment = RootCauseAssessment(
                primary_root_cause=primary_cause,
                confidence=primary.confidence if sufficient else min(primary.confidence, 0.45),
                causal_chain=causal_chain,
                supporting_evidence_refs=list(primary.supporting_evidence_refs),
                alternative_hypotheses=alternatives,
                missing_evidence=missing,
                summary=summary,
                status=status,
            )

        next_pivots = self._recommended_next_pivots(state, entity_state)
        next_actions = self._recommended_next_actions(deterministic_decision, assessment.to_dict())

        return {
            "root_cause_assessment": assessment.to_dict(),
            "explanation_confidence": assessment.confidence,
            "causal_chain": list(assessment.causal_chain),
            "supporting_evidence_refs": list(assessment.supporting_evidence_refs),
            "alternative_hypotheses": list(assessment.alternative_hypotheses),
            "missing_evidence": list(assessment.missing_evidence),
            "recommended_next_pivots": next_pivots,
            "recommended_next_actions": next_actions,
            "reasoning_status": state.get("status", "collecting_evidence"),
            "entity_summary": self._entity_summary(entity_state),
        }

    def _normalize_reasoning_state(self, raw: Dict[str, Any], *, session_id: str, goal: str) -> Dict[str, Any]:
        state = dict(raw)
        state.setdefault("schema_version", self.SCHEMA_VERSION)
        state.setdefault("session_id", session_id)
        state.setdefault("goal_focus", self._extract_focus(goal))
        state.setdefault("status", "collecting_evidence")
        state.setdefault("open_questions", [])
        state.setdefault("missing_evidence", [])
        state.setdefault("recent_evidence_refs", [])
        state.setdefault("created_at", _now_iso())
        state.setdefault("last_updated_at", _now_iso())
        normalized = [self._normalize_hypothesis(item).to_dict() for item in state.get("hypotheses", [])]
        state["hypotheses"] = normalized
        return state

    def _normalize_hypothesis(self, raw: Dict[str, Any]) -> Hypothesis:
        if isinstance(raw, Hypothesis):
            return raw
        payload = dict(raw or {})
        return Hypothesis(
            id=str(payload.get("id") or self._new_hypothesis_id()),
            statement=str(payload.get("statement") or "Unspecified hypothesis"),
            status=str(payload.get("status") or "open"),
            confidence=float(payload.get("confidence") or 0.0),
            supporting_evidence_refs=list(payload.get("supporting_evidence_refs", [])),
            contradicting_evidence_refs=list(payload.get("contradicting_evidence_refs", [])),
            open_questions=self._dedupe(list(payload.get("open_questions", [])))[:6],
            created_at=str(payload.get("created_at") or _now_iso()),
            updated_at=str(payload.get("updated_at") or _now_iso()),
        )

    def _new_hypothesis_id(self) -> str:
        return f"hyp-{uuid.uuid4().hex[:8]}"

    def _extract_focus(self, goal: str) -> str:
        matches = self._IOC_RE.findall(goal or "")
        if matches:
            return matches[0]
        trimmed = " ".join(str(goal or "").strip().split())
        if len(trimmed) > 96:
            trimmed = trimmed[:93] + "..."
        return trimmed or "the investigation target"

    def _domain_hypothesis(self, goal: str) -> Optional[Hypothesis]:
        lowered = str(goal or "").lower()
        if any(term in lowered for term in ("email", "phish", "sender", "attachment")):
            return Hypothesis(
                id=self._new_hypothesis_id(),
                statement="Initial access likely occurred through phishing or malicious email content.",
                confidence=0.18,
                open_questions=[
                    "Is there delivery evidence tying the email to the affected host or user?",
                    "Was a malicious attachment or link executed after delivery?",
                ],
            )
        if any(term in lowered for term in ("file", "binary", "malware", "sample", "exe", "dll", "script")):
            return Hypothesis(
                id=self._new_hypothesis_id(),
                statement="Malware execution or staged payload activity is central to this investigation.",
                confidence=0.18,
                open_questions=[
                    "Is there execution evidence on disk, process, or sandbox telemetry?",
                    "Can the malware be linked to outbound network activity or persistence?",
                ],
            )
        if any(term in lowered for term in ("login", "credential", "account", "session", "user")):
            return Hypothesis(
                id=self._new_hypothesis_id(),
                statement="Credential misuse or account compromise is the most likely root cause candidate.",
                confidence=0.18,
                open_questions=[
                    "Which authenticated user or session is tied to the suspicious activity?",
                    "Is there evidence of impossible travel, anomalous login, or lateral use of credentials?",
                ],
            )
        return None

    def _base_hypothesis_indexes(self, hypotheses: List[Hypothesis]) -> Tuple[Optional[int], Optional[int]]:
        if not hypotheses:
            return None, None
        support_idx = 0
        benign_idx = 1 if len(hypotheses) > 1 else None
        return support_idx, benign_idx

    def _specialized_hypothesis_index(self, hypotheses: List[Hypothesis]) -> Optional[int]:
        return 2 if len(hypotheses) > 2 else None

    def _classify_observation(
        self,
        tool_name: str,
        params: Dict[str, Any],
        result: Any,
    ) -> Tuple[str, float, str, List[str]]:
        payload = result.get("result") if isinstance(result, dict) and isinstance(result.get("result"), dict) else result
        if not isinstance(payload, dict):
            return (
                "neutral",
                0.0,
                f"{tool_name} returned a non-structured observation.",
                [f"Review raw output from {tool_name} to understand how it affects the investigation."],
            )

        if payload.get("error"):
            return (
                "neutral",
                0.0,
                f"{tool_name} error: {str(payload.get('error'))[:180]}",
                [f"Retry {tool_name} or pivot to an alternate source because this observation failed."],
            )

        verdict = str(payload.get("verdict") or "").upper()
        severity = str(payload.get("severity") or "").upper()
        threat_score = payload.get("threat_score", payload.get("score"))
        found = payload.get("found")
        manual_lookup = payload.get("manual_lookup_required")
        explicit_support = bool(
            payload.get("flagged")
            or payload.get("malicious")
            or payload.get("is_malicious")
            or verdict in {"MALICIOUS", "SUSPICIOUS"}
            or severity in {"HIGH", "CRITICAL"}
            or (isinstance(threat_score, (int, float)) and threat_score >= 70)
        )
        explicit_benign = bool(
            verdict in {"CLEAN", "BENIGN"}
            or severity in {"LOW", "INFO"}
            or (isinstance(threat_score, (int, float)) and threat_score <= 20)
            or found is False
        )
        suspicious_language = self._contains_suspicious_language(payload)
        benign_language = self._contains_benign_language(payload)
        suspicious_indicator = bool(explicit_support or (suspicious_language and not explicit_benign))
        benign_indicator = bool(explicit_benign or (benign_language and not explicit_support))

        summary = self._summarize_payload(tool_name, payload, params)
        open_questions: List[str] = []
        if manual_lookup:
            open_questions.append(f"{tool_name} needs a manual pivot or a richer source to confirm this lead.")
        if payload.get("timed_out"):
            open_questions.append(f"{tool_name} timed out; collect the same evidence from a secondary source.")
        if not suspicious_indicator and not benign_indicator:
            open_questions.append(f"How should the {tool_name} observation change the current hypothesis set?")

        if suspicious_indicator and not benign_indicator:
            delta = 0.16
            if verdict == "MALICIOUS" or severity == "CRITICAL" or (isinstance(threat_score, (int, float)) and threat_score >= 90):
                delta = 0.3
            elif verdict == "SUSPICIOUS" or severity == "HIGH" or (isinstance(threat_score, (int, float)) and threat_score >= 70):
                delta = 0.22
            return "supports", delta, summary, open_questions
        if benign_indicator and not suspicious_indicator:
            delta = 0.16
            if verdict == "BENIGN" or verdict == "CLEAN" or severity == "LOW" or (isinstance(threat_score, (int, float)) and threat_score <= 10):
                delta = 0.3
            return "contradicts", delta, summary, open_questions
        return "neutral", 0.05 if suspicious_indicator or benign_indicator else 0.0, summary, open_questions

    def _contains_suspicious_language(self, payload: Dict[str, Any]) -> bool:
        blob = jsonish(payload).lower()
        return any(term in blob for term in ("phishing", "beacon", "c2", "malware", "ransom", "newly_registered", "suspicious"))

    def _contains_benign_language(self, payload: Dict[str, Any]) -> bool:
        blob = jsonish(payload).lower()
        return any(term in blob for term in ("benign", "legitimate", "known good", "no findings", "clean"))

    def _summarize_payload(self, tool_name: str, payload: Dict[str, Any], params: Dict[str, Any]) -> str:
        if payload.get("verdict"):
            verdict = str(payload.get("verdict")).upper()
            score = payload.get("threat_score", payload.get("score"))
            if score is not None:
                return f"{tool_name} reported verdict={verdict} with score={score}."
            return f"{tool_name} reported verdict={verdict}."
        if payload.get("severity"):
            return f"{tool_name} reported severity={str(payload.get('severity')).upper()}."
        if payload.get("error"):
            return f"{tool_name} failed with error={str(payload.get('error'))[:160]}."
        if payload.get("manual_lookup_required"):
            return f"{tool_name} requires a manual lookup to continue the pivot."

        interesting = []
        for key in ("ioc", "ip", "domain", "host", "user", "session_id"):
            value = payload.get(key) or params.get(key)
            if value:
                interesting.append(f"{key}={value}")
        if interesting:
            return f"{tool_name} observed " + ", ".join(interesting[:3]) + "."
        return f"{tool_name} returned additional evidence."

    def _apply_support(self, hypothesis: Hypothesis, evidence: Dict[str, Any], delta: float) -> None:
        hypothesis.supporting_evidence_refs.append(evidence)
        hypothesis.confidence = min(0.99, hypothesis.confidence + max(delta, 0.05))
        hypothesis.status = "supported" if hypothesis.confidence >= 0.6 else "open"
        hypothesis.updated_at = _now_iso()

    def _apply_contradiction(self, hypothesis: Hypothesis, evidence: Dict[str, Any], delta: float) -> None:
        hypothesis.contradicting_evidence_refs.append(evidence)
        hypothesis.confidence = max(0.01, hypothesis.confidence - max(delta, 0.05))
        if hypothesis.confidence <= 0.2:
            hypothesis.status = "contradicted"
        elif hypothesis.status == "supported":
            hypothesis.status = "inconclusive"
        hypothesis.updated_at = _now_iso()

    def _merge_questions_into_hypotheses(self, hypotheses: List[Hypothesis], questions: List[str]) -> None:
        if not questions:
            return
        for hypothesis in hypotheses:
            hypothesis.open_questions = self._dedupe([*hypothesis.open_questions, *questions])[:6]
            hypothesis.updated_at = _now_iso()

    def _derive_missing_evidence(self, hypotheses: List[Hypothesis]) -> List[str]:
        missing: List[str] = []
        for hypothesis in hypotheses:
            if not hypothesis.supporting_evidence_refs:
                missing.extend(hypothesis.open_questions[:2])
            if hypothesis.status == "supported" and not hypothesis.contradicting_evidence_refs:
                continue
        return self._dedupe(missing)[:6]

    def _derive_state_status(self, hypotheses: List[Hypothesis], missing_evidence: List[str]) -> str:
        if any(hypothesis.status == "supported" and hypothesis.confidence >= 0.7 for hypothesis in hypotheses):
            return "sufficient_evidence"
        if missing_evidence and not any(hypothesis.supporting_evidence_refs for hypothesis in hypotheses):
            return "insufficient_evidence"
        return "collecting_evidence"

    def _tool_supports_specialized_hypothesis(self, statement: str, tool_name: str, result: Any) -> bool:
        statement_lower = statement.lower()
        tool_lower = str(tool_name or "").lower()
        payload = jsonish(result).lower()
        if "phishing" in statement_lower:
            return any(term in tool_lower or term in payload for term in ("email", "phish", "attachment", "sender"))
        if "malware" in statement_lower or "payload" in statement_lower:
            return any(term in tool_lower or term in payload for term in ("malware", "sandbox", "yara", "hash", "sample"))
        if "credential" in statement_lower or "account compromise" in statement_lower:
            return any(term in tool_lower or term in payload for term in ("user", "login", "session", "auth", "credential"))
        return False

    def _build_causal_chain(
        self,
        hypothesis: Optional[Hypothesis],
        deterministic_decision: Dict[str, Any],
        evidence_refs: List[Dict[str, Any]],
        *,
        evidence_state: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        if hypothesis is None:
            return []
        chain = [hypothesis.statement]
        for evidence in hypothesis.supporting_evidence_refs[:3]:
            summary = str(evidence.get("summary") or "").strip()
            if summary:
                chain.append(summary)
        if isinstance(evidence_state, dict):
            timeline = evidence_state.get("timeline", []) if isinstance(evidence_state.get("timeline"), list) else []
            for event in timeline[-3:]:
                summary = str(event.get("summary") or "").strip()
                if summary and summary not in chain:
                    chain.append(summary)
        verdict = deterministic_decision.get("verdict")
        if verdict:
            chain.append(f"Deterministic decision remains {str(verdict).upper()}.")
        if len(chain) == 1:
            for evidence in evidence_refs[:2]:
                summary = str(evidence.get("summary") or "").strip()
                if summary:
                    chain.append(summary)
        return chain[:5]

    def _recommended_next_pivots(self, state: Dict[str, Any], entity_state: Optional[Dict[str, Any]]) -> List[str]:
        questions = list(state.get("open_questions", []))
        relationships = entity_state.get("relationships", []) if isinstance(entity_state, dict) and isinstance(entity_state.get("relationships"), list) else []
        entity_types = {}
        if isinstance(entity_state, dict) and isinstance(entity_state.get("entities"), dict):
            entity_types = {
                entity_id: payload.get("type")
                for entity_id, payload in entity_state.get("entities", {}).items()
                if isinstance(payload, dict)
            }

        if relationships:
            for relationship in relationships[:8]:
                relation = relationship.get("relation")
                source = relationship.get("source")
                target = relationship.get("target")
                source_type = entity_types.get(source)
                target_type = entity_types.get(target)
                if relation == "associated_with" and {source_type, target_type} == {"user", "ip"}:
                    questions.append("Which host and session connect the observed user and IP together?")
                if relation == "occurred_on" and {source_type, target_type} == {"session", "host"}:
                    questions.append("What user and process activity followed the suspicious session on that host?")
                if relation == "follows_session" and {source_type, target_type} == {"process", "session"}:
                    questions.append("Which outbound IPs or files were linked to the process after the session began?")

        entity_counts = set(entity_types.values())
        if "ip" in entity_counts and "user" not in entity_counts:
            questions.append("Which user is associated with the suspicious IP activity?")
        if "session" in entity_counts and "host" not in entity_counts:
            questions.append("What host did the suspicious session occur on?")
        if "session" in entity_counts and "process" not in entity_counts:
            questions.append("What process activity followed the suspicious session?")
        return self._dedupe(questions)[:5]

    def _recommended_next_actions(
        self,
        deterministic_decision: Dict[str, Any],
        root_cause_assessment: Dict[str, Any],
    ) -> List[str]:
        actions: List[str] = []
        verdict = str(deterministic_decision.get("verdict") or "").upper()
        if verdict in {"MALICIOUS", "SUSPICIOUS"}:
            actions.append("Correlate the current evidence with host, user, and session telemetry before closing the case.")
            actions.append("Preserve the supporting evidence chain and pivot to adjacent entities for scope expansion.")
        if root_cause_assessment.get("status") == "insufficient_evidence":
            actions.append("Collect additional logs or endpoint telemetry to resolve the remaining open questions.")
        actions.append("Review contradictory evidence before final analyst sign-off.")
        return self._dedupe(actions)[:4]

    def _entity_summary(self, entity_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not isinstance(entity_state, dict):
            return {"entity_count": 0, "relationship_count": 0}
        entities = entity_state.get("entities", {})
        relationships = entity_state.get("relationships", [])
        return {
            "entity_count": len(entities) if isinstance(entities, dict) else 0,
            "relationship_count": len(relationships) if isinstance(relationships, list) else 0,
        }

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            normalized = str(value or "").strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(normalized)
        return result


def jsonish(value: Any) -> str:
    try:
        import json

        return json.dumps(value, default=str)
    except Exception:
        return str(value)
