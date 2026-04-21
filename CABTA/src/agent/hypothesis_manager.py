"""Structured hypothesis tracking for agentic investigations."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


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
    observation_id: Optional[str] = None
    source_kind: str = "tool_result"
    source_path: str = "result"
    quality: float = 0.0
    entity_ids: List[str] = field(default_factory=list)
    extraction_method: str = "normalizer"
    confidence: float = 0.0
    stance: str = "neutral"
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["quality"] = round(float(payload.get("quality", 0.0)), 3)
        payload["confidence"] = round(float(payload.get("confidence", 0.0)), 3)
        return payload


@dataclass
class Hypothesis:
    id: str
    statement: str
    status: str = "open"
    confidence: float = 0.25
    topics: List[str] = field(default_factory=list)
    supporting_evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    contradicting_evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    open_questions: List[str] = field(default_factory=list)
    evidence_score: float = 0.0
    contradiction_score: float = 0.0
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    last_updated_at: str = field(default_factory=_now_iso)
    priority: float = 0.0
    ranking_score: float = 0.0
    competition_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(float(payload.get("confidence", 0.0)), 3)
        payload["evidence_score"] = round(float(payload.get("evidence_score", 0.0)), 3)
        payload["contradiction_score"] = round(float(payload.get("contradiction_score", 0.0)), 3)
        payload["priority"] = round(float(payload.get("priority", 0.0)), 3)
        payload["ranking_score"] = round(float(payload.get("ranking_score", 0.0)), 3)
        payload["competition_score"] = round(float(payload.get("competition_score", 0.0)), 3)
        return payload


@dataclass
class ObservationAssessment:
    stance: str
    evidence_strength: float
    evidence_quality: float
    tool_reliability: float
    entity_coverage: float
    causal_relevance: float
    tags: List[str]
    summary: str
    open_questions: List[str]


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
    """Own structured reasoning state for one CABTA investigation session."""

    SCHEMA_VERSION = 2
    _IOC_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")

    def bootstrap(
        self,
        goal: str,
        session_id: str,
        existing: Optional[Dict[str, Any]] = None,
        investigation_plan: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if isinstance(existing, dict) and (
            existing.get("hypotheses")
            or existing.get("goal_focus")
            or existing.get("open_questions")
            or existing.get("missing_evidence")
            or existing.get("recent_evidence_refs")
        ):
            state = self._normalize_reasoning_state(existing, session_id=session_id, goal=goal)
            state["last_updated_at"] = _now_iso()
            if investigation_plan:
                state["plan"] = dict(investigation_plan)
                state["investigation_lane"] = investigation_plan.get("lane")
            return state

        goal_text = str(goal or "").strip()
        focus = self._extract_focus(goal_text)
        lane = str((investigation_plan or {}).get("lane") or self._lane_from_goal(goal_text))
        seeded = self._seed_hypotheses(goal_text, lane, investigation_plan)
        session_questions = self._default_open_questions(lane, focus)

        seeded_missing = [
            str(item)
            for item in ((investigation_plan or {}).get("evidence_gaps") or [])
            if str(item).strip()
        ]
        return {
            "schema_version": self.SCHEMA_VERSION,
            "session_id": session_id,
            "status": "collecting_evidence",
            "goal_focus": focus,
            "investigation_lane": lane,
            "plan": dict(investigation_plan or {}),
            "hypotheses": [item.to_dict() for item in seeded],
            "open_questions": session_questions,
            "missing_evidence": seeded_missing[:8],
            "recent_evidence_refs": [],
            "competition": {},
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
        observations: Optional[List[Dict[str, Any]]] = None,
        entity_state: Optional[Dict[str, Any]] = None,
        evidence_state: Optional[Dict[str, Any]] = None,
        investigation_plan: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        state = self.bootstrap(
            goal,
            session_id,
            existing=reasoning_state,
            investigation_plan=investigation_plan,
        )
        hypotheses = [self._normalize_hypothesis(item) for item in state.get("hypotheses", [])]
        normalized_observations = observations or [self._legacy_observation(tool_name, params or {}, result, session_id, step_number)]

        recent_refs = list(state.get("recent_evidence_refs", []))
        question_accumulator = list(state.get("open_questions", []))
        for observation in normalized_observations:
            if not isinstance(observation, dict):
                continue
            evidence_ref = self._build_evidence_ref(
                observation=observation,
                session_id=session_id,
                tool_name=tool_name,
                step_number=step_number,
                finding_index=finding_index,
            )
            recent_ref_payload = evidence_ref.to_dict()
            observation_supported = False
            observation_contradicted = False
            strongest_strength = 0.0
            for hypothesis in hypotheses:
                assessment = self._assess_observation(
                    hypothesis=hypothesis,
                    observation=observation,
                    tool_name=tool_name,
                    entity_state=entity_state,
                    evidence_state=evidence_state,
                    lane=str(state.get("investigation_lane") or ""),
                )
                if assessment.stance == "supports":
                    observation_supported = True
                    strongest_strength = max(strongest_strength, assessment.evidence_strength)
                    self._apply_support(hypothesis, evidence_ref.to_dict(), assessment)
                elif assessment.stance == "contradicts":
                    observation_contradicted = True
                    strongest_strength = max(strongest_strength, assessment.evidence_strength)
                    self._apply_contradiction(hypothesis, evidence_ref.to_dict(), assessment)
                hypothesis.open_questions = self._dedupe([*hypothesis.open_questions, *assessment.open_questions])[:6]
                self._refresh_hypothesis_status(hypothesis)
                question_accumulator.extend(assessment.open_questions)
            recent_ref_payload["stance"] = "supports" if observation_supported else "contradicts" if observation_contradicted else "neutral"
            if strongest_strength:
                recent_ref_payload["confidence"] = round(max(float(recent_ref_payload.get("confidence", 0.0) or 0.0), strongest_strength), 3)
            recent_refs.append(recent_ref_payload)

        ranked_hypotheses = self._rank_hypotheses(hypotheses)
        state["hypotheses"] = [item.to_dict() for item in ranked_hypotheses]
        state["recent_evidence_refs"] = recent_refs[-16:]
        state["open_questions"] = self._dedupe(question_accumulator)[:10]
        state["missing_evidence"] = self._derive_missing_evidence(
            hypotheses,
            entity_state=entity_state,
            evidence_state=evidence_state,
            lane=str(state.get("investigation_lane") or ""),
            plan=state.get("plan"),
        )
        state["competition"] = self._competition_state(ranked_hypotheses)
        state["status"] = self._derive_state_status(ranked_hypotheses, state["missing_evidence"])
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
        root_cause_assessment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        state = self.bootstrap(goal, str((reasoning_state or {}).get("session_id") or "session"), existing=reasoning_state)
        hypotheses = self._rank_hypotheses([self._normalize_hypothesis(item) for item in state.get("hypotheses", [])])
        primary = hypotheses[0] if hypotheses else None
        alternatives = [item.statement for item in hypotheses[1:4]]
        missing = self._dedupe([*state.get("missing_evidence", []), *state.get("open_questions", [])])[:8]
        assessment = root_cause_assessment or {}
        if not assessment and primary is not None:
            status = "supported" if primary.status == "supported" else "inconclusive"
            assessment = RootCauseAssessment(
                primary_root_cause=primary.statement,
                confidence=primary.confidence,
                causal_chain=[primary.statement],
                supporting_evidence_refs=list(primary.supporting_evidence_refs)[:8],
                alternative_hypotheses=alternatives,
                missing_evidence=missing,
                summary=f"Current lead hypothesis: {primary.statement}",
                status=status,
            ).to_dict()

        return {
            "root_cause_assessment": assessment,
            "explanation_confidence": float(assessment.get("confidence", 0.0) or 0.0),
            "causal_chain": list(assessment.get("causal_chain", []) or []),
            "supporting_evidence_refs": list(assessment.get("supporting_evidence_refs", []) or []),
            "alternative_hypotheses": list(assessment.get("alternative_hypotheses", alternatives) or []),
            "missing_evidence": list(assessment.get("missing_evidence", missing) or []),
            "competition": self._competition_state(hypotheses),
            "recommended_next_pivots": self._recommended_next_pivots(state, entity_state),
            "recommended_next_actions": self._recommended_next_actions(deterministic_decision or {}, assessment),
            "reasoning_status": state.get("status", "collecting_evidence"),
            "entity_summary": self._entity_summary(entity_state),
            "hypotheses": [item.to_dict() for item in hypotheses[:5]],
        }

    def _normalize_reasoning_state(self, raw: Dict[str, Any], *, session_id: str, goal: str) -> Dict[str, Any]:
        state = dict(raw)
        state.setdefault("schema_version", self.SCHEMA_VERSION)
        state.setdefault("session_id", session_id)
        state.setdefault("goal_focus", self._extract_focus(goal))
        state.setdefault("status", "collecting_evidence")
        state.setdefault("investigation_lane", self._lane_from_goal(goal))
        state.setdefault("plan", {})
        state.setdefault("open_questions", [])
        state.setdefault("missing_evidence", [])
        state.setdefault("recent_evidence_refs", [])
        state.setdefault("competition", {})
        state.setdefault("created_at", _now_iso())
        state.setdefault("last_updated_at", _now_iso())
        state["hypotheses"] = [self._normalize_hypothesis(item).to_dict() for item in state.get("hypotheses", [])]
        return state

    def _normalize_hypothesis(self, raw: Dict[str, Any]) -> Hypothesis:
        if isinstance(raw, Hypothesis):
            return raw
        payload = dict(raw or {})
        updated_at = str(payload.get("updated_at") or payload.get("last_updated_at") or _now_iso())
        return Hypothesis(
            id=str(payload.get("id") or self._new_hypothesis_id()),
            statement=str(payload.get("statement") or "Unspecified hypothesis"),
            status=str(payload.get("status") or "open"),
            confidence=float(payload.get("confidence") or 0.0),
            topics=self._dedupe(list(payload.get("topics", [])))[:6],
            supporting_evidence_refs=list(payload.get("supporting_evidence_refs", [])),
            contradicting_evidence_refs=list(payload.get("contradicting_evidence_refs", [])),
            open_questions=self._dedupe(list(payload.get("open_questions", [])))[:8],
            evidence_score=float(payload.get("evidence_score") or 0.0),
            contradiction_score=float(payload.get("contradiction_score") or 0.0),
            created_at=str(payload.get("created_at") or _now_iso()),
            updated_at=updated_at,
            last_updated_at=str(payload.get("last_updated_at") or updated_at),
            priority=float(payload.get("priority") or 0.0),
            ranking_score=float(payload.get("ranking_score") or payload.get("priority") or 0.0),
            competition_score=float(payload.get("competition_score") or 0.0),
        )

    def _seed_hypotheses(self, goal: str, lane: str, investigation_plan: Optional[Dict[str, Any]]) -> List[Hypothesis]:
        statements = list((investigation_plan or {}).get("initial_hypotheses", []))
        if not statements:
            focus = self._extract_focus(goal)
            statements = [
                f"The activity under investigation involving {focus} reflects a real malicious security incident.",
                f"The observed activity around {focus} is benign, noisy, or lacks enough context to confirm maliciousness.",
            ]
            specialized = self._specialized_statement(lane)
            if specialized:
                statements.append(specialized)
        hypotheses: List[Hypothesis] = []
        for index, statement in enumerate(statements):
            topics = self._topics_for_statement(statement, lane)
            confidence = 0.34 if index == 0 else 0.2 if index == 1 else 0.18
            hypotheses.append(
                Hypothesis(
                    id=self._new_hypothesis_id(),
                    statement=statement,
                    confidence=confidence,
                    topics=topics,
                    open_questions=self._open_questions_for_topics(topics),
                    priority=confidence,
                    ranking_score=confidence,
                )
            )
        return hypotheses

    def _specialized_statement(self, lane: str) -> Optional[str]:
        if lane == "email":
            return "Initial access likely occurred through phishing or malicious email delivery."
        if lane == "file":
            return "Malware execution or staged payload behavior is central to this investigation."
        if lane == "log_identity":
            return "Credential misuse or session abuse is the strongest specialized hypothesis."
        if lane == "vulnerability":
            return "The activity may be explained by exploitation of an exposed vulnerability."
        return None

    def _default_open_questions(self, lane: str, focus: str) -> List[str]:
        questions = [
            f"What is the strongest evidence tying {focus} to the suspected activity?",
            "Which entities can be linked with explicit evidence rather than co-observation alone?",
            "Is the current evidence sufficient to support a root-cause assessment?",
        ]
        if lane == "log_identity":
            questions.extend(
                [
                    "Which user, session, host, and process are explicitly tied together?",
                    "Which telemetry pivot most reduces identity or session attribution uncertainty?",
                ]
            )
        return self._dedupe(questions)[:6]

    def _build_evidence_ref(
        self,
        *,
        observation: Dict[str, Any],
        session_id: str,
        tool_name: str,
        step_number: int,
        finding_index: int,
    ) -> EvidenceRef:
        provenance = observation.get("provenance", {}) if isinstance(observation.get("provenance"), dict) else {}
        typed_fact = observation.get("typed_fact", {}) if isinstance(observation.get("typed_fact"), dict) else {}
        entity_ids = [
            f"{item.get('type')}:{item.get('value')}".lower()
            for item in observation.get("entities", [])
            if isinstance(item, dict) and item.get("type") and item.get("value")
        ]
        entity_ids = list(observation.get("entity_ids", []) or entity_ids)
        source_paths = list(observation.get("source_paths", []) or provenance.get("source_paths", []) or [])
        quality = float(
            typed_fact.get("quality", observation.get("quality", 0.0)) or 0.0
        )
        return EvidenceRef(
            session_id=session_id,
            step_number=step_number,
            finding_index=finding_index,
            tool_name=str(observation.get("tool_name") or provenance.get("tool_name") or tool_name),
            summary=str(
                typed_fact.get("summary")
                or observation.get("summary")
                or f"{tool_name} observation"
            ),
            result_path=source_paths[0] if source_paths else None,
            observation_id=str(observation.get("observation_id") or provenance.get("observation_id") or ""),
            source_kind=str(observation.get("source_kind") or provenance.get("source_kind") or "tool_result"),
            source_path=source_paths[0] if source_paths else "result",
            quality=quality,
            entity_ids=entity_ids[:10],
            extraction_method=str(
                provenance.get("extraction_method")
                or observation.get("extraction_method")
                or "observation_normalizer"
            ),
            confidence=max(0.4, quality),
            stance="neutral",
        )

    def _assess_observation(
        self,
        *,
        hypothesis: Hypothesis,
        observation: Dict[str, Any],
        tool_name: str,
        entity_state: Optional[Dict[str, Any]],
        evidence_state: Optional[Dict[str, Any]],
        lane: str,
    ) -> ObservationAssessment:
        typed_fact = observation.get("typed_fact", {}) if isinstance(observation.get("typed_fact"), dict) else {}
        provenance = observation.get("provenance", {}) if isinstance(observation.get("provenance"), dict) else {}
        obs_type = str(
            typed_fact.get("type")
            or observation.get("observation_type")
            or "correlation_observation"
        )
        facts = observation.get("facts", {}) if isinstance(observation.get("facts"), dict) else {}
        fact_family = str(
            typed_fact.get("family")
            or observation.get("fact_family")
            or "generic"
        ).strip().lower()
        quality = float(typed_fact.get("quality", observation.get("quality", 0.0)) or 0.0)
        reliability = self._tool_reliability(tool_name)
        entity_count = len(observation.get("entity_ids", []) or []) or len(
            observation.get("entities", []) if isinstance(observation.get("entities"), list) else []
        )
        entity_coverage = min(1.0, max(entity_count / 3.0, 0.2))
        relation_signal = self._relation_signal(observation, entity_state)
        timeline_signal = self._timeline_signal(evidence_state)
        provenance_signal = 0.0
        if provenance.get("source_paths"):
            provenance_signal += 0.08
        if provenance.get("entity_count") or observation.get("entity_ids"):
            provenance_signal += 0.08
        if provenance.get("extraction_method"):
            provenance_signal += 0.04
        quality = min(1.0, max(quality, relation_signal * 0.72, timeline_signal * 0.68) + provenance_signal)
        entity_coverage = min(1.0, max(entity_coverage, relation_signal))
        causal_relevance = self._causal_relevance(obs_type, facts) * (1.0 if relation_signal < 0.7 else 1.08)
        if typed_fact.get("family") in {"log", "ioc", "email", "file"}:
            causal_relevance += 0.04
        causal_relevance = min(1.0, causal_relevance)
        tags = self._observation_tags(observation, lane)
        relevance = self._topic_relevance(hypothesis, obs_type, fact_family, tags)
        malicious_signal = self._is_supportive_signal(observation)
        benign_signal = self._is_benign_signal(observation)
        statement = hypothesis.statement.lower()
        stance = "neutral"

        if "benign" in statement or "noisy" in statement or "insufficient" in statement:
            if benign_signal:
                stance = "supports"
            elif malicious_signal:
                stance = "contradicts"
        else:
            if malicious_signal and relevance >= 0.3:
                stance = "supports"
            elif benign_signal and relevance >= 0.2:
                stance = "contradicts"
            elif (
                relation_signal >= 0.9
                and relevance >= 0.75
                and obs_type in {"auth_event", "process_event", "network_event", "email_delivery", "file_execution"}
            ):
                stance = "supports"

        if obs_type == "correlation_observation" and facts.get("results_count") == 0 and not malicious_signal and not benign_signal:
            stance = "neutral"

        summary = str(observation.get("summary") or f"{tool_name} observation").strip()
        open_questions = self._questions_from_observation(observation, lane)
        evidence_strength = max(0.0, min(1.0, relevance * quality * reliability * causal_relevance))
        return ObservationAssessment(
            stance=stance,
            evidence_strength=evidence_strength,
            evidence_quality=quality,
            tool_reliability=reliability,
            entity_coverage=entity_coverage,
            causal_relevance=causal_relevance,
            tags=tags,
            summary=summary,
            open_questions=open_questions,
        )

    def _apply_support(self, hypothesis: Hypothesis, evidence: Dict[str, Any], assessment: ObservationAssessment) -> None:
        support_gain = self._support_gain(assessment)
        evidence = {
            **evidence,
            "stance": "supports",
            "confidence": round(assessment.evidence_strength, 3),
            "weighted_support": round(support_gain, 3),
            "entity_coverage": round(float(assessment.entity_coverage), 3),
            "evidence_quality": round(float(assessment.evidence_quality), 3),
            "tool_reliability": round(float(assessment.tool_reliability), 3),
            "causal_relevance": round(float(assessment.causal_relevance), 3),
        }
        hypothesis.supporting_evidence_refs.append(evidence)
        hypothesis.confidence = min(0.99, hypothesis.confidence + support_gain * (1 - hypothesis.confidence))
        hypothesis.evidence_score += support_gain
        hypothesis.priority = self._priority_score(hypothesis)
        hypothesis.updated_at = _now_iso()
        hypothesis.last_updated_at = hypothesis.updated_at

    def _apply_contradiction(self, hypothesis: Hypothesis, evidence: Dict[str, Any], assessment: ObservationAssessment) -> None:
        contradiction_loss = self._contradiction_loss(assessment)
        evidence = {
            **evidence,
            "stance": "contradicts",
            "confidence": round(assessment.evidence_strength, 3),
            "weighted_contradiction": round(contradiction_loss, 3),
            "entity_coverage": round(float(assessment.entity_coverage), 3),
            "evidence_quality": round(float(assessment.evidence_quality), 3),
            "tool_reliability": round(float(assessment.tool_reliability), 3),
            "causal_relevance": round(float(assessment.causal_relevance), 3),
        }
        hypothesis.contradicting_evidence_refs.append(evidence)
        hypothesis.confidence = max(0.01, hypothesis.confidence - contradiction_loss * hypothesis.confidence)
        hypothesis.contradiction_score += contradiction_loss
        hypothesis.priority = self._priority_score(hypothesis)
        hypothesis.updated_at = _now_iso()
        hypothesis.last_updated_at = hypothesis.updated_at

    def _refresh_hypothesis_status(self, hypothesis: Hypothesis) -> None:
        support_count = len(hypothesis.supporting_evidence_refs)
        contradiction_count = len(hypothesis.contradicting_evidence_refs)
        contradiction_margin = hypothesis.contradiction_score - hypothesis.evidence_score

        if hypothesis.confidence >= 0.68 and hypothesis.evidence_score > hypothesis.contradiction_score + 0.08:
            hypothesis.status = "supported"
        elif contradiction_margin > 0.2 and contradiction_count >= max(2, support_count + 1):
            hypothesis.status = "unsupported"
        elif hypothesis.contradiction_score > hypothesis.evidence_score + 0.16 or hypothesis.confidence <= 0.18:
            hypothesis.status = "contradicted"
        elif hypothesis.supporting_evidence_refs and hypothesis.contradicting_evidence_refs:
            hypothesis.status = "inconclusive"
        else:
            hypothesis.status = "open"

    def _derive_missing_evidence(
        self,
        hypotheses: List[Hypothesis],
        *,
        entity_state: Optional[Dict[str, Any]],
        evidence_state: Optional[Dict[str, Any]],
        lane: str,
        plan: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        ranked = self._rank_hypotheses(hypotheses)
        missing: List[str] = [
            str(item)
            for item in ((plan or {}).get("evidence_gaps") or [])
            if str(item).strip()
        ]

        entity_types = set()
        relationships: List[Dict[str, Any]] = []
        explicit_relationships: List[Dict[str, Any]] = []
        if isinstance(entity_state, dict):
            if isinstance(entity_state.get("entities"), dict):
                entity_types = {
                    payload.get("type")
                    for payload in entity_state.get("entities", {}).values()
                    if isinstance(payload, dict)
                }
            relationships = entity_state.get("relationships", []) if isinstance(entity_state.get("relationships"), list) else []
            explicit_relationships = [
                item for item in relationships
                if isinstance(item, dict) and item.get("relation_strength") == "explicit"
            ]

        timeline: List[Dict[str, Any]] = []
        if isinstance(evidence_state, dict):
            timeline = evidence_state.get("timeline", []) if isinstance(evidence_state.get("timeline"), list) else []

        if ranked:
            primary = ranked[0]
            support_count = len(primary.supporting_evidence_refs)
            contradiction_count = len(primary.contradicting_evidence_refs)
            primary_topics = {str(topic).strip().lower() for topic in primary.topics}

            if not primary.supporting_evidence_refs:
                missing.extend(primary.open_questions[:3])

            if contradiction_count and support_count <= contradiction_count:
                missing.append("Collect a higher-quality supporting observation that can outweigh the current contradictory evidence.")
            if primary.status in {"open", "inconclusive"} and primary.confidence < 0.55:
                missing.append("Collect a decisive observation that improves confidence in the leading hypothesis without relying on co-observation alone.")

            if lane == "log_identity" or {"identity", "session", "auth_event"}.intersection(primary_topics):
                if "user" not in entity_types:
                    missing.append("Identify the user tied to the suspicious session or log activity.")
                if "host" not in entity_types:
                    missing.append("Identify the host tied to the suspicious session or process activity.")
                if "session" not in entity_types:
                    missing.append("Collect explicit session identifiers to improve attribution.")
                if not any(isinstance(item, dict) and item.get("relation") in {"belongs_to", "occurred_on", "authenticated_from"} for item in explicit_relationships):
                    missing.append("Need explicit user, session, host, or source-IP relationships to improve identity attribution.")

            if lane == "email" or {"phishing", "email_delivery"}.intersection(primary_topics):
                if "sender" not in entity_types and "email" not in entity_types:
                    missing.append("Identify the sender or originating email identity tied to the suspicious delivery.")
                if "recipient" not in entity_types and "user" not in entity_types:
                    missing.append("Identify the recipient or impacted user tied to the suspicious delivery.")
                if not any(isinstance(item, dict) and item.get("relation") in {"received_from", "received_attachment"} for item in relationships):
                    missing.append("Need explicit email delivery or attachment evidence linking sender, recipient, and follow-on activity.")

            if lane == "file" or {"malware", "file_execution", "process_event", "sandbox_behavior"}.intersection(primary_topics):
                if "file" not in entity_types and "hash" not in entity_types:
                    missing.append("Identify the file or hash artifact tied to the suspected execution chain.")
                if "process" not in entity_types:
                    missing.append("Identify the process tied to the suspected file or payload execution.")
                if not any(isinstance(item, dict) and item.get("relation") in {"spawned_process", "executed_on", "connects_to"} for item in relationships):
                    missing.append("Need explicit process, host, or network relationships that prove execution rather than static presence alone.")

            if lane == "vulnerability":
                if "asset" not in entity_types and "host" not in entity_types:
                    missing.append("Identify the exposed asset or host tied to the suspected vulnerability.")
                if "alert" not in entity_types:
                    missing.append("Identify the alert or exposure finding tied to the vulnerable asset.")
                if not any(isinstance(item, dict) and item.get("relation") == "exposed_by" for item in relationships):
                    missing.append("Need explicit evidence linking the vulnerable asset to an exposure or exploitation finding.")

            if lane == "ioc" or "ioc_enrichment" in primary_topics:
                if not {"ip", "domain", "hash", "url"}.intersection(entity_types):
                    missing.append("Identify a concrete IOC artifact to anchor downstream pivots and attribution.")
                if support_count == 0:
                    missing.append("Need deterministic enrichment or corroboration that ties the IOC to malicious or benign activity.")

            if len(timeline) < 2:
                missing.append("Build a clearer timeline with at least two corroborating observations.")

        if not explicit_relationships:
            missing.append("Need at least one explicit relationship rather than co-observation alone.")
        return self._dedupe(missing)[:10]

    def _derive_state_status(self, hypotheses: List[Hypothesis], missing_evidence: List[str]) -> str:
        ranked = self._rank_hypotheses(hypotheses)
        if not ranked:
            return "insufficient_evidence"
        top = ranked[0]
        second = ranked[1] if len(ranked) > 1 else None
        margin = top.confidence - (second.confidence if second else 0.0)
        if top.status == "supported" and top.confidence >= 0.68 and margin >= 0.12:
            return "sufficient_evidence"
        if top.status in {"unsupported", "contradicted"} and top.contradiction_score > top.evidence_score + 0.12:
            return "unsupported_hypothesis"
        if top.status == "inconclusive":
            return "inconclusive"
        if top.evidence_score < 0.12 and top.confidence < 0.5 and missing_evidence:
            return "insufficient_evidence"
        return "collecting_evidence"

    def _recommended_next_pivots(self, state: Dict[str, Any], entity_state: Optional[Dict[str, Any]]) -> List[str]:
        pivots = list(state.get("open_questions", []))
        missing = [str(item) for item in state.get("missing_evidence", []) if str(item).strip()]
        if missing:
            pivots.insert(0, f"Reduce the top evidence gap first: {missing[0]}")
        if isinstance(entity_state, dict) and isinstance(entity_state.get("relationships"), list):
            for relationship in entity_state.get("relationships", [])[:10]:
                if not isinstance(relationship, dict):
                    continue
                relation = relationship.get("relation")
                strength = str(relationship.get("relation_strength") or "")
                if relation == "authenticated_from":
                    pivots.append("Pivot from the authenticated source IP to adjacent session or host telemetry.")
                elif relation == "executed_on":
                    pivots.append("Review the process execution chain on the affected host.")
                elif relation == "connects_to":
                    pivots.append("Pivot on the connected IP or domain to confirm downstream infrastructure overlap.")
                elif relation == "received_from":
                    pivots.append("Pivot from sender-recipient delivery evidence into downstream host or user execution.")
                elif relation == "received_attachment":
                    pivots.append("Validate whether the delivered attachment was opened or spawned a process.")
                if strength == "co_observed":
                    pivots.append("Prefer a pivot that upgrades co-observed entities into an explicit relationship.")
        return self._dedupe(pivots)[:7]

    def _recommended_next_actions(self, deterministic_decision: Dict[str, Any], root_cause_assessment: Dict[str, Any]) -> List[str]:
        actions: List[str] = []
        status = str(root_cause_assessment.get("status") or "")
        if status == "supported":
            actions.append("Prepare the case summary and analyst recommendation from the current evidence.")
        elif status == "unsupported_hypothesis":
            actions.append("State clearly that the leading hypothesis is currently unsupported by the available evidence.")
            actions.append("Reframe the investigation around the strongest alternative explanation or collect contradicting context that resolves the conflict.")
        elif status == "inconclusive":
            actions.append("Keep the current explanation provisional and collect evidence that separates competing hypotheses.")
        else:
            actions.append("Collect the most decisive missing evidence before closing the investigation.")
        verdict = str(deterministic_decision.get("verdict") or "").upper()
        if verdict in {"MALICIOUS", "SUSPICIOUS"}:
            actions.append("Keep deterministic verdict authority visible in the final response.")
        if root_cause_assessment.get("missing_evidence"):
            actions.append("State the missing evidence explicitly to avoid overclaiming confidence.")
        return self._dedupe(actions)[:5]

    def _entity_summary(self, entity_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not isinstance(entity_state, dict):
            return {"entity_count": 0, "relationship_count": 0}
        entities = entity_state.get("entities", {}) if isinstance(entity_state.get("entities"), dict) else {}
        relationships = entity_state.get("relationships", []) if isinstance(entity_state.get("relationships"), list) else []
        return {
            "entity_count": len(entities),
            "relationship_count": len(relationships),
            "top_entities": list(entities.values())[:8],
        }

    def _rank_hypotheses(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        ranked = list(hypotheses)
        for item in ranked:
            item.ranking_score = self._ranking_score(item)
        sorted_ranked = sorted(
            ranked,
            key=lambda item: (
                item.ranking_score,
                item.confidence,
                item.evidence_score - item.contradiction_score,
                len(item.supporting_evidence_refs) - len(item.contradicting_evidence_refs),
            ),
            reverse=True,
        )
        lead_score = sorted_ranked[0].ranking_score if sorted_ranked else 0.0
        for item in sorted_ranked:
            item.priority = item.ranking_score
            item.competition_score = round(max(0.0, lead_score - item.ranking_score), 3)
        return sorted_ranked

    def _competition_state(self, hypotheses: List[Hypothesis]) -> Dict[str, Any]:
        ranked = list(hypotheses)
        if not ranked:
            return {
                "lead_hypothesis_id": None,
                "lead_margin": 0.0,
                "competition_level": "none",
                "top_hypotheses": [],
            }
        lead = ranked[0]
        runner_up = ranked[1] if len(ranked) > 1 else None
        lead_margin = max(0.0, float(lead.ranking_score) - float(runner_up.ranking_score if runner_up else 0.0))
        if runner_up is None:
            competition_level = "clear_lead"
        elif lead_margin < 0.08:
            competition_level = "tight"
        elif lead_margin < 0.18:
            competition_level = "contested"
        else:
            competition_level = "clear_lead"
        return {
            "lead_hypothesis_id": lead.id,
            "runner_up_hypothesis_id": runner_up.id if runner_up else None,
            "lead_margin": round(lead_margin, 3),
            "competition_level": competition_level,
            "top_hypotheses": [
                {
                    "id": item.id,
                    "statement": item.statement,
                    "status": item.status,
                    "ranking_score": round(float(item.ranking_score), 3),
                    "competition_score": round(float(item.competition_score), 3),
                    "confidence": round(float(item.confidence), 3),
                }
                for item in ranked[:3]
            ],
        }

    def _ranking_score(self, hypothesis: Hypothesis) -> float:
        support_quality = sum(
            float(item.get("weighted_support", item.get("confidence", 0.0)) or 0.0)
            for item in hypothesis.supporting_evidence_refs
            if isinstance(item, dict)
        )
        contradiction_quality = sum(
            float(item.get("weighted_contradiction", item.get("confidence", 0.0)) or 0.0)
            for item in hypothesis.contradicting_evidence_refs
            if isinstance(item, dict)
        )
        support_count = len(hypothesis.supporting_evidence_refs)
        contradiction_count = len(hypothesis.contradicting_evidence_refs)
        typed_support_bonus = min(
            0.14,
            sum(
                0.035
                for item in hypothesis.supporting_evidence_refs
                if isinstance(item, dict)
                and float(item.get("evidence_quality", 0.0) or 0.0) >= 0.62
                and float(item.get("causal_relevance", 0.0) or 0.0) >= 0.72
            ),
        )
        contradiction_penalty = min(0.18, contradiction_quality * 0.45)
        return (
            float(hypothesis.confidence) * 0.55
            + float(hypothesis.evidence_score) * 1.0
            + support_quality * 0.35
            + typed_support_bonus
            - float(hypothesis.contradiction_score) * 0.95
            - contradiction_penalty
            + min(0.08, support_count * 0.015)
            - min(0.1, contradiction_count * 0.02)
        )

    def _priority_score(self, hypothesis: Hypothesis) -> float:
        support_count = len(hypothesis.supporting_evidence_refs)
        contradiction_count = len(hypothesis.contradicting_evidence_refs)
        coverage_bias = min(0.18, support_count * 0.025)
        contradiction_penalty = min(0.2, contradiction_count * 0.03)
        return (
            float(hypothesis.confidence)
            + float(hypothesis.evidence_score)
            - float(hypothesis.contradiction_score)
            + coverage_bias
            - contradiction_penalty
        )

    def _support_gain(self, assessment: ObservationAssessment) -> float:
        quality_factor = max(0.3, assessment.evidence_quality)
        coverage_factor = max(0.35, assessment.entity_coverage)
        causal_factor = max(0.35, assessment.causal_relevance)
        reliability_factor = max(0.35, assessment.tool_reliability)
        chain_bonus = 1.08 if assessment.entity_coverage >= 0.75 and assessment.causal_relevance >= 0.75 else 1.0
        gain = 0.34 * assessment.evidence_strength * quality_factor * coverage_factor * causal_factor * reliability_factor * chain_bonus
        if assessment.evidence_quality >= 0.55 and assessment.tool_reliability >= 0.8:
            gain = max(gain, 0.018)
        return gain

    def _contradiction_loss(self, assessment: ObservationAssessment) -> float:
        quality_factor = max(0.3, assessment.evidence_quality)
        coverage_factor = max(0.35, assessment.entity_coverage)
        causal_factor = max(0.35, assessment.causal_relevance)
        reliability_factor = max(0.35, assessment.tool_reliability)
        severity_bonus = 1.12 if assessment.evidence_quality >= 0.8 and assessment.causal_relevance >= 0.72 else 1.0
        return 0.29 * assessment.evidence_strength * quality_factor * coverage_factor * causal_factor * reliability_factor * severity_bonus

    def _tool_reliability(self, tool_name: str) -> float:
        mapping = {
            "search_logs": 0.88,
            "investigate_ioc": 0.82,
            "analyze_email": 0.86,
            "analyze_malware": 0.86,
            "correlate_findings": 0.7,
        }
        lowered = str(tool_name or "").lower()
        if lowered in mapping:
            return mapping[lowered]
        if "." in lowered:
            return 0.78
        return 0.68

    def _expand_hypothesis_topics(self, topics: set[str]) -> set[str]:
        expanded = set(topics)
        for topic in list(topics):
            expanded.update(self._typed_topics_for_observation(topic, ""))
            expanded.update(self._typed_topics_for_observation("", topic))
        return {topic for topic in expanded if str(topic).strip()}

    def _topic_relevance(self, hypothesis: Hypothesis, obs_type: str, fact_family: str, tags: List[str]) -> float:
        raw_topics = {str(topic).strip().lower() for topic in (hypothesis.topics or []) if str(topic).strip()}
        if not raw_topics:
            return 0.45

        obs_type = str(obs_type or "").strip().lower()
        fact_family = str(fact_family or "").strip().lower()
        tags_lower = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
        typed_topics = self._typed_topics_for_observation(obs_type, fact_family)
        hypothesis_topics = self._expand_hypothesis_topics(raw_topics)

        if obs_type and obs_type in raw_topics:
            return 0.95
        if fact_family and fact_family in raw_topics:
            return 0.9

        if obs_type and obs_type in hypothesis_topics:
            return 0.94
        if fact_family and fact_family in hypothesis_topics:
            return 0.9

        typed_overlap = hypothesis_topics.intersection(typed_topics)
        if typed_overlap:
            if obs_type and obs_type in typed_overlap:
                return 0.92
            if fact_family and fact_family in typed_overlap:
                return 0.88
            if {"identity", "session", "log_identity"}.intersection(typed_overlap):
                return 0.86
            if {"phishing", "email", "email_delivery"}.intersection(typed_overlap):
                return 0.86
            if {"malware", "file_execution", "process_event", "sandbox_behavior"}.intersection(typed_overlap):
                return 0.86
            if {"ioc", "ioc_enrichment", "network_event"}.intersection(typed_overlap):
                return 0.84
            if {"vulnerability", "vulnerability_exposure", "asset"}.intersection(typed_overlap):
                return 0.84
            return 0.82

        typed_signal_present = bool(obs_type or fact_family or typed_topics)
        if "benign" in raw_topics and "benign" in tags_lower:
            return 0.72 if typed_signal_present else 0.9
        if "malicious" in raw_topics and "malicious" in tags_lower:
            return 0.72 if typed_signal_present else 0.9

        semantic_overlap = self._statement_semantic_overlap(hypothesis.statement, typed_topics)
        if semantic_overlap:
            # Typed observations should outrank narrative similarity when they point to a different lane.
            return 0.46 if typed_signal_present else 0.64

        tag_overlap = raw_topics.intersection(tags_lower)
        if tag_overlap:
            return 0.4 if typed_signal_present else 0.56
        expanded_tag_overlap = hypothesis_topics.intersection(tags_lower)
        if expanded_tag_overlap:
            return 0.36 if typed_signal_present else 0.52
        return 0.28

    def _typed_topics_for_observation(self, obs_type: str, fact_family: str) -> set[str]:
        topics = {str(obs_type or "").strip().lower(), str(fact_family or "").strip().lower()}
        family_map = {
            "identity": {"auth_event", "identity", "session", "log_identity", "network_event", "credential"},
            "network": {"network_event", "ioc_enrichment", "ioc", "domain", "ip", "url", "beacon", "c2"},
            "execution": {"process_event", "file_execution", "sandbox_behavior", "file", "malware", "execution"},
            "email": {"email_delivery", "phishing", "email", "sender", "recipient", "attachment"},
            "vulnerability": {"vulnerability_exposure", "vulnerability", "asset", "cve", "exploit"},
            "correlation": {"correlation_observation"},
            "generic": {"correlation_observation"},
            "log_identity": {"auth_event", "identity", "session", "credential", "log_identity"},
            "ioc": {"ioc_enrichment", "network_event", "ioc", "ip", "domain", "url", "hash"},
            "file": {"file_execution", "process_event", "sandbox_behavior", "file", "malware", "hash"},
            "phishing": {"email_delivery", "phishing", "email", "sender", "attachment", "url"},
            "malware": {"file_execution", "process_event", "sandbox_behavior", "malware", "execution"},
        }
        topics.update(family_map.get(str(fact_family or "").strip().lower(), set()))
        topics.update(family_map.get(str(obs_type or "").strip().lower(), set()))
        type_map = {
            "auth_event": {"identity", "session", "log_identity", "credential", "user"},
            "process_event": {"process_event", "file_execution", "malware", "execution", "host", "process"},
            "network_event": {"network_event", "ioc_enrichment", "ioc", "ip", "domain", "url", "beacon", "c2"},
            "file_execution": {"file_execution", "process_event", "malware", "execution", "file", "hash"},
            "sandbox_behavior": {"sandbox_behavior", "file_execution", "malware", "execution", "file"},
            "email_delivery": {"email_delivery", "phishing", "email", "sender", "recipient", "attachment", "url"},
            "ioc_enrichment": {"ioc_enrichment", "ioc", "network_event", "ip", "domain", "url", "hash"},
            "vulnerability_exposure": {"vulnerability", "asset", "cve", "exploit"},
            "host_timeline_event": {"host", "timeline", "process_event", "session"},
        }
        topics.update(type_map.get(str(obs_type or "").strip().lower(), set()))
        return {topic for topic in topics if str(topic).strip()}

    def _statement_semantic_overlap(self, statement: str, typed_topics: set[str]) -> bool:
        lowered = str(statement or "").lower()
        token_groups = {
            "identity": ("identity", "credential", "session", "login", "signin", "auth"),
            "session": ("session", "logon", "token", "credential"),
            "phishing": ("phishing", "email", "sender", "recipient", "attachment", "link"),
            "email": ("email", "mail", "sender", "recipient"),
            "malware": ("malware", "payload", "execution", "ransomware", "trojan"),
            "file_execution": ("file", "binary", "process", "execution", "payload"),
            "process_event": ("process", "cmdline", "powershell", "execution"),
            "network_event": ("network", "domain", "ip", "url", "beacon", "c2"),
            "ioc": ("ioc", "indicator", "domain", "ip", "hash", "url"),
            "vulnerability": ("vulnerability", "cve", "exploit", "exposure", "patch"),
        }
        for topic in typed_topics:
            if any(token in lowered for token in token_groups.get(topic, ())):
                return True
        return False

    def _relation_signal(self, observation: Dict[str, Any], entity_state: Optional[Dict[str, Any]]) -> float:
        if not isinstance(entity_state, dict):
            return 0.0
        observation_entity_ids = {
            f"{item.get('type')}:{item.get('value')}".lower()
            for item in observation.get("entities", [])
            if isinstance(item, dict) and item.get("type") and item.get("value")
        }
        if not observation_entity_ids:
            return 0.0
        relationships = entity_state.get("relationships", []) if isinstance(entity_state.get("relationships"), list) else []
        best = 0.0
        for relationship in relationships:
            if not isinstance(relationship, dict):
                continue
            source = str(relationship.get("source") or "").lower()
            target = str(relationship.get("target") or "").lower()
            if source not in observation_entity_ids and target not in observation_entity_ids:
                continue
            relation_strength = str(relationship.get("relation_strength") or "")
            if relation_strength == "explicit":
                best = max(best, 0.95)
            elif relation_strength == "inferred":
                best = max(best, 0.76)
            elif relation_strength == "co_observed":
                best = max(best, 0.45)
        return best

    def _timeline_signal(self, evidence_state: Optional[Dict[str, Any]]) -> float:
        if not isinstance(evidence_state, dict):
            return 0.0
        timeline = evidence_state.get("timeline", []) if isinstance(evidence_state.get("timeline"), list) else []
        if len(timeline) >= 4:
            return 0.9
        if len(timeline) >= 2:
            return 0.72
        if len(timeline) == 1:
            return 0.48
        return 0.0

    def _causal_relevance(self, obs_type: str, facts: Dict[str, Any]) -> float:
        base = {
            "auth_event": 0.9,
            "process_event": 0.88,
            "network_event": 0.82,
            "file_execution": 0.84,
            "sandbox_behavior": 0.84,
            "email_delivery": 0.8,
            "ioc_enrichment": 0.66,
            "correlation_observation": 0.54,
        }.get(obs_type, 0.56)
        if facts.get("session_id") or facts.get("process_name") or facts.get("dest_ip"):
            base += 0.06
        return min(1.0, base)

    def _observation_tags(self, observation: Dict[str, Any], lane: str) -> List[str]:
        typed_fact = observation.get("typed_fact", {}) if isinstance(observation.get("typed_fact"), dict) else {}
        obs_type = str(typed_fact.get("type") or observation.get("observation_type") or "")
        fact_family = str(typed_fact.get("family") or observation.get("fact_family") or "")
        tags = [obs_type, lane]
        if fact_family:
            tags.append(fact_family)
        facts = observation.get("facts", {}) if isinstance(observation.get("facts"), dict) else {}
        verdict = str(facts.get("verdict") or "").lower()
        severity = str(facts.get("severity") or "").lower()
        if verdict:
            tags.append(verdict)
        if severity:
            tags.append(severity)
        if facts.get("results_count") == 0:
            tags.append("no_matches")
        text_blob = jsonish(observation).lower()
        for token in ("phishing", "malware", "beacon", "c2", "credential", "session", "process", "network", "benign"):
            if token in text_blob:
                tags.append(token)
        if self._is_benign_signal(observation):
            tags.append("benign")
        if self._is_supportive_signal(observation):
            tags.append("malicious")
        return self._dedupe(tags)

    def _questions_from_observation(self, observation: Dict[str, Any], lane: str) -> List[str]:
        facts = observation.get("facts", {}) if isinstance(observation.get("facts"), dict) else {}
        obs_type = str(observation.get("observation_type") or "")
        questions: List[str] = []
        if obs_type == "auth_event":
            if not facts.get("host"):
                questions.append("Which host did the suspicious authentication occur on?")
            if not facts.get("session_id"):
                questions.append("Which session identifier ties the suspicious authentication together?")
        if obs_type in {"process_event", "file_execution"} and not facts.get("dest_ip") and not facts.get("domain"):
            questions.append("Is there follow-on network activity tied to the observed process or file execution?")
        if obs_type == "email_delivery":
            questions.append("Was the delivered email followed by user execution or host activity?")
        if lane == "log_identity" and facts.get("results_count") == 0:
            questions.append("Which adjacent observable should be used for the next log pivot?")
        return self._dedupe(questions)[:4]

    def _is_supportive_signal(self, observation: Dict[str, Any]) -> bool:
        facts = observation.get("facts", {}) if isinstance(observation.get("facts"), dict) else {}
        verdict = str(facts.get("verdict") or "").upper()
        severity = str(facts.get("severity") or "").upper()
        score = facts.get("threat_score", facts.get("score"))
        text_blob = jsonish(observation).lower()
        if verdict in {"MALICIOUS", "SUSPICIOUS"}:
            return True
        if severity in {"HIGH", "CRITICAL"}:
            return True
        if isinstance(score, (int, float)) and float(score) >= 70:
            return True
        if any(token in text_blob for token in ("phishing", "malware", "beacon", "c2", "credential theft", "newly_registered")):
            return True
        if facts.get("results_count", 0) and any(token in text_blob for token in ("powershell", "rundll32", "encodedcommand", "admin$", "remote_ip")):
            return True
        return False

    def _is_benign_signal(self, observation: Dict[str, Any]) -> bool:
        facts = observation.get("facts", {}) if isinstance(observation.get("facts"), dict) else {}
        verdict = str(facts.get("verdict") or "").upper()
        severity = str(facts.get("severity") or "").upper()
        score = facts.get("threat_score", facts.get("score"))
        text_blob = jsonish(observation).lower()
        if verdict in {"BENIGN", "CLEAN"}:
            return True
        if severity in {"LOW", "INFO"}:
            return True
        if isinstance(score, (int, float)) and float(score) <= 20:
            return True
        if facts.get("found") is False:
            return True
        if any(token in text_blob for token in ("benign", "legitimate", "known good", "no findings", "clean")):
            return True
        return False

    def _lane_from_goal(self, goal: str) -> str:
        lowered = str(goal or "").lower()
        if any(token in lowered for token in ("log", "session", "login", "signin", "identity")):
            return "log_identity"
        if any(token in lowered for token in ("email", "phish", "sender", "mail")):
            return "email"
        if any(token in lowered for token in ("file", "malware", "exe", "dll", "sandbox", "process")):
            return "file"
        if any(token in lowered for token in ("cve", "vulnerability", "exploit")):
            return "vulnerability"
        return "ioc"

    def _topics_for_statement(self, statement: str, lane: str) -> List[str]:
        lowered = str(statement or "").lower()
        topics = [lane]
        if any(token in lowered for token in ("benign", "noisy", "insufficient")):
            topics.append("benign")
        else:
            topics.append("malicious")
        if "phishing" in lowered or lane == "email":
            topics.extend(["email_delivery", "phishing"])
        if "malware" in lowered or "payload" in lowered or lane == "file":
            topics.extend(["file_execution", "process_event", "sandbox_behavior", "malware"])
        if "credential" in lowered or "session" in lowered or lane == "log_identity":
            topics.extend(["auth_event", "network_event", "identity", "session"])
        if lane == "ioc":
            topics.append("ioc_enrichment")
        return self._dedupe(topics)

    def _open_questions_for_topics(self, topics: List[str]) -> List[str]:
        questions = ["What evidence directly supports or contradicts this hypothesis?"]
        if "identity" in topics or "session" in topics:
            questions.append("Which user, session, and host can be linked with explicit evidence?")
        if "malware" in topics:
            questions.append("Which process, file, or sandbox artifacts prove execution or staging?")
        if "phishing" in topics:
            questions.append("Is there delivery evidence and follow-on user or host activity?")
        return self._dedupe(questions)[:4]

    def _extract_focus(self, goal: str) -> str:
        matches = self._IOC_RE.findall(goal or "")
        if matches:
            return matches[0]
        trimmed = " ".join(str(goal or "").strip().split())
        if len(trimmed) > 96:
            trimmed = trimmed[:93] + "..."
        return trimmed or "the investigation target"

    def _legacy_observation(self, tool_name: str, params: Dict[str, Any], result: Any, session_id: str, step_number: int) -> Dict[str, Any]:
        payload = result.get("result") if isinstance(result, dict) and isinstance(result.get("result"), dict) else result
        facts = payload if isinstance(payload, dict) else {"value": str(payload)}
        return {
            "observation_id": f"obs:{session_id}:{step_number}:0:{tool_name}:legacy".lower(),
            "observation_type": "correlation_observation",
            "summary": self._legacy_summary(tool_name, facts, params),
            "quality": 0.55 if isinstance(facts, dict) and any(key in facts for key in ("verdict", "severity", "results_count")) else 0.35,
            "source_kind": "legacy",
            "source_paths": ["result"],
            "entities": [],
            "facts": facts,
        }

    def _legacy_summary(self, tool_name: str, facts: Dict[str, Any], params: Dict[str, Any]) -> str:
        if facts.get("verdict"):
            return f"{tool_name} reported verdict={facts.get('verdict')}."
        if "results_count" in facts:
            return f"{tool_name} returned {facts.get('results_count', 0)} matching records."
        for key in ("ioc", "ip", "domain", "host", "user", "session_id"):
            if facts.get(key) or params.get(key):
                return f"{tool_name} observed {key}={facts.get(key) or params.get(key)}."
        return f"{tool_name} returned additional evidence."

    def _new_hypothesis_id(self) -> str:
        return f"hyp-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            clean = str(value or "").strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(clean)
        return ordered


def jsonish(value: Any) -> str:
    try:
        return json.dumps(value, default=str, sort_keys=True)
    except Exception:
        return str(value)
