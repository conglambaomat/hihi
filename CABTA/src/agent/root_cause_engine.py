"""Root-cause assessment support for structured agent investigations."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class RootCauseAssessmentResult:
    status: str
    primary_root_cause: str
    confidence: float
    causal_chain: List[str]
    supporting_evidence_refs: List[Dict[str, Any]]
    alternative_hypotheses: List[str]
    missing_evidence: List[str]
    summary: str
    assessed_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(float(payload.get("confidence", 0.0)), 3)
        return payload


class RootCauseEngine:
    """Rank hypotheses and emit supported vs inconclusive vs insufficient evidence output."""

    def assess(
        self,
        *,
        goal: str,
        reasoning_state: Optional[Dict[str, Any]],
        deterministic_decision: Optional[Dict[str, Any]] = None,
        evidence_state: Optional[Dict[str, Any]] = None,
        entity_state: Optional[Dict[str, Any]] = None,
        active_observations: Optional[List[Dict[str, Any]]] = None,
        unresolved_questions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        hypotheses = [
            item for item in (reasoning_state or {}).get("hypotheses", [])
            if isinstance(item, dict)
        ]
        ranked = sorted(
            hypotheses,
            key=lambda item: (
                float(item.get("ranking_score", item.get("priority", self._root_cause_rank_score(item))) or 0.0),
                self._root_cause_rank_score(item),
            ),
            reverse=True,
        )
        missing = self._dedupe(
            [
                *(unresolved_questions or []),
                *((reasoning_state or {}).get("missing_evidence", []) if isinstance(reasoning_state, dict) else []),
                *((reasoning_state or {}).get("open_questions", []) if isinstance(reasoning_state, dict) else []),
            ]
        )[:8]

        if not ranked:
            return RootCauseAssessmentResult(
                status="insufficient_evidence",
                primary_root_cause="Insufficient evidence to determine root cause.",
                confidence=0.0,
                causal_chain=[],
                supporting_evidence_refs=[],
                alternative_hypotheses=[],
                missing_evidence=missing,
                summary="No structured hypotheses are available yet.",
            ).to_dict()

        top = ranked[0]
        second = ranked[1] if len(ranked) > 1 else None
        top_conf = float(top.get("confidence", 0.0) or 0.0)
        second_conf = float(second.get("confidence", 0.0) or 0.0) if second else 0.0
        top_rank_score = float(top.get("ranking_score", top.get("priority", self._root_cause_rank_score(top))) or 0.0)
        second_rank_score = (
            float(second.get("ranking_score", second.get("priority", self._root_cause_rank_score(second))) or 0.0)
            if second else 0.0
        )
        score_margin = top_rank_score - second_rank_score
        competition = (
            reasoning_state.get("competition", {})
            if isinstance(reasoning_state, dict) and isinstance(reasoning_state.get("competition"), dict)
            else {}
        )
        competition_level = str(competition.get("competition_level") or "")
        lead_margin = float(competition.get("lead_margin", score_margin) or score_margin)
        support_refs = list(top.get("supporting_evidence_refs", []) or [])
        contradiction_refs = list(top.get("contradicting_evidence_refs", []) or [])
        evidence_score = float(top.get("evidence_score", 0.0) or 0.0)
        contradiction_score = float(top.get("contradiction_score", 0.0) or 0.0)
        lane = self._investigation_lane(goal=goal, reasoning_state=reasoning_state)
        lane_thresholds = self._lane_thresholds(lane)
        quality = self._observation_quality(active_observations, support_refs)
        typed_profile = self._typed_evidence_profile(active_observations, support_refs)
        typed_evidence_ratio = typed_profile["ratio"]
        typed_support_count = typed_profile["typed_count"]
        narrative_support_ratio = self._narrative_support_ratio(active_observations, support_refs)
        relation_profile = self._relation_profile(entity_state)
        relation_quality = relation_profile["quality"]
        explicit_relation_ratio = relation_profile["explicit_ratio"]
        timeline_quality = self._timeline_quality(evidence_state)
        graph_support = self._graph_support_quality(evidence_state)
        gap_pressure = self._gap_pressure(missing)
        chain_quality = self._chain_quality(
            top=top,
            evidence_state=evidence_state,
            entity_state=entity_state,
            active_observations=active_observations or [],
        )
        support_balance = self._support_balance(
            top_conf=top_conf,
            second_conf=second_conf,
            score_margin=score_margin,
            evidence_score=evidence_score,
            contradiction_score=contradiction_score,
            quality=quality,
            typed_evidence_ratio=typed_evidence_ratio,
            relation_quality=relation_quality,
            timeline_quality=timeline_quality,
            graph_support=graph_support,
            chain_quality=chain_quality,
        )
        contradiction_pressure = self._contradiction_pressure(
            lane=lane,
            evidence_score=evidence_score,
            contradiction_score=contradiction_score,
            contradiction_refs=contradiction_refs,
            second_conf=second_conf,
            score_margin=score_margin,
            support_balance=support_balance,
        )
        best_explanation = str(top.get("statement") or "Likely root cause candidate.").strip() or "Likely root cause candidate."

        if (
            str(top.get("status") or "") in {"unsupported", "contradicted"}
            or self._is_materially_contradicted(
                lane=lane,
                evidence_score=evidence_score,
                contradiction_score=contradiction_score,
                contradiction_refs=contradiction_refs,
                support_balance=support_balance,
                score_margin=score_margin,
            )
        ):
            status = "unsupported_hypothesis"
        elif not support_refs or ((quality < lane_thresholds["minimum_observation_quality"] and relation_quality < lane_thresholds["minimum_relation_quality"]) and evidence_score < lane_thresholds["minimum_evidence_score"]):
            status = "insufficient_evidence"
        elif narrative_support_ratio > lane_thresholds["maximum_narrative_support_ratio"]:
            missing = self._dedupe([
                *missing,
                self._narrative_dependence_gap_message(lane),
            ])[:8]
            status = "insufficient_evidence"
        elif self._typed_evidence_required(lane=lane, relation_quality=relation_quality) and typed_evidence_ratio < lane_thresholds["required_typed_ratio"]:
            missing = self._dedupe([
                *missing,
                self._typed_evidence_gap_message(lane),
            ])[:8]
            status = "insufficient_evidence"
        elif self._lane_requires_explicit_relations(lane=lane, gap_pressure=gap_pressure) and (
            relation_quality < lane_thresholds["explicit_relation_quality_floor"] or explicit_relation_ratio < self._required_explicit_ratio(lane)
        ):
            missing = self._dedupe([
                *missing,
                self._explicit_relation_gap_message(lane),
            ])[:8]
            status = "insufficient_evidence"
        elif self._has_structural_conflict(
            lane=lane,
            typed_support_count=typed_support_count,
            support_refs=support_refs,
            contradiction_refs=contradiction_refs,
            relation_quality=relation_quality,
            explicit_relation_ratio=explicit_relation_ratio,
            graph_support=graph_support,
            chain_quality=chain_quality,
        ):
            missing = self._dedupe([
                *missing,
                self._structural_conflict_gap_message(lane),
            ])[:8]
            status = "inconclusive"
        elif gap_pressure >= lane_thresholds["high_gap_pressure"] and relation_quality < lane_thresholds["explicit_relation_quality_floor"] and chain_quality < lane_thresholds["supported_chain_floor"]:
            status = "insufficient_evidence"
        elif contradiction_pressure >= lane_thresholds["contradiction_inconclusive_floor"]:
            missing = self._dedupe([
                *missing,
                self._contradiction_gap_message(lane),
            ])[:8]
            status = "inconclusive"
        elif competition_level == "tight" and lead_margin < 0.08:
            missing = self._dedupe([
                *missing,
                "Separate the two strongest competing hypotheses with one more decisive observation before closing the case.",
            ])[:8]
            status = "inconclusive"
        elif self._is_supported(
            lane=lane,
            top_conf=top_conf,
            top_rank_score=top_rank_score,
            score_margin=score_margin,
            evidence_score=evidence_score,
            contradiction_score=contradiction_score,
            typed_evidence_ratio=typed_evidence_ratio,
            relation_quality=relation_quality,
            explicit_relation_ratio=explicit_relation_ratio,
            timeline_quality=timeline_quality,
            graph_support=graph_support,
            chain_quality=chain_quality,
            support_balance=support_balance,
            contradiction_pressure=contradiction_pressure,
            lane_thresholds=lane_thresholds,
            narrative_support_ratio=narrative_support_ratio,
        ):
            status = "supported"
        else:
            status = "inconclusive"

        alternatives = [
            str(item.get("statement") or "").strip()
            for item in ranked[1:4]
            if str(item.get("statement") or "").strip()
        ]
        causal_chain = self._build_causal_chain(
            top=top,
            evidence_state=evidence_state,
            entity_state=entity_state,
            active_observations=active_observations or [],
            deterministic_decision=deterministic_decision or {},
        )
        derived_root_cause = self._derive_root_cause_statement(
            top=top,
            causal_chain=causal_chain,
            relation_quality=relation_quality,
            chain_quality=chain_quality,
        )

        if status == "supported":
            primary_root_cause = derived_root_cause or best_explanation
            summary = f"Best explanation so far is now a confident root cause: {primary_root_cause}"
            if typed_evidence_ratio >= 0.75:
                summary += " Most supporting evidence is typed and attributable rather than narrative-only."
            if relation_quality >= 0.9:
                summary += " Explicit entity relationships materially strengthen this assessment."
            if graph_support >= 0.75:
                summary += " Evidence-graph support paths show consistent hypothesis-to-root-cause alignment."
            if chain_quality >= 0.8:
                summary += " The causal chain is materially complete across evidence, relation, and timeline signals."
            confidence = max(0.0, min(0.99, max(top_conf, (top_conf + typed_evidence_ratio + relation_quality + chain_quality + graph_support) / 5)))
        elif status == "unsupported_hypothesis":
            primary_root_cause = derived_root_cause or best_explanation
            summary = "The current leading explanation is the best available candidate, but it is materially undercut by contradictory evidence and should not be treated as a confident root cause."
            if missing:
                summary += f" Highest-priority gap: {missing[0]}"
            confidence = min(max(top_conf, quality * 0.55), 0.58)
        elif status == "inconclusive":
            primary_root_cause = derived_root_cause or best_explanation
            summary = "The investigation has a best explanation so far, but competing explanations or unresolved gaps remain too strong to declare a confident root cause."
            if competition_level == "tight":
                summary += " The two strongest hypotheses remain tightly ranked, so the evidence does not yet separate them cleanly."
            elif competition_level == "contested":
                summary += " The leading explanation is still contested by a nearby alternative hypothesis."
            if missing:
                summary += f" Highest-priority gap: {missing[0]}"
            confidence = min(max(top_conf, relation_quality * 0.7, chain_quality * 0.72, graph_support * 0.68), 0.74)
        else:
            primary_root_cause = "Insufficient evidence to determine root cause confidently."
            summary = "The investigation still lacks enough high-quality, well-attributed evidence to name a reliable root cause."
            if missing:
                summary += f" Highest-priority gap: {missing[0]}"
            confidence = min(max(top_conf, relation_quality * 0.45, graph_support * 0.42), 0.44)
        if contradiction_refs and status != "supported":
            contradiction_guidance = ["Collect stronger contradictory or corroborating evidence before closing the investigation."]
            if status == "inconclusive":
                contradiction_guidance.insert(0, self._contradiction_gap_message(lane))
            missing = self._dedupe([*missing, *contradiction_guidance])[:8]
        if status == "unsupported_hypothesis":
            missing = self._dedupe([*missing, "Re-test the leading explanation against the strongest alternative hypothesis before closing the case."])[:8]
        return RootCauseAssessmentResult(
            status=status,
            primary_root_cause=primary_root_cause,
            confidence=confidence,
            causal_chain=causal_chain,
            supporting_evidence_refs=support_refs[:8],
            alternative_hypotheses=alternatives,
            missing_evidence=missing,
            summary=summary,
        ).to_dict()

    def _build_causal_chain(
        self,
        *,
        top: Dict[str, Any],
        evidence_state: Optional[Dict[str, Any]],
        entity_state: Optional[Dict[str, Any]],
        active_observations: List[Dict[str, Any]],
        deterministic_decision: Dict[str, Any],
    ) -> List[str]:
        chain: List[str] = []
        statement = str(top.get("statement") or "").strip()
        if statement:
            chain.append(statement)

        refs = [item for item in top.get("supporting_evidence_refs", []) if isinstance(item, dict)]
        observation_lookup = {
            str(item.get("observation_id") or ""): item
            for item in active_observations
            if isinstance(item, dict) and item.get("observation_id")
        }
        for ref in refs[:4]:
            observation_id = str(ref.get("observation_id") or "").strip()
            observation = observation_lookup.get(observation_id, {}) if observation_id else {}
            typed_fact = observation.get("typed_fact", {}) if isinstance(observation, dict) and isinstance(observation.get("typed_fact"), dict) else {}
            provenance = observation.get("provenance", {}) if isinstance(observation, dict) and isinstance(observation.get("provenance"), dict) else {}
            if observation:
                summary = str(
                    typed_fact.get("summary")
                    or observation.get("summary")
                    or ref.get("summary")
                    or ""
                ).strip()
            else:
                summary = str(ref.get("summary") or "").strip()
            if summary and summary not in chain:
                chain.append(summary)
            if provenance.get("source_paths") and provenance.get("extraction_method"):
                provenance_summary = (
                    f"Evidence provenance preserved via {provenance.get('extraction_method')} "
                    f"from {list(provenance.get('source_paths', []) or [])[:1][0]}."
                )
                if provenance_summary not in chain:
                    chain.append(provenance_summary)

        relationships = entity_state.get("relationships", []) if isinstance(entity_state, dict) and isinstance(entity_state.get("relationships"), list) else []
        ranked_relationships = sorted(
            [item for item in relationships if isinstance(item, dict)],
            key=lambda item: float(item.get("relation_confidence", item.get("confidence", 0.0)) or 0.0),
            reverse=True,
        )
        for relationship in ranked_relationships[:4]:
            relation = str(relationship.get("relation") or "").strip()
            strength = str(relationship.get("relation_strength") or "").strip()
            source = str(relationship.get("source") or "").strip()
            target = str(relationship.get("target") or "").strip()
            confidence_band = str(relationship.get("confidence_band") or "").strip()
            if relation and source and target and strength in {"explicit", "inferred"}:
                relation_summary = f"Relationship {relation} links {source} to {target} ({strength})."
                if confidence_band:
                    relation_summary = relation_summary[:-1] + f", confidence {confidence_band})."
                if relation_summary not in chain:
                    chain.append(relation_summary)

        causal_support = (
            evidence_state.get("causal_support", {})
            if isinstance(evidence_state, dict) and isinstance(evidence_state.get("causal_support"), dict)
            else {}
        )
        preferred_paths = (
            causal_support.get("root_path_summaries", [])
            if isinstance(causal_support.get("root_path_summaries", []), list)
            else []
        )
        if preferred_paths:
            for path in preferred_paths[:2]:
                if not isinstance(path, dict):
                    continue
                summary = str(path.get("path_summary") or "").strip()
                if summary:
                    sentence = f"Evidence graph path: {summary}."
                    if sentence not in chain:
                        chain.append(sentence)
        else:
            for path in causal_support.get("strongest_support_paths", [])[:2] if isinstance(causal_support.get("strongest_support_paths", []), list) else []:
                if not isinstance(path, dict):
                    continue
                source = str(path.get("source") or "").strip()
                target = str(path.get("target") or "").strip()
                relation = str(path.get("relation") or "").strip()
                if source and target and relation:
                    summary = f"Evidence graph shows {source} {relation} {target}."
                    if summary not in chain:
                        chain.append(summary)

        timeline = evidence_state.get("timeline", []) if isinstance(evidence_state, dict) and isinstance(evidence_state.get("timeline"), list) else []
        for event in timeline[-4:]:
            summary = str(event.get("summary") or "").strip()
            if summary and summary not in chain:
                chain.append(summary)

        verdict = str((deterministic_decision or {}).get("verdict") or "").strip().upper()
        if verdict:
            chain.append(f"Deterministic verdict remains {verdict}.")
        return chain[:7]

    @staticmethod
    def _derive_root_cause_statement(
        *,
        top: Dict[str, Any],
        causal_chain: List[str],
        relation_quality: float,
        chain_quality: float,
    ) -> str:
        statement = str(top.get("statement") or "").strip()
        support_refs = [item for item in top.get("supporting_evidence_refs", []) if isinstance(item, dict)]
        support_summaries = [
            str(item.get("summary") or "").strip().rstrip(".")
            for item in support_refs[:2]
            if str(item.get("summary") or "").strip()
        ]
        relation_summaries = [
            item.rstrip(".")
            for item in causal_chain
            if isinstance(item, str) and item.startswith("Relationship ")
        ]

        if chain_quality >= 0.78 and support_summaries:
            base = support_summaries[0]
            if relation_quality >= 0.9 and relation_summaries:
                relation_text = relation_summaries[0].replace("Relationship ", "", 1)
                return f"{base}; {relation_text}."
            return f"{base}."
        if chain_quality >= 0.68 and len(support_summaries) >= 2:
            return f"{support_summaries[0]}; corroborated by {support_summaries[1]}."
        return statement

    @staticmethod
    def _investigation_lane(*, goal: str, reasoning_state: Optional[Dict[str, Any]]) -> str:
        lane = ""
        if isinstance(reasoning_state, dict):
            lane = str(reasoning_state.get("investigation_lane") or "").strip().lower()
        if lane:
            return lane
        lowered = str(goal or "").lower()
        if any(token in lowered for token in ("email", "phish", "mailbox", "sender", "attachment")):
            return "email"
        if any(token in lowered for token in ("login", "logon", "credential", "session", "auth")):
            return "log_identity"
        if any(token in lowered for token in ("malware", "payload", "process", "file", "sandbox")):
            return "file"
        if any(token in lowered for token in ("cve", "vulnerability", "exposure", "exploit")):
            return "vulnerability"
        return "ioc"

    @staticmethod
    def _lane_requires_explicit_relations(*, lane: str, gap_pressure: float) -> bool:
        return lane in {"log_identity", "email", "file", "vulnerability"} and gap_pressure >= 0.62

    @staticmethod
    def _lane_thresholds(lane: str) -> Dict[str, float]:
        thresholds = {
            "minimum_observation_quality": 0.45,
            "minimum_relation_quality": 0.5,
            "minimum_evidence_score": 0.25,
            "required_typed_ratio": 0.5,
            "explicit_relation_quality_floor": 0.9,
            "supported_chain_floor": 0.78,
            "high_gap_pressure": 0.85,
            "contradiction_inconclusive_floor": 0.72,
            "maximum_narrative_support_ratio": 0.74,
            "supported_confidence_floor": 0.66,
            "supported_rank_floor": 0.88,
            "supported_margin_floor": 0.12,
            "supported_balance_floor": 0.55,
            "supported_relation_floor": 0.76,
            "supported_chain_accept_floor": 0.62,
            "supported_contradiction_ceiling": 0.28,
            "supported_structure_floor": 0.72,
        }
        if lane == "ioc":
            thresholds.update(
                {
                    "required_typed_ratio": 0.55,
                    "maximum_narrative_support_ratio": 0.45,
                    "supported_confidence_floor": 0.62,
                    "supported_rank_floor": 0.82,
                    "supported_margin_floor": 0.08,
                    "supported_balance_floor": 0.5,
                    "supported_structure_floor": 0.72,
                    "supported_contradiction_ceiling": 0.34,
                }
            )
        elif lane == "log_identity":
            thresholds.update(
                {
                    "required_typed_ratio": 0.0,
                    "supported_balance_floor": 0.48,
                    "maximum_narrative_support_ratio": 0.58,
                }
            )
        elif lane in {"email", "file", "vulnerability"}:
            thresholds.update(
                {
                    "minimum_observation_quality": 0.5,
                    "required_typed_ratio": 0.5,
                    "supported_margin_floor": 0.16,
                    "supported_balance_floor": 0.58,
                    "maximum_narrative_support_ratio": 0.34,
                }
            )
        return thresholds

    @staticmethod
    def _support_balance(
        *,
        top_conf: float,
        second_conf: float,
        score_margin: float,
        evidence_score: float,
        contradiction_score: float,
        quality: float,
        typed_evidence_ratio: float,
        relation_quality: float,
        timeline_quality: float,
        graph_support: float,
        chain_quality: float,
    ) -> float:
        advantage = max(0.0, top_conf - second_conf)
        evidence_advantage = max(0.0, evidence_score - contradiction_score)
        structure_strength = max(relation_quality, timeline_quality, graph_support, chain_quality)
        return min(
            1.0,
            (advantage * 0.2)
            + (max(0.0, score_margin) * 0.24)
            + (evidence_advantage * 0.2)
            + (quality * 0.1)
            + (typed_evidence_ratio * 0.12)
            + (structure_strength * 0.14),
        )

    @staticmethod
    def _is_supported(
        *,
        lane: str,
        top_conf: float,
        top_rank_score: float,
        score_margin: float,
        evidence_score: float,
        contradiction_score: float,
        typed_evidence_ratio: float,
        relation_quality: float,
        explicit_relation_ratio: float,
        timeline_quality: float,
        graph_support: float,
        chain_quality: float,
        support_balance: float,
        contradiction_pressure: float,
        lane_thresholds: Dict[str, float],
        narrative_support_ratio: float,
    ) -> bool:
        if evidence_score <= contradiction_score or contradiction_pressure >= 0.5:
            return False
        if narrative_support_ratio > lane_thresholds["maximum_narrative_support_ratio"]:
            return False
        if lane == "ioc":
            return (
                top_conf >= lane_thresholds["supported_confidence_floor"]
                and top_rank_score >= lane_thresholds["supported_rank_floor"]
                and score_margin >= lane_thresholds["supported_margin_floor"]
                and support_balance >= lane_thresholds["supported_balance_floor"]
                and typed_evidence_ratio >= lane_thresholds["required_typed_ratio"]
                and contradiction_pressure <= lane_thresholds["supported_contradiction_ceiling"]
                and max(relation_quality, timeline_quality, graph_support, chain_quality) >= lane_thresholds["supported_structure_floor"]
            )
        required_typed_ratio = lane_thresholds["required_typed_ratio"]
        required_support_balance = lane_thresholds["supported_balance_floor"]
        required_score_margin = lane_thresholds["supported_margin_floor"]
        required_explicit_ratio = RootCauseEngine._required_explicit_ratio(lane)
        if lane == "log_identity" and relation_quality >= 0.9:
            required_typed_ratio = 0.0
        return (
            top_conf >= lane_thresholds["supported_confidence_floor"]
            and top_rank_score >= lane_thresholds["supported_rank_floor"]
            and score_margin >= required_score_margin
            and support_balance >= required_support_balance
            and typed_evidence_ratio >= required_typed_ratio
            and relation_quality >= lane_thresholds["supported_relation_floor"]
            and explicit_relation_ratio >= required_explicit_ratio
            and chain_quality >= lane_thresholds["supported_chain_accept_floor"]
            and contradiction_pressure <= lane_thresholds["supported_contradiction_ceiling"]
            and max(timeline_quality, graph_support, relation_quality) >= lane_thresholds["supported_structure_floor"]
        )

    @staticmethod
    def _root_cause_rank_score(hypothesis: Optional[Dict[str, Any]]) -> float:
        if not isinstance(hypothesis, dict):
            return 0.0
        confidence = float(hypothesis.get("confidence", 0.0) or 0.0)
        evidence_score = float(hypothesis.get("evidence_score", 0.0) or 0.0)
        contradiction_score = float(hypothesis.get("contradiction_score", 0.0) or 0.0)
        support_count = len(hypothesis.get("supporting_evidence_refs", []) or [])
        contradiction_count = len(hypothesis.get("contradicting_evidence_refs", []) or [])
        status = str(hypothesis.get("status") or "")
        status_bonus = {
            "supported": 0.08,
            "open": 0.0,
            "inconclusive": -0.03,
            "unsupported": -0.08,
            "contradicted": -0.12,
        }.get(status, 0.0)
        return (
            confidence
            + evidence_score
            - contradiction_score
            + min(0.12, support_count * 0.02)
            - min(0.12, contradiction_count * 0.025)
            + status_bonus
        )

    @staticmethod
    def _chain_quality(
        *,
        top: Dict[str, Any],
        evidence_state: Optional[Dict[str, Any]],
        entity_state: Optional[Dict[str, Any]],
        active_observations: List[Dict[str, Any]],
    ) -> float:
        support_refs = list(top.get("supporting_evidence_refs", []) or [])
        observation_quality = RootCauseEngine._observation_quality(active_observations, support_refs)
        relation_quality = RootCauseEngine._relation_quality(entity_state)
        timeline_quality = RootCauseEngine._timeline_quality(evidence_state)
        graph_support = RootCauseEngine._graph_support_quality(evidence_state)
        support_density = min(1.0, len(support_refs) / 3.0)
        return min(
            1.0,
            (observation_quality * 0.32)
            + (relation_quality * 0.24)
            + (timeline_quality * 0.16)
            + (graph_support * 0.16)
            + (support_density * 0.12),
        )

    @staticmethod
    def _observation_quality(active_observations: Optional[List[Dict[str, Any]]], refs: List[Dict[str, Any]]) -> float:
        if not refs:
            return 0.0
        lookup = {
            str(item.get("observation_id") or ""): item
            for item in (active_observations or [])
            if isinstance(item, dict) and item.get("observation_id")
        }
        qualities = []
        for ref in refs:
            observation_id = str(ref.get("observation_id") or "").strip()
            if observation_id and observation_id in lookup:
                observation = lookup[observation_id]
                typed_fact = observation.get("typed_fact", {}) if isinstance(observation.get("typed_fact"), dict) else {}
                provenance = observation.get("provenance", {}) if isinstance(observation.get("provenance"), dict) else {}
                quality = float(typed_fact.get("quality", observation.get("quality", 0.0)) or 0.0)
                if provenance.get("source_paths"):
                    quality += 0.04
                if provenance.get("entity_count") or observation.get("entity_ids"):
                    quality += 0.04
                if typed_fact.get("family") in {"log", "ioc", "email", "file"}:
                    quality += 0.03
                qualities.append(min(1.0, quality))
            elif isinstance(ref.get("quality"), (int, float)):
                qualities.append(float(ref.get("quality")))
        if not qualities:
            return 0.0
        return sum(qualities) / len(qualities)

    @staticmethod
    def _typed_evidence_profile(active_observations: Optional[List[Dict[str, Any]]], refs: List[Dict[str, Any]]) -> Dict[str, float]:
        if not refs:
            return {"ratio": 0.0, "typed_count": 0.0, "total_count": 0.0}
        lookup = {
            str(item.get("observation_id") or ""): item
            for item in (active_observations or [])
            if isinstance(item, dict) and item.get("observation_id")
        }
        typed = 0
        total = 0
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            total += 1
            observation_id = str(ref.get("observation_id") or "").strip()
            observation = lookup.get(observation_id, {}) if observation_id else {}
            typed_fact = observation.get("typed_fact", {}) if isinstance(observation, dict) and isinstance(observation.get("typed_fact"), dict) else {}
            if typed_fact.get("family") or typed_fact.get("type"):
                typed += 1
        if not total:
            return {"ratio": 0.0, "typed_count": 0.0, "total_count": 0.0}
        return {
            "ratio": typed / total,
            "typed_count": float(typed),
            "total_count": float(total),
        }

    @staticmethod
    def _typed_evidence_ratio(active_observations: Optional[List[Dict[str, Any]]], refs: List[Dict[str, Any]]) -> float:
        return RootCauseEngine._typed_evidence_profile(active_observations, refs)["ratio"]

    @staticmethod
    def _narrative_support_ratio(active_observations: Optional[List[Dict[str, Any]]], refs: List[Dict[str, Any]]) -> float:
        if not refs:
            return 1.0
        profile = RootCauseEngine._typed_evidence_profile(active_observations, refs)
        total = max(profile["total_count"], 1.0)
        narrative_count = max(0.0, total - profile["typed_count"])
        return narrative_count / total

    @staticmethod
    def _typed_evidence_required(*, lane: str, relation_quality: float) -> bool:
        return lane in {"email", "file", "vulnerability"} or (lane == "ioc" and relation_quality >= 0.72)

    @staticmethod
    def _required_explicit_ratio(lane: str) -> float:
        if lane in {"email", "file", "vulnerability"}:
            return 0.67
        if lane == "log_identity":
            # One explicit anchor plus corroborating inferred links should still clear the lane.
            return 0.33
        return 0.0

    @staticmethod
    def _relation_profile(entity_state: Optional[Dict[str, Any]]) -> Dict[str, float]:
        if not isinstance(entity_state, dict):
            return {"quality": 0.0, "explicit_ratio": 0.0}
        relationships = entity_state.get("relationships", []) if isinstance(entity_state.get("relationships"), list) else []
        scores: List[float] = []
        explicit_count = 0
        qualifying_count = 0
        for relationship in relationships:
            if not isinstance(relationship, dict):
                continue
            confidence = float(relationship.get("relation_confidence", relationship.get("confidence", 0.0)) or 0.0)
            strength = str(relationship.get("relation_strength") or "")
            if strength == "explicit":
                confidence = max(confidence, 0.95)
                explicit_count += 1
                qualifying_count += 1
            elif strength == "inferred":
                confidence = max(confidence, 0.72)
                qualifying_count += 1
            elif strength == "co_observed":
                confidence = max(confidence, 0.4)
            if relationship.get("guarded"):
                confidence -= 0.08
            scores.append(max(0.0, min(1.0, confidence)))
        if not scores:
            return {"quality": 0.0, "explicit_ratio": 0.0}
        scores.sort(reverse=True)
        return {
            "quality": sum(scores[:3]) / min(3, len(scores)),
            "explicit_ratio": (explicit_count / qualifying_count) if qualifying_count else 0.0,
        }

    @staticmethod
    def _relation_quality(entity_state: Optional[Dict[str, Any]]) -> float:
        return RootCauseEngine._relation_profile(entity_state)["quality"]

    @staticmethod
    def _graph_support_quality(evidence_state: Optional[Dict[str, Any]]) -> float:
        if not isinstance(evidence_state, dict):
            return 0.0
        causal_support = evidence_state.get("causal_support", {}) if isinstance(evidence_state.get("causal_support"), dict) else {}
        support_paths = causal_support.get("strongest_support_paths", []) if isinstance(causal_support.get("strongest_support_paths"), list) else []
        if not support_paths:
            return 0.0
        confidences = [
            float(item.get("confidence", 0.0) or 0.0)
            for item in support_paths
            if isinstance(item, dict)
        ]
        if not confidences:
            return 0.0
        return min(1.0, sum(confidences[:3]) / min(3, len(confidences)))

    @staticmethod
    def _timeline_quality(evidence_state: Optional[Dict[str, Any]]) -> float:
        if not isinstance(evidence_state, dict):
            return 0.0
        timeline = evidence_state.get("timeline", []) if isinstance(evidence_state.get("timeline"), list) else []
        if len(timeline) >= 4:
            return 0.9
        if len(timeline) >= 2:
            return 0.72
        if len(timeline) == 1:
            return 0.45
        return 0.0

    @staticmethod
    def _gap_pressure(missing: List[str]) -> float:
        if not missing:
            return 0.0
        joined = " ".join(str(item) for item in missing).lower()
        if any(token in joined for token in ("need explicit", "insufficient evidence", "stronger attribution", "determine root cause confidently")):
            return 0.9
        if len(missing) >= 4:
            return 0.78
        if len(missing) >= 2:
            return 0.62
        return 0.4

    @staticmethod
    def _typed_evidence_gap_message(lane: str) -> str:
        if lane == "email":
            return "Need typed delivery or attachment observations before elevating email root-cause confidence."
        if lane == "file":
            return "Need typed execution, file, or sandbox observations before elevating file root-cause confidence."
        if lane == "vulnerability":
            return "Need typed exploitation or exposure observations before elevating vulnerability root-cause confidence."
        return "Need typed supporting observations before elevating root-cause confidence."

    @staticmethod
    def _explicit_relation_gap_message(lane: str) -> str:
        if lane == "email":
            return "Need explicit sender, recipient, attachment, or follow-on activity links before closing the email hypothesis."
        if lane == "file":
            return "Need explicit file, process, host, or user linkage before closing the file hypothesis."
        if lane == "vulnerability":
            return "Need explicit asset, exposure, and exploitation linkage before closing the vulnerability hypothesis."
        return "Need explicit entity linkage before closing the leading hypothesis."

    @staticmethod
    def _structural_conflict_gap_message(lane: str) -> str:
        if lane == "email":
            return "Need one more typed and explicitly linked delivery or follow-on observation before treating the email hypothesis as closed."
        if lane == "file":
            return "Need one more typed and explicitly linked execution or behavior observation before treating the file hypothesis as closed."
        return "Need one more typed and explicitly linked supporting observation before treating the leading hypothesis as closed."

    @staticmethod
    def _contradiction_gap_message(lane: str) -> str:
        if lane == "email":
            return "Resolve contradictory delivery, attachment, or mailbox evidence before closing the email hypothesis."
        if lane == "log_identity":
            return "Resolve contradictory authentication, session, or host linkage before closing the identity hypothesis."
        if lane == "file":
            return "Resolve contradictory execution or behavior evidence before closing the file hypothesis."
        return "Resolve the strongest contradictory evidence before closing the leading hypothesis."

    @staticmethod
    def _narrative_dependence_gap_message(lane: str) -> str:
        if lane == "email":
            return "Need more typed delivery, attachment, or mailbox evidence and less narrative-only support before closing the email hypothesis."
        if lane == "file":
            return "Need more typed execution or sandbox evidence and less narrative-only support before closing the file hypothesis."
        if lane == "log_identity":
            return "Need more typed authentication, process, or session evidence and less narrative-only support before closing the identity hypothesis."
        return "Need more typed supporting observations and less narrative-only support before closing the leading hypothesis."

    @staticmethod
    def _is_materially_contradicted(
        *,
        lane: str,
        evidence_score: float,
        contradiction_score: float,
        contradiction_refs: List[Dict[str, Any]],
        support_balance: float,
        score_margin: float,
    ) -> bool:
        if contradiction_score > evidence_score + 0.16:
            return True
        if not contradiction_refs:
            return False
        if contradiction_score >= evidence_score * 0.92:
            return True
        if lane in {"email", "file", "vulnerability"} and contradiction_score >= evidence_score * 0.82 and score_margin < 0.12:
            return True
        return support_balance < 0.34 and contradiction_score >= 0.2

    @staticmethod
    def _contradiction_pressure(
        *,
        lane: str,
        evidence_score: float,
        contradiction_score: float,
        contradiction_refs: List[Dict[str, Any]],
        second_conf: float,
        score_margin: float,
        support_balance: float,
    ) -> float:
        if contradiction_score <= 0.0 and not contradiction_refs:
            return 0.0
        contradiction_ratio = contradiction_score / max(evidence_score, 0.01)
        pressure = min(1.0, contradiction_ratio * 0.45)
        pressure += min(0.25, len(contradiction_refs) * 0.08)
        pressure += max(0.0, 0.12 - score_margin) * 1.2
        pressure += max(0.0, second_conf - 0.35) * 0.2
        pressure += max(0.0, 0.52 - support_balance) * 0.35
        if lane in {"email", "file", "vulnerability"}:
            pressure += 0.06
        return min(1.0, pressure)

    @staticmethod
    def _has_structural_conflict(
        *,
        lane: str,
        typed_support_count: float,
        support_refs: List[Dict[str, Any]],
        contradiction_refs: List[Dict[str, Any]],
        relation_quality: float,
        explicit_relation_ratio: float,
        graph_support: float,
        chain_quality: float,
    ) -> bool:
        if lane not in {"email", "file", "vulnerability"}:
            return False
        if contradiction_refs:
            return False
        if len(support_refs) < 2:
            return False
        if typed_support_count >= 2 and explicit_relation_ratio >= 0.67:
            return False
        strong_structure = max(relation_quality, graph_support, chain_quality) >= 0.8
        return strong_structure and typed_support_count < 2

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
