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
            key=lambda item: self._root_cause_rank_score(item),
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
        top_rank_score = self._root_cause_rank_score(top)
        second_rank_score = self._root_cause_rank_score(second) if second else 0.0
        score_margin = top_rank_score - second_rank_score
        support_refs = list(top.get("supporting_evidence_refs", []) or [])
        contradiction_refs = list(top.get("contradicting_evidence_refs", []) or [])
        evidence_score = float(top.get("evidence_score", 0.0) or 0.0)
        contradiction_score = float(top.get("contradiction_score", 0.0) or 0.0)
        quality = self._observation_quality(active_observations, support_refs)
        relation_quality = self._relation_quality(entity_state)
        timeline_quality = self._timeline_quality(evidence_state)
        gap_pressure = self._gap_pressure(missing)
        chain_quality = self._chain_quality(
            top=top,
            evidence_state=evidence_state,
            entity_state=entity_state,
            active_observations=active_observations or [],
        )
        best_explanation = str(top.get("statement") or "Likely root cause candidate.").strip() or "Likely root cause candidate."

        if (
            str(top.get("status") or "") in {"unsupported", "contradicted"}
            or contradiction_score > evidence_score + 0.16
        ):
            status = "unsupported_hypothesis"
        elif not support_refs or ((quality < 0.45 and relation_quality < 0.5) and evidence_score < 0.25):
            status = "insufficient_evidence"
        elif gap_pressure >= 0.85 and relation_quality < 0.9 and chain_quality < 0.78:
            status = "insufficient_evidence"
        elif (
            top_conf >= 0.62
            and top_rank_score >= 0.82
            and score_margin >= 0.08
            and evidence_score > contradiction_score
            and (relation_quality >= 0.76 or timeline_quality >= 0.72 or chain_quality >= 0.78)
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
            if relation_quality >= 0.9:
                summary += " Explicit entity relationships materially strengthen this assessment."
            if chain_quality >= 0.8:
                summary += " The causal chain is materially complete across evidence, relation, and timeline signals."
            confidence = max(0.0, min(0.99, max(top_conf, (top_conf + relation_quality + chain_quality) / 3)))
        elif status == "unsupported_hypothesis":
            primary_root_cause = derived_root_cause or best_explanation
            summary = "The current leading explanation is the best available candidate, but it is materially undercut by contradictory evidence and should not be treated as a confident root cause."
            if missing:
                summary += f" Highest-priority gap: {missing[0]}"
            confidence = min(max(top_conf, quality * 0.55), 0.58)
        elif status == "inconclusive":
            primary_root_cause = derived_root_cause or best_explanation
            summary = "The investigation has a best explanation so far, but competing explanations or unresolved gaps remain too strong to declare a confident root cause."
            if missing:
                summary += f" Highest-priority gap: {missing[0]}"
            confidence = min(max(top_conf, relation_quality * 0.7, chain_quality * 0.72), 0.74)
        else:
            primary_root_cause = "Insufficient evidence to determine root cause confidently."
            summary = "The investigation still lacks enough high-quality, well-attributed evidence to name a reliable root cause."
            if missing:
                summary += f" Highest-priority gap: {missing[0]}"
            confidence = min(max(top_conf, relation_quality * 0.45), 0.44)
        if contradiction_refs and status != "supported":
            missing = self._dedupe([*missing, "Collect stronger contradictory or corroborating evidence before closing the investigation."])[:8]
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
        for relationship in relationships[:4]:
            if not isinstance(relationship, dict):
                continue
            relation = str(relationship.get("relation") or "").strip()
            strength = str(relationship.get("relation_strength") or "").strip()
            source = str(relationship.get("source") or "").strip()
            target = str(relationship.get("target") or "").strip()
            if relation and source and target and strength in {"explicit", "inferred"}:
                relation_summary = f"Relationship {relation} links {source} to {target} ({strength})."
                if relation_summary not in chain:
                    chain.append(relation_summary)

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
        support_density = min(1.0, len(support_refs) / 3.0)
        return min(
            1.0,
            (observation_quality * 0.38)
            + (relation_quality * 0.27)
            + (timeline_quality * 0.2)
            + (support_density * 0.15),
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
    def _relation_quality(entity_state: Optional[Dict[str, Any]]) -> float:
        if not isinstance(entity_state, dict):
            return 0.0
        relationships = entity_state.get("relationships", []) if isinstance(entity_state.get("relationships"), list) else []
        best = 0.0
        for relationship in relationships:
            if not isinstance(relationship, dict):
                continue
            strength = str(relationship.get("relation_strength") or "")
            if strength == "explicit":
                best = max(best, 0.95)
            elif strength == "inferred":
                best = max(best, 0.72)
            elif strength == "co_observed":
                best = max(best, 0.4)
        return best

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
