"""Build objective-aware investigation context maps from AISA agent state."""

from __future__ import annotations

from typing import Any, Dict, List

from .context_pack import AUTHORITY_POLICY


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _score_quality(value: Any, default: float = 0.0) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


class InvestigationContextMapBuilder:
    """Extract and conservatively rank context from reasoning/evidence state."""

    def build(self, state: Any, *, objective: str = "decide_next_tool", analyst_focus: str = "") -> Dict[str, Any]:
        reasoning = getattr(state, "reasoning_state", {}) if isinstance(getattr(state, "reasoning_state", {}), dict) else {}
        entity_state = getattr(state, "entity_state", {}) if isinstance(getattr(state, "entity_state", {}), dict) else {}
        evidence_state = getattr(state, "evidence_state", {}) if isinstance(getattr(state, "evidence_state", {}), dict) else {}
        agentic = getattr(state, "agentic_explanation", {}) if isinstance(getattr(state, "agentic_explanation", {}), dict) else {}
        deterministic = getattr(state, "deterministic_decision", {}) if isinstance(getattr(state, "deterministic_decision", {}), dict) else {}
        focus = analyst_focus or str(reasoning.get("goal_focus") or getattr(state, "goal", "") or "")
        ranked_hypotheses = self._rank_hypotheses(reasoning)
        ranked_entities = self._rank_entities(entity_state, focus=focus)
        ranked_relationships = self._rank_relationships(entity_state)
        ranked_evidence_refs = self._rank_evidence_refs(reasoning, evidence_state, getattr(state, "findings", []) or [], focus=focus)
        coverage_gaps = self._coverage_gaps(reasoning)
        missing_evidence = self._missing_evidence(reasoning, agentic, coverage_gaps)
        contradictions = self._contradictions(ranked_hypotheses, evidence_state)
        root_cause = agentic.get("root_cause_assessment", {}) if isinstance(agentic.get("root_cause_assessment"), dict) else {}
        return {
            "schema_version": "investigation-context-map/v1",
            "session_id": getattr(state, "session_id", None),
            "objective": objective,
            "authority_policy": AUTHORITY_POLICY,
            "ranked_entities": ranked_entities,
            "ranked_relationships": ranked_relationships,
            "ranked_hypotheses": ranked_hypotheses,
            "ranked_evidence_refs": ranked_evidence_refs,
            "contradictions": contradictions,
            "missing_evidence": missing_evidence,
            "coverage_gaps": coverage_gaps,
            "root_cause_state": {
                **root_cause,
                "authority": "agentic_explanation",
                "authoritative_for_verdict": False,
            } if root_cause else {},
            "deterministic_decision": {
                **deterministic,
                "authority": "deterministic",
                "authoritative_for_verdict": bool(deterministic),
            },
            "memory_contract": {
                "restored_memory_scope": getattr(state, "restored_memory_scope", None),
                "chat_context_restored_memory_scope": getattr(state, "chat_context_restored_memory_scope", None),
                "authority": "memory_snapshot",
                "authoritative_for_verdict": False,
            },
            "query_attempts": list(reasoning.get("query_attempts", []) or [])[-6:],
            "retry_state": reasoning.get("retry_state", {}) if isinstance(reasoning.get("retry_state"), dict) else {},
        }

    def _rank_hypotheses(self, reasoning: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = []
        for hyp in _as_list(reasoning.get("hypotheses")):
            if not isinstance(hyp, dict):
                continue
            support = len(hyp.get("supporting_evidence_refs", []) or [])
            contradict = len(hyp.get("contradicting_evidence_refs", []) or [])
            score = float(hyp.get("ranking_score") or hyp.get("priority") or hyp.get("confidence") or 0.0)
            score += min(0.25, support * 0.04) + min(0.25, contradict * 0.08)
            if hyp.get("status") in {"supported", "inconclusive", "open"}:
                score += 0.08
            items.append({
                **hyp,
                "score": round(score, 4),
                "authority": "agentic_explanation",
                "authoritative_for_verdict": False,
                "evidence_refs": list(hyp.get("supporting_evidence_refs", []) or [])[:8],
                "contradiction_refs": list(hyp.get("contradicting_evidence_refs", []) or [])[:8],
            })
        for candidate in _as_list(reasoning.get("candidate_hypotheses")):
            if isinstance(candidate, dict):
                items.append({
                    **candidate,
                    "id": candidate.get("candidate_id") or candidate.get("id"),
                    "score": round(float(candidate.get("confidence_prior") or 0.18), 4),
                    "authority": "candidate",
                    "authoritative_for_verdict": False,
                })
        return sorted(items, key=lambda item: float(item.get("score") or 0.0), reverse=True)[:12]

    def _rank_entities(self, entity_state: Dict[str, Any], *, focus: str) -> List[Dict[str, Any]]:
        entities = entity_state.get("entities", {}) if isinstance(entity_state.get("entities"), dict) else {}
        focus_l = str(focus or "").lower()
        ranked = []
        for entity in entities.values():
            if not isinstance(entity, dict):
                continue
            value = str(entity.get("value") or entity.get("canonical_value") or entity.get("id") or "")
            score = _score_quality(entity.get("confidence"), 0.4)
            score += min(0.2, int(entity.get("observation_count") or 0) * 0.03)
            score += min(0.16, len(entity.get("evidence_refs", []) or []) * 0.03)
            if value and value.lower() in focus_l:
                score += 0.25
            ranked.append({
                **entity,
                "score": round(score, 4),
                "authority": "tool_observation",
                "authoritative_for_verdict": False,
            })
        return sorted(ranked, key=lambda item: float(item.get("score") or 0.0), reverse=True)[:24]

    def _rank_relationships(self, entity_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        ranked = []
        for rel in _as_list(entity_state.get("relationships")):
            if not isinstance(rel, dict):
                continue
            score = _score_quality(rel.get("relation_confidence", rel.get("confidence")), 0.3)
            if rel.get("relation_strength") == "explicit" or rel.get("explicit"):
                score += 0.2
            if rel.get("guarded"):
                score -= 0.08
            ranked.append({
                **rel,
                "score": round(max(0.0, score), 4),
                "authority": "tool_observation",
                "authoritative_for_verdict": False,
            })
        return sorted(ranked, key=lambda item: float(item.get("score") or 0.0), reverse=True)[:24]

    def _rank_evidence_refs(self, reasoning: Dict[str, Any], evidence_state: Dict[str, Any], findings: List[Dict[str, Any]], *, focus: str) -> List[Dict[str, Any]]:
        refs: List[Dict[str, Any]] = []
        for ref in _as_list(reasoning.get("recent_evidence_refs")):
            if isinstance(ref, dict):
                refs.append({**ref, "source_bucket": "recent_evidence_refs"})
        for hyp in _as_list(reasoning.get("hypotheses")):
            if not isinstance(hyp, dict):
                continue
            for ref in _as_list(hyp.get("supporting_evidence_refs")):
                if isinstance(ref, dict):
                    refs.append({**ref, "hypothesis_id": hyp.get("id"), "stance": "supports", "source_bucket": "hypothesis_support"})
            for ref in _as_list(hyp.get("contradicting_evidence_refs")):
                if isinstance(ref, dict):
                    refs.append({**ref, "hypothesis_id": hyp.get("id"), "stance": "contradicts", "source_bucket": "hypothesis_contradiction"})
        timeline = evidence_state.get("timeline", []) if isinstance(evidence_state, dict) else []
        for event in _as_list(timeline)[-12:]:
            if isinstance(event, dict):
                refs.append({
                    "observation_id": event.get("observation_id") or event.get("id"),
                    "tool_name": event.get("tool_name"),
                    "step_number": event.get("step_number"),
                    "summary": event.get("summary") or event.get("title"),
                    "created_at": event.get("timestamp"),
                    "source_bucket": "evidence_timeline",
                    "stance": "neutral",
                    "quality": 0.55,
                })
        for idx, finding in enumerate(findings):
            if isinstance(finding, dict) and finding.get("type") == "tool_result":
                refs.append({
                    "finding_index": idx,
                    "step_number": finding.get("step", idx),
                    "tool_name": finding.get("tool"),
                    "summary": self._finding_summary(finding),
                    "created_at": finding.get("timestamp"),
                    "source_bucket": "finding",
                    "stance": "neutral",
                    "quality": 0.42,
                })
        deduped = []
        seen = set()
        focus_l = str(focus or "").lower()
        for ref in refs:
            key = (str(ref.get("observation_id") or ""), str(ref.get("tool_name") or ""), str(ref.get("step_number") or ""), str(ref.get("finding_index") or ""), str(ref.get("summary") or "")[:80])
            if key in seen:
                continue
            seen.add(key)
            stance = str(ref.get("stance") or "neutral")
            score = _score_quality(ref.get("confidence"), _score_quality(ref.get("quality"), 0.35))
            if ref.get("source_bucket") == "hypothesis_contradiction" or stance == "contradicts":
                score += 0.35
            elif ref.get("source_bucket") == "hypothesis_support" or stance == "supports":
                score += 0.22
            if str(ref.get("summary") or "").lower() and focus_l and any(token in str(ref.get("summary") or "").lower() for token in focus_l.split()[:6]):
                score += 0.08
            deduped.append({
                **ref,
                "score": round(score, 4),
                "authority": "tool_observation",
                "authoritative_for_verdict": False,
            })
        return sorted(deduped, key=lambda item: float(item.get("score") or 0.0), reverse=True)[:40]

    @staticmethod
    def _coverage_gaps(reasoning: Dict[str, Any]) -> List[Dict[str, Any]]:
        coverage = reasoning.get("coverage_matrix", {}) if isinstance(reasoning.get("coverage_matrix"), dict) else {}
        gaps = []
        for gap in _as_list(coverage.get("blocking_gaps")):
            if isinstance(gap, dict):
                gaps.append({**gap, "authority": "coverage_metadata", "authoritative_for_verdict": False, "score": 0.9})
        for cell in _as_list(coverage.get("cells")):
            if isinstance(cell, dict) and cell.get("blocking_gap") and len(gaps) < 12:
                gaps.append({
                    "facet": cell.get("facet"),
                    "status": cell.get("status"),
                    "basis": cell.get("basis"),
                    "missing_fields": list(cell.get("missing_fields") or [])[:8],
                    "authority": "coverage_metadata",
                    "authoritative_for_verdict": False,
                    "score": 0.78,
                })
        return gaps[:12]

    @staticmethod
    def _missing_evidence(reasoning: Dict[str, Any], agentic: Dict[str, Any], coverage_gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        values = []
        for value in [*(_as_list(reasoning.get("missing_evidence"))), *(_as_list(reasoning.get("open_questions"))), *(_as_list(agentic.get("missing_evidence")))]:
            text = str(value or "").strip()
            if text:
                values.append(text)
        for gap in coverage_gaps[:6]:
            facet = str(gap.get("facet") or "").strip()
            if facet:
                values.append(f"Coverage gap remains for {facet}")
        seen = set()
        out = []
        for text in values:
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append({"summary": text, "authority": "coverage_metadata", "authoritative_for_verdict": False, "score": 0.86})
        return out[:12]

    @staticmethod
    def _contradictions(hypotheses: List[Dict[str, Any]], evidence_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        contradictions = []
        for hyp in hypotheses:
            for ref in _as_list(hyp.get("contradiction_refs")):
                if isinstance(ref, dict):
                    contradictions.append({
                        **ref,
                        "hypothesis_id": hyp.get("id"),
                        "summary": ref.get("summary") or f"Contradicts hypothesis {hyp.get('id')}",
                        "authority": "tool_observation",
                        "authoritative_for_verdict": False,
                        "score": 0.98,
                    })
        for edge in _as_list(evidence_state.get("edges") if isinstance(evidence_state, dict) else []):
            if isinstance(edge, dict) and edge.get("relation") == "contradicts":
                contradictions.append({**edge, "authority": "tool_observation", "authoritative_for_verdict": False, "score": 0.92})
        return contradictions[:8]

    @staticmethod
    def _finding_summary(finding: Dict[str, Any]) -> str:
        tool = str(finding.get("tool") or "tool_result")
        result = finding.get("result")
        if isinstance(result, dict):
            payload = result.get("result") if isinstance(result.get("result"), dict) else result
            for key in ("summary", "verdict", "severity", "error"):
                if isinstance(payload, dict) and payload.get(key):
                    return f"{tool}: {key}={payload.get(key)}"
        return f"{tool} result"
