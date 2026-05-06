"""Objective-aware evidence retrieval for AISA context packs."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .token_estimator import estimate_json_tokens


DEFAULT_RANKING_WEIGHTS = {
    "objective_relevance": 0.28,
    "authority": 0.20,
    "evidence_quality": 0.16,
    "hypothesis_or_gap": 0.12,
    "contradiction": 0.10,
    "recency": 0.08,
    "diversity": 0.06,
    "analyst_focus": 0.0,
}


def normalize_ranking_weights(config: Dict[str, Any] | None = None) -> Dict[str, float]:
    """Return telemetry-tunable retrieval weights with stable defaults."""
    cfg = config or {}
    nested = cfg.get("context_management", {}) if isinstance(cfg.get("context_management"), dict) else {}
    weights = nested.get("ranking_weights", {}) if isinstance(nested.get("ranking_weights"), dict) else {}
    agent_cfg = cfg.get("agent", {}) if isinstance(cfg.get("agent"), dict) else {}
    agent_ctx = agent_cfg.get("context", {}) if isinstance(agent_cfg.get("context"), dict) else {}
    if isinstance(agent_ctx.get("ranking_weights"), dict):
        weights = {**weights, **agent_ctx.get("ranking_weights", {})}
    merged = dict(DEFAULT_RANKING_WEIGHTS)
    for key, value in weights.items():
        if key not in merged:
            continue
        try:
            merged[key] = max(0.0, float(value))
        except (TypeError, ValueError):
            continue
    return merged


class EvidenceRetriever:
    """Select high-value evidence briefs from an investigation context map."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.ranking_weights = normalize_ranking_weights(config)
        self.ranking_weights_version = "context-ranking-weights/v1"

    def retrieve(
        self,
        context_map: Dict[str, Any],
        *,
        objective: str = "decide_next_tool",
        max_briefs: int = 12,
        analyst_focus: str = "",
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        candidates: List[Dict[str, Any]] = []
        for ref in context_map.get("ranked_evidence_refs", []) or []:
            if isinstance(ref, dict):
                candidates.append(self._brief_from_ref(ref, selected_reason="ranked evidence relevance"))
        for contradiction in context_map.get("contradictions", []) or []:
            if isinstance(contradiction, dict):
                candidates.append(self._brief_from_ref(contradiction, selected_reason="top contradiction must remain visible", contradiction=True))
        for missing in context_map.get("missing_evidence", []) or []:
            if isinstance(missing, dict):
                candidates.append(self._missing_brief(missing))
        for gap in context_map.get("coverage_gaps", []) or []:
            if isinstance(gap, dict):
                candidates.append(self._coverage_gap_brief(gap))

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in candidates:
            key = (
                str(item.get("evidence_ref", {}).get("observation_id") or ""),
                str(item.get("evidence_ref", {}).get("tool_name") or ""),
                str(item.get("evidence_ref", {}).get("step_number") or ""),
                str(item.get("summary") or "")[:100],
                str(item.get("kind") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            score_detail = self._score_detail(item, objective=objective, analyst_focus=analyst_focus)
            item["score"] = round(float(score_detail["score"]), 4)
            item["ranking_score_detail"] = score_detail
            item["ranking_weights_version"] = self.ranking_weights_version
            item["token_estimate"] = estimate_json_tokens(item)
            deduped.append(item)

        ranked = sorted(deduped, key=lambda item: float(item.get("score") or 0.0), reverse=True)
        required = [item for item in ranked if item.get("do_not_drop")]
        optional = [item for item in ranked if not item.get("do_not_drop")]
        selected = [*required, *optional]
        final_selected = selected[:max(1, int(max_briefs or 12))]
        selected_ids = {item.get("brief_id") for item in final_selected}
        excluded = [
            {**item, "exclude_reason": "lower relevance after objective/authority/coverage ranking"}
            for item in ranked
            if item.get("brief_id") not in selected_ids
        ]
        return final_selected, excluded

    @staticmethod
    def _brief_from_ref(ref: Dict[str, Any], *, selected_reason: str, contradiction: bool = False) -> Dict[str, Any]:
        summary = str(ref.get("summary") or ref.get("label") or ref.get("basis") or "Evidence reference").strip()
        evidence_ref = {
            key: ref.get(key)
            for key in ("session_id", "step_number", "finding_index", "tool_name", "observation_id", "result_path", "source_path")
            if ref.get(key) is not None
        }
        brief_id = "ebr-" + str(ref.get("observation_id") or ref.get("finding_index") or ref.get("step_number") or abs(hash(summary)) % 100000)
        stance = "contradicts" if contradiction else str(ref.get("stance") or "neutral")
        return {
            "brief_id": brief_id,
            "kind": "evidence_brief",
            "section": "evidence",
            "evidence_ref": evidence_ref,
            "summary": summary,
            "supports": [ref.get("hypothesis_id")] if stance == "supports" and ref.get("hypothesis_id") else [],
            "contradicts": [ref.get("hypothesis_id")] if stance == "contradicts" and ref.get("hypothesis_id") else [],
            "entities": list(ref.get("entity_ids") or [])[:8],
            "authority": ref.get("authority") or "tool_observation",
            "authoritative_for_verdict": bool(ref.get("authoritative_for_verdict", False)),
            "quality": ref.get("quality") or ref.get("confidence") or 0.0,
            "recency": ref.get("recency", 0.5),
            "diversity_bonus": ref.get("diversity_bonus", 0.5),
            "stance": stance,
            "selected_reason": selected_reason,
            "reason": selected_reason,
            "do_not_drop": bool(contradiction),
            "source_refs": [evidence_ref] if evidence_ref else [],
            "score": float(ref.get("score") or 0.0),
        }

    @staticmethod
    def _missing_brief(item: Dict[str, Any]) -> Dict[str, Any]:
        summary = str(item.get("summary") or item.get("facet") or "Missing evidence remains")
        return {
            "brief_id": "missing-" + str(abs(hash(summary)) % 100000),
            "kind": "missing_evidence",
            "section": "coverage",
            "summary": summary,
            "evidence_ref": {},
            "supports": [],
            "contradicts": [],
            "entities": [],
            "authority": item.get("authority") or "coverage_metadata",
            "authoritative_for_verdict": False,
            "quality": 0.8,
            "recency": item.get("recency", 0.5),
            "diversity_bonus": item.get("diversity_bonus", 0.5),
            "stance": "missing",
            "selected_reason": "missing evidence prevents overclaiming",
            "reason": "missing evidence prevents overclaiming",
            "do_not_drop": True,
            "source_refs": [],
            "score": float(item.get("score") or 0.86),
        }

    @staticmethod
    def _coverage_gap_brief(gap: Dict[str, Any]) -> Dict[str, Any]:
        facet = str(gap.get("facet") or "coverage_gap")
        summary = f"Coverage gap: {facet} status={gap.get('status') or 'missing'} basis={gap.get('basis') or 'unknown'}"
        return {
            "brief_id": "gap-" + str(abs(hash(summary)) % 100000),
            "kind": "coverage_gap",
            "section": "coverage",
            "summary": summary,
            "evidence_ref": {},
            "supports": [],
            "contradicts": [],
            "entities": [],
            "authority": "coverage_metadata",
            "authoritative_for_verdict": False,
            "quality": 0.75,
            "recency": gap.get("recency", 0.5),
            "diversity_bonus": gap.get("diversity_bonus", 0.5),
            "stance": "missing",
            "selected_reason": "blocking coverage gap for next action",
            "reason": "blocking coverage gap for next action",
            "do_not_drop": True,
            "source_refs": [],
            "score": float(gap.get("score") or 0.78),
        }

    def _score_detail(self, item: Dict[str, Any], *, objective: str, analyst_focus: str = "") -> Dict[str, Any]:
        authority_weight = {
            "deterministic": 1.0,
            "tool_observation": 0.82,
            "accepted_fact": 0.78,
            "coverage_metadata": 0.72,
            "memory_snapshot": 0.45,
            "agentic_explanation": 0.42,
            "candidate": 0.28,
        }.get(str(item.get("authority") or "").strip(), 0.35)
        quality = min(1.0, max(0.0, float(item.get("quality") or 0.0)))
        relevance = min(1.0, max(0.0, float(item.get("score") or 0.0)))
        gap = 1.0 if item.get("kind") in {"coverage_gap", "missing_evidence"} else 0.35
        contradiction = 1.0 if item.get("stance") == "contradicts" or item.get("contradicts") else 0.0
        recency = min(1.0, max(0.0, float(item.get("recency") or 0.5)))
        diversity = min(1.0, max(0.0, float(item.get("diversity_bonus") or 0.5)))
        focus_l = str(analyst_focus or "").lower()
        summary_l = str(item.get("summary") or "").lower()
        analyst_focus_score = 1.0 if focus_l and any(tok in summary_l for tok in focus_l.split()[:8]) else 0.0
        objective_boost = 0.12 if objective == "decide_next_tool" and item.get("kind") in {"coverage_gap", "missing_evidence"} else 0.0
        factors = {
            "objective_relevance": relevance,
            "authority": authority_weight,
            "evidence_quality": quality,
            "hypothesis_or_gap": gap,
            "contradiction": contradiction,
            "recency": recency,
            "diversity": diversity,
            "analyst_focus": analyst_focus_score,
        }
        weighted = sum(float(self.ranking_weights.get(k, 0.0)) * v for k, v in factors.items()) + objective_boost
        return {
            "score": round(weighted, 6),
            "factors": factors,
            "weights": dict(self.ranking_weights),
            "weights_version": self.ranking_weights_version,
            "why_included": item.get("selected_reason") or item.get("reason") or "ranked by context retriever",
            "telemetry_authority": "orchestration_metadata_non_authoritative",
        }
