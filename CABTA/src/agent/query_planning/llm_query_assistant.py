"""Safe advisory LLM query proposal for AISA log hunt planning."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

from ..log_query_coverage import build_query_fingerprint

ProviderCallable = Callable[[str], Optional[str]]


class LLMQueryAssistant:
    """Request non-authoritative query suggestions and never execute them directly."""

    def __init__(self, *, config: Dict[str, Any] | None = None, provider: ProviderCallable | None = None) -> None:
        self.config = config if isinstance(config, dict) else {}
        self.provider = provider
        hunting = self.config.get("log_hunting", {}) if isinstance(self.config.get("log_hunting", {}), dict) else {}
        self.enabled = bool(hunting.get("llm_query_assist_enabled", False))
        self.max_candidates = max(1, int(hunting.get("llm_query_assist_max_candidates", 3) or 3))
        self.require_validation = bool(hunting.get("llm_query_assist_require_validation", True))

    def propose(
        self,
        *,
        goal: str,
        lane: str,
        focus: str,
        coverage_matrix: Dict[str, Any] | None = None,
        hypotheses: List[Dict[str, Any]] | None = None,
        existing_variants: List[Dict[str, Any]] | None = None,
        retry_state: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return self._status("disabled", "LLM query assistance is disabled by configuration.")
        if self.provider is None:
            return self._status("unavailable", "No LLM query assistance provider is configured.")

        prompt = self.build_prompt(
            goal=goal,
            lane=lane,
            focus=focus,
            coverage_matrix=coverage_matrix or {},
            hypotheses=hypotheses or [],
            existing_variants=existing_variants or [],
            retry_state=retry_state or {},
        )
        try:
            raw = self.provider(prompt)
        except Exception as exc:  # pragma: no cover - defensive runtime boundary
            return self._status("degraded", f"LLM query assistance provider failed: {exc}")
        if not raw:
            return self._status("unavailable", "LLM query assistance provider returned no response.")

        parsed = self._parse_json(str(raw))
        if parsed is None:
            return self._status("degraded", "LLM query assistance response was not valid JSON.", raw_preview=str(raw)[:300])
        raw_candidates = parsed.get("candidates") if isinstance(parsed, dict) else parsed
        if not isinstance(raw_candidates, list):
            return self._status("degraded", "LLM query assistance JSON did not include a candidates list.")

        accepted: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        for idx, item in enumerate(raw_candidates[: self.max_candidates]):
            candidate = self._normalize_candidate(item, idx)
            if candidate.get("rejection_reason"):
                rejected.append(candidate)
            else:
                accepted.append(candidate)

        status = "ok" if accepted else "degraded"
        reason = "LLM query assistance returned advisory candidates." if accepted else "No usable LLM query candidates were returned."
        return {
            "status": status,
            "reason": reason,
            "enabled": True,
            "authoritative": False,
            "requires_validation": self.require_validation,
            "candidate_count": len(accepted),
            "candidates": accepted,
            "rejected_candidates": rejected,
        }

    def suggest_rewrite_after_result(
        self,
        *,
        failed_query: Any,
        result_class: str,
        coverage_gaps: List[Any] | None = None,
        retry_state: Dict[str, Any] | None = None,
        lane: str = "",
        focus: str = "",
    ) -> Dict[str, Any]:
        coverage_matrix = {
            "blocking_gaps": coverage_gaps or [],
            "missing_facets": [str(item.get("facet")) for item in (coverage_gaps or []) if isinstance(item, dict) and item.get("facet")],
        }
        if not coverage_matrix["missing_facets"]:
            coverage_matrix["missing_facets"] = [str(item) for item in (coverage_gaps or []) if str(item).strip()]
        proposal = self.propose(
            goal=f"Rewrite failed or partial query after result_class={result_class}.",
            lane=lane,
            focus=focus,
            coverage_matrix=coverage_matrix,
            hypotheses=[],
            existing_variants=[{"query": failed_query, "strategy": "failed_or_partial_query", "variant_id": "failed_query"}],
            retry_state={**dict(retry_state or {}), "last_result_class": result_class},
        )
        proposal["advisory_type"] = "post_result_rewrite"
        proposal["failed_query_fingerprint"] = build_query_fingerprint(failed_query)
        proposal["result_class"] = result_class
        return proposal

    def build_prompt(
        self,
        *,
        goal: str,
        lane: str,
        focus: str,
        coverage_matrix: Dict[str, Any],
        hypotheses: List[Dict[str, Any]],
        existing_variants: List[Dict[str, Any]],
        retry_state: Dict[str, Any],
    ) -> str:
        gaps = coverage_matrix.get("blocking_gaps") or coverage_matrix.get("missing_facets") or []
        if isinstance(gaps, list):
            compact_gaps = gaps[:6]
        else:
            compact_gaps = []
        compact = {
            "goal": str(goal or "")[:300],
            "lane": str(lane or "")[:80],
            "focus": str(focus or "")[:160],
            "coverage_gaps": compact_gaps,
            "required_facets": list((coverage_matrix.get("required_facets") or coverage_matrix.get("coverage_targets") or [])[:8]),
            "hypotheses": [str(item.get("statement") or item.get("id") or "")[:180] for item in hypotheses[:4] if isinstance(item, dict)],
            "existing_variant_strategies": [str(item.get("strategy") or item.get("variant_id") or "")[:80] for item in existing_variants[:8] if isinstance(item, dict)],
            "retry_state": {"last_result_class": retry_state.get("last_result_class"), "last_remaining_gaps": retry_state.get("last_remaining_gaps")},
        }
        return "\n".join([
            "You are proposing non-authoritative AISA log query candidates.",
            "Safety rules: read-only log queries only; no destructive/admin actions; no outputlookup, collect, delete, update, map, rest, script, or external side effects.",
            "Avoid broad unbounded searches; include bounded SPL with head/limit and keep scope tied to the focus, facets, or objective.",
            "Emit JSON only with shape: {\"candidates\":[{\"backend\":\"splunk\",\"query\":\"...\",\"objective\":\"...\",\"expected_facets\":[\"...\"],\"strategy\":\"...\"}]}",
            "Every candidate must include query, objective, and expected_facets. These suggestions will be policy validated before execution and cannot decide verdicts/root cause.",
            "Do not include secrets, tokens, credentials, or configuration values.",
            "Context JSON:",
            json.dumps(compact, ensure_ascii=True, default=str),
        ])

    @staticmethod
    def _parse_json(raw: str) -> Any:
        text = raw.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"(\{.*\}|\[.*\])", text, flags=re.DOTALL)
            if not match:
                return None
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                return None

    def _normalize_candidate(self, item: Any, idx: int) -> Dict[str, Any]:
        if not isinstance(item, dict):
            return {"candidate_index": idx, "rejection_reason": "candidate_not_object"}
        query = str(item.get("query") or item.get("spl") or "").strip()
        objective = str(item.get("objective") or item.get("reason") or "").strip()
        facets = item.get("expected_facets") or item.get("target_facets") or []
        facets = [str(facet).strip() for facet in facets if str(facet).strip()] if isinstance(facets, list) else []
        candidate = {
            "variant_id": str(item.get("variant_id") or f"llm_suggestion_{idx + 1}"),
            "backend": str(item.get("backend") or "splunk"),
            "strategy": str(item.get("strategy") or "llm_query_assist"),
            "target_facets": facets,
            "expected_facets": facets,
            "expected_entities": list(item.get("expected_entities") or []) if isinstance(item.get("expected_entities"), list) else [],
            "objective": objective,
            "query": query,
            "reason": objective,
            "source": "llm_suggestion",
            "generation_source": "llm_query_assist",
            "authoritative": False,
        }
        if query:
            candidate["fingerprint"] = build_query_fingerprint(query)
        if not query:
            candidate["rejection_reason"] = "missing_query"
        elif not objective:
            candidate["rejection_reason"] = "missing_objective"
        elif not facets:
            candidate["rejection_reason"] = "missing_expected_facets"
        return candidate

    @staticmethod
    def _status(status: str, reason: str, **extra: Any) -> Dict[str, Any]:
        return {
            "status": status,
            "reason": reason,
            "enabled": status != "disabled",
            "authoritative": False,
            "candidate_count": 0,
            "candidates": [],
            "rejected_candidates": [],
            **extra,
        }
