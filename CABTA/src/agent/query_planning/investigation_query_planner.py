"""High-level investigation query planner wrapping log query plans."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from ..log_query_coverage import build_query_fingerprint
from ..log_query_planner import LogQueryPlanner
from .llm_query_assistant import LLMQueryAssistant
from .query_model import InvestigationQueryPlan
from .query_rewriter import QueryRewriter
from .query_validator import QueryValidator

_OBS_BY_FACET = {
    "user": "auth_event", "session": "auth_event", "source_ip": "auth_event", "host": "host_timeline_event",
    "process": "process_event", "network": "network_event", "sender": "email_delivery", "recipient": "email_delivery",
    "delivery": "email_delivery", "url_or_attachment": "email_delivery", "file_hash": "file_execution", "file_path": "file_execution",
    "ioc": "ioc_enrichment", "timeline": "timeline_event",
}


class InvestigationQueryPlanner:
    """Create deterministic, policy-validated query intent metadata."""

    def __init__(self, *, config: Dict[str, Any] | None = None, llm_provider: Optional[Callable[[str], Optional[str]]] = None) -> None:
        self.config = config if isinstance(config, dict) else {}
        self.log_planner = LogQueryPlanner()
        self.validator = QueryValidator()
        self.rewriter = QueryRewriter()
        self.llm_assistant = LLMQueryAssistant(config=self.config, provider=llm_provider)

    def build_log_hunt_plan(self, *, goal: str, lane: str, focus: str = "", unresolved_questions: List[str] | None = None, entity_state: Dict[str, Any] | None = None, coverage_matrix: Dict[str, Any] | None = None, retry_state: Dict[str, Any] | None = None, timerange: str = "24h", max_results: int = 200) -> Dict[str, Any]:
        log_plan = self.log_planner.build_plan(
            focus=focus,
            analyst_request=goal,
            lane=lane,
            unresolved_questions=unresolved_questions or [],
            entity_state=entity_state,
            timerange=timerange,
            max_results=max_results,
        )
        effective_timerange = str(log_plan.get("timerange") or timerange or "24h")
        targets = list((coverage_matrix or {}).get("coverage_targets") or (coverage_matrix or {}).get("missing_facets") or log_plan.get("required_facets") or [])
        missing = list((coverage_matrix or {}).get("missing_facets") or [])
        fallback = self.rewriter.fallback_variants(focus=log_plan.get("focus") or focus, missing_facets=missing or targets, max_results=max_results)
        validation = self.validator.validate_bundle(log_plan.get("query_bundle"), timerange=effective_timerange, query_origin="generated")
        variants = list(log_plan.get("query_variants") or [])
        llm_assist = self._build_llm_assist_metadata(
            goal=goal,
            lane=lane,
            focus=log_plan.get("focus") or focus,
            coverage_matrix=coverage_matrix or log_plan.get("coverage_matrix") or {},
            entity_state=entity_state or {},
            existing_variants=variants,
            retry_state=retry_state or {},
            timerange=effective_timerange,
        )
        variants.extend(llm_assist.get("accepted_variants", []))
        fingerprints = [build_query_fingerprint(item.get("query")) for item in variants if isinstance(item, dict)]
        quality = 0.4 + min(0.4, len(variants) * 0.08) + (0.1 if targets else 0.0)
        risk = 0.2 if validation.get("status") == "executable" else 0.7
        plan = InvestigationQueryPlan(
            objective=f"Collect log evidence for {', '.join(targets[:4]) or 'current investigation'} coverage.",
            hypothesis_ids=[str(item.get("id")) for item in (entity_state or {}).get("hypotheses", []) if isinstance(item, dict) and item.get("id")],
            coverage_targets=targets,
            queries=log_plan.get("query_bundle") or {},
            query_variants=variants,
            expected_observation_types=list(dict.fromkeys(_OBS_BY_FACET.get(facet, "correlation_observation") for facet in targets)),
            expected_entities=list(log_plan.get("next_entities") or []),
            expected_facets=targets,
            source_coverage={"source": "log_query_planner", "coverage_matrix_status": (coverage_matrix or {}).get("overall_status") or (coverage_matrix or {}).get("coverage_status")},
            success_criteria=[f"Facet {facet} has direct or typed evidence." for facet in targets[:6]],
            fallback_variants=fallback,
            negative_controls=["Do not treat empty results as benign verdict.", "Do not execute blocked or approval-required searches automatically."],
            quality_score=min(1.0, quality),
            risk_score=risk,
            validation_metadata=validation,
            fingerprints=fingerprints,
        ).to_dict()
        plan["llm_query_assist"] = {k: v for k, v in llm_assist.items() if k != "accepted_variants"}
        plan["log_query_plan"] = log_plan
        return plan

    def _build_llm_assist_metadata(
        self,
        *,
        goal: str,
        lane: str,
        focus: str,
        coverage_matrix: Dict[str, Any],
        entity_state: Dict[str, Any],
        existing_variants: List[Dict[str, Any]],
        retry_state: Dict[str, Any],
        timerange: str,
    ) -> Dict[str, Any]:
        hypotheses = entity_state.get("hypotheses", []) if isinstance(entity_state, dict) else []
        proposal = self.llm_assistant.propose(
            goal=goal,
            lane=lane,
            focus=focus,
            coverage_matrix=coverage_matrix,
            hypotheses=hypotheses if isinstance(hypotheses, list) else [],
            existing_variants=existing_variants,
            retry_state=retry_state,
        )
        accepted: List[Dict[str, Any]] = []
        rejected = list(proposal.get("rejected_candidates") or [])
        for candidate in proposal.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            validation = self.validator.validate_bundle({candidate.get("backend") or "splunk": [candidate.get("query", "")]}, timerange=timerange, query_origin="llm_suggestion")
            staged = {**candidate, "validation_metadata": validation}
            if validation.get("status") == "executable":
                accepted.append(staged)
            else:
                staged["rejection_reason"] = f"policy_validation_{validation.get('status') or 'failed'}"
                rejected.append(staged)
        return {
            **proposal,
            "accepted_variants": accepted,
            "accepted_count": len(accepted),
            "rejected_candidates": rejected,
            "validation_gate": "validate_bundle",
            "execution_authority": "deterministic_policy_validator",
        }
