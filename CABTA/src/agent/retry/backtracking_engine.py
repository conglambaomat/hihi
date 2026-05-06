"""Safe backtracking from coverage gaps to fallback query variants."""

from __future__ import annotations

from typing import Any, Dict, List

from ..query_planning.llm_query_assistant import LLMQueryAssistant
from ..query_planning.query_rewriter import QueryRewriter
from ..query_planning.query_validator import QueryValidator
from .retry_policy import RetryPolicy
from .tool_result_classifier import ToolResultClassifier


class BacktrackingEngine:
    def __init__(self, policy: RetryPolicy | None = None, llm_assistant: LLMQueryAssistant | None = None) -> None:
        self.classifier = ToolResultClassifier()
        self.policy = policy or RetryPolicy()
        self.rewriter = QueryRewriter()
        self.validator = QueryValidator()
        self.llm_assistant = llm_assistant

    def plan_next(self, *, result: Dict[str, Any], coverage_matrix: Dict[str, Any], focus: str, objective: str, retry_state: Dict[str, Any] | None = None) -> Dict[str, Any]:
        result_class = self.classifier.classify(result)
        diagnosis = self.classifier.diagnose(result)
        gaps = coverage_matrix.get("blocking_gaps", []) if isinstance(coverage_matrix, dict) else []
        missing = [str(item.get("facet")) for item in gaps if isinstance(item, dict) and item.get("facet")]
        if not missing:
            missing = [str(item) for item in (coverage_matrix.get("missing_facets", []) if isinstance(coverage_matrix, dict) else [])]
        gap = missing[0] if missing else "unknown"
        decision = self.policy.decide(result_class=result_class, gap=gap, objective=objective, retry_state=retry_state)
        if decision.get("action") != "retry":
            return {"result_class": result_class, "diagnosis": diagnosis, **decision, "remaining_gaps": missing}
        variants = self.rewriter.fallback_variants(focus=focus, missing_facets=missing)
        llm_rewrite = self._llm_rewrite_advisory(
            result=result,
            result_class=result_class,
            coverage_matrix=coverage_matrix,
            focus=focus,
            retry_state=retry_state,
        )
        accepted_llm = list(llm_rewrite.get("accepted_variants", [])) if isinstance(llm_rewrite, dict) else []
        all_variants = [*variants, *accepted_llm]
        return {
            "result_class": result_class,
            "diagnosis": diagnosis,
            **decision,
            "remaining_gaps": missing,
            "next_objective": f"Retry log hunt for missing coverage facet {gap}.",
            "query_variant": all_variants[0] if all_variants else {},
            "fallback_variants": variants,
            "llm_rewrite_advisory": llm_rewrite,
        }

    def _llm_rewrite_advisory(self, *, result: Dict[str, Any], result_class: str, coverage_matrix: Dict[str, Any], focus: str, retry_state: Dict[str, Any] | None) -> Dict[str, Any]:
        if self.llm_assistant is None:
            return {"status": "disabled", "reason": "No LLM rewrite assistant configured.", "accepted_variants": [], "rejected_candidates": []}
        gaps = coverage_matrix.get("blocking_gaps") or coverage_matrix.get("missing_facets") or []
        proposal = self.llm_assistant.suggest_rewrite_after_result(
            failed_query=result.get("queries") or result.get("query"),
            result_class=result_class,
            coverage_gaps=gaps,
            retry_state=retry_state or {},
            lane=str((retry_state or {}).get("lane") or ""),
            focus=focus,
        )
        accepted: List[Dict[str, Any]] = []
        rejected = list(proposal.get("rejected_candidates") or [])
        for candidate in proposal.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            validation = self.validator.validate_bundle({candidate.get("backend") or "splunk": [candidate.get("query", "")]}, query_origin="llm_rewrite")
            staged = {**candidate, "validation_metadata": validation}
            if validation.get("status") == "executable":
                accepted.append(staged)
            else:
                rejected.append({**staged, "rejection_reason": f"policy_validation_{validation.get('status')}"})
        return {**proposal, "accepted_variants": accepted, "accepted_count": len(accepted), "rejected_candidates": rejected, "validation_gate": "validate_bundle"}
