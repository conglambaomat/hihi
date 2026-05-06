"""Map query results to expected coverage outcomes."""

from __future__ import annotations

from typing import Any, Dict, List


class QueryResultEvaluator:
    def evaluate(self, *, result: Dict[str, Any], expected_facets: List[str]) -> Dict[str, Any]:
        coverage = result.get("coverage_matrix") if isinstance(result, dict) else {}
        covered = set(coverage.get("covered_facets", []) if isinstance(coverage, dict) else [])
        missing = [facet for facet in expected_facets if facet not in covered]
        if not isinstance(result, dict):
            result_class = "schema_mismatch"
        elif result.get("status") in {"manual_lookup_required"}:
            result_class = "manual_required"
        elif result.get("status") == "approval_required":
            result_class = "approval_required"
        elif result.get("status") == "blocked":
            result_class = "blocked_by_policy"
        elif result.get("status") == "collection_failed" or result.get("collection_status") == "collection_failed":
            result_class = "collection_failed"
        elif result.get("error") or str(result.get("status") or "").startswith("error"):
            result_class = "transient_error"
        elif missing and int(result.get("results_count", 0) or 0) > 0:
            result_class = "success_partial"
        elif int(result.get("results_count", 0) or 0) <= 0:
            result_class = "empty_result"
        else:
            result_class = "success_sufficient"
        return {"result_class": result_class, "covered_facets": sorted(covered), "remaining_facets": missing}
