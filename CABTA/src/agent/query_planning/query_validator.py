"""Validation helpers for investigation query plans."""

from __future__ import annotations

from typing import Any, Dict, List

from ...utils.log_hunting_policy import evaluate_hunt_request, normalize_query_bundle


class QueryValidator:
    """Validate generated queries through existing log-hunting policy."""

    def validate_bundle(self, query_bundle: Any, *, timerange: str = "24h", query_origin: str = "generated") -> Dict[str, Any]:
        normalized = normalize_query_bundle(query_bundle)
        validations: List[Dict[str, Any]] = []
        for backend, queries in normalized.items():
            if backend not in {"spl", "splunk", "generic"}:
                continue
            for query in queries:
                validations.append(evaluate_hunt_request(query, timerange=timerange, query_origin=query_origin))
        statuses = {item.get("status") for item in validations}
        if "blocked" in statuses:
            status = "blocked"
        elif "approval_required" in statuses:
            status = "approval_required"
        elif validations and statuses <= {"executable"}:
            status = "executable"
        else:
            status = "no_query"
        return {"status": status, "validations": validations, "query_count": len(validations)}
