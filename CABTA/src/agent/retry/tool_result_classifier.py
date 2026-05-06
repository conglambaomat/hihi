"""Classify tool/query results for bounded retry decisions."""

from __future__ import annotations

from typing import Any, Dict


class ToolResultClassifier:
    CLASSES = {
        "success_sufficient", "success_partial", "empty_result", "manual_required", "approval_required",
        "blocked_by_policy", "backend_unavailable", "transient_error", "schema_mismatch", "low_quality_evidence",
    }
    DIAGNOSES = {
        "wrong_field", "too_narrow_time", "wrong_index_or_source", "no_telemetry", "schema_mismatch",
        "backend_unavailable", "approval_blocked", "manual_required", "empty_but_query_valid",
    }

    def classify(self, result: Any) -> str:
        if not isinstance(result, dict):
            return "schema_mismatch"
        status = str(result.get("status") or "").lower()
        mode = str(result.get("mode") or "").lower()
        if status == "manual_lookup_required" or mode == "query_generation_only":
            return "manual_required"
        if status == "approval_required":
            return "approval_required"
        if status == "blocked":
            return "blocked_by_policy"
        if status in {"not_configured", "backend_unavailable"} or "not connected" in str(result.get("message") or "").lower():
            return "backend_unavailable"
        if result.get("error") or status.startswith("error"):
            return "transient_error"
        coverage = result.get("coverage_matrix") if isinstance(result.get("coverage_matrix"), dict) else {}
        if coverage.get("blocking_gaps") or coverage.get("retry_recommended") or coverage.get("coverage_status") in {"partial", "missing"}:
            return "success_partial" if int(result.get("results_count", 0) or 0) > 0 else "empty_result"
        if int(result.get("results_count", 0) or 0) <= 0 and status in {"executed", "partial", ""}:
            return "empty_result"
        if coverage.get("overall_score") is not None and float(coverage.get("overall_score") or 0.0) < 0.35:
            return "low_quality_evidence"
        return "success_sufficient"

    def diagnose(self, result: Any) -> Dict[str, Any]:
        result_class = self.classify(result)
        if not isinstance(result, dict):
            return {"diagnosis": "schema_mismatch", "result_class": result_class, "reason": "Result payload is not an object.", "diagnosis_confidence": "high"}
        status = str(result.get("status") or "").lower()
        mode = str(result.get("mode") or "").lower()
        message = str(result.get("message") or result.get("error") or "").lower()
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        validation = result.get("validation_metadata") if isinstance(result.get("validation_metadata"), dict) else {}
        executed_queries = result.get("executed_queries") if isinstance(result.get("executed_queries"), list) else []
        coverage = result.get("coverage_matrix") if isinstance(result.get("coverage_matrix"), dict) else {}
        queries = result.get("queries") if isinstance(result.get("queries"), dict) else {}
        query_blob = " ".join(str(item) for values in queries.values() for item in (values if isinstance(values, list) else [values])) if queries else str(result.get("query") or "")
        query_blob_lower = query_blob.lower()
        evidence_blob = " ".join(str(item) for item in [status, mode, message, metadata, validation, executed_queries]).lower()
        diagnosis = "empty_but_query_valid"
        reason = "Query executed but did not fully cover required evidence."
        confidence = "low"
        if result_class == "manual_required":
            diagnosis, reason, confidence = "manual_required", "No automated telemetry backend is connected.", "high"
        elif result_class in {"approval_required", "blocked_by_policy"}:
            diagnosis, reason, confidence = "approval_blocked", "Query requires approval or was blocked by policy.", "high"
        elif result_class == "backend_unavailable":
            diagnosis, reason, confidence = "backend_unavailable", "Telemetry backend is unavailable.", "high"
        elif result_class == "schema_mismatch" or any(token in evidence_blob for token in ("unknown field", "invalid field", "field does not exist", "schema", "parse error", "unrecognized column")):
            diagnosis, reason, confidence = "schema_mismatch", "Tool response or backend error indicates a schema/field contract mismatch.", "medium"
        elif any(token in evidence_blob for token in ("index not found", "unknown index", "sourcetype not found", "source not found", "no such index", "dataset not found")):
            diagnosis, reason, confidence = "wrong_index_or_source", "Backend metadata suggests the selected index, source, or dataset was unavailable.", "medium"
        elif "index=" in query_blob_lower and (mode.endswith("blocked") or "invalid index" in evidence_blob):
            diagnosis, reason, confidence = "wrong_index_or_source", "Selected index/source could not be used safely or was invalid.", "medium"
        elif any(token in evidence_blob for token in ("time range", "timerange", "outside retention", "no data in time", "earliest", "latest")) or ("earliest=" in query_blob_lower and result_class == "empty_result"):
            diagnosis, reason, confidence = "too_narrow_time", "Time window may be too narrow or outside retention for the missing evidence.", "medium"
        elif any(token in evidence_blob for token in ("no telemetry", "not onboarded", "source unavailable", "data source unavailable", "no events indexed")):
            diagnosis, reason, confidence = "no_telemetry", "No telemetry source appears to contain events for this request.", "medium"
        elif coverage.get("missing_facets") and any(f in coverage.get("missing_facets", []) for f in ("process", "session", "host", "network")):
            diagnosis, reason, confidence = "wrong_field", "Query likely targeted the wrong field family for missing facets.", "low"
        elif result_class == "empty_result" and "not connected" in message:
            diagnosis, reason, confidence = "no_telemetry", "No telemetry source returned rows for the request.", "medium"
        elif result_class == "empty_result":
            diagnosis, reason, confidence = "empty_but_query_valid", "The query was valid but returned no rows.", "low"
        return {"diagnosis": diagnosis, "result_class": result_class, "reason": reason, "diagnosis_confidence": confidence, "retryable": result_class in {"empty_result", "success_partial", "low_quality_evidence", "transient_error"}}
