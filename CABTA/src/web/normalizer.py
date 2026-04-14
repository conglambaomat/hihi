"""CABTA web job normalization helpers."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _first(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _extract_score(result: Dict[str, Any], job: Dict[str, Any]) -> int:
    score = _first(
        result.get("score"),
        result.get("threat_score"),
        result.get("composite_score"),
        result.get("base_phishing_score"),
        _as_dict(result.get("score_breakdown")).get("final_score"),
        _as_dict(result.get("scoring")).get("final_score"),
        job.get("score"),
        0,
    )
    try:
        return int(score)
    except (TypeError, ValueError):
        return 0


def _extract_confidence(result: Dict[str, Any]) -> Any:
    confidence = _first(
        result.get("confidence"),
        _as_dict(result.get("score_breakdown")).get("confidence"),
        _as_dict(result.get("scoring")).get("confidence"),
        _as_dict(result.get("llm_analysis")).get("confidence"),
    )
    if isinstance(confidence, (int, float)):
        return round(float(confidence), 2)
    return confidence or "unknown"


def _extract_errors(job: Dict[str, Any], result: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for item in _as_list(result.get("errors")):
        if isinstance(item, str) and item.strip():
            errors.append(item.strip())
    llm_error = _as_dict(result.get("llm_analysis")).get("error")
    if isinstance(llm_error, str) and llm_error.strip():
        errors.append(llm_error.strip())
    if job.get("status") == "failed" and isinstance(job.get("current_step"), str):
        current_step = job["current_step"].strip()
        if current_step:
            errors.append(current_step)
    return list(dict.fromkeys(errors))


def _extract_warnings(result: Dict[str, Any], errors: Iterable[str]) -> List[str]:
    warnings: List[str] = []
    for item in _as_list(result.get("warnings")):
        if isinstance(item, str) and item.strip():
            warnings.append(item.strip())
    if errors and not warnings and _as_dict(result.get("llm_analysis")).get("note"):
        warnings.append(str(_as_dict(result.get("llm_analysis")).get("note")).strip())
    return list(dict.fromkeys([item for item in warnings if item]))


def _extract_target(params: Dict[str, Any], result: Dict[str, Any], job_type: str) -> str:
    if job_type == "ioc":
        return str(
            _first(
                params.get("value"),
                result.get("normalized_value"),
                result.get("ioc"),
                result.get("input"),
                "",
            )
        )
    if job_type == "file":
        return str(
            _first(
                params.get("filename"),
                _as_dict(result.get("file_metadata")).get("filename"),
                _as_dict(result.get("file_info")).get("filename"),
                _as_dict(result.get("file_info")).get("name"),
                "",
            )
        )
    if job_type == "email":
        email_meta = _as_dict(result.get("email_metadata"))
        email_data = _as_dict(result.get("email_data"))
        return str(
            _first(
                params.get("filename"),
                email_meta.get("subject"),
                email_data.get("subject"),
                "",
            )
        )
    return str(_first(params.get("value"), params.get("filename"), job_type, ""))


def _coerce_mode(job: Dict[str, Any], explicit_mode: Optional[str]) -> str:
    params = _as_dict(job.get("params"))
    if explicit_mode:
        return explicit_mode
    if params.get("mode") == "demo" or job.get("is_demo"):
        return "demo"
    return str(job.get("mode") or "live")


def normalize_job(
    job: Dict[str, Any],
    *,
    mode: Optional[str] = None,
    case_links: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    base = deepcopy(job)
    params = _as_dict(base.get("params"))
    result = _as_dict(base.get("result"))
    job_type = str(_first(base.get("analysis_type"), base.get("job_type"), "unknown"))
    resolved_mode = _coerce_mode(base, mode)
    errors = _extract_errors(base, result)
    warnings = _extract_warnings(result, errors)
    confidence = _extract_confidence(result)
    target = _extract_target(params, result, job_type)
    normalized = {
        "job_id": str(_first(base.get("id"), base.get("job_id"), "")),
        "job_type": job_type,
        "status": str(base.get("status") or "queued"),
        "mode": resolved_mode,
        "is_demo": resolved_mode == "demo",
        "submitted_input": deepcopy(params),
        "progress": int(base.get("progress") or 0),
        "current_step": str(base.get("current_step") or ""),
        "verdict": str(_first(result.get("verdict"), base.get("verdict"), "UNKNOWN")),
        "score": _extract_score(result, base),
        "confidence": confidence,
        "warnings": warnings,
        "errors": errors,
        "result": deepcopy(result),
        "report_links": {
            "html": f"/report/{_first(base.get('id'), base.get('job_id'), '')}",
            "json": f"/api/reports/{_first(base.get('id'), base.get('job_id'), '')}/json",
            "mitre": f"/api/reports/{_first(base.get('id'), base.get('job_id'), '')}/mitre",
        },
        "case_links": deepcopy(case_links or []),
        "started_at": _first(base.get("created_at"), base.get("started_at")),
        "completed_at": _first(base.get("completed_at"), result.get("completed_at")),
        "target": target,
        "id": str(_first(base.get("id"), base.get("job_id"), "")),
        "analysis_type": job_type,
        "params": deepcopy(params),
        "created_at": _first(base.get("created_at"), base.get("started_at")),
    }
    return {**base, **normalized}


def normalize_case(case: Dict[str, Any], *, mode: str = "live") -> Dict[str, Any]:
    base = deepcopy(case)
    analyses = _as_list(base.get("analyses"))
    notes = _as_list(base.get("notes"))
    workflows = _as_list(base.get("workflows"))
    events = _as_list(base.get("events"))
    normalized = {
        "mode": mode,
        "is_demo": mode == "demo",
        "analysis_count": base.get("analysis_count", len(analyses)),
        "note_count": base.get("note_count", len(notes)),
        "workflow_count": base.get("workflow_count", len(workflows)),
        "event_count": base.get("event_count", len(events)),
    }
    return {**base, **normalized}
