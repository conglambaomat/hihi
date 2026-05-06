"""Coverage helpers for AISA log-hunt planning and results."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set


_FACET_KEYWORDS = {
    "user": ("user", "account", "identity", "alice", "bob", "admin", "svc_"),
    "host": ("host", "hostname", "device", "endpoint", "computer", "ws-", "srv-"),
    "session": ("session", "logon", "token", "sid", "logon_id", "4624", "4625"),
    "process": ("process", "command", "binary", "execution", "image", ".exe", ".dll", ".ps1"),
    "network": ("network", "ip", "dest", "src", "domain", "url", "egress", "outbound", "beacon", "callback", "fortigate"),
}

_ROW_KEYS_BY_FACET = {
    "timestamp": ("timestamp", "time", "_time", "event_time"),
    "user": ("user", "username", "account", "Account_Name", "src_user", "src_user_name", "dest_user", "user_name"),
    "host": ("host", "hostname", "device", "ComputerName", "dest_host", "dst_host", "src_host", "dvc", "devname"),
    "session": ("session", "session_id", "logon_id", "Logon_ID", "Logon_Type", "EventCode", "event_id"),
    "process": ("process", "process_name", "Image", "image", "command_line", "cmdline", "CommandLine", "process_path"),
    "command_line": ("command_line", "cmdline", "CommandLine", "process_command_line", "Process_Command_Line"),
    "event_code": ("event_code", "EventCode", "event_id", "EventID", "eventid"),
    "source_sourcetype": ("source", "sourcetype", "source_type", "index"),
    "backend": ("backend", "log_backend", "configured_backend"),
    "raw_event": ("raw_event", "_raw", "raw"),
    "network": ("dest_ip", "dst_ip", "dstip", "src_ip", "srcip", "source_ip", "remote_ip", "domain", "url", "query", "service", "dest", "dst", "src", "destination", "source"),
}


def infer_facets_from_text(text: Any) -> List[str]:
    lowered = str(text or "").lower()
    facets: List[str] = []
    for facet, keywords in _FACET_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            facets.append(facet)
    return facets


def build_query_fingerprint(query: Any) -> str:
    payload = json.dumps(query, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def build_initial_coverage_matrix(
    *,
    required_facets: List[str],
    questions: List[str],
    entity_targets: List[Dict[str, Any]],
) -> Dict[str, Any]:
    question_coverage = []
    for question in questions:
        facets = infer_facets_from_text(question)
        question_coverage.append(
            {
                "question": question,
                "facets": facets,
                "status": "not_executed",
                "covered_by_queries": [],
                "evidence_refs": [],
            }
        )

    entity_coverage = {}
    for target in entity_targets:
        value = str(target.get("value") or "").strip()
        if not value:
            continue
        entity_coverage[value] = {
            "type": str(target.get("type") or "unknown"),
            "status": "not_executed",
            "query_indexes": [],
        }

    return {
        "required_facets": list(dict.fromkeys(required_facets)),
        "covered_facets": [],
        "missing_facets": list(dict.fromkeys(required_facets)),
        "question_coverage": question_coverage,
        "entity_coverage": entity_coverage,
        "coverage_status": "not_executed",
        "retry_recommended": False,
        "retry_reason": "Log hunt has not executed yet.",
    }


def evaluate_log_result_coverage(
    *,
    query_plan: Optional[Dict[str, Any]],
    result: Dict[str, Any],
    executed: bool,
) -> Dict[str, Any]:
    """Classify log-hunt result coverage without changing verdict authority."""
    plan = query_plan if isinstance(query_plan, dict) else {}
    base = plan.get("coverage_matrix") if isinstance(plan.get("coverage_matrix"), dict) else {}
    required = list(dict.fromkeys(base.get("required_facets") or plan.get("required_facets") or []))
    questions = [str(item) for item in plan.get("unresolved_questions", []) if str(item).strip()]
    if not required:
        required = infer_facets_from_text(" ".join(questions) + " " + str(plan.get("focus") or "")) or ["network"]

    rows = result.get("results", []) if isinstance(result.get("results", []), list) else []
    executed_queries = result.get("executed_queries", []) if isinstance(result.get("executed_queries", []), list) else []
    covered: Set[str] = set()
    facet_query_indexes: Dict[str, List[int]] = {facet: [] for facet in required}
    evidence_refs_by_facet: Dict[str, List[Dict[str, Any]]] = {facet: [] for facet in required}
    if executed:
        for row_index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            for facet, keys in _ROW_KEYS_BY_FACET.items():
                if any(str(row.get(key) or "").strip() for key in keys):
                    covered.add(facet)
                    if facet in evidence_refs_by_facet:
                        evidence_refs_by_facet[facet].append({"source": "result_row", "row_index": row_index})
        if result.get("suspicious_indicators"):
            covered.add("network")
            evidence_refs_by_facet.setdefault("network", []).append({"source": "suspicious_indicators"})
        if result.get("suspicious_files") or result.get("suspicious_executables"):
            covered.add("process")
            evidence_refs_by_facet.setdefault("process", []).append({"source": "suspicious_executables"})
        for query_index, query_info in enumerate(executed_queries):
            if not isinstance(query_info, dict):
                continue
            try:
                matched_count = int(query_info.get("matched_count", 0))
            except Exception:
                matched_count = 0
            if matched_count <= 0:
                continue
            for facet in infer_facets_from_text(query_info.get("query", "")):
                covered.add(facet)
                facet_query_indexes.setdefault(facet, []).append(query_index)
                evidence_refs_by_facet.setdefault(facet, []).append({"source": "executed_query", "query_index": query_index})

    missing = [facet for facet in required if facet not in covered]
    if not executed:
        coverage_status = "unknown"
        retry = False
        reason = "Log backend did not execute the generated queries; coverage is unknown."
    elif missing and covered:
        coverage_status = "partial"
        retry = True
        reason = "Missing required log coverage facets: " + ", ".join(missing) + "."
    elif missing:
        coverage_status = "missing"
        retry = True
        reason = "No required log coverage facets were matched."
    else:
        coverage_status = "covered"
        retry = False
        reason = "Required log coverage facets were covered by executed results."

    question_coverage = []
    source_questions = base.get("question_coverage") or [
        {"question": question, "facets": infer_facets_from_text(question)} for question in questions
    ]
    for item in source_questions:
        facets = list(dict.fromkeys(item.get("facets") or infer_facets_from_text(item.get("question", ""))))
        item_missing = [facet for facet in facets if facet not in covered]
        status = "unknown" if not executed else "covered" if not item_missing else "partial" if set(facets) & covered else "missing"
        query_indexes: List[int] = []
        evidence_refs: List[Dict[str, Any]] = []
        for facet in facets:
            query_indexes.extend(facet_query_indexes.get(facet, []))
            evidence_refs.extend(evidence_refs_by_facet.get(facet, [])[:3])
        question_coverage.append({
            **item,
            "status": status,
            "covered_by_queries": list(dict.fromkeys(query_indexes)),
            "evidence_refs": evidence_refs[:6],
        })

    entity_coverage = dict(base.get("entity_coverage") or {})
    row_text = json.dumps(rows, default=str).lower()
    query_texts = [str(item.get("query") or "").lower() for item in executed_queries if isinstance(item, dict)]
    for value, meta in list(entity_coverage.items()):
        matched = bool(value and value.lower() in row_text)
        query_indexes = [index for index, query_text in enumerate(query_texts) if value and value.lower() in query_text]
        entity_coverage[value] = {
            **meta,
            "status": "matched" if matched else "missing" if executed else "unknown",
            "query_indexes": query_indexes,
        }

    return normalize_log_coverage_matrix(
        {
            "required_facets": required,
            "covered_facets": [facet for facet in required if facet in covered],
            "missing_facets": missing,
            "question_coverage": question_coverage,
            "entity_coverage": entity_coverage,
            "facet_query_indexes": {facet: list(dict.fromkeys(indexes)) for facet, indexes in facet_query_indexes.items() if indexes},
            "coverage_status": coverage_status,
            "retry_recommended": retry,
            "retry_reason": reason,
        },
        lane=str(plan.get("lane") or "log_identity"),
    )


def normalize_log_coverage_matrix(raw: Optional[Dict[str, Any]], *, lane: str = "log_identity") -> Dict[str, Any]:
    """Adapt legacy log coverage metadata to the common CoverageMatrix shape.

    Log-specific extensions are preserved while adding `cells`, `blocking_gaps`,
    `overall_status`, and `schema_version` for package consumers.
    """
    source = raw if isinstance(raw, dict) else {}
    source_cells = [item for item in (source.get("cells") or []) if isinstance(item, dict)]
    cell_facets = [str(item.get("facet") or "").strip() for item in source_cells if str(item.get("facet") or "").strip()]
    source_blocking = [item for item in (source.get("blocking_gaps") or []) if isinstance(item, dict)]
    required = list(dict.fromkeys([*(source.get("required_facets") or []), *(source.get("coverage_targets") or []), *cell_facets]))
    covered = set(source.get("covered_facets") or [item.get("facet") for item in source_cells if item.get("status") == "covered"])
    missing = list(dict.fromkeys(source.get("missing_facets") or [item.get("facet") for item in source_blocking if item.get("facet")] or [facet for facet in required if facet not in covered]))
    status = str(source.get("coverage_status") or source.get("overall_status") or "unknown")
    cells = []
    for facet in required:
        if facet in covered:
            cell_status = "covered"
            basis = "log_result_metadata"
        elif facet in missing:
            cell_status = "missing" if status != "unknown" else "unknown"
            basis = "no_matching_log_evidence" if status != "unknown" else "not_executed_or_degraded"
        else:
            cell_status = "partial"
            basis = "log_result_metadata"
        existing = next((item for item in source_cells if item.get("facet") == facet), {})
        cells.append(
            {
                **existing,
                "facet": facet,
                "status": existing.get("status") or cell_status,
                "basis": existing.get("basis") or basis,
                "evidence_refs": existing.get("evidence_refs") or [],
                "missing_fields": existing.get("missing_fields") if isinstance(existing.get("missing_fields"), list) else ([] if cell_status == "covered" else [facet]),
                "blocking_gap": bool(existing.get("blocking_gap", cell_status in {"missing", "unknown"})),
                "confidence": existing.get("confidence", 0.7 if cell_status == "covered" else 0.0),
            }
        )
    blocking = [
        {"facet": item["facet"], "status": item["status"], "basis": item["basis"], "missing_fields": item["missing_fields"]}
        for item in cells
        if item.get("blocking_gap")
    ]
    overall_score = len([facet for facet in required if facet in covered]) / max(len(required), 1)
    return {
        **source,
        "schema_version": "coverage-matrix/v1",
        "lane": lane or "log_identity",
        "requirements": [
            {"lane": lane or "log_identity", "facet": facet, "required": True, "description": "Required log hunt facet", "minimum_basis": "executed_log_query_or_typed_evidence"}
            for facet in required
        ],
        "cells": cells,
        "coverage_targets": required,
        "overall_status": status,
        "coverage_status": status,
        "overall_score": round(float(overall_score), 3),
        "blocking_gaps": blocking,
        "summary": source.get("retry_reason") or f"Log coverage {status} for {', '.join(required) or 'unknown facets'}.",
        "required_facets": required,
        "covered_facets": [facet for facet in required if facet in covered],
        "missing_facets": missing,
        "question_coverage": source.get("question_coverage", []),
        "entity_coverage": source.get("entity_coverage", {}),
        "retry_recommended": bool(source.get("retry_recommended")),
        "retry_reason": source.get("retry_reason"),
    }
