"""Shared guardrails for automated log hunting."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

_QUERY_COMMENT_PREFIXES = ("#", "//")
_DANGEROUS_SPL_TOKENS = (
    "| outputlookup",
    "| collect",
    "| map ",
    "| rest ",
    "| sendemail",
    "| script ",
    "| outputcsv",
    "| delete",
)


def parse_timerange(timerange: str | None, default: str = "7d") -> Tuple[str, str, int, str]:
    """Return Splunk-compatible earliest/latest plus a normalized timerange."""
    text = str(timerange or default).strip().lower()
    if not text:
        text = default

    match = re.fullmatch(r"-?(\d+)\s*([hdw])", text)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        hours = amount if unit == "h" else amount * 24 if unit == "d" else amount * 24 * 7
        normalized = f"{amount}{unit}"
        return f"-{hours}h", "now", hours, normalized

    if text.startswith("-") and len(text) > 1:
        text = text[1:]
        return parse_timerange(text, default=default)

    return parse_timerange(default, default=default)


def normalize_query_text(raw: Any) -> str:
    """Collapse multi-line SPL while stripping comments and empty lines."""
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        raw = "\n".join(str(item) for item in raw)
    text = str(raw).strip()
    if not text:
        return ""

    lines: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(_QUERY_COMMENT_PREFIXES):
            continue
        lines.append(stripped)
    return " ".join(lines).strip()


def normalize_query_bundle(raw: Any) -> Dict[str, List[str]]:
    """Normalize hunt queries into a backend/language -> list[str] map."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        normalized: Dict[str, List[str]] = {}
        for key, value in raw.items():
            if isinstance(value, list):
                queries = [normalize_query_text(item) for item in value]
            elif value in (None, ""):
                queries = []
            else:
                queries = [normalize_query_text(value)]
            queries = [query for query in queries if query]
            if queries:
                normalized[str(key).lower()] = queries
        return normalized
    query = normalize_query_text(raw)
    return {"generic": [query]} if query else {}


def evaluate_hunt_request(
    query_text: str,
    *,
    timerange: str,
    query_origin: str = "generated",
    max_window_hours: int = 24 * 7,
    max_results: int = 200,
) -> Dict[str, Any]:
    """Classify a hunt query as executable, approval-required, or blocked."""
    query = normalize_query_text(query_text)
    earliest, latest, window_hours, normalized_timerange = parse_timerange(timerange)

    if not query:
        return {
            "status": "no_query",
            "reason": "No executable SPL query was provided.",
            "query": "",
            "timerange": normalized_timerange,
            "earliest": earliest,
            "latest": latest,
            "window_hours": window_hours,
            "max_results": max_results,
            "query_origin": query_origin,
        }

    lowered = f" {query.lower()} "
    if any(token in lowered for token in _DANGEROUS_SPL_TOKENS):
        return {
            "status": "blocked",
            "reason": "The SPL query includes mutating or unsafe commands that are not allowed.",
            "query": query,
            "timerange": normalized_timerange,
            "earliest": earliest,
            "latest": latest,
            "window_hours": window_hours,
            "max_results": max_results,
            "query_origin": query_origin,
        }

    if window_hours > max_window_hours:
        return {
            "status": "approval_required",
            "reason": (
                f"The requested hunt window ({window_hours}h) exceeds the automatic limit "
                f"of {max_window_hours}h."
            ),
            "query": query,
            "timerange": normalized_timerange,
            "earliest": earliest,
            "latest": latest,
            "window_hours": window_hours,
            "max_results": max_results,
            "query_origin": query_origin,
        }

    broad_query = "index=*" in lowered or "| tstats" in lowered or " datamodel=" in lowered
    raw_query = query_origin == "raw" or query.lower() == str(query_text or "").strip().lower()
    if broad_query and raw_query:
        return {
            "status": "approval_required",
            "reason": "Broad raw Splunk searches require analyst approval before live execution.",
            "query": query,
            "timerange": normalized_timerange,
            "earliest": earliest,
            "latest": latest,
            "window_hours": window_hours,
            "max_results": max_results,
            "query_origin": query_origin,
        }

    return {
        "status": "executable",
        "reason": "Query approved for automatic live hunting.",
        "query": query,
        "timerange": normalized_timerange,
        "earliest": earliest,
        "latest": latest,
        "window_hours": window_hours,
        "max_results": max_results,
        "query_origin": query_origin,
    }
