"""Shared guardrails for automated log hunting."""

from __future__ import annotations

import re
from datetime import datetime, timezone
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


def _canonical_iso_time(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return raw
    candidate = raw.replace("t", "T").replace("z", "Z")
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return candidate
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
        return parsed.replace(tzinfo=None).isoformat(timespec="seconds") + "Z"
    return parsed.isoformat(timespec="seconds")


def parse_timerange(timerange: str | None, default: str = "7d") -> Tuple[str, str, int, str]:
    """Return Splunk-compatible earliest/latest plus a normalized timerange."""
    raw_text = str(timerange or default).strip()
    text = raw_text.lower()
    if not text:
        text = default
        raw_text = default

    absolute_match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}[tT]\d{2}:\d{2}:\d{2}(?:[zZ]|[+-]\d{2}:?\d{2})?)\s*(?:\.\.|/)\s*(\d{4}-\d{2}-\d{2}[tT]\d{2}:\d{2}:\d{2}(?:[zZ]|[+-]\d{2}:?\d{2})?)",
        raw_text,
    )
    if absolute_match:
        earliest = _canonical_iso_time(absolute_match.group(1))
        latest = _canonical_iso_time(absolute_match.group(2))
        try:
            start = datetime.fromisoformat(earliest.replace("Z", "+00:00"))
            end = datetime.fromisoformat(latest.replace("Z", "+00:00"))
            hours = max(1, int((end - start).total_seconds() // 3600) or 1)
        except ValueError:
            hours = 1
        normalized = f"{earliest}..{latest}"
        return earliest, latest, hours, normalized

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


def is_bounded_entity_specific_spl(query: str, *, max_results: int = 200) -> bool:
    """Return True for SPL constrained by concrete entities and row limits."""
    q = normalize_query_text(query)
    lowered = f" {q.lower()} "
    if not q or any(token in lowered for token in _DANGEROUS_SPL_TOKENS):
        return False
    limits = [int(item) for item in re.findall(r"\|\s*(?:head|limit)\s+(\d+)", lowered)]
    if not limits or min(limits) > max_results:
        return False
    concrete_field = re.search(
        r"\b(?:computer|computername|host|user|processguid|parentprocessguid|image|parentimage|sha256|sha1|md5|hashes|commandline|command_line|process_name)\s*=\s*\"?[^\"*()|]{3,}\"?",
        lowered,
    )
    guid_or_hash_literal = re.search(r"\{[0-9a-f-]{20,}\}|\b[a-f0-9]{32,64}\b", lowered)
    quoted_path_or_exe = re.search(r"\"[^\"]+\.(?:exe|dll|ps1|bat|cmd)\"", lowered)
    return bool(concrete_field or guid_or_hash_literal or quoted_path_or_exe)


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
    raw_query = query_origin == "raw" or (query_origin not in {"generated", "llm_suggestion"} and query.lower() == str(query_text or "").strip().lower())
    if broad_query and raw_query and is_bounded_entity_specific_spl(query, max_results=max_results):
        raw_query = False
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
