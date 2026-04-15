"""Deterministic log-hunt fixtures for local playbook demos and tests."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEMO_LOG_HUNT_DIR = PROJECT_ROOT / "data" / "demo" / "log_hunts"

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_QUOTED_RE = re.compile(r'"([^"]+)"')

_KEYWORD_HINTS = (
    "beacon",
    "credential",
    "malware",
    "payload",
    "phishing",
    "powershell",
    "rundll32",
    "suspicious",
)

_BENIGN_PROCESS_NAMES = {
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "outlook.exe",
    "thunderbird.exe",
}


@lru_cache(maxsize=8)
def load_demo_log_dataset(dataset: str) -> Dict[str, Any]:
    """Load a seeded demo log dataset by name."""
    path = DEMO_LOG_HUNT_DIR / f"{dataset}.json"
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Demo log dataset '{dataset}' must be a JSON object")
    return payload


def _parse_timerange(timerange: str) -> Optional[timedelta]:
    text = str(timerange or "").strip().lower()
    if not text:
        return None
    try:
        if text.endswith("m"):
            return timedelta(minutes=int(text[:-1]))
        if text.endswith("h"):
            return timedelta(hours=int(text[:-1]))
        if text.endswith("d"):
            return timedelta(days=int(text[:-1]))
    except ValueError:
        return None
    return None


def _record_timestamp(record: Dict[str, Any], now: datetime) -> str:
    if record.get("timestamp"):
        return str(record["timestamp"])
    offset_minutes = int(record.get("offset_minutes", 0) or 0)
    return (now - timedelta(minutes=offset_minutes)).isoformat()


def _expand_placeholders(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("${PROJECT_ROOT}", str(PROJECT_ROOT))
    if isinstance(value, dict):
        return {key: _expand_placeholders(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_expand_placeholders(item) for item in value]
    return value


def _flatten_strings(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, dict):
        for nested in value.values():
            yield from _flatten_strings(nested)
        return
    if isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from _flatten_strings(nested)
        return
    yield str(value)


def _extract_query_terms(query: str) -> Tuple[Set[str], Set[str]]:
    terms: Set[str] = set()
    keywords: Set[str] = set()
    text = str(query or "")
    lowered = text.lower()

    for value in _QUOTED_RE.findall(text):
        cleaned = value.strip().strip("*").lower()
        if cleaned:
            terms.add(cleaned)

    for regex in (_IPV4_RE, _HASH_RE, _DOMAIN_RE):
        for match in regex.findall(text):
            cleaned = str(match).strip().strip("*").lower()
            if cleaned:
                terms.add(cleaned)

    for keyword in _KEYWORD_HINTS:
        if keyword in lowered:
            keywords.add(keyword)

    return terms, keywords


def _record_matches(record: Dict[str, Any], terms: Set[str], keywords: Set[str]) -> bool:
    haystack = " ".join(_flatten_strings(record)).lower()
    if terms and any(term in haystack for term in terms):
        return True
    if keywords and any(keyword in haystack for keyword in keywords):
        return True
    if not terms and not keywords:
        return bool(record.get("suspicious"))
    return False


def _materialize_record(record: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    materialized = _expand_placeholders(dict(record))
    materialized["timestamp"] = _record_timestamp(materialized, now)
    materialized.setdefault("summary", "")
    materialized.setdefault("tags", [])
    return materialized


def _collect_unique(values: List[str], seen: Set[str], candidate: Any) -> None:
    if candidate in (None, "", [], {}):
        return
    if isinstance(candidate, (list, tuple, set)):
        for nested in candidate:
            _collect_unique(values, seen, nested)
        return
    if isinstance(candidate, dict):
        for nested_key in (
            "ioc",
            "indicator",
            "dest_ip",
            "src_ip",
            "domain",
            "url",
            "sha256",
            "md5",
            "path",
            "file_path",
            "process_path",
        ):
            if nested_key in candidate:
                _collect_unique(values, seen, candidate.get(nested_key))
        return
    text = str(candidate).strip()
    if not text or text in seen:
        return
    seen.add(text)
    values.append(text)


def execute_demo_log_hunt(
    dataset: str,
    queries: Dict[str, List[str]],
    *,
    timerange: str = "24h",
    max_results: int = 100,
) -> Dict[str, Any]:
    """Execute a seeded log-hunt query bundle against a deterministic fixture."""
    now = datetime.now(timezone.utc)
    try:
        payload = load_demo_log_dataset(dataset)
    except FileNotFoundError:
        return {
            "status": "error",
            "mode": "demo_fixture",
            "timerange": timerange or "24h",
            "configured_backends": ["demo_fixture"],
            "query_count": sum(len(values) for values in (queries or {}).values()),
            "executed_queries": [],
            "queries": queries or {},
            "results_count": 0,
            "results": [],
            "suspicious_indicators": [],
            "suspicious_files": [],
            "suspicious_executables": [],
            "message": f"Demo log dataset '{dataset}' was not found.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "mode": "demo_fixture",
            "timerange": timerange or "24h",
            "configured_backends": ["demo_fixture"],
            "query_count": sum(len(values) for values in (queries or {}).values()),
            "executed_queries": [],
            "queries": queries or {},
            "results_count": 0,
            "results": [],
            "suspicious_indicators": [],
            "suspicious_files": [],
            "suspicious_executables": [],
            "message": f"Failed to load demo log dataset '{dataset}': {exc}",
        }

    raw_records = payload.get("records", [])
    if not isinstance(raw_records, list):
        raw_records = []

    delta = _parse_timerange(timerange)
    cutoff = now - delta if delta else None
    records = []
    for entry in raw_records:
        if not isinstance(entry, dict):
            continue
        materialized = _materialize_record(entry, now)
        if cutoff is not None:
            try:
                record_time = datetime.fromisoformat(materialized["timestamp"])
                if record_time < cutoff:
                    continue
            except Exception:
                pass
        records.append(materialized)

    candidate_queries = (
        list(queries.get("splunk") or [])
        + list(queries.get("spl") or [])
        + list(queries.get("generic") or [])
        + list(queries.get("kql") or [])
    )

    executed_queries: List[Dict[str, Any]] = []
    combined_results: List[Dict[str, Any]] = []
    seen_event_ids: Set[str] = set()
    suspicious_indicators: List[str] = []
    suspicious_files: List[str] = []
    suspicious_executables: List[str] = []
    indicator_seen: Set[str] = set()
    file_seen: Set[str] = set()
    executable_seen: Set[str] = set()

    for index, query in enumerate(candidate_queries):
        terms, keywords = _extract_query_terms(query)
        query_matches = [record for record in records if _record_matches(record, terms, keywords)]
        executed_queries.append(
            {
                "query": query,
                "timerange": timerange or "24h",
                "status": "executed",
                "backend": "demo_fixture",
                "matched_count": len(query_matches),
            }
        )

        for record in query_matches:
            event_id = str(record.get("event_id") or f"event-{index}-{record.get('timestamp')}")
            if event_id in seen_event_ids:
                continue
            seen_event_ids.add(event_id)
            combined_results.append(record)

            for indicator_key in (
                "dest_ip",
                "domain",
                "url",
                "sha256",
                "md5",
                "related_indicators",
            ):
                _collect_unique(suspicious_indicators, indicator_seen, record.get(indicator_key))

            _collect_unique(suspicious_files, file_seen, record.get("file_path"))
            _collect_unique(suspicious_files, file_seen, record.get("download_path"))

            process_name = str(record.get("process_name", "")).strip().lower()
            executable_candidates = [
                record.get("process_path") if process_name and process_name not in _BENIGN_PROCESS_NAMES else None,
                record.get("file_path") if str(record.get("file_path", "")).lower().endswith((".exe", ".dll", ".ps1", ".bat")) else None,
            ]
            for candidate in executable_candidates:
                _collect_unique(suspicious_executables, executable_seen, candidate)

            if len(combined_results) >= max_results:
                break
        if len(combined_results) >= max_results:
            break

    status = "executed"
    message = "Seeded demo log hunt executed successfully."
    if not combined_results:
        message = "Seeded demo log hunt completed without matches."

    return {
        "status": status,
        "mode": "demo_fixture",
        "dataset": dataset,
        "timerange": timerange or "24h",
        "configured_backends": ["demo_fixture"],
        "query_count": sum(len(values) for values in (queries or {}).values()),
        "executed_queries": executed_queries,
        "queries": queries or {},
        "results_count": len(combined_results),
        "results": combined_results,
        "suspicious_indicators": suspicious_indicators[:50],
        "suspicious_files": suspicious_files[:50],
        "suspicious_executables": suspicious_executables[:50],
        "message": message,
        "dataset_metadata": {
            "name": payload.get("name", dataset),
            "description": payload.get("description", ""),
        },
    }
