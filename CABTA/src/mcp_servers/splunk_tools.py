"""Read-only Splunk MCP server for log hunting and SOC pivots."""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.parse
import urllib.error
import urllib.request
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP

from src.utils.log_hunting_policy import evaluate_hunt_request, normalize_query_text

mcp = FastMCP("splunk")

SPLUNK_URL = os.environ.get("SPLUNK_URL", "").rstrip("/")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "").strip()
SPLUNK_APP = os.environ.get("SPLUNK_APP", "search").strip() or "search"
SPLUNK_OWNER = os.environ.get("SPLUNK_OWNER", "nobody").strip() or "nobody"
SPLUNK_VERIFY_TLS = os.environ.get("SPLUNK_VERIFY_TLS", "true").strip().lower() not in {"0", "false", "no"}
SPLUNK_ALLOWED_INDEXES = [item.strip() for item in os.environ.get("SPLUNK_ALLOWED_INDEXES", "").split(",") if item.strip()]
SPLUNK_MAX_WINDOW_HOURS = int(os.environ.get("SPLUNK_MAX_WINDOW_HOURS", "168") or 168)
SPLUNK_MAX_RESULTS = int(os.environ.get("SPLUNK_MAX_RESULTS", "200") or 200)
TIMEOUT = int(os.environ.get("SPLUNK_TIMEOUT_SECONDS", "30") or 30)

_SSL_CONTEXT = ssl.create_default_context() if SPLUNK_VERIFY_TLS else ssl._create_unverified_context()


def _config_error(message: str) -> Dict[str, Any]:
    return {"status": "not_configured", "error": message, "backend": "splunk"}


def _request(path: str, *, method: str = "GET", data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not SPLUNK_URL or not SPLUNK_TOKEN:
        return _config_error("Set SPLUNK_URL and SPLUNK_TOKEN in the MCP server environment.")
    url = f"{SPLUNK_URL}{path}"
    body = None
    if method.upper() == "GET" and data:
        url = f"{url}?{urllib.parse.urlencode(data)}"
    elif data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {SPLUNK_TOKEN}",
            "Accept": "application/json",
            "User-Agent": "CABTA-Splunk-MCP/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_SSL_CONTEXT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return {"status": "error", "backend": "splunk", "error": f"HTTP {exc.code}: {detail[:300]}"}


def _safe_query(query: str) -> str:
    normalized = normalize_query_text(query)
    if SPLUNK_ALLOWED_INDEXES and not any(f"index={index_name.lower()}" in normalized.lower() for index_name in SPLUNK_ALLOWED_INDEXES):
        prefix = " OR ".join(f'index={index_name}' for index_name in SPLUNK_ALLOWED_INDEXES)
        base = normalized[7:].strip() if normalized.lower().startswith("search ") else normalized
        normalized = f"search ({prefix}) ({base})"
    return normalized


def _collect_entities(results: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    indicators, files, executables = set(), set(), set()
    indicator_fields = {"ip", "src_ip", "dest_ip", "dest", "dest_host", "query", "domain", "url", "sha256", "sha1", "md5"}
    file_fields = {"file_path", "filepath", "targetfilename", "folderpath", "path"}
    exec_fields = {"image", "process", "process_path", "process_name", "originalfile"}

    for row in results:
        for key, value in row.items():
            text = str(value).strip()
            if not text:
                continue
            key_l = str(key).lower()
            if key_l in indicator_fields:
                indicators.add(text)
            if key_l in file_fields and ("/" in text or "\\" in text):
                files.add(text)
            if key_l in exec_fields and text.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".vbs")):
                executables.add(text)
    return {
        "suspicious_indicators": sorted(indicators)[:50],
        "suspicious_files": sorted(files)[:50],
        "suspicious_executables": sorted(executables)[:50],
    }


def _run_search(query: str, timerange: str = "24h", max_results: int = 100, note: str = "") -> Dict[str, Any]:
    plan = evaluate_hunt_request(
        query,
        timerange=timerange,
        query_origin="generated",
        max_window_hours=SPLUNK_MAX_WINDOW_HOURS,
        max_results=min(max_results or SPLUNK_MAX_RESULTS, SPLUNK_MAX_RESULTS),
    )
    if plan["status"] != "executable":
        return {
            "status": plan["status"],
            "backend": "splunk",
            "message": plan["reason"],
            "query": plan["query"],
            "timerange": plan["timerange"],
        }

    query_text = _safe_query(plan["query"])
    create = _request(
        "/services/search/jobs",
        method="POST",
        data={
            "search": query_text,
            "earliest_time": plan["earliest"],
            "latest_time": plan["latest"],
            "output_mode": "json",
            "exec_mode": "normal",
            "adhoc_search_level": "smart",
        },
    )
    if create.get("status") == "not_configured":
        return create
    sid = create.get("sid")
    if not sid:
        return {"status": "error", "backend": "splunk", "message": f"Failed to create Splunk search job: {create}"}

    for _ in range(20):
        job = _request(f"/services/search/jobs/{sid}", data={"output_mode": "json"})
        content = ((job.get("entry") or [{}])[0]).get("content", {})
        if str(content.get("isDone", "0")) == "1" or str(content.get("dispatchState", "")).upper() == "DONE":
            break
        time.sleep(0.5)

    results_payload = _request(
        f"/services/search/jobs/{sid}/results",
        data={"output_mode": "json", "count": plan["max_results"]},
    )
    rows = results_payload.get("results", [])
    entities = _collect_entities(rows)
    try:
        _request(f"/services/search/jobs/{sid}", method="POST", data={"action": "cancel"})
    except Exception:
        pass

    return {
        "status": "executed",
        "backend": "splunk",
        "sid": sid,
        "timerange": plan["timerange"],
        "query": query_text,
        "results_count": len(rows),
        "results": rows,
        "note": note,
        **entities,
    }


@mcp.tool()
def search_logs(query: str, timerange: str = "24h", max_results: int = 100, note: str = "") -> Dict[str, Any]:
    """Run a read-only Splunk hunt query and return summarized results."""
    return _run_search(query, timerange=timerange, max_results=max_results, note=note)


@mcp.tool()
def search_ip_activity(ip: str, timerange: str = "24h", max_results: int = 100) -> Dict[str, Any]:
    """Pivot on an IP address across Splunk logs."""
    query = f'search index=* ("{ip}" OR src_ip="{ip}" OR dest_ip="{ip}") | head {min(max_results, SPLUNK_MAX_RESULTS)}'
    return _run_search(query, timerange=timerange, max_results=max_results, note=f"IP pivot for {ip}")


@mcp.tool()
def search_domain_activity(domain: str, timerange: str = "24h", max_results: int = 100) -> Dict[str, Any]:
    """Pivot on a domain or DNS query across Splunk logs."""
    query = f'search index=* ("{domain}" OR query="{domain}" OR dest_host="{domain}" OR url="*{domain}*") | head {min(max_results, SPLUNK_MAX_RESULTS)}'
    return _run_search(query, timerange=timerange, max_results=max_results, note=f"Domain pivot for {domain}")


@mcp.tool()
def search_hash_execution(hash_value: str, timerange: str = "7d", max_results: int = 100) -> Dict[str, Any]:
    """Find hash sightings and execution telemetry in Splunk."""
    query = f'search index=* (sha256="{hash_value}" OR sha1="{hash_value}" OR md5="{hash_value}" OR hashes="{hash_value}") | head {min(max_results, SPLUNK_MAX_RESULTS)}'
    return _run_search(query, timerange=timerange, max_results=max_results, note=f"Hash pivot for {hash_value}")


@mcp.tool()
def search_user_activity(user: str, timerange: str = "24h", max_results: int = 100) -> Dict[str, Any]:
    """Pivot on a user identity across Splunk logs."""
    query = f'search index=* (user="{user}" OR user_name="{user}" OR Account_Name="{user}") | head {min(max_results, SPLUNK_MAX_RESULTS)}'
    return _run_search(query, timerange=timerange, max_results=max_results, note=f"User pivot for {user}")


@mcp.tool()
def get_host_timeline(host: str, timerange: str = "24h", max_results: int = 200) -> Dict[str, Any]:
    """Retrieve a lightweight host timeline from Splunk logs."""
    query = (
        f'search index=* (host="{host}" OR ComputerName="{host}" OR dest_host="{host}") '
        "| sort 0 _time | table _time host sourcetype source user process_name Image dest_ip dest url query"
    )
    return _run_search(query, timerange=timerange, max_results=max_results, note=f"Host timeline for {host}")


if __name__ == "__main__":
    mcp.run()
