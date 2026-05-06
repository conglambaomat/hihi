import json
import os
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fastapi.testclient import TestClient
from src.web.app import create_app

PROMPT = "dùng splunk để hãy điều tra alert sau Event ID 1002 Rule Name TET-101: Detect System Information Discovery via WMI Alert Type Malware Severity Medium Alert Time Jan 11 2025, 4:21 PM Investigation Start Time Apr 29 2026, 8:49 PM Analyst N/A Alert Details System information discovery activity (Get-WmiObject -Class Win32_Bios) detected via WMI on HR-WIN-001"
OUT = Path(".tmp-runtime-chat-bounded-result.json")
POLL_TIMEOUT_SECONDS = int(os.environ.get("CHAT_PROBE_POLL_TIMEOUT_SECONDS", "75"))

def write(data):
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

def compact(data):
    md = data.get("metadata") or {}
    soc = data.get("soc_progress") or md.get("soc_progress") or {}
    steps = data.get("steps") or []
    findings = data.get("findings") or []
    search_steps = [s for s in steps if "search_logs" in json.dumps(s, ensure_ascii=False, default=str).lower() or "splunk" in json.dumps(s, ensure_ascii=False, default=str).lower()]
    return {
        "session_id": data.get("id") or data.get("session_id"),
        "status": data.get("status"),
        "answer": data.get("answer") or data.get("response"),
        "summary": data.get("summary"),
        "answer_mode": md.get("answer_mode") or md.get("chat_answer_mode"),
        "capability_id": soc.get("capability_id") or md.get("capability_id"),
        "backend_mode": md.get("backend_mode") or md.get("log_backend_mode") or md.get("data_backend"),
        "configured_backends": md.get("configured_backends") or md.get("log_configured_backends") or soc.get("configured_backends"),
        "coverage_status": soc.get("coverage_status"),
        "coverage_gaps": md.get("coverage_gaps") or soc.get("coverage_gaps") or soc.get("degraded_capabilities"),
        "evidence_chips": soc.get("evidence_chips"),
        "findings": findings,
        "steps_count": len(steps),
        "search_steps": search_steps[-8:],
        "metadata_keys": sorted(md.keys()),
        "mcp_status": data.get("mcp_status"),
    }

result = {"prompt": PROMPT, "started_at": time.time(), "phase": "starting"}
write(result)
try:
    app = create_app()
    with TestClient(app) as client:
        result["phase"] = "lifespan_started"
        result["mcp_status_start"] = app.state.mcp_client.get_connection_status() if getattr(app.state, "mcp_client", None) else {}
        write(result)
        post = client.post("/api/chat", json={"message": PROMPT})
        result["post_status"] = post.status_code
        try:
            result["post_json"] = post.json()
        except Exception:
            result["post_text"] = post.text[:4000]
            result["post_json"] = {}
        result["phase"] = "posted"
        write(result)
        sid = result.get("post_json", {}).get("session_id")
        deadline = time.time() + POLL_TIMEOUT_SECONDS
        last = {}
        polls = []
        while sid and time.time() < deadline:
            resp = client.get(f"/api/chat/sessions/{sid}")
            last = resp.json()
            polls.append({"t": time.time(), "http": resp.status_code, "status": last.get("status"), "summary_prefix": str(last.get("summary") or last.get("answer") or "")[:300]})
            result["polls"] = polls[-20:]
            result["final_raw"] = last
            result["final_compact"] = compact(last)
            write(result)
            if last.get("status") != "active":
                break
            time.sleep(2)
        if sid and last.get("status") == "active":
            result["timed_out"] = True
            result["timeout_seconds"] = POLL_TIMEOUT_SECONDS
            result["phase"] = "poll_timeout"
        else:
            result["timed_out"] = False
            result["phase"] = "complete"
        write(result)
except Exception as exc:
    result["phase"] = "exception"
    result["exception"] = repr(exc)
    result["traceback"] = traceback.format_exc()
    write(result)
    raise
print(json.dumps({k: result.get(k) for k in ("phase", "post_status", "timed_out", "timeout_seconds", "final_compact")}, ensure_ascii=False, indent=2, default=str))
