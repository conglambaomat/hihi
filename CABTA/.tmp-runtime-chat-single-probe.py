import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fastapi.testclient import TestClient
from src.web.app import create_app

PROMPT = "dùng splunk để hãy điều tra alert sau Event ID 1002 Rule Name TET-101: Detect System Information Discovery via WMI Alert Type Malware Severity Medium Alert Time Jan 11 2025, 4:21 PM Investigation Start Time Apr 29 2026, 8:49 PM Analyst N/A Alert Details System information discovery activity (Get-WmiObject -Class Win32_Bios) detected via WMI on HR-WIN-001"
OUT = Path(".tmp-runtime-chat-single-probe-result.json")

def compact(data):
    md = data.get("metadata") or {}
    soc = data.get("soc_progress") or md.get("soc_progress") or {}
    steps = data.get("steps") or []
    configured = md.get("configured_backends") or md.get("log_configured_backends") or soc.get("configured_backends")
    return {
        "session_id": data.get("id") or data.get("session_id"),
        "status": data.get("status"),
        "summary": data.get("summary") or data.get("answer") or data.get("response"),
        "capability_id": soc.get("capability_id") or md.get("capability_id"),
        "current_action": soc.get("current_action"),
        "coverage_status": soc.get("coverage_status"),
        "splunk_live": md.get("splunk_live") or soc.get("splunk_live"),
        "configured_backends": configured,
        "backend_mode": md.get("backend_mode") or md.get("log_backend_mode") or md.get("data_backend"),
        "steps_count": len(steps),
        "tools_count": sum(1 for s in steps if (s.get("tool") or s.get("tool_name") or s.get("type") == "tool")),
        "safe_stop": md.get("safe_stop") or soc.get("safe_stop"),
        "coverage_gaps": md.get("coverage_gaps") or soc.get("coverage_gaps") or soc.get("degraded_capabilities"),
        "mcp_status": data.get("mcp_status"),
        "metadata_keys": sorted(md.keys()),
        "last_steps": steps[-10:],
    }

app = create_app()
result = {"prompt": PROMPT}
with TestClient(app) as client:
    result["mcp_status_start"] = app.state.mcp_client.get_connection_status() if getattr(app.state, "mcp_client", None) else {}
    post = client.post("/api/chat", json={"message": PROMPT})
    result["post_status"] = post.status_code
    result["post_json"] = post.json()
    sid = result["post_json"].get("session_id")
    last = {}
    deadline = time.time() + 120
    while sid and time.time() < deadline:
        last = client.get(f"/api/chat/sessions/{sid}").json()
        if last.get("status") != "active":
            break
        time.sleep(2)
    result["final_raw"] = last
    result["final_compact"] = compact(last)
OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
print(json.dumps(result["final_compact"], ensure_ascii=False, indent=2, default=str))
