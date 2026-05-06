import json, time, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from fastapi.testclient import TestClient
from src.web.app import create_app

PROMPT = "dùng splunk để hãy điều tra alert sau Event ID 1002 Rule Name TET-101: Detect System Information Discovery via WMI Alert Type Malware Severity Medium Alert Time Jan 11 2025, 4:21 PM Investigation Start Time Apr 29 2026, 8:49 PM Analyst N/A Alert Details System information discovery activity (Get-WmiObject -Class Win32_Bios) detected via WMI on HR-WIN-001."
FOLLOWUPS = [
    "Hãy tiếp tục dùng Splunk/log search để tìm các event liên quan trên HR-WIN-001 quanh thời điểm alert, gồm process command line, user, parent process và source index.",
    "Nếu chưa chạy tool Splunk thì hãy chạy ngay truy vấn log/Splunk phù hợp. Nếu bị chặn do thiếu capability/config thì nói rõ capability/tool nào thiếu và bằng chứng runtime.",
]

app = create_app()
client = TestClient(app)
log = []

def snap(label, obj):
    log.append({"label": label, "data": obj})
    print("\n===", label, "===")
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str)[:6000])

def poll(session_id, max_wait=45):
    last = None
    for i in range(max_wait):
        r = client.get(f"/api/chat/sessions/{session_id}")
        data = r.json()
        last = data
        status = data.get("status")
        if status != "active":
            return data
        time.sleep(1)
    return last

r = client.get('/agent/chat')
snap('GET /agent/chat', {"status_code": r.status_code, "text_start": r.text[:300]})
r = client.post('/api/chat', json={"message": PROMPT})
snap('POST initial', {"status_code": r.status_code, "json": r.json()})
session_id = r.json().get('session_id')
if session_id:
    snap('POLL initial final', poll(session_id))
    current = session_id
    for idx, msg in enumerate(FOLLOWUPS, 1):
        r = client.post('/api/chat', json={"message": msg, "session_id": current})
        payload = {"status_code": r.status_code, "json": r.json()}
        snap(f'POST followup {idx}', payload)
        new_id = r.json().get('session_id') or current
        snap(f'POLL followup {idx} final', poll(new_id))
        current = new_id

Path('.tmp-runtime-chat-investigation.json').write_text(json.dumps(log, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
