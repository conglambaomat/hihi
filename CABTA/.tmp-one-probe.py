import json, time, sys
from pathlib import Path
sys.path.insert(0, str(Path('.').resolve()))
from fastapi.testclient import TestClient
from src.web.app import create_app
p='dùng splunk để hãy điều tra alert sau Event ID 1002 Rule Name TET-101: Detect System Information Discovery via WMI Alert Type Malware Severity Medium Alert Time Jan 11 2025, 4:21 PM Investigation Start Time Apr 29 2026, 8:49 PM Analyst N/A Alert Details System information discovery activity (Get-WmiObject -Class Win32_Bios) detected via WMI on HR-WIN-001.'
c=TestClient(create_app())
r=c.post('/api/chat',json={'message':p})
sid=r.json()['session_id']
print('POST',r.json()['soc_progress']['coverage_status'],sid)
for i in range(45):
    d=c.get(f'/api/chat/sessions/{sid}').json()
    if d.get('status')!='active':
        break
    time.sleep(1)
sp=d.get('soc_progress') or {}
print(json.dumps({'status':d.get('status'),'summary':d.get('summary'),'coverage':sp.get('coverage_status'),'gate':sp.get('final_answer_gate_status'),'findings_tools':[f.get('tool') for f in d.get('findings',[]) if isinstance(f,dict) and f.get('type')=='tool_result'],'missing':(sp.get('final_answer_gate') or {}).get('missing_evidence')},ensure_ascii=False,indent=2))
