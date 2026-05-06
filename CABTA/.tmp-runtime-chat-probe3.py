import json, time, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from fastapi.testclient import TestClient
from src.web.app import create_app

PROMPT = "dùng splunk để hãy điều tra alert sau Event ID 1002 Rule Name TET-101: Detect System Information Discovery via WMI Alert Type Malware Severity Medium Alert Time Jan 11 2025, 4:21 PM Investigation Start Time Apr 29 2026, 8:49 PM Analyst N/A Alert Details System information discovery activity (Get-WmiObject -Class Win32_Bios) detected via WMI on HR-WIN-001."
FOLLOWUPS = [
    "Tiếp tục dùng Splunk/live log search, pivot trên host HR-WIN-001 quanh thời điểm alert để lấy process command line, parent process, user và source index. Không dừng ở manual lookup nếu Splunk có thể chạy.",
    "Tiếp tục pivot WMI và PowerShell: tìm Get-WmiObject, Win32_Bios, powershell.exe, wmiprvse.exe, process_guid/process_id, parent_process_id và user liên quan trong Splunk/live logs.",
    "Tiếp tục pivot network và lateral movement cho cùng host/user/process. Nếu không thể tiếp tục, nêu rõ giới hạn đã được chứng minh bởi runtime/tool result nào.",
]

def compact_session(data):
    md = data.get('metadata') or {}
    soc = data.get('soc_progress') or md.get('soc_progress') or {}
    findings = data.get('findings') or []
    if isinstance(findings, str):
        try: findings = json.loads(findings)
        except Exception: findings = []
    return {'session_id': data.get('id') or data.get('session_id'),'status': data.get('status'),'answer_summary': (data.get('summary') or data.get('answer') or '')[:1200],'answer_mode': md.get('answer_mode') or md.get('chat_answer_mode'),'capability_id': soc.get('capability_id') or md.get('capability_id'),'backend_mode': md.get('backend_mode') or md.get('log_backend_mode') or md.get('data_backend'),'chat_execution_mode': md.get('chat_execution_mode'),'coverage_status': soc.get('coverage_status'),'evidence_chips': soc.get('evidence_chips'),'current_action': soc.get('current_action'),'findings_tail': findings[-8:] if isinstance(findings, list) else findings,'mcp_status': data.get('mcp_status')}

def poll(client, session_id, max_wait=90):
    last=None
    for _ in range(max_wait):
        data=client.get(f'/api/chat/sessions/{session_id}').json(); last=data
        if data.get('status')!='active': return data
        time.sleep(1)
    return last

app=create_app()
log=[]
with TestClient(app) as client:
    mcp_status = app.state.mcp_client.get_connection_status() if getattr(app.state,'mcp_client',None) else {}
    print('MCP_STATUS', json.dumps(mcp_status, ensure_ascii=False, default=str))
    current=None
    for idx,msg in enumerate([PROMPT]+FOLLOWUPS):
        label='initial' if idx==0 else f'followup_{idx}'
        body={'message':msg}
        if current: body['session_id']=current
        r=client.post('/api/chat', json=body)
        sid=r.json().get('session_id') or current
        final=poll(client,sid) if sid else {}
        current=sid
        entry={'label':label,'prompt':msg,'post_status':r.status_code,'post_json':r.json(),'final_compact':compact_session(final),'final_raw':final}
        log.append(entry)
        print('\nTURN',label,json.dumps(entry['final_compact'],ensure_ascii=False,default=str)[:4000])
Path('.tmp-runtime-chat-investigation3.json').write_text(json.dumps(log,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
