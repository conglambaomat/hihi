import json
from pathlib import Path
p=Path('.tmp-runtime-chat-investigation.json')
data=json.loads(p.read_text(encoding='utf-8'))
for e in data:
    label=e['label']; d=e['data']
    print('\n##',label)
    j=d.get('json',d)
    if isinstance(j,dict):
        print('status_code',d.get('status_code'),'session',j.get('session_id'),'status',j.get('status'))
        sp=j.get('soc_progress') or {}
        print('capability',sp.get('capability_id'),'coverage',sp.get('coverage_status'),'badge',j.get('verdict_badge') or sp.get('ui_badge'))
        ci=sp.get('compiled_input') or {}
        print('lane',ci.get('lane'),'requested_backends',ci.get('requested_backends'),'entities',[(x.get('type'),x.get('value')) for x in ci.get('entities',[])])
        print('response', (j.get('response') or j.get('message') or '')[:1200].replace('\n',' | '))
        print('steps', j.get('steps') or sp.get('steps'))
        print('tools', j.get('tools') or sp.get('tools'))
        print('limitations', j.get('limitations') or sp.get('limitations'))
        print('errors', j.get('error') or sp.get('error'))
        print('events', [(ev.get('event_type'), ev.get('status'), ev.get('capability_id') or ev.get('capabilities')) for ev in (j.get('progress_events') or sp.get('progress_events') or [])][-10:])
        fe= j.get('final_answer_gate') or sp.get('final_answer_gate') or {}
        print('final_gate', fe.get('status'), fe.get('limitations'))
