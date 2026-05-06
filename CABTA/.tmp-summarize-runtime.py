import json

d=json.load(open('.tmp-runtime-chat-investigation.json',encoding='utf-8'))
print([x['label'] for x in d])
for x in d:
    data=x['data']; j=data.get('json',data)
    print('\n'+x['label'], 'code',data.get('status_code'), 'sid', j.get('session_id'), 'status', j.get('status'))
    sp=j.get('soc_progress') or {}
    print('cap',sp.get('capability_id'),'coverage',sp.get('coverage_status'),'gate',sp.get('final_answer_gate_status'),'chips',len(sp.get('evidence_chips') or []))
    if 'steps' in j:
        print('steps',len(j.get('steps') or []),'summary',j.get('summary'))
        print('steps_tools',[s.get('tool') for s in (j.get('steps') or [])])
        print('findings_tools',[f.get('tool') for f in (j.get('findings') or []) if isinstance(f,dict) and f.get('type')=='tool_result'])
        md=j.get('metadata') or {}
        print('metadata answer_mode', md.get('answer_mode'), 'capability_id', md.get('capability_id'))
        print('response', (j.get('response') or j.get('summary') or '')[:500].replace('\n',' '))
