import json
p='.tmp-runtime-chat-investigation2.json'
data=json.load(open(p,encoding='utf-8'))
for e in data:
    print('\nTURN', e['label'])
    c=e['final_compact']
    for k in ['session_id','status','answer_summary','answer_mode','capability_id','backend_mode','chat_execution_mode','coverage_status']:
        print(k,':',c.get(k))
    ft=c.get('findings_tail') or []
    for f in ft:
        print(' finding', f.get('type'), f.get('tool'), str(f.get('result'))[:700].replace('\n',' '))
    print('chips', len(c.get('evidence_chips') or []))
