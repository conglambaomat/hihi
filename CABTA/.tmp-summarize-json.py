import json
from pathlib import Path

data=json.loads(Path('.tmp-runtime-chat-investigation2.json').read_text(encoding='utf-8'))
for i,e in enumerate(data):
    raw=e.get('final_raw') or {}
    fc=e.get('final_compact') or {}
    print('TURN', i, e.get('label'))
    print('post_status', (e.get('post') or e).get('post_status'))
    print('session', fc.get('session_id'), 'status', fc.get('status'), 'cap', fc.get('capability_id'), 'coverage', fc.get('coverage_status'))
    print('answer', (fc.get('answer_summary') or raw.get('summary') or raw.get('answer') or '')[:1200].replace('\n',' '))
    steps=raw.get('steps') or []
    print('steps', len(steps))
    names=[]
    for s in steps:
        name=s.get('tool') or s.get('tool_name') or s.get('name') or s.get('step_type') or s.get('type')
        if name: names.append(str(name))
    print('tools', names[:30])
    md=raw.get('metadata') or {}
    soc=raw.get('soc_progress') or md.get('soc_progress') or {}
    print('md backends', {k:md.get(k) for k in md if 'backend' in k.lower() or 'splunk' in k.lower()})
    print('soc keys', {k:soc.get(k) for k in soc if k in ('configured_backends','splunk_live','degraded_capabilities','coverage_status','final_answer_gate_status')})
    print('structured', (soc.get('structured_verdict') or {}).get('completion_status'), (soc.get('structured_verdict') or {}).get('stop_reason'), (soc.get('structured_verdict') or {}).get('limitations'))
    print()
