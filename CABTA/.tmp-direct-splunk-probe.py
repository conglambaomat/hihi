import json
import os
import sys
import time
import traceback
from pathlib import Path

OUT = Path('.tmp-direct-splunk-result.json')
os.environ['SPLUNK_TIMEOUT_SECONDS'] = os.environ.get('SPLUNK_TIMEOUT_SECONDS', '5')
sys.path.insert(0, str(Path(__file__).parent))

query = 'search index=* host="HR-WIN-001" ("Get-WmiObject" OR "Win32_Bios" OR EventCode=1002 OR event_id=1002 OR rule_name="*TET-101*") | head 5'
result = {'query': query, 'timerange': '-30m..+2h around Jan 11 2025 4:21 PM', 'started_at': time.time()}
try:
    from src.mcp_servers import splunk_tools
    safe_cfg = {
        'splunk_url_configured': bool(splunk_tools.SPLUNK_URL),
        'splunk_token_configured': bool(splunk_tools.SPLUNK_TOKEN),
        'timeout': splunk_tools.TIMEOUT,
        'max_results': splunk_tools.SPLUNK_MAX_RESULTS,
    }
    result['safe_config'] = safe_cfg
    result['tool_result'] = splunk_tools.search_logs(query=query, timerange='24h', max_results=5, note='bounded diagnostic probe for WMI alert')
except Exception as exc:
    result['exception'] = repr(exc)
    result['traceback'] = traceback.format_exc()
finally:
    result['elapsed_seconds'] = round(time.time() - result['started_at'], 3)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
