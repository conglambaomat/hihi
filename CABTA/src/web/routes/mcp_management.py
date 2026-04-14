"""
Author: Ugur Ates
MCP Server management routes.
"""

import asyncio
import logging
import shlex
import shutil
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Category metadata (Turkish + English labels) ─────────────────────────
CATEGORY_META: Dict[str, Dict[str, str]] = {
    'analysis': {
        'label': 'Analiz / Analysis',
        'icon': 'bi-search',
        'description_tr': 'Zararli yazilim ve dosya analiz araclari',
    },
    'reverse_engineering': {
        'label': 'Tersine Muhendislik / Reverse Engineering',
        'icon': 'bi-cpu',
        'description_tr': 'Ikili dosya analizi ve tersine muhendislik',
    },
    'sandbox': {
        'label': 'Sandbox',
        'icon': 'bi-box-seam',
        'description_tr': 'Izole ortamda zararli yazilim calistirma',
    },
    'threat_intel': {
        'label': 'Tehdit Istihbarati / Threat Intelligence',
        'icon': 'bi-globe2',
        'description_tr': 'IOC sorgulama ve tehdit istihbarati kaynaklari',
    },
    'detection': {
        'label': 'Tespit Muhendisligi / Detection Engineering',
        'icon': 'bi-shield-exclamation',
        'description_tr': 'Tespit kurali olusturma ve yonetimi',
    },
    'siem': {
        'label': 'SIEM',
        'icon': 'bi-bar-chart-line',
        'description_tr': 'Guvenlik bilgi ve olay yonetimi',
    },
    'edr': {
        'label': 'EDR / XDR',
        'icon': 'bi-pc-display',
        'description_tr': 'Uc nokta tespit ve mudahale',
    },
    'forensics': {
        'label': 'Adli Bilisim / Forensics',
        'icon': 'bi-fingerprint',
        'description_tr': 'Dijital adli bilisim ve olay mudahale',
    },
    'network': {
        'label': 'Ag Guvenligi / Network Security',
        'icon': 'bi-diagram-3',
        'description_tr': 'Ag trafigi analizi ve IDS/IPS',
    },
    'vulnerability': {
        'label': 'Zafiyet Tarama / Vulnerability',
        'icon': 'bi-bug',
        'description_tr': 'Zafiyet tarama ve degerlendirme',
    },
    'osint': {
        'label': 'OSINT',
        'icon': 'bi-binoculars',
        'description_tr': 'Acik kaynak istihbarat toplama',
    },
    'cloud': {
        'label': 'Bulut Guvenligi / Cloud Security',
        'icon': 'bi-cloud-check',
        'description_tr': 'Bulut ortami guvenlik denetimi',
    },
    'utility': {
        'label': 'Yardimci Araclar / Utility',
        'icon': 'bi-wrench-adjustable',
        'description_tr': 'Genel amacli MCP yardimci sunuculari',
    },
}


class MCPServerAdd(BaseModel):
    name: str
    transport: str  # stdio, sse, http
    command: Optional[str] = None
    args: Optional[List[str]] = None
    url: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    token: Optional[str] = None
    description: str = ""
    auto_connect: bool = False


def _mask_secret(value):
    if value and isinstance(value, str) and len(value) > 8:
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
    return value


def sanitize_mcp_server_record(entry: Dict) -> Dict:
    """Return a safe server record for web/UI responses."""
    safe = dict(entry)
    if isinstance(safe.get('env'), dict):
        safe['env'] = {k: _mask_secret(v) for k, v in safe['env'].items()}
    if safe.get('token'):
        safe['token'] = _mask_secret(safe['token'])
    cfg = safe.get('config_json')
    if isinstance(cfg, dict):
        cfg = dict(cfg)
        if isinstance(cfg.get('env'), dict):
            cfg['env'] = {k: _mask_secret(v) for k, v in cfg['env'].items()}
        if cfg.get('token'):
            cfg['token'] = _mask_secret(cfg['token'])
        safe['config_json'] = cfg
    return safe


def merge_mcp_server_records(app, include_live_status: bool = True) -> List[dict]:
    """Merge config-managed and DB-managed MCP servers into one view."""
    store = getattr(app.state, 'agent_store', None)
    db_servers = store.list_mcp_connections() if store else []
    db_lookup = {s['name']: dict(s) for s in db_servers if s.get('name')}

    config = getattr(app.state, 'config', None) or {}
    config_servers = config.get('mcp_servers', []) if isinstance(config, dict) else []

    merged: List[dict] = []
    seen_names: set = set()

    for cfg in config_servers:
        name = cfg.get('name', '')
        if not name:
            continue
        entry = dict(cfg)
        db_entry = db_lookup.get(name)
        if db_entry:
            entry.update({k: v for k, v in db_entry.items() if v is not None})
        entry['source'] = 'config'
        entry['managed_by_config'] = True
        entry.setdefault('status', 'planned')
        entry['auto_connect'] = bool(entry.get('auto_connect', False))
        merged.append(entry)
        seen_names.add(name)

    for s in db_servers:
        if s['name'] in seen_names:
            continue
        entry = dict(s)
        cfg_data = entry.get('config_json')
        if isinstance(cfg_data, dict):
            # Legacy UI-added servers had no explicit auto_connect flag.
            # Treat them as startup-managed by default so they remain
            # first-class extensions after upgrade.
            entry['auto_connect'] = bool(cfg_data.get('auto_connect', True))
        else:
            entry['auto_connect'] = bool(entry.get('auto_connect', False))
        entry['source'] = 'user'
        entry['managed_by_config'] = False
        entry.setdefault('status', 'requires_install')
        merged.append(entry)

    if include_live_status and hasattr(app.state, 'mcp_client') and app.state.mcp_client:
        live_status = app.state.mcp_client.get_connection_status()
        for entry in merged:
            live = live_status.get(entry['name'], {})
            entry['live_status'] = live
            if live:
                if live.get('connected'):
                    entry['status'] = 'connected'
                elif live.get('error'):
                    entry['status'] = f"error: {str(live['error'])[:120]}"
                else:
                    entry['status'] = 'disconnected'

                if live.get('tool_count') is not None:
                    entry['tool_count'] = live.get('tool_count')
                if live.get('tools'):
                    entry['tools_json'] = [
                        {"name": tool_name}
                        for tool_name in live.get('tools', [])
                        if tool_name
                    ]

    return merged


def get_startup_mcp_server_configs(app) -> List[dict]:
    """Return MCP server configs that should auto-connect on startup."""
    startup_configs: List[dict] = []

    for entry in merge_mcp_server_records(app, include_live_status=False):
        if entry.get('managed_by_config'):
            should_auto_connect = bool(entry.get('auto_connect', False))
            if not should_auto_connect:
                continue
            cfg = dict(entry)
        else:
            cfg_data = entry.get('config_json', entry)
            if not isinstance(cfg_data, dict):
                continue
            should_auto_connect = bool(
                cfg_data.get('auto_connect', entry.get('auto_connect', False))
            )
            # User-added servers should be able to persist across restarts
            # once explicitly marked for auto-connect.
            if not should_auto_connect:
                continue
            cfg = dict(cfg_data)

        cfg.setdefault('name', entry.get('name'))
        cfg.setdefault('transport', entry.get('transport', 'stdio'))
        startup_configs.append(cfg)

    return startup_configs


def _get_category_meta() -> Dict[str, Dict[str, str]]:
    """Return category metadata dict."""
    return CATEGORY_META


@router.get('/categories')
async def list_categories():
    """Return all MCP server category metadata."""
    return {"categories": CATEGORY_META}


@router.get('/servers')
async def list_servers(request: Request):
    """List all configured MCP servers.

    Merges pre-configured servers from config.yaml with any servers
    stored in the database, so users see all available servers and
    their connection status.
    """
    return {"servers": [sanitize_mcp_server_record(s) for s in merge_mcp_server_records(request.app)]}


@router.post('/servers')
async def add_server(request: Request, body: MCPServerAdd):
    """Add a new MCP server configuration."""
    store = request.app.state.agent_store
    payload = body.model_dump()
    if body.transport == 'stdio':
        command = str(body.command or "").strip()
        args = list(body.args or [])
        if command and not args and any(ch.isspace() for ch in command):
            try:
                tokens = shlex.split(command, posix=False)
            except ValueError:
                tokens = command.split()
            if len(tokens) > 1:
                payload['command'] = tokens[0]
                payload['args'] = tokens[1:]

    server_id = store.save_mcp_connection(body.name, body.transport, payload)
    return {"id": server_id, "name": body.name}


@router.delete('/servers/{server_name}')
async def remove_server(request: Request, server_name: str):
    """Remove an MCP server configuration."""
    merged = merge_mcp_server_records(request.app, include_live_status=False)
    server_entry = next((s for s in merged if s.get('name') == server_name), None)
    if server_entry is None:
        raise HTTPException(404, "Server configuration not found")
    if server_entry.get('managed_by_config'):
        raise HTTPException(409, "Server is managed by config.yaml and cannot be removed from the web UI")

    mcp_client = getattr(request.app.state, 'mcp_client', None)
    tool_registry = getattr(request.app.state, 'tool_registry', None)
    if mcp_client:
        await mcp_client.disconnect(server_name)
    if tool_registry:
        tool_registry.unregister_server(server_name)

    store = request.app.state.agent_store
    store.delete_mcp_connection(server_name)
    return {"status": "deleted"}


@router.post('/servers/{server_name}/connect')
async def connect_server(request: Request, server_name: str):
    """Connect to an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    store = request.app.state.agent_store

    # Look up server config from BOTH config.yaml and DB
    config = None

    # 1) Check config.yaml first (pre-configured servers)
    app_config = getattr(request.app.state, 'config', None) or {}
    config_servers = app_config.get('mcp_servers', []) if isinstance(app_config, dict) else []
    for s in config_servers:
        if s.get('name') == server_name:
            config = dict(s)
            break

    # 2) Fall back to DB
    if not config and store:
        for s in store.list_mcp_connections():
            if s['name'] == server_name:
                config = s
                break

    if not config:
        raise HTTPException(404, "Server configuration not found")
    try:
        from src.agent.mcp_client import MCPServerConfig
        import json as _json
        cfg_data = config.get('config_json', config)
        if isinstance(cfg_data, str):
            cfg_data = _json.loads(cfg_data)
        if isinstance(cfg_data, dict):
            cfg_data.setdefault('name', server_name)
            cfg_data.setdefault('transport', config.get('transport', 'stdio'))
        server_cfg = MCPServerConfig.from_dict(cfg_data)
        success = await mcp_client.connect(server_cfg)
        if success:
            # Register MCP tools into the ToolRegistry so the LLM can see them
            tool_registry = getattr(request.app.state, 'tool_registry', None)
            if tool_registry:
                try:
                    tools = await mcp_client.list_tools(server_name)
                    if tools:
                        tool_registry.register_mcp_tools(server_name, tools)
                except Exception:
                    pass  # Non-critical - tools still callable via MCP direct
            return {"status": "connected", "name": server_name}
        else:
            raise HTTPException(500, "Connection failed - check server logs")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Connection failed: {str(e)}")


@router.post('/servers/{server_name}/disconnect')
async def disconnect_server(request: Request, server_name: str):
    """Disconnect from an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    try:
        await mcp_client.disconnect(server_name)
        # Remove MCP tools from ToolRegistry
        tool_registry = getattr(request.app.state, 'tool_registry', None)
        if tool_registry:
            tool_registry.unregister_server(server_name)
        return {"status": "disconnected", "name": server_name}
    except Exception as e:
        raise HTTPException(500, f"Disconnect failed: {str(e)}")


@router.get('/servers/{server_name}/tools')
async def list_server_tools(request: Request, server_name: str):
    """List tools available from an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    tools = await mcp_client.list_tools(server_name)
    return {"tools": tools}


@router.post('/servers/{server_name}/check')
async def check_server_availability(request: Request, server_name: str):
    """Check if an MCP server's command exists on PATH (stdio)
    or if its URL is reachable (http/sse).

    Returns a JSON object with:
      - available (bool)
      - message (str) - human-readable status
      - detail (str) - technical detail
    """
    # Find server config
    app_config = getattr(request.app.state, 'config', None) or {}
    config_servers = app_config.get('mcp_servers', []) if isinstance(app_config, dict) else []
    server_cfg = None

    for s in config_servers:
        if s.get('name') == server_name:
            server_cfg = s
            break

    # Also check DB
    if not server_cfg:
        store = request.app.state.agent_store
        if store:
            for s in store.list_mcp_connections():
                if s['name'] == server_name:
                    server_cfg = s
                    break

    if not server_cfg:
        raise HTTPException(404, f"Server '{server_name}' not found")

    transport = (server_cfg.get('transport') or 'stdio').lower()

    if transport == 'stdio':
        return await _check_stdio_server(server_cfg)
    else:
        return await _check_http_server(server_cfg)


async def _check_stdio_server(cfg: dict) -> dict:
    """Check if a stdio server's command binary exists on PATH."""
    command = cfg.get('command', '')
    if not command:
        return {
            "available": False,
            "message": "Komut tanimlanmamis / No command defined",
            "detail": "stdio server has no 'command' field",
        }

    # For npx/uvx commands, check the launcher itself
    base_cmd = command.split()[0] if ' ' in command else command
    found_path = shutil.which(base_cmd)

    if found_path:
        return {
            "available": True,
            "message": f"Komut bulundu / Command found: {base_cmd}",
            "detail": f"Resolved to: {found_path}",
        }
    else:
        install_cmd = cfg.get('install_command', '')
        install_hint = f" -- Kurulum / Install: {install_cmd}" if install_cmd else ""
        return {
            "available": False,
            "message": f"Komut bulunamadi / Command not found: {base_cmd}{install_hint}",
            "detail": f"'{base_cmd}' is not on PATH",
        }


async def _check_http_server(cfg: dict) -> dict:
    """Check if an HTTP/SSE server URL is reachable."""
    import urllib.request
    import urllib.error

    url = cfg.get('url', '')
    if not url:
        return {
            "available": False,
            "message": "URL tanimlanmamis / No URL defined",
            "detail": "http/sse server has no 'url' field",
        }

    try:
        loop = asyncio.get_event_loop()

        def _probe():
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'BlueTeamAssistant/2.0')
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                return resp.status
            except urllib.error.HTTPError as he:
                # Even a 4xx/5xx means the server is reachable
                return he.code
            except Exception:
                raise

        status_code = await loop.run_in_executor(None, _probe)
        return {
            "available": True,
            "message": f"Sunucu erisilebilir / Server reachable (HTTP {status_code})",
            "detail": f"URL: {url} responded with status {status_code}",
        }
    except Exception as e:
        install_cmd = cfg.get('install_command', '')
        install_hint = f" -- Kurulum / Install: {install_cmd}" if install_cmd else ""
        return {
            "available": False,
            "message": f"Sunucu erisilemedi / Server unreachable{install_hint}",
            "detail": f"URL: {url} -- Error: {str(e)}",
        }
