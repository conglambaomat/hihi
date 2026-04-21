"""
Author: Ugur Ates
FastAPI Application Factory - CABTA Web Dashboard.

Usage::

    uvicorn src.web.app:create_app --factory --host 0.0.0.0 --port 8080
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .routes import analysis, dashboard, reports, config_api, cases
from .routes import agent as agent_routes
from .routes import chat as chat_routes
from .routes import playbooks as playbook_routes
from .routes import mcp_management as mcp_routes
from .routes import governance as governance_routes
from .routes import workflows as workflow_routes
from . import websocket
from .analysis_manager import AnalysisManager
from .case_store import CaseStore
from .data_provider import WebDataProvider
from .runtime_refresh import apply_runtime_config_bridges

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
CONFIG_FILE = PROJECT_ROOT / 'config.yaml'


def _load_config(config_file: Path | None = None) -> dict:
    """Load configuration from the provided config file (or sensible defaults)."""
    active_config_file = Path(config_file) if config_file else CONFIG_FILE
    try:
        from src.utils.config import load_config
        from src.utils.config_history import snapshot_config
        cfg = load_config(str(active_config_file) if active_config_file.is_file() else None)
        if active_config_file.is_file():
            try:
                snapshot_config(active_config_file, reason="startup snapshot")
            except Exception as history_exc:
                logger.warning("[WEB] Config history snapshot skipped: %s", history_exc)
        logger.info("[WEB] Configuration loaded for CABTA")
        return cfg
    except Exception as exc:
        logger.warning("[WEB] Failed to load config.yaml: %s", exc)

    return {
        'llm': {
            'provider': 'openrouter',
            'auto_failover': False,
            'fallback_providers': [],
            'openrouter_endpoint': 'https://openrouter.ai/api/v1',
            'openrouter_model': 'arcee-ai/trinity-large-preview:free',
            'ollama_endpoint': 'http://localhost:11434',
            'ollama_model': 'llama3.1:8b',
            'gemini_endpoint': 'https://generativelanguage.googleapis.com/v1beta/openai',
            'gemini_model': 'gemini-2.5-flash',
        },
        'agent': {'max_steps': 50},
        'api_keys': {},
        'web': {
            'demo_mode': {
                'enabled': False,
                'dataset': 'default',
            },
        },
    }
TEMPLATES_DIR = PROJECT_ROOT / 'templates'
STATIC_DIR = PROJECT_ROOT / 'static'


class NoCacheStaticMiddleware(BaseHTTPMiddleware):
    """Prevent browser caching of static JS/CSS during development."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        if request.url.path.startswith('/static/'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Application lifespan: auto-connect MCP servers on startup."""
    await _auto_connect_mcp_servers(app)
    yield
    # Cleanup: disconnect MCP servers on shutdown
    mcp_client = getattr(app.state, 'mcp_client', None)
    if mcp_client:
        try:
            await mcp_client.disconnect_all()
        except Exception:
            pass


def create_app(config_file: str | Path | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    active_config_file = Path(config_file).expanduser().resolve() if config_file else CONFIG_FILE

    app = FastAPI(
        title='CABTA',
        description='CABTA localhost SOC triage and investigation platform',
        version='2.0.0',
        docs_url='/api/docs',
        redoc_url='/api/redoc',
        lifespan=_lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_credentials=True,
        allow_methods=['*'],
        allow_headers=['*'],
    )

    # Prevent static file caching
    app.add_middleware(NoCacheStaticMiddleware)

    # Static files
    if STATIC_DIR.exists():
        app.mount('/static', StaticFiles(directory=str(STATIC_DIR)), name='static')

    # Shared state
    app.state.analysis_manager = AnalysisManager()
    app.state.case_store = CaseStore()
    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.state.templates.env.globals.update({
        'product_name': 'CABTA',
        'product_full_name': 'Cyan Agent Blue Team Assistant',
    })

    # Agent components (lazy-initialized; set to None so routes can check availability)
    app.state.agent_store = None
    app.state.thread_store = None
    app.state.agent_loop = None
    app.state.mcp_client = None
    app.state.playbook_engine = None
    app.state.tool_registry = None

    # Load configuration
    config = apply_runtime_config_bridges(_load_config(active_config_file))
    app.state.config_file = active_config_file
    app.state.config = config
    app.state.web_provider = WebDataProvider(config)
    app.state.agent_profiles = None
    app.state.workflow_registry = None
    app.state.capability_catalog = None
    app.state.workflow_service = None
    app.state.governance_store = None
    app.state.case_intelligence = None
    app.state.case_memory_service = None
    app.state.headless_soc_daemon = None

    try:
        from src.agent.profiles import AgentProfileRegistry
        app.state.agent_profiles = AgentProfileRegistry.default()
        logger.info("[WEB] AgentProfileRegistry initialized")
    except Exception as exc:
        logger.warning(f"[WEB] AgentProfileRegistry not available: {exc}")

    try:
        from src.workflows.registry import WorkflowRegistry
        app.state.workflow_registry = WorkflowRegistry()
        logger.info("[WEB] WorkflowRegistry initialized")
    except Exception as exc:
        logger.warning(f"[WEB] WorkflowRegistry not available: {exc}")

    try:
        from src.agent.capability_catalog import CapabilityCatalog
        app.state.capability_catalog = CapabilityCatalog()
        logger.info("[WEB] CapabilityCatalog initialized")
    except Exception as exc:
        logger.warning(f"[WEB] CapabilityCatalog not available: {exc}")

    try:
        from src.agent.governance_store import GovernanceStore
        app.state.governance_store = GovernanceStore()
        logger.info("[WEB] GovernanceStore initialized")
    except Exception as exc:
        logger.warning(f"[WEB] GovernanceStore not available: {exc}")

    try:
        from src.agent.agent_store import AgentStore
        app.state.agent_store = AgentStore()
        logger.info("[WEB] AgentStore initialized")
    except Exception as exc:
        logger.warning(f"[WEB] AgentStore not available: {exc}")

    try:
        from src.agent.thread_store import ThreadStore
        thread_db_path = None
        if getattr(app.state.agent_store, "_db_path", None) is not None:
            thread_db_path = str(Path(app.state.agent_store._db_path).with_name("threads.db"))
        app.state.thread_store = ThreadStore(db_path=thread_db_path)
        logger.info("[WEB] ThreadStore initialized")
    except Exception as exc:
        logger.warning(f"[WEB] ThreadStore not available: {exc}")

    try:
        from src.agent.case_memory_service import CaseMemoryService
        app.state.case_memory_service = CaseMemoryService(
            case_store=app.state.case_store,
            agent_store=app.state.agent_store,
        )
        logger.info("[WEB] CaseMemoryService initialized")
    except Exception as exc:
        logger.warning(f"[WEB] CaseMemoryService not available: {exc}")

    # Tool instances (used by ToolRegistry)
    app.state.ioc_investigator = None
    app.state.malware_analyzer = None
    app.state.email_analyzer = None
    app.state.correlation_engine = None
    app.state.investigation_memory = None
    app.state.sandbox_orchestrator = None

    try:
        from src.agent.tool_registry import ToolRegistry
        app.state.tool_registry = ToolRegistry()

        # Instantiate real tool classes
        ioc_inv = None
        mal_ana = None
        email_ana = None

        try:
            from src.tools.ioc_investigator import IOCInvestigator
            ioc_inv = IOCInvestigator(config)
            app.state.ioc_investigator = ioc_inv
            logger.info("[WEB] IOCInvestigator initialized")
        except Exception as e:
            logger.warning(f"[WEB] IOCInvestigator not available: {e}")

        try:
            from src.tools.malware_analyzer import MalwareAnalyzer
            mal_ana = MalwareAnalyzer(config)
            app.state.malware_analyzer = mal_ana
            logger.info("[WEB] MalwareAnalyzer initialized")
        except Exception as e:
            logger.warning(f"[WEB] MalwareAnalyzer not available: {e}")

        try:
            from src.tools.email_analyzer import EmailAnalyzer
            email_ana = EmailAnalyzer(config)
            app.state.email_analyzer = email_ana
            logger.info("[WEB] EmailAnalyzer initialized")
        except Exception as e:
            logger.warning(f"[WEB] EmailAnalyzer not available: {e}")

        # Wire cross-tool references
        if email_ana and ioc_inv:
            email_ana.ioc_investigator = ioc_inv
        if email_ana and mal_ana:
            email_ana.file_analyzer = mal_ana
        if mal_ana and ioc_inv:
            mal_ana.ioc_investigator = ioc_inv

        # Register all tools (with full instances where available)
        try:
            app.state.tool_registry.register_default_tools(
                config,
                ioc_investigator=ioc_inv,
                malware_analyzer=mal_ana,
                email_analyzer=email_ana,
                governance_store=app.state.governance_store,
                case_store=app.state.case_store,
            )
        except Exception as reg_exc:
            logger.warning(f"[WEB] Default tool registration partial: {reg_exc}")

        logger.info("[WEB] ToolRegistry initialized with %d tools", len(app.state.tool_registry.list_tools()))
    except Exception as exc:
        logger.warning(f"[WEB] ToolRegistry not available: {exc}")

    # Correlation Engine
    try:
        from src.agent.correlation import CorrelationEngine
        app.state.correlation_engine = CorrelationEngine()
        logger.info("[WEB] CorrelationEngine initialized")
    except Exception as exc:
        logger.warning(f"[WEB] CorrelationEngine not available: {exc}")

    # Investigation Memory
    try:
        from src.agent.memory import InvestigationMemory
        app.state.investigation_memory = InvestigationMemory()
        logger.info("[WEB] InvestigationMemory initialized")
    except Exception as exc:
        logger.warning(f"[WEB] InvestigationMemory not available: {exc}")

    # Sandbox Orchestrator
    try:
        from src.agent.sandbox_orchestrator import SandboxOrchestrator
        app.state.sandbox_orchestrator = SandboxOrchestrator(config)
        logger.info("[WEB] SandboxOrchestrator initialized")
    except Exception as exc:
        logger.warning(f"[WEB] SandboxOrchestrator not available: {exc}")

    try:
        from src.agent.mcp_client import MCPClientManager
        app.state.mcp_client = MCPClientManager(agent_store=app.state.agent_store)
        logger.info("[WEB] MCPClientManager initialized")
    except Exception as exc:
        logger.warning(f"[WEB] MCPClientManager not available: {exc}")

    if app.state.sandbox_orchestrator is not None:
        app.state.sandbox_orchestrator.mcp_client = app.state.mcp_client

    if app.state.tool_registry is not None:
        try:
            app.state.tool_registry.register_default_tools(
                config,
                ioc_investigator=app.state.ioc_investigator,
                malware_analyzer=app.state.malware_analyzer,
                email_analyzer=app.state.email_analyzer,
                sandbox_orchestrator=app.state.sandbox_orchestrator,
                mcp_client=app.state.mcp_client,
                governance_store=app.state.governance_store,
                case_store=app.state.case_store,
            )
        except Exception as reg_exc:
            logger.warning(f"[WEB] Sandbox-aware tool registration partial: {reg_exc}")

    try:
        from src.agent.agent_loop import AgentLoop
        app.state.agent_loop = AgentLoop(
            config=config,
            tool_registry=app.state.tool_registry or ToolRegistry(),
            agent_store=app.state.agent_store,
            mcp_client=app.state.mcp_client,
            agent_profiles=app.state.agent_profiles,
            workflow_registry=app.state.workflow_registry,
            governance_store=app.state.governance_store,
            case_store=app.state.case_store,
            thread_store=app.state.thread_store,
            case_memory_service=app.state.case_memory_service,
        )
        logger.info("[WEB] AgentLoop initialized")
    except Exception as exc:
        logger.warning(f"[WEB] AgentLoop not available: {exc}")

    try:
        from src.agent.playbook_engine import PlaybookEngine
        app.state.playbook_engine = PlaybookEngine(
            agent_loop=app.state.agent_loop,
            agent_store=app.state.agent_store,
            governance_store=app.state.governance_store,
        )
        # Wire playbook engine back into agent loop so LLM can trigger playbooks
        if app.state.agent_loop is not None:
            app.state.agent_loop._playbook_engine = app.state.playbook_engine
        logger.info("[WEB] PlaybookEngine initialized")
    except Exception as exc:
        logger.warning(f"[WEB] PlaybookEngine not available: {exc}")

    try:
        from src.workflows.service import WorkflowService
        app.state.workflow_service = WorkflowService(
            workflow_registry=app.state.workflow_registry,
            agent_store=app.state.agent_store,
            case_store=app.state.case_store,
            governance_store=app.state.governance_store,
        )
        logger.info("[WEB] WorkflowService initialized")
    except Exception as exc:
        logger.warning(f"[WEB] WorkflowService not available: {exc}")

    try:
        from src.case_intelligence.service import CaseIntelligenceService
        app.state.case_intelligence = CaseIntelligenceService(
            analysis_manager=app.state.analysis_manager,
            agent_store=app.state.agent_store,
            case_store=app.state.case_store,
            governance_store=app.state.governance_store,
        )
        logger.info("[WEB] CaseIntelligenceService initialized")
    except Exception as exc:
        logger.warning(f"[WEB] CaseIntelligenceService not available: {exc}")

    try:
        from src.daemon.service import HeadlessSOCDaemon
        app.state.headless_soc_daemon = HeadlessSOCDaemon(
            config=config,
            workflow_registry=app.state.workflow_registry,
            workflow_service=app.state.workflow_service,
        )
        logger.info("[WEB] HeadlessSOCDaemon initialized")
    except Exception as exc:
        logger.warning(f"[WEB] HeadlessSOCDaemon not available: {exc}")

    # Register routers
    app.include_router(dashboard.router, prefix='/api/dashboard', tags=['Dashboard'])
    app.include_router(analysis.router, prefix='/api/analysis', tags=['Analysis'])
    app.include_router(reports.router, prefix='/api/reports', tags=['Reports'])
    app.include_router(config_api.router, prefix='/api/config', tags=['Config'])
    app.include_router(cases.router, prefix='/api/cases', tags=['Cases'])
    app.include_router(agent_routes.router, prefix='/api/agent', tags=['Agent'])
    app.include_router(chat_routes.router, prefix='/api/chat', tags=['Chat'])
    app.include_router(playbook_routes.router, prefix='/api/playbooks', tags=['Playbooks'])
    app.include_router(workflow_routes.router, prefix='/api/workflows', tags=['Workflows'])
    app.include_router(governance_routes.router, prefix='/api/governance', tags=['Governance'])
    app.include_router(mcp_routes.router, prefix='/api/mcp', tags=['MCP'])
    app.include_router(websocket.router)

    # Page routes (HTML templates)
    _register_page_routes(app)

    logger.info("[WEB] CABTA Web Dashboard initialized")
    return app


async def _auto_connect_mcp_servers(app: FastAPI) -> None:
    """Connect to MCP servers that have auto_connect: true in config."""
    mcp_client = app.state.mcp_client
    if not mcp_client:
        return
    from src.web.routes.mcp_management import get_startup_mcp_server_configs

    auto_servers = get_startup_mcp_server_configs(app)
    if not auto_servers:
        return
    logger.info("[WEB] Auto-connecting to %d MCP servers...", len(auto_servers))
    tool_registry = getattr(app.state, 'tool_registry', None)
    for srv_cfg in auto_servers:
        try:
            from src.agent.mcp_client import MCPServerConfig
            mcp_cfg = MCPServerConfig.from_dict(srv_cfg)
            success = await mcp_client.connect(mcp_cfg)
            if success:
                logger.info("[WEB] Connected to MCP server: %s", srv_cfg['name'])
                # Register MCP tools into the ToolRegistry so the LLM can see them
                if tool_registry:
                    try:
                        tools = await mcp_client.list_tools(srv_cfg['name'])
                        if tools:
                            tool_registry.register_mcp_tools(srv_cfg['name'], tools)
                            logger.info("[WEB] Registered %d MCP tools from %s into ToolRegistry",
                                        len(tools), srv_cfg['name'])
                    except Exception as te:
                        logger.warning("[WEB] Failed to register MCP tools for %s: %s",
                                       srv_cfg['name'], te)
            else:
                logger.warning("[WEB] Failed to connect to MCP server: %s", srv_cfg['name'])
        except Exception as exc:
            logger.warning("[WEB] MCP auto-connect error for %s: %s", srv_cfg.get('name', '?'), exc)


def _register_page_routes(app: FastAPI) -> None:
    """Register HTML page routes for the dashboard."""
    from fastapi import Request
    from fastapi.responses import HTMLResponse

    templates = app.state.templates
    provider = app.state.web_provider

    def page_context(request: Request, **extra):
        return provider.build_template_context(app, request, **extra)

    @app.get('/', response_class=HTMLResponse, include_in_schema=False)
    async def index(request: Request):
        stats = provider.get_dashboard_stats(app)
        recent = provider.list_jobs(app, limit=10)
        sources = provider.get_sources(app)
        return templates.TemplateResponse(request, 'dashboard.html', page_context(request, stats=stats, recent_jobs=recent, sources=sources))

    @app.get('/dashboard', response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_page(request: Request):
        stats = provider.get_dashboard_stats(app)
        recent = provider.list_jobs(app, limit=10)
        sources = provider.get_sources(app)
        return templates.TemplateResponse(request, 'dashboard.html', page_context(request, stats=stats, recent_jobs=recent, sources=sources))

    @app.get('/analysis/ioc', response_class=HTMLResponse, include_in_schema=False)
    async def ioc_page(request: Request):
        return templates.TemplateResponse(request, 'analysis_ioc.html', page_context(request))

    @app.get('/analysis/file', response_class=HTMLResponse, include_in_schema=False)
    async def file_page(request: Request):
        return templates.TemplateResponse(request, 'analysis_file.html', page_context(request))

    @app.get('/analysis/email', response_class=HTMLResponse, include_in_schema=False)
    async def email_page(request: Request):
        return templates.TemplateResponse(request, 'analysis_email.html', page_context(request))

    @app.get('/history', response_class=HTMLResponse, include_in_schema=False)
    async def history_page(request: Request):
        jobs = provider.list_jobs(app, limit=100)
        for job in jobs:
            job['type'] = job.get('analysis_type', '')
            job['target'] = job.get('target', '')
        return templates.TemplateResponse(request, 'history.html', page_context(request, jobs=jobs))

    @app.get('/cases', response_class=HTMLResponse, include_in_schema=False)
    async def cases_page(request: Request):
        case_list = provider.list_cases(app, limit=100)
        return templates.TemplateResponse(request, 'cases.html', page_context(request, cases=case_list))

    @app.get('/cases/{case_id}', response_class=HTMLResponse, include_in_schema=False)
    async def case_detail_page(request: Request, case_id: str):
        case = provider.get_case(app, case_id)
        if not case:
            return HTMLResponse('<h3>Case not found</h3>', status_code=404)
        return templates.TemplateResponse(request, 'case_detail.html', page_context(request, case=case))

    @app.get('/report/{job_id}', response_class=HTMLResponse, include_in_schema=False)
    async def report_page(request: Request, job_id: str):
        job = provider.get_job(app, job_id)
        if not job:
            return HTMLResponse('<h3>Report not found</h3>', status_code=404)
        return templates.TemplateResponse(request, 'report_view.html', page_context(request, job=job))

    # ----- Agent pages -----

    @app.get('/agent/chat', response_class=HTMLResponse, include_in_schema=False)
    async def agent_chat_page(request: Request):
        return templates.TemplateResponse(request, 'agent_chat.html', page_context(request))

    @app.get('/agent/investigations', response_class=HTMLResponse, include_in_schema=False)
    async def agent_investigations_page(request: Request):
        sessions = []
        stats = {"total": 0, "active": 0, "completed": 0, "failed": 0}
        if app.state.agent_store:
            sessions = app.state.agent_store.list_sessions(limit=100)
            stats = app.state.agent_store.get_agent_stats()
        return templates.TemplateResponse(request, 'agent_investigations.html', page_context(request, sessions=sessions, stats=stats))

    @app.get('/agent/playbooks', response_class=HTMLResponse, include_in_schema=False)
    async def agent_playbooks_page(request: Request):
        playbooks = []
        if app.state.playbook_engine:
            playbooks = app.state.playbook_engine.list_playbooks()
        elif app.state.agent_store:
            playbooks = app.state.agent_store.list_playbooks()
        return templates.TemplateResponse(request, 'playbooks.html', page_context(request, playbooks=playbooks))

    @app.get('/agent/workflows', response_class=HTMLResponse, include_in_schema=False)
    async def agent_workflows_page(request: Request):
        workflows = []
        if app.state.workflow_registry:
            workflows = app.state.workflow_registry.list_workflows()
            if app.state.workflow_service:
                workflows = [
                    {
                        **workflow,
                        "dependency_status": app.state.workflow_service.validate_dependencies(app, workflow["id"]).get("status"),
                    }
                    for workflow in workflows
                ]
        return templates.TemplateResponse(request, 'workflows.html', page_context(request, workflows=workflows))

    @app.get('/agent/approvals', response_class=HTMLResponse, include_in_schema=False)
    async def agent_approvals_page(request: Request):
        approvals = []
        if app.state.governance_store:
            approvals = app.state.governance_store.list_approvals(limit=100)
        return templates.TemplateResponse(request, 'approvals.html', page_context(request, approvals=approvals))

    @app.get('/agent/decisions', response_class=HTMLResponse, include_in_schema=False)
    async def agent_decisions_page(request: Request):
        decisions = []
        if app.state.governance_store:
            decisions = app.state.governance_store.list_ai_decisions(limit=100)
        return templates.TemplateResponse(request, 'decisions.html', page_context(request, decisions=decisions))

    @app.get('/mcp/servers', response_class=HTMLResponse, include_in_schema=False)
    async def mcp_servers_page(request: Request):
        from src.web.routes.mcp_management import CATEGORY_META, merge_mcp_server_records, sanitize_mcp_server_record

        merged = [sanitize_mcp_server_record(s) for s in merge_mcp_server_records(app)]

        # Category metadata for grouping/filtering
        categories = CATEGORY_META

        # Collect unique categories present in the server list
        active_categories = []
        seen_cats = set()
        for s in merged:
            cat = s.get('category', 'other')
            if cat not in seen_cats:
                seen_cats.add(cat)
                meta = categories.get(cat, {'label': cat.replace('_', ' ').title(), 'icon': 'bi-server'})
                active_categories.append({'key': cat, **meta})

        return templates.TemplateResponse(request, 'mcp_servers.html', page_context(
            request,
            servers=merged,
            categories=categories,
            active_categories=active_categories,
        ))

    @app.get('/settings', response_class=HTMLResponse, include_in_schema=False)
    async def settings_page(request: Request):
        from src.web.routes.config_api import API_KEY_CATALOG
        return templates.TemplateResponse(request, 'settings.html', page_context(request, api_key_catalog=API_KEY_CATALOG))
