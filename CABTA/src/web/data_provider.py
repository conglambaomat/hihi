"""CABTA web data provider for live and demo modes."""

from __future__ import annotations

import json
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from .normalizer import normalize_case, normalize_job
from ..utils.api_key_validator import is_valid_api_key

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEMO_DATA_DIR = PROJECT_ROOT / "data" / "demo"


@lru_cache(maxsize=4)
def _load_demo_dataset(dataset: str) -> Dict[str, Any]:
    path = DEMO_DATA_DIR / f"{dataset}.json"
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


class WebDataProvider:
    """Resolve web-facing state from live services or demo fixtures."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def is_demo_mode(self) -> bool:
        return bool(self.config.get("web", {}).get("demo_mode", {}).get("enabled", False))

    def dataset_name(self) -> str:
        return str(self.config.get("web", {}).get("demo_mode", {}).get("dataset", "default"))

    def app_mode(self) -> str:
        return "demo" if self.is_demo_mode() else "live"

    def demo_data(self) -> Dict[str, Any]:
        if not self.is_demo_mode():
            return {}
        return deepcopy(_load_demo_dataset(self.dataset_name()))

    def _api_keys(self) -> Dict[str, Any]:
        return self.config.get("api_keys", {}) if isinstance(self.config, dict) else {}

    def _has_api_key(self, *names: str) -> bool:
        api_keys = self._api_keys()
        return any(is_valid_api_key(api_keys.get(name)) for name in names)

    def _mcp_status(self, app: Any) -> Dict[str, Any]:
        mcp_client = getattr(app.state, "mcp_client", None)
        if not mcp_client:
            return {"connected": 0, "configured": 0, "status": "optional", "label": "Optional"}

        try:
            live_status = mcp_client.get_connection_status() or {}
        except Exception:
            live_status = {}

        connected = sum(1 for meta in live_status.values() if meta.get("connected"))
        configured = len(live_status)
        if connected:
            return {
                "connected": connected,
                "configured": configured,
                "status": "available",
                "label": f"{connected} connected",
            }
        return {
            "connected": 0,
            "configured": configured,
            "status": "optional",
            "label": "Optional",
        }

    def _has_configured_mcp_server(self, name: str) -> bool:
        servers = self.config.get("mcp_servers", []) if isinstance(self.config, dict) else []
        return any(isinstance(server, dict) and str(server.get("name", "")).strip() == name for server in servers)

    def _sandbox_inventory(self, app: Any) -> List[Dict[str, Any]]:
        orchestrator = getattr(app.state, "sandbox_orchestrator", None)
        if orchestrator is None:
            return []
        try:
            return orchestrator.get_sandbox_status() or []
        except Exception:
            return []

    def _has_sandbox_lookup_provider(self) -> bool:
        return self._has_api_key(
            "virustotal",
            "hybrid_analysis",
            "hybridanalysis",
            "anyrun",
            "joe_sandbox",
            "joesandbox",
            "triage",
            "threatzone",
        )

    def feature_status(self, app: Any) -> Dict[str, Dict[str, Any]]:
        cfg = self.config or {}
        llm = cfg.get("llm", {})
        analysis = cfg.get("analysis", {})
        agent_enabled = bool(getattr(app.state, "agent_loop", None))
        workflow_enabled = bool(getattr(app.state, "workflow_registry", None)) and bool(
            getattr(app.state, "agent_profiles", None)
        )
        governance_enabled = bool(getattr(app.state, "governance_store", None))
        daemon = getattr(app.state, "headless_soc_daemon", None)
        daemon_meta = daemon.build_status(app) if daemon is not None else {}
        mcp_meta = self._mcp_status(app)
        provider = str(llm.get("provider") or "").strip().lower()

        if not provider:
            llm_status = {"status": "disabled", "label": "Disabled"}
        elif provider == "groq":
            llm_status = {
                "status": "configured" if self._has_api_key("groq") else "degraded",
                "label": "Groq" if self._has_api_key("groq") else "Groq (key missing)",
            }
        elif provider == "anthropic":
            llm_status = {
                "status": "configured" if self._has_api_key("anthropic") else "degraded",
                "label": "Anthropic" if self._has_api_key("anthropic") else "Anthropic (key missing)",
            }
        elif provider == "gemini":
            llm_status = {
                "status": "configured" if self._has_api_key("gemini") else "degraded",
                "label": "Gemini" if self._has_api_key("gemini") else "Gemini (key missing)",
            }
        else:
            llm_status = {
                "status": "configured" if llm.get("ollama_endpoint") or llm.get("base_url") else "degraded",
                "label": "Ollama",
            }

        sandbox_enabled = bool(
            analysis.get("enable_sandbox", analysis.get("enable_sandboxes", False))
            or cfg.get("agent", {}).get("default_sandbox") not in (None, "", "none")
        )

        sandbox_inventory = self._sandbox_inventory(app)
        dynamic_ready = any(
            item.get("id") in {"docker", "vm", "cloud_api"} and item.get("available")
            for item in sandbox_inventory
        )
        static_ready = any(
            item.get("id") == "local_static" and item.get("available")
            for item in sandbox_inventory
        )
        lookup_ready = self._has_sandbox_lookup_provider()

        if not sandbox_enabled:
            sandbox_status = {"status": "disabled", "label": "Disabled"}
        elif dynamic_ready:
            sandbox_status = {"status": "enabled", "label": "Ready"}
        elif static_ready and lookup_ready:
            sandbox_status = {"status": "degraded", "label": "Static + lookup"}
        elif lookup_ready:
            sandbox_status = {"status": "degraded", "label": "Lookup-only"}
        elif static_ready:
            sandbox_status = {"status": "degraded", "label": "Static-only"}
        else:
            sandbox_status = {"status": "degraded", "label": "Unavailable"}

        return {
            "llm": llm_status,
            "sandbox": sandbox_status,
            "agent": {
                "status": "available" if agent_enabled else "optional",
                "label": "Available" if agent_enabled else "Optional",
            },
            "workflow_engine": {
                "status": "available" if workflow_enabled else "optional",
                "label": "Profiles + workflows ready" if workflow_enabled else "Optional",
            },
            "governance": {
                "status": "available" if governance_enabled else "optional",
                "label": "Approval + decision logs" if governance_enabled else "Optional",
            },
            "daemon": {
                "status": "configured" if daemon_meta.get("enabled") else "optional",
                "label": (
                    f"{daemon_meta.get('schedule_count', 0)} scheduled workflow(s), "
                    f"{daemon_meta.get('queue', {}).get('queued', 0)} queued"
                    if daemon_meta.get("enabled") else "Optional"
                ),
            },
            "mcp": {
                "status": mcp_meta["status"],
                "label": mcp_meta["label"],
            },
        }

    def get_sources(self, app: Any) -> List[Dict[str, Any]]:
        if self.is_demo_mode():
            return self.demo_data().get("sources", [])

        premium_sources = [
            {
                "name": "VirusTotal",
                "category": "premium",
                "status": "configured" if self._has_api_key("virustotal") else "not_configured",
                "detail": "API key configured for live reputation and behavior lookups." if self._has_api_key("virustotal") else "VirusTotal API key not configured.",
            },
            {
                "name": "AbuseIPDB",
                "category": "premium",
                "status": "configured" if self._has_api_key("abuseipdb") else "not_configured",
                "detail": "API key configured for live IP abuse checks." if self._has_api_key("abuseipdb") else "AbuseIPDB API key not configured.",
            },
            {
                "name": "Shodan",
                "category": "premium",
                "status": "configured" if self._has_api_key("shodan") else "not_configured",
                "detail": "API key configured for host intelligence lookups." if self._has_api_key("shodan") else "Shodan API key not configured.",
            },
            {
                "name": "AlienVault OTX",
                "category": "premium",
                "status": "configured" if self._has_api_key("alienvault") else "not_configured",
                "detail": "API key configured for OTX pulse enrichment." if self._has_api_key("alienvault") else "AlienVault OTX API key not configured.",
            },
            {
                "name": "GreyNoise",
                "category": "premium",
                "status": "configured" if self._has_api_key("greynoise") else "not_configured",
                "detail": "API key configured for scanner/noise classification." if self._has_api_key("greynoise") else "GreyNoise API key not configured.",
            },
            {
                "name": "URLScan",
                "category": "premium",
                "status": "manual" if self._has_api_key("urlscan") else "not_configured",
                "detail": "API key is stored, but URLScan is not yet wired into the live IOC enrichment pipeline." if self._has_api_key("urlscan") else "URLScan API key not configured.",
            },
        ]

        osint_sources = [
            {
                "name": name,
                "category": "osint",
                "status": "available",
                "mode": "live",
                "detail": "Built-in free source queried on demand without an API key.",
            }
            for name in [
                "Abuse.ch URLhaus",
                "Abuse.ch MalwareBazaar",
                "Abuse.ch ThreatFox",
                "OpenPhish",
                "Ransomwatch",
            ]
        ]

        sources = [{**item, "mode": "live"} for item in premium_sources] + osint_sources

        splunk_connected = False
        mcp_client = getattr(app.state, "mcp_client", None)
        if mcp_client is not None:
            try:
                splunk_connected = bool(mcp_client.is_connected("splunk"))
            except Exception:
                splunk_connected = False
        if splunk_connected or self._has_configured_mcp_server("splunk"):
            sources.append(
                {
                    "name": "Splunk SIEM",
                    "category": "siem",
                    "status": "available" if splunk_connected else "optional",
                    "mode": "live",
                    "detail": (
                        "Read-only Splunk hunting backend is connected for agent-driven log pivots."
                        if splunk_connected
                        else "Splunk MCP server is configured but not currently connected."
                    ),
                }
            )

        mcp_meta = self._mcp_status(app)
        if getattr(app.state, "mcp_client", None):
            sources.append(
                {
                    "name": "MCP Integrations",
                    "category": "optional",
                    "status": "healthy" if mcp_meta["connected"] else "optional",
                    "mode": "live",
                    "detail": f"{mcp_meta['connected']} MCP server(s) connected." if mcp_meta["connected"] else "MCP client is available but no server is currently connected.",
                }
            )
        return sources

    def source_health_summary(self, app: Any) -> Dict[str, int]:
        summary = {
            "healthy": 0,
            "available": 0,
            "configured": 0,
            "manual": 0,
            "degraded": 0,
            "offline": 0,
            "optional": 0,
            "not_configured": 0,
        }
        for item in self.get_sources(app):
            status = str(item.get("status") or "offline")
            summary[status] = summary.get(status, 0) + 1
        summary["ready"] = (
            summary.get("healthy", 0)
            + summary.get("available", 0)
            + summary.get("configured", 0)
        )
        return summary

    def _normalize_jobs(self, app: Any, jobs: List[Dict[str, Any]], mode: Optional[str]) -> List[Dict[str, Any]]:
        return [normalize_job(job, mode=mode, case_links=self._case_links(app, job.get("id"))) for job in jobs]

    def _case_links(self, app: Any, job_id: Optional[str]) -> List[Dict[str, Any]]:
        if not job_id:
            return []
        case_links: List[Dict[str, Any]] = []
        case_store = getattr(app.state, "case_store", None)
        if case_store:
            for case in case_store.list_cases(limit=200):
                full_case = case_store.get_case(case["id"])
                if full_case and any(link.get("analysis_id") == job_id for link in full_case.get("analyses", [])):
                    case_links.append({"id": full_case["id"], "title": full_case["title"], "href": f"/cases/{full_case['id']}"})
        if self.is_demo_mode():
            for case in self.demo_data().get("cases", []):
                if any(link.get("analysis_id") == job_id for link in case.get("analyses", [])):
                    case_links.append({"id": case["id"], "title": case["title"], "href": f"/cases/{case['id']}"})
        return case_links

    def list_jobs(self, app: Any, limit: int = 50, offset: int = 0, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.is_demo_mode():
            return self._normalize_jobs(app, app.state.analysis_manager.list_jobs(limit=limit, offset=offset, status=status), None)
        live_jobs = self._normalize_jobs(
            app,
            app.state.analysis_manager.list_jobs(limit=limit + offset, offset=0, status=status),
            None,
        )
        demo_jobs = self._normalize_jobs(app, self.demo_data().get("jobs", []), "demo")
        combined = sorted(live_jobs + demo_jobs, key=lambda item: item.get("created_at") or "", reverse=True)
        if status:
            combined = [job for job in combined if job.get("status") == status]
        return combined[offset : offset + limit]

    def get_job(self, app: Any, job_id: str) -> Optional[Dict[str, Any]]:
        live_job = app.state.analysis_manager.get_job(job_id)
        if live_job:
            return normalize_job(live_job, mode=None, case_links=self._case_links(app, job_id))
        if not self.is_demo_mode():
            return None
        for job in self.demo_data().get("jobs", []):
            if job.get("id") == job_id:
                return normalize_job(job, mode="demo", case_links=self._case_links(app, job_id))
        return None

    def get_dashboard_stats(self, app: Any) -> Dict[str, Any]:
        stats = dict(app.state.analysis_manager.get_stats())
        stats.setdefault("daily_counts", [0, 0, 0, 0, 0, 0, 0])
        stats.setdefault("active_agents", 0)
        if getattr(app.state, "agent_store", None):
            try:
                agent_stats = app.state.agent_store.get_agent_stats()
                stats["active_agents"] = int(agent_stats.get("active", stats["active_agents"]))
            except Exception:
                pass
        if not self.is_demo_mode():
            return stats
        demo_stats = self.demo_data().get("stats", {})
        for key, value in demo_stats.items():
            if key not in stats or not stats[key]:
                stats[key] = value
        return stats

    def list_cases(self, app: Any, limit: int = 50, offset: int = 0, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.is_demo_mode():
            return [normalize_case(case, mode="live") for case in app.state.case_store.list_cases(limit=limit, offset=offset, status=status)]
        live_cases = [
            normalize_case(case, mode="live")
            for case in app.state.case_store.list_cases(limit=limit + offset, offset=0, status=status)
        ]
        # Seeded demo cases keep the localhost experience from feeling empty,
        # but once analysts create real cases we should not pollute their list
        # or break API callers that expect only persisted user data.
        if live_cases:
            return live_cases[offset : offset + limit]
        demo_cases = [normalize_case(case, mode="demo") for case in self.demo_data().get("cases", [])]
        combined = sorted(live_cases + demo_cases, key=lambda item: item.get("updated_at") or item.get("created_at") or "", reverse=True)
        if status:
            combined = [case for case in combined if case.get("status") == status]
        return combined[offset : offset + limit]

    def get_case(self, app: Any, case_id: str) -> Optional[Dict[str, Any]]:
        live_case = app.state.case_store.get_case(case_id)
        if live_case:
            return normalize_case(live_case, mode="live")
        if not self.is_demo_mode():
            return None
        for case in self.demo_data().get("cases", []):
            if case.get("id") == case_id:
                return normalize_case(case, mode="demo")
        return None

    def build_template_context(self, app: Any, request: Any, **extra: Any) -> Dict[str, Any]:
        capability_catalog = getattr(app.state, "capability_catalog", None)
        capability_summary = (
            capability_catalog.build_summary(app)
            if capability_catalog is not None else {}
        )
        context = {
            "request": request,
            "product_name": "AISA",
            "product_full_name": "AI Security Assistant",
            "app_mode": self.app_mode(),
            "demo_enabled": self.is_demo_mode(),
            "feature_status": self.feature_status(app),
            "source_health_summary": self.source_health_summary(app),
            "capability_summary": capability_summary,
        }
        context.update(extra)
        return context

    def build_demo_job_result(self, analysis_type: str, params: Dict[str, Any], job_id: str) -> Dict[str, Any]:
        demo_jobs = self.demo_data().get("jobs", [])
        template = next((job for job in demo_jobs if job.get("analysis_type") == analysis_type), {})
        result = deepcopy(template.get("result", {}))
        if analysis_type == "ioc":
            value = params.get("value", result.get("ioc", "suspicious.example"))
            result["ioc"] = value
            result["normalized_value"] = value
            result["input"] = value
            if params.get("ioc_type"):
                result["ioc_type"] = params["ioc_type"]
        elif analysis_type == "file":
            info = result.setdefault("file_info", {})
            info["filename"] = params.get("filename", info.get("filename", "sample.exe"))
            hashes = result.setdefault("hashes", {})
            if params.get("sha256"):
                hashes["sha256"] = params["sha256"]
        elif analysis_type == "email":
            meta = result.setdefault("email_data", {})
            meta.setdefault("subject", "Credential reset verification required")
            result["input"] = params.get("filename", "sample.eml")
        result["mode"] = "demo"
        result["job_id"] = job_id
        return result
