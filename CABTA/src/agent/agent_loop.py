"""
Agent Loop - ReAct reasoning engine for autonomous security investigations.

The loop cycles through THINK -> ACT -> OBSERVE until the LLM decides to emit
a final answer or the step budget is exhausted.  Dangerous actions pause for
analyst approval (WAITING_HUMAN).
"""

import asyncio
import copy
import json
import logging
import re
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp

from .agent_state import AgentPhase, AgentState
from .agent_store import AgentStore
from .case_memory_service import CaseMemoryService
from .case_sync_service import CaseSyncService
from .chat_intent_router import ChatIntentRouter
from .entity_resolver import EntityResolver
from .evidence_graph import EvidenceGraph
from .hypothesis_manager import HypothesisManager
from .investigation_planner import InvestigationPlanner
from .log_query_planner import LogQueryPlanner
from .next_action_planner import NextActionPlanner
from .observation_normalizer import ObservationNormalizer
from .profiles import AgentProfileRegistry
from .prompt_composer import PromptComposer
from .provider_chat_gateway import ProviderChatGateway
from .provider_gateway import ProviderGateway
from .provider_health_service import ProviderHealthService
from .root_cause_engine import RootCauseEngine
from .session_context_service import SessionContextService
from .session_response_builder import SessionResponseBuilder
from .specialist_router import SpecialistRouter
from .specialist_supervisor import SpecialistSupervisor
from .thread_store import ThreadStore
from .thread_sync_service import ThreadSyncService
from .tool_registry import ToolRegistry
from ..utils.api_key_validator import get_valid_key, is_valid_api_key

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------- #
#  System prompt template
# -------------------------------------------------------------------- #

_SYSTEM_PROMPT = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Investigation goal: {goal}

Previous findings:
{findings_block}

{response_style_block}

{chat_decision_block}

Current structured reasoning state:
{reasoning_block}

{profile_block}

{workflow_block}

{playbooks_block}

INSTRUCTIONS:
1. When the analyst needs fresh evidence, you MUST use tools before drawing conclusions. Never answer from memory alone for investigation claims.
2. For IOC investigations: call investigate_ioc first, then use MCP tools like osint-tools.whois_lookup, network-analysis.geoip_lookup, threat-intel-free.threatfox_ioc_lookup for deeper analysis.
3. For file analysis: call analyze_malware first, then use MCP tools like remnux.pe_analyze, flare.strings_analysis, remnux.yara_scan, forensics-tools.file_metadata for deeper analysis.
4. For email analysis: call analyze_email first, then use MCP tools like osint-tools.email_security_check, free-osint.openphish_lookup for deeper analysis.
5. After gathering evidence, call correlate_findings to produce the final verdict.
6. Only write a final text answer (no tool call) AFTER you have gathered real evidence from at least 2 tools.
7. When calling a tool, ONLY pass the tool's own parameters (e.g. {{"ioc": "8.8.8.8"}}). Do NOT include extra keys like "action", "reasoning", or "tool" in the arguments.
8. Use DIFFERENT tools each step. Never call the same tool with the same parameters twice.
9. For quick analyst chat questions, prefer the highest-value pivots first and stop honestly once the evidence is sufficient. Avoid low-value manual or auth-required pivots unless the current evidence is still insufficient.

If previous findings are "(none yet)" and the analyst gave you a concrete IOC, file, email, URL, hash, log artifact, or alert to investigate, you MUST call a tool now. Do NOT skip to a conclusion in that case.

RULES:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use the tools provided. Do NOT invent tool names.
"""

# Fallback prompt for when no native tool calling is available
_SYSTEM_PROMPT_NO_TOOLS = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Available tools:
{tools_block}

{response_style_block}

{chat_decision_block}

{profile_block}

{workflow_block}

{playbooks_block}

Investigation goal: {goal}

Previous findings:
{findings_block}

Current structured reasoning state:
{reasoning_block}

Decide your next action. Respond in JSON (no markdown, no extra text):
{{"action": "use_tool", "tool": "tool_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "run_playbook", "playbook_id": "playbook_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "final_answer", "answer": "investigation summary", "verdict": "MALICIOUS/SUSPICIOUS/CLEAN", "reasoning": "why"}}

IMPORTANT:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Actions marked as requiring approval will pause for analyst review.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use tools that are listed above. Do NOT invent tool names.
- If a playbook matches the investigation goal, prefer running the playbook for structured analysis.
- Always include the "action" key in your JSON response.
"""

_CHAT_DIRECT_ANSWER_PROMPT = """\
You are a Blue Team Security Agent continuing an analyst conversation.

Investigation goal: {goal}

Previous findings:
{findings_block}

{response_style_block}

Current structured reasoning state:
{reasoning_block}

{profile_block}

Answer the analyst directly in natural language using only the evidence that is already available.
Do not output JSON.
Do not request or call more tools in this response.
Do not propose a playbook, workflow step, or next tool unless you are explicitly stating what evidence is still missing.
If the evidence is still insufficient, say that clearly and explain what is missing.
"""

_SUMMARY_PROMPT = """\
You are a Blue Team Security Agent. Summarise the following investigation
in 3-5 sentences suitable for a SOC ticket.  Include the verdict
(MALICIOUS / SUSPICIOUS / CLEAN), key evidence, and recommended next steps.

{response_style_block}

Goal: {goal}

Current structured reasoning state:
{reasoning_block}

Steps taken: {step_count}

Findings:
{findings_json}

Respond in plain text (no JSON).
"""


class AgentLoop:
    """Orchestrates the ReAct loop, delegates to LLM + tools."""

    def __init__(
        self,
        config: Dict[str, Any],
        tool_registry: ToolRegistry,
        agent_store: AgentStore,
        llm_analyzer=None,
        mcp_client=None,
        playbook_engine=None,
        agent_profiles: Optional[AgentProfileRegistry] = None,
        workflow_registry=None,
        governance_store=None,
        case_store=None,
        thread_store=None,
        case_memory_service=None,
    ):
        self.config = config
        self.tools = tool_registry
        self.store = agent_store
        self.llm = llm_analyzer
        self.mcp_client = mcp_client
        self._playbook_engine = playbook_engine
        self.agent_profiles = agent_profiles
        self.workflow_registry = workflow_registry
        self.governance_store = governance_store
        self.case_store = case_store
        if thread_store is not None:
            self.thread_store = thread_store
        else:
            inferred_db_path = None
            if agent_store is not None and getattr(agent_store, "_db_path", None) is not None:
                inferred_db_path = str(Path(agent_store._db_path).with_name("threads.db"))
            self.thread_store = ThreadStore(db_path=inferred_db_path)
        self.case_memory_service = case_memory_service
        if self.case_memory_service is None and (case_store is not None or agent_store is not None):
            self.case_memory_service = CaseMemoryService(case_store=case_store, agent_store=agent_store)
        self.case_sync_service = CaseSyncService(
            case_store=case_store,
            case_memory_service=self.case_memory_service,
            entity_resolver=None,
            evidence_graph=None,
        )
        self.specialist_supervisor = SpecialistSupervisor(agent_store) if agent_store is not None else None
        self.specialist_router = SpecialistRouter(
            workflow_registry=self.workflow_registry,
            agent_profiles=self.agent_profiles,
            notify=self._notify,
            log_decision=self._log_decision,
        )
        self.investigation_planner = InvestigationPlanner()
        self.log_query_planner = LogQueryPlanner()
        self.hypothesis_manager = HypothesisManager()
        self.observation_normalizer = ObservationNormalizer()
        self.entity_resolver = EntityResolver()
        self.evidence_graph = EvidenceGraph()
        self.case_sync_service.entity_resolver = self.entity_resolver
        self.case_sync_service.evidence_graph = self.evidence_graph
        self.root_cause_engine = RootCauseEngine()
        self.chat_intent_router = ChatIntentRouter()
        self.prompt_composer = PromptComposer()
        self.next_action_planner = NextActionPlanner(
            get_tool=self.tools.get_tool,
            has_tool_result=self._has_tool_result,
            guess_first_tool=self._guess_first_tool,
            guess_tool_params=self._guess_tool_params,
            latest_analyst_message=self._latest_analyst_message,
            latest_focus_candidate=self._latest_focus_candidate,
            resolve_authoritative_outcome=self._resolve_authoritative_outcome,
            simple_chat_has_strong_evidence=self._simple_chat_has_strong_evidence,
            looks_like_artifact_submission=self._looks_like_artifact_submission,
            build_reasoning_search_request=self._build_reasoning_search_request,
        )
        self.session_context_service = SessionContextService(
            store=self.store,
            thread_store=self.thread_store,
        )
        self.session_response_builder = SessionResponseBuilder()
        self.thread_sync_service = ThreadSyncService(
            thread_store=self.thread_store,
            store=self.store,
            notify=self._notify,
        )

        agent_cfg = config.get('agent', {})
        self.max_steps = agent_cfg.get('max_steps', 50)
        self.auto_enrich_timeout_seconds = int(agent_cfg.get('auto_enrich_timeout_seconds', 12))
        self.chat_tool_cap = int(agent_cfg.get('chat_tool_cap', 14))
        self.chat_prompt_findings_limit = int(agent_cfg.get('chat_prompt_findings_limit', 5))
        self.chat_auto_enrich_limit = int(agent_cfg.get('chat_auto_enrich_limit', 1))
        self.chat_response_timeout_seconds = float(agent_cfg.get('chat_response_timeout_seconds', 15))
        self.llm_unavailable_cooldown_seconds = float(agent_cfg.get('llm_unavailable_cooldown_seconds', 30))

        # LLM connection settings (mirrors LLMAnalyzer)
        llm_cfg = config.get('llm', {})
        self.provider = llm_cfg.get('provider', 'openrouter')
        self.ollama_endpoint = llm_cfg.get('ollama_endpoint', llm_cfg.get('base_url', 'http://localhost:11434'))
        self.ollama_model = llm_cfg.get('ollama_model', llm_cfg.get('model', 'llama3.1:8b'))
        self.anthropic_key = get_valid_key(config.get('api_keys', {}), 'anthropic') or ''
        self.anthropic_model = llm_cfg.get('anthropic_model', llm_cfg.get('model', 'claude-sonnet-4-20250514'))
        self.groq_key = (
            get_valid_key(config.get('api_keys', {}), 'groq')
            or (llm_cfg.get('api_key', '') if is_valid_api_key(llm_cfg.get('api_key', '')) else '')
        )
        self.groq_endpoint = llm_cfg.get('groq_endpoint', llm_cfg.get('base_url', 'https://api.groq.com/openai/v1')).rstrip('/')
        self.groq_model = llm_cfg.get('groq_model', llm_cfg.get('model', 'openai/gpt-oss-20b'))
        self.gemini_key = (
            get_valid_key(config.get('api_keys', {}), 'gemini')
            or (llm_cfg.get('api_key', '') if is_valid_api_key(llm_cfg.get('api_key', '')) else '')
        )
        self.gemini_endpoint = llm_cfg.get(
            'gemini_endpoint',
            llm_cfg.get('base_url', 'https://generativelanguage.googleapis.com/v1beta/openai'),
        ).rstrip('/')
        self.gemini_model = llm_cfg.get('gemini_model', llm_cfg.get('model', 'gemini-2.5-flash'))
        self.nvidia_key = (
            get_valid_key(config.get('api_keys', {}), 'nvidia')
            or (llm_cfg.get('api_key', '') if is_valid_api_key(llm_cfg.get('api_key', '')) else '')
        )
        self.nvidia_endpoint = llm_cfg.get(
            'nvidia_endpoint',
            llm_cfg.get('base_url', 'https://integrate.api.nvidia.com/v1'),
        ).rstrip('/')
        self.nvidia_model = llm_cfg.get('nvidia_model', llm_cfg.get('model', 'deepseek-ai/deepseek-v3.2'))
        self.openrouter_key = (
            get_valid_key(config.get('api_keys', {}), 'openrouter')
            or (llm_cfg.get('api_key', '') if is_valid_api_key(llm_cfg.get('api_key', '')) else '')
        )
        self.openrouter_endpoint = llm_cfg.get(
            'openrouter_endpoint',
            llm_cfg.get('base_url', 'https://openrouter.ai/api/v1'),
        ).rstrip('/')
        self.openrouter_model = llm_cfg.get(
            'openrouter_model',
            llm_cfg.get('model', 'arcee-ai/trinity-large-preview:free'),
        )
        self.openrouter_force_json_decision_mode = bool(
            llm_cfg.get('openrouter_force_json_decision_mode', False)
        )
        self.auto_failover = bool(llm_cfg.get('auto_failover', False))
        configured_fallbacks = llm_cfg.get('fallback_providers', llm_cfg.get('fallback_order', []))
        if isinstance(configured_fallbacks, str):
            configured_fallbacks = [configured_fallbacks]
        self.fallback_providers = [
            str(provider).strip().lower()
            for provider in (configured_fallbacks or [])
            if str(provider).strip()
        ]
        analysis_cfg = config.get('analysis', {})
        llm_timeout_seconds = float(
            llm_cfg.get(
                'timeout_seconds',
                analysis_cfg.get('llm_timeout_seconds', 25),
            ) or 25
        )
        self.timeout = aiohttp.ClientTimeout(total=max(5.0, llm_timeout_seconds))
        self.provider_health_service = ProviderHealthService(
            primary_provider=self.provider,
            auto_failover=self.auto_failover,
            fallback_providers=self.fallback_providers,
            llm_unavailable_cooldown_seconds=self.llm_unavailable_cooldown_seconds,
            openrouter_force_json_decision_mode=self.openrouter_force_json_decision_mode,
            model_name_resolver=self._active_model_name_from_config,
            provider_configured_resolver=self._provider_is_configured_from_config,
        )
        self.provider_runtime_status = self.provider_health_service.provider_runtime_status
        self.provider_runtime_statuses = self.provider_health_service.provider_runtime_statuses
        self.provider_chat_gateway = ProviderChatGateway()
        self.provider_gateway = ProviderGateway(
            candidate_providers=self._candidate_providers,
            primary_provider=lambda: self._normalize_provider(self.provider),
            logger=logger,
        )

        # Active sessions & pub-sub
        self._active_sessions: Dict[str, AgentState] = {}
        self._approval_events: Dict[str, asyncio.Event] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None  # set on first investigate()

    # ================================================================== #
    #  Public API
    # ================================================================== #

    async def investigate(
        self,
        goal: str,
        case_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
        max_steps: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Start an autonomous investigation. Returns *session_id* immediately."""

        metadata = dict(metadata or {})
        investigation_plan = self.investigation_planner.build_plan(
            goal,
            metadata=metadata,
            workflow_registry=self.workflow_registry,
            existing=metadata.get("investigation_plan"),
        )
        if not metadata.get("workflow_id") and investigation_plan.get("workflow_id"):
            metadata["workflow_id"] = investigation_plan.get("workflow_id")
        specialist_team = self._resolve_specialist_team(metadata)
        lead_profile_id = metadata.get("agent_profile_id")
        active_specialist = specialist_team[0] if specialist_team else (lead_profile_id or "workflow_controller")
        metadata = {
            **metadata,
            "investigation_plan": investigation_plan,
            "lead_agent_profile_id": lead_profile_id or active_specialist,
            "agent_profile_id": active_specialist,
            "specialist_team": specialist_team,
            "active_specialist": active_specialist,
            "specialist_index": 0,
            "specialist_handoffs": [],
            "collaboration_mode": "multi_agent" if len(specialist_team) > 1 else "single_agent",
            "current_step": 0,
        }

        session_id = self.store.create_session(
            goal=goal,
            case_id=case_id,
            playbook_id=playbook_id,
            metadata={
                "execution_mode": "agent",
                "max_steps": max_steps if max_steps is not None else self.max_steps,
                **metadata,
            },
        )

        effective_max_steps = max_steps if max_steps is not None else self.max_steps
        thread_id = self._resolve_thread_id(session_id, case_id, metadata)
        metadata["thread_id"] = thread_id
        self.store.update_session_metadata(
            session_id,
            {
                "thread_id": thread_id,
                "investigation_plan": investigation_plan,
            },
            merge=True,
        )
        state = AgentState(
            session_id=session_id,
            goal=goal,
            max_steps=effective_max_steps,
            agent_profile_id=active_specialist,
            workflow_id=metadata.get("workflow_id"),
            investigation_plan=investigation_plan,
            thread_id=thread_id,
        )
        state.configure_specialist_team(specialist_team, active_specialist=active_specialist)
        self._maybe_record_thread_user_message(state, metadata)
        self._restore_follow_up_context(session_id, state, metadata)
        state.reasoning_state = self.hypothesis_manager.bootstrap(
            goal,
            session_id,
            existing=state.reasoning_state,
            investigation_plan=state.investigation_plan,
        )
        state.reasoning_state["session_id"] = session_id
        latest_focus = self._latest_focus_candidate(state)
        existing_focus = str(state.reasoning_state.get("goal_focus") or "").strip() if isinstance(state.reasoning_state, dict) else ""
        if latest_focus and (not existing_focus or not self._goal_has_observable(existing_focus)):
            state.reasoning_state["goal_focus"] = latest_focus
        state.unresolved_questions = list(state.reasoning_state.get("open_questions", [])) if isinstance(state.reasoning_state, dict) else []
        self._refresh_reasoning_outputs(session_id, state)
        self._active_sessions[session_id] = state
        self._approval_events[session_id] = asyncio.Event()

        # Capture the main event loop so _notify() can safely push
        # messages to subscriber queues from background threads.
        try:
            self._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._main_loop = None

        # Fire-and-forget the loop in a background thread so the caller
        # gets the session_id without blocking.
        def _run():
            asyncio.run(self._run_loop(session_id))

        t = threading.Thread(target=_run, daemon=True, name=f"agent-{session_id}")
        t.start()

        logger.info(f"[AGENT] Investigation started: {session_id} - {goal[:80]}")
        return session_id

    @staticmethod
    def _restore_state_from_snapshot(state: AgentState, snapshot: Dict[str, Any]) -> None:
        SessionContextService.restore_state_from_snapshot(state, snapshot)

    def _restore_follow_up_context(
        self,
        session_id: str,
        state: AgentState,
        metadata: Optional[Dict[str, Any]],
    ) -> bool:
        return self.session_context_service.restore_follow_up_context(
            session_id=session_id,
            state=state,
            metadata=metadata,
        )

    def _record_llm_runtime_status(
        self,
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        available: bool,
        error: Optional[str] = None,
        http_status: Optional[int] = None,
    ) -> None:
        self.provider_health_service.record_runtime_status(
            provider=provider,
            model=model,
            available=available,
            error=error,
            http_status=http_status,
        )
        self.provider_runtime_status = self.provider_health_service.provider_runtime_status
        self.provider_runtime_statuses = self.provider_health_service.provider_runtime_statuses

    def _runtime_status_for_provider(self, provider: Optional[str] = None) -> Dict[str, Any]:
        provider_name = self._normalize_provider(provider)
        status = self.provider_health_service.runtime_status_for_provider(provider_name)
        if status:
            return status

        legacy_status = self.provider_runtime_status if isinstance(self.provider_runtime_status, dict) else {}
        if isinstance(legacy_status, dict) and self._normalize_provider(legacy_status.get("provider")) == provider_name:
            return legacy_status
        return {}

    def _provider_is_currently_unavailable(self, provider: Optional[str] = None) -> bool:
        status = self._runtime_status_for_provider(provider)
        return bool(status) and status.get("available") is False

    def _provider_is_recently_unavailable(self, provider: Optional[str] = None) -> bool:
        status = self._runtime_status_for_provider(provider)
        if not status or status.get("available") is not False:
            return False

        checked_at = str(status.get("checked_at") or "").strip()
        cooldown_seconds = max(0.0, float(self.llm_unavailable_cooldown_seconds or 0.0))
        if cooldown_seconds <= 0:
            return False
        if not checked_at:
            return True

        try:
            checked_at_dt = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        except ValueError:
            return True

        if checked_at_dt.tzinfo is None:
            checked_at_dt = checked_at_dt.replace(tzinfo=timezone.utc)

        age_seconds = (datetime.now(timezone.utc) - checked_at_dt).total_seconds()
        return age_seconds <= cooldown_seconds

    def _normalize_provider(self, provider: Optional[str]) -> str:
        return self.provider_health_service.normalize_provider(provider)

    @staticmethod
    def _is_groq_chat_model_compatible(model_name: str) -> bool:
        normalized = str(model_name or '').strip().lower()
        if not normalized:
            return False
        incompatible_tokens = ('prompt-guard', 'safeguard', 'moderation')
        return not any(token in normalized for token in incompatible_tokens)

    def _active_model_name(self, provider: Optional[str] = None) -> str:
        return self._active_model_name_from_config(self._normalize_provider(provider))

    def _active_model_name_from_config(self, provider_name: str) -> str:
        provider_name = str(provider_name or 'openrouter').strip().lower() or 'openrouter'
        if provider_name == 'anthropic':
            return self.anthropic_model
        if provider_name == 'groq':
            if self._is_groq_chat_model_compatible(self.groq_model):
                return self.groq_model
            return 'openai/gpt-oss-20b'
        if provider_name == 'gemini':
            return self.gemini_model
        if provider_name == 'openrouter':
            return self.openrouter_model
        if provider_name == 'nvidia':
            return self.nvidia_model
        return self.ollama_model

    def _provider_is_configured(self, provider: Optional[str]) -> bool:
        return self._provider_is_configured_from_config(self._normalize_provider(provider))

    def _provider_is_configured_from_config(self, provider_name: str) -> bool:
        provider_name = str(provider_name or 'openrouter').strip().lower() or 'openrouter'
        if provider_name == 'anthropic':
            return bool(self.anthropic_key)
        if provider_name == 'groq':
            return bool(self.groq_key)
        if provider_name == 'gemini':
            return bool(self.gemini_key)
        if provider_name == 'nvidia':
            return bool(self.nvidia_key)
        if provider_name == 'openrouter':
            return bool(self.openrouter_key)
        if provider_name == 'ollama':
            return bool(self.ollama_endpoint)
        return False

    def _provider_prefers_json_decision_mode(self, provider: Optional[str] = None) -> bool:
        """Return True only when a provider should avoid native tool calling."""
        return self.provider_health_service.provider_prefers_json_decision_mode(provider)

    def _candidate_providers(self) -> List[str]:
        current_provider = self._normalize_provider(self.provider)
        if hasattr(self.provider_health_service, "primary_provider"):
            self.provider_health_service.primary_provider = current_provider
        if hasattr(self.provider_health_service, "auto_failover"):
            self.provider_health_service.auto_failover = bool(self.auto_failover)
        if hasattr(self.provider_health_service, "fallback_providers"):
            self.provider_health_service.fallback_providers = [
                self._normalize_provider(provider)
                for provider in list(self.fallback_providers or [])
                if self._normalize_provider(provider)
            ]
        return self.provider_health_service.candidate_providers()

    async def approve_action(self, session_id: str) -> bool:
        """Approve the pending action so the loop can resume."""
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        # Signal the event so _wait_for_approval unblocks
        evt = self._approval_events.get(session_id)
        if evt:
            state.pending_approval["approved"] = True
            evt.set()
        return True

    async def reject_action(self, session_id: str) -> bool:
        """Reject the pending action; the loop will skip it and re-think."""
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        evt = self._approval_events.get(session_id)
        if evt:
            state.pending_approval["approved"] = False
            evt.set()
        return True

    async def cancel_session(self, session_id: str) -> None:
        """Cancel a running investigation."""
        state = self._active_sessions.get(session_id)
        if state and not state.is_terminal():
            state.errors.append("Cancelled by analyst")
            state.phase = AgentPhase.FAILED  # direct set to avoid transition check
            self.store.update_session_status(session_id, 'failed', 'Cancelled by analyst')
            self._notify(session_id, {"type": "cancelled"})
            # Unblock any waiting approval
            evt = self._approval_events.get(session_id)
            if evt:
                evt.set()
        logger.info(f"[AGENT] Session cancelled: {session_id}")

    def get_state(self, session_id: str) -> Optional[Dict]:
        """Return live state dict (or None)."""
        state = self._active_sessions.get(session_id)
        return state.to_dict() if state else None

    async def run_tool(
        self,
        tool_name: str,
        params: Dict,
        execution_context: Optional[Dict[str, Any]] = None,
    ) -> Dict:
        """Execute a single tool by name (used by PlaybookEngine).

        Supports multiple tool name formats:
        - ``mcp:server-name/tool_name`` (playbook YAML format)
        - ``server-name.tool_name`` (internal registry format)
        - ``tool_name`` (local tool)

        Returns the tool result dict.
        """
        # ---- Normalise playbook-style "mcp:server/tool" references ----
        original_name = tool_name
        mcp_server = None
        mcp_tool = None

        if tool_name.startswith("mcp:"):
            # Format: mcp:server-name/tool_name
            rest = tool_name[4:]  # strip "mcp:"
            if "/" in rest:
                mcp_server, mcp_tool = rest.split("/", 1)
                # Convert to registry format: server-name.tool_name
                tool_name = f"{mcp_server}.{mcp_tool}"
            else:
                # mcp:tool_name (no server specified)
                tool_name = rest

        tool_def = self.tools.get_tool(tool_name)

        if tool_def is None and mcp_server and mcp_tool:
            # Tool not registered yet -- try calling MCP directly
            if self.mcp_client is not None:
                try:
                    result = await self.mcp_client.call_tool(
                        mcp_server, mcp_tool, params,
                    )
                    return result if isinstance(result, dict) else {"result": result}
                except Exception as exc:
                    return {"error": f"MCP tool '{original_name}' call failed: {exc}"}
            return {"error": f"MCP client not available for tool: {original_name}"}

        if tool_def is None:
            return {"error": f"Tool not found: {original_name}"}

        if tool_def.source == 'local':
            return await self.tools.execute_local_tool(
                tool_name,
                _execution_context=execution_context or {},
                **params,
            )
        elif self.mcp_client is not None:
            return await self.mcp_client.call_tool(
                tool_def.source, tool_name.split(".", 1)[-1], params,
            )
        else:
            return {"error": f"MCP client not available for tool: {original_name}"}

    def _resolve_specialist_team(self, metadata: Optional[Dict[str, Any]] = None) -> List[str]:
        return self.specialist_router.resolve_specialist_team(metadata)

    def _persist_specialist_metadata(
        self,
        session_id: str,
        state: AgentState,
        terminal_status: Optional[str] = None,
        reason: str = "",
    ) -> None:
        """Persist collaboration metadata for web/API consumers."""
        self.store.update_session_metadata(
            session_id,
            {
                "agent_profile_id": state.agent_profile_id,
                "active_specialist": state.active_specialist,
                "specialist_index": state.specialist_index,
                "specialist_team": list(state.specialist_team),
                "specialist_handoffs": list(state.specialist_handoffs),
                "collaboration_mode": "multi_agent" if len(state.specialist_team) > 1 else "single_agent",
                "current_step": state.step_count,
            },
            merge=True,
        )
        if self.specialist_supervisor is not None:
            self.specialist_supervisor.sync_session(
                session_id,
                state.workflow_id,
                state,
                reason=reason,
                terminal_status=terminal_status,
            )

    def _build_deterministic_decision_output(self, state: AgentState) -> Dict[str, Any]:
        """Return the best deterministic decision available from collected findings."""
        decision: Dict[str, Any] = {
            "score": None,
            "severity": None,
            "verdict": "UNKNOWN",
            "confidence": None,
            "policy_flags": [],
            "source": None,
        }

        for finding in reversed(state.findings):
            if finding.get("type") != "tool_result":
                continue
            result = finding.get("result")
            payload = result.get("result") if isinstance(result, dict) and isinstance(result.get("result"), dict) else result
            if not isinstance(payload, dict):
                continue

            source = str(finding.get("tool") or "tool_result")
            if decision["source"] is None:
                decision["source"] = source
            if decision["score"] is None and isinstance(payload.get("score"), (int, float)):
                decision["score"] = payload.get("score")
                decision["source"] = source
            if decision["severity"] is None and payload.get("severity") is not None:
                decision["severity"] = payload.get("severity")
                decision["source"] = source
            if decision["confidence"] is None and isinstance(payload.get("confidence"), (int, float)):
                decision["confidence"] = payload.get("confidence")
            if payload.get("policy_flags"):
                decision["policy_flags"] = list(payload.get("policy_flags") or [])
            if payload.get("verdict") is not None:
                decision["verdict"] = str(payload.get("verdict")).upper()
                decision["source"] = source
                break

        if decision["severity"] is None:
            authoritative = self._resolve_authoritative_outcome(state)
            if authoritative and authoritative.get("kind") == "severity":
                decision["severity"] = authoritative.get("label", "").replace("SEVERITY:", "").lower() or None
                decision["source"] = authoritative.get("source")
            elif authoritative and authoritative.get("kind") == "verdict" and decision["source"] is None:
                decision["source"] = authoritative.get("source")

        return decision

    def _refresh_reasoning_outputs(
        self,
        session_id: str,
        state: AgentState,
        *,
        tool_name: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        result: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Refresh structured reasoning state and persist it to session metadata."""
        normalized_observations: List[Dict[str, Any]] = []
        latest_quality_summary: Dict[str, Any] = {}
        if tool_name is not None:
            last_finding = state.findings[-1] if state.findings else {}
            finding_index = len(state.findings) - 1 if state.findings else 0
            step_number = int(last_finding.get("step", state.step_count))
            normalization = self.observation_normalizer.normalize(
                session_id=session_id,
                tool_name=tool_name,
                params=params or {},
                result=result or {},
                step_number=step_number,
            )
            normalized_observations = list(normalization.get("observations", []))
            latest_quality_summary = dict(normalization.get("evidence_quality_summary", {}))
            if normalized_observations:
                state.active_observations = [*state.active_observations, *normalized_observations][-60:]
            state.accepted_facts = self._merge_fact_snapshots(
                state.accepted_facts,
                list(normalization.get("accepted_facts_delta", [])),
            )
            state.evidence_quality_summary = self._combine_evidence_quality_summary(
                state.evidence_quality_summary,
                latest_quality_summary,
            )
            evidence_ref = {
                "session_id": session_id,
                "step_number": step_number,
                "finding_index": finding_index,
                "tool_name": tool_name,
                "summary": (
                    str(normalized_observations[0].get("summary") or "").strip()
                    if normalized_observations
                    else f"{tool_name} observation"
                ),
                "created_at": last_finding.get("timestamp") if isinstance(last_finding, dict) else None,
            }
            state.entity_state = self.entity_resolver.ingest_observation(
                state.entity_state,
                session_id=session_id,
                tool_name=tool_name,
                params=params or {},
                result=result or {},
                step_number=step_number,
                evidence_ref=evidence_ref,
                observations=normalized_observations,
            )
            state.evidence_state = self.evidence_graph.ingest_observation(
                state.evidence_state,
                session_id=session_id,
                tool_name=tool_name,
                step_number=step_number,
                evidence_ref=evidence_ref,
                entity_state=state.entity_state,
                observations=normalized_observations,
            )
            state.reasoning_state = self.hypothesis_manager.revise(
                state.reasoning_state,
                goal=state.goal,
                session_id=session_id,
                tool_name=tool_name,
                params=params or {},
                result=result or {},
                finding_index=finding_index,
                step_number=step_number,
                observations=normalized_observations,
                entity_state=state.entity_state,
                evidence_state=state.evidence_state,
                investigation_plan=state.investigation_plan,
            )
        else:
            state.reasoning_state = self.hypothesis_manager.bootstrap(
                state.goal,
                session_id,
                existing=state.reasoning_state,
                investigation_plan=state.investigation_plan,
            )
            state.entity_state = self.entity_resolver.bootstrap(state.entity_state)
            state.evidence_state = self.evidence_graph.bootstrap(state.evidence_state)

        state.unresolved_questions = self._dedupe_text(
            [
                *(state.reasoning_state.get("open_questions", []) if isinstance(state.reasoning_state, dict) else []),
                *(state.reasoning_state.get("missing_evidence", []) if isinstance(state.reasoning_state, dict) else []),
            ]
        )[:10]
        state.deterministic_decision = self._build_deterministic_decision_output(state)
        root_cause_assessment = self.root_cause_engine.assess(
            goal=state.goal,
            reasoning_state=state.reasoning_state,
            deterministic_decision=state.deterministic_decision,
            evidence_state=state.evidence_state,
            active_observations=state.active_observations,
            unresolved_questions=state.unresolved_questions,
        )
        state.agentic_explanation = self.hypothesis_manager.build_agentic_explanation(
            state.reasoning_state,
            goal=state.goal,
            deterministic_decision=state.deterministic_decision,
            entity_state=state.entity_state,
            evidence_state=state.evidence_state,
            root_cause_assessment=root_cause_assessment,
        )
        state.evidence_state = self.evidence_graph.sync_reasoning(
            state.evidence_state,
            session_id=session_id,
            reasoning_state=state.reasoning_state,
            root_cause_assessment=root_cause_assessment,
        )
        self._persist_reasoning_metadata(session_id, state)

    def _normalize_terminal_snapshot_publication(self, state: AgentState) -> None:
        lifecycle = str(getattr(state, "snapshot_lifecycle", "") or "").strip().lower()
        if lifecycle in {"working", "candidate", "accepted", "published"}:
            return
        if state.phase != AgentPhase.COMPLETED:
            return

        root_cause = getattr(state, "root_cause_assessment", {}) or {}
        accepted_facts = getattr(state, "accepted_facts", []) or []
        reasoning_state = getattr(state, "reasoning_state", {}) or {}

        has_root_cause = isinstance(root_cause, dict) and bool(str(root_cause.get("primary_root_cause") or "").strip())
        has_accepted_facts = isinstance(accepted_facts, list) and any(isinstance(item, dict) for item in accepted_facts)
        reasoning_status = str(reasoning_state.get("status") or "").strip().lower() if isinstance(reasoning_state, dict) else ""
        reasoning_ready = reasoning_status in {"supported", "sufficient_evidence", "complete", "completed"}

        if bool(getattr(state, "is_published", False)):
            state.snapshot_lifecycle = "published"
            return

        if has_root_cause or has_accepted_facts or reasoning_ready:
            state.snapshot_lifecycle = "accepted"
            return

        state.snapshot_lifecycle = "candidate"

    def _persist_reasoning_metadata(self, session_id: str, state: AgentState) -> None:
        self._normalize_terminal_snapshot_publication(state)
        snapshot_id = self._sync_thread_snapshot(session_id, state)
        if snapshot_id:
            state.session_snapshot_id = snapshot_id
        self.store.update_session_metadata(
            session_id,
            {
                "thread_id": state.thread_id,
                "session_snapshot_id": state.session_snapshot_id,
                "investigation_plan": state.investigation_plan,
                "normalized_observations": state.active_observations[-24:],
                "reasoning_state": state.reasoning_state,
                "entity_state": state.entity_state,
                "evidence_state": state.evidence_state,
                "deterministic_decision": state.deterministic_decision,
                "deterministic_decision_output": state.deterministic_decision,
                "agentic_explanation": state.agentic_explanation,
                "agentic_explanation_output": state.agentic_explanation,
                "root_cause_assessment": state.agentic_explanation.get("root_cause_assessment", {}),
                "active_observations": state.active_observations[-24:],
                "accepted_facts": state.accepted_facts[-16:],
                "accepted_facts_delta": state.accepted_facts[-12:],
                "unresolved_questions": state.unresolved_questions,
                "evidence_quality_summary": state.evidence_quality_summary,
            },
            merge=True,
        )

    def _sync_case_reasoning_checkpoint(
        self,
        session_id: str,
        state: AgentState,
        *,
        terminal_status: Optional[str] = None,
    ) -> None:
        self.case_sync_service.sync_reasoning_checkpoint(
            case_id=self._session_case_id(session_id),
            session_id=session_id,
            state=state,
            terminal_status=terminal_status,
        )

    def _sync_specialist_progress(self, session_id: str, state: AgentState, reason: str = "") -> None:
        self.specialist_router.sync_specialist_progress(
            session_id=session_id,
            state=state,
            store=self.store,
            persist_specialist_metadata=self._persist_specialist_metadata,
            reason=reason,
        )

    def _specialist_index_from_evidence(self, state: AgentState) -> Optional[int]:
        return self.specialist_router.specialist_index_from_evidence(state)

    # ------------------------------------------------------------------ #
    #  Pub / Sub
    # ------------------------------------------------------------------ #

    def subscribe(self, session_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(session_id, []).append(q)
        return q

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(session_id, [])
        if queue in subs:
            subs.remove(queue)

    def _notify(self, session_id: str, message: Dict) -> None:
        """Push a message to all WebSocket subscribers for *session_id*.

        Thread-safe: if called from a background thread (agent loop),
        schedules the put on the main event loop so asyncio.Queue
        operations happen in the correct loop context.
        """
        subs = self._subscribers.get(session_id, [])
        if not subs:
            return

        main_loop = self._main_loop

        def _put_all():
            for q in subs:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    pass

        # If we have a reference to the main loop AND we're in a different
        # thread, use call_soon_threadsafe to schedule the put.
        if main_loop is not None and main_loop.is_running():
            try:
                main_loop.call_soon_threadsafe(_put_all)
                return
            except RuntimeError:
                pass  # loop closed, fall through

        # Fallback: direct put (works when called from the main loop)
        _put_all()

    # ================================================================== #
    #  Main ReAct Loop
    # ================================================================== #

    async def _run_loop(self, session_id: str) -> None:
        state = self._active_sessions.get(session_id)
        if state is None:
            return

        # Track previously called tools to prevent infinite loops
        _prev_tool_calls: list = []

        try:
            state.transition(AgentPhase.THINKING)
            self._sync_specialist_progress(session_id, state, reason="Workflow session initialized.")

            while not state.is_terminal() and state.step_count < state.max_steps:
                self._consume_pending_thread_command(session_id, state)
                self._sync_specialist_progress(session_id, state)
                # ---- THINK ----
                state.phase = AgentPhase.THINKING
                state.current_tool = None
                self._notify(session_id, {
                    "type": "phase", "phase": "thinking",
                    "step": state.step_count,
                    "max_steps": state.max_steps,
                    "active_specialist": state.active_specialist,
                })

                decision = self._chat_short_circuit_decision(state)
                if decision is None:
                    decision = await self._think(state)

                if decision is None:
                    # Retry once: LLM may have returned an unparseable
                    # response or had a transient connection issue.
                    logger.warning("[AGENT] First LLM call returned None, retrying...")
                    await asyncio.sleep(1)
                    decision = self._chat_short_circuit_decision(state)
                    if decision is None:
                        decision = await self._think(state)

                if decision is None:
                    state.errors.append(self._provider_failure_message())
                    state.transition(AgentPhase.FAILED)
                    break

                if self._consume_pending_thread_command(session_id, state):
                    continue

                # Record the thinking step
                self.store.add_step(
                    session_id, state.step_count, 'thinking',
                    json.dumps(decision, default=str),
                )

                # ---- Check for final answer ----
                if decision.get('action') == 'final_answer':
                    self._log_decision(
                        session_id,
                        state,
                        decision_type='final_answer',
                        summary=decision.get('answer', '')[:500],
                        rationale=decision.get('reasoning', ''),
                        metadata={'verdict': decision.get('verdict', 'UNKNOWN')},
                    )
                    summary = decision.get('answer', '')
                    verdict = decision.get('verdict', 'UNKNOWN')
                    authoritative_outcome = self._resolve_authoritative_outcome(state)
                    self._refresh_reasoning_outputs(session_id, state)
                    deterministic_decision = state.deterministic_decision
                    agentic_explanation = state.agentic_explanation
                    state.add_finding({
                        "type": "final_answer",
                        "answer": summary,
                        "verdict": verdict,
                        "verdict_authority": "deterministic_core" if authoritative_outcome else "llm_advisory",
                        "authoritative_outcome": authoritative_outcome,
                        "deterministic_decision": deterministic_decision,
                        "agentic_explanation": agentic_explanation,
                        "root_cause_assessment": agentic_explanation.get("root_cause_assessment", {}),
                        "entity_state": state.entity_state,
                        "evidence_state": state.evidence_state,
                        "reasoning": decision.get('reasoning', ''),
                    })
                    self._record_thread_assistant_message(state, summary)
                    self.store.add_step(
                        session_id, state.step_count, 'final_answer',
                        json.dumps(decision, default=str),
                    )
                    break

                # ---- Check for run_playbook action ----
                if decision.get('action') == 'run_playbook':
                    self._log_decision(
                        session_id,
                        state,
                        decision_type='run_playbook',
                        summary=f"Run playbook {decision.get('playbook_id', '')}",
                        rationale=decision.get('reasoning', ''),
                        metadata={'params': decision.get('params', {})},
                    )
                    pb_id = decision.get('playbook_id', '')
                    pb_params = decision.get('params', {})
                    reasoning = decision.get('reasoning', '')

                    if hasattr(self, '_playbook_engine') and self._playbook_engine:
                        self.store.add_step(
                            session_id, state.step_count, 'run_playbook',
                            json.dumps({
                                "playbook_id": pb_id,
                                "params": pb_params,
                                "reasoning": reasoning,
                            }, default=str),
                        )
                        self._notify(session_id, {
                            "type": "phase", "phase": "running_playbook",
                            "step": state.step_count, "playbook_id": pb_id,
                        })
                        try:
                            session_case_id = self._session_case_id(session_id)
                            pb_session = await self._playbook_engine.execute(
                                pb_id,
                                pb_params,
                                case_id=session_case_id,
                            )
                            state.add_finding({
                                "type": "playbook_started",
                                "playbook_id": pb_id,
                                "session_id": pb_session,
                                "case_id": session_case_id,
                                "status": "started",
                                "reasoning": reasoning,
                            })
                            self.store.add_step(
                                session_id, state.step_count, 'playbook_result',
                                json.dumps({
                                    "playbook_id": pb_id,
                                    "sub_session_id": pb_session,
                                    "case_id": session_case_id,
                                    "status": "started",
                                }, default=str),
                            )
                        except Exception as exc:
                            state.add_finding({
                                "type": "playbook_error",
                                "playbook_id": pb_id,
                                "error": str(exc),
                            })
                            self.store.add_step(
                                session_id, state.step_count, 'playbook_error',
                                json.dumps({
                                    "playbook_id": pb_id,
                                    "error": str(exc),
                                }, default=str),
                            )
                        state.step_count += 1
                        self._sync_specialist_progress(session_id, state, reason="Playbook phase dispatched to a sub-workflow.")
                        continue
                    else:
                        state.errors.append(f"Playbook engine not available for: {pb_id}")
                        state.step_count += 1
                        self._sync_specialist_progress(session_id, state, reason="Playbook backend unavailable; workflow continued.")
                        continue

                # ---- Validate action field ----
                action = decision.get('action', '')
                if action not in ('use_tool', 'final_answer', 'run_playbook'):
                    # LLM returned a JSON without a valid action - treat as
                    # a thinking step and continue so it can try again.
                    state.errors.append(
                        f"LLM returned invalid action '{action}'. "
                        "Expected: use_tool, final_answer, or run_playbook."
                    )
                    state.step_count += 1
                    self._sync_specialist_progress(session_id, state, reason="Invalid action returned; specialist team advanced.")
                    continue

                # ---- Resolve tool ----
                tool_name = decision.get('tool', '')
                tool_def = self.tools.get_tool(tool_name)

                if tool_def is None:
                    # Unknown tool - record error and let agent re-think
                    state.errors.append(f"Unknown tool: {tool_name}")
                    state.add_finding({
                        "type": "error",
                        "message": f"Tool '{tool_name}' not found in registry.",
                    })
                    state.step_count += 1
                    self._sync_specialist_progress(session_id, state, reason="Unknown tool forced workflow to progress.")
                    continue

                # ---- Approval gate ----
                if tool_def.requires_approval:
                    approval_id = None
                    if self.governance_store is not None:
                        approval_id = self.governance_store.create_approval(
                            session_id=session_id,
                            case_id=self._session_case_id(session_id),
                            workflow_id=state.workflow_id,
                            action_type='tool_execution',
                            tool_name=tool_name,
                            target=decision.get('params', {}),
                            rationale=f"Tool '{tool_name}' requires analyst approval before execution.",
                            confidence=0.75,
                            metadata={
                                'agent_profile_id': state.agent_profile_id,
                                'decision': decision,
                            },
                        )
                    state.request_approval(
                        {**decision, 'approval_id': approval_id},
                        f"Tool '{tool_name}' requires analyst approval before execution.",
                    )
                    state.phase = AgentPhase.WAITING_HUMAN
                    self._notify(session_id, {
                        "type": "approval_required",
                        "tool": tool_name,
                        "params": decision.get('params', {}),
                        "reason": state.pending_approval["reason"],
                    })

                    # Wait until approve/reject/cancel
                    approved = await self._wait_for_approval(session_id, state)
                    if state.is_terminal():
                        break
                    if not approved:
                        # Rejected - skip tool and re-think
                        state.add_finding({
                            "type": "approval_rejected",
                            "tool": tool_name,
                        })
                        state.step_count += 1
                        self._sync_specialist_progress(session_id, state, reason="Approval was rejected; ownership moved to the next specialist.")
                        state.transition(AgentPhase.THINKING)
                        continue
                    # Approved - fall through to ACT
                    state.transition(AgentPhase.ACTING)
                else:
                    state.transition(AgentPhase.ACTING)

                # ---- Duplicate call guard ----
                call_sig = (tool_name, json.dumps(decision.get('params', {}), sort_keys=True, default=str))
                if call_sig in _prev_tool_calls:
                    duplicate_tool = tool_name
                    alternate = self._reasoning_guided_next_action(
                        state,
                        exclude_tools={tool_name},
                    )
                    if alternate is not None:
                        alt_sig = (
                            alternate.get("tool", ""),
                            json.dumps(alternate.get("params", {}), sort_keys=True, default=str),
                        )
                        if alt_sig not in _prev_tool_calls:
                            decision = alternate
                            tool_name = decision.get("tool", "")
                            call_sig = alt_sig
                            tool_def = self.tools.get_tool(tool_name)
                            logger.warning(
                                "[AGENT] Duplicate tool call detected for %s. Pivoting to %s instead.",
                                duplicate_tool,
                                alternate.get("tool", ""),
                            )
                    if call_sig in _prev_tool_calls:
                        logger.warning(
                            "[AGENT] Duplicate tool call detected: %s. "
                            "Forcing final_answer.", duplicate_tool,
                        )
                        # Force conclusion instead of repeating
                        if state.findings:
                            break  # exit loop → generate summary
                        # No findings at all → escalate via the best available pivot
                        decision = self._build_next_action_from_context(
                            state,
                            exclude_tools={tool_name},
                        )
                        decision["reasoning"] = (
                            "Breaking a duplicate loop. " + str(decision.get("reasoning") or "")
                        ).strip()
                        tool_name = decision.get("tool", "")
                        call_sig = (
                            tool_name,
                            json.dumps(decision.get("params", {}), sort_keys=True, default=str),
                        )
                _prev_tool_calls.append(call_sig)

                # ---- ACT ----
                state.current_tool = tool_name
                is_mcp = '.' in tool_name
                self._notify(session_id, {
                    "type": "phase", "phase": "acting",
                    "step": state.step_count, "max_steps": state.max_steps,
                    "tool": tool_name,
                    "tool_source": "mcp" if is_mcp else "local",
                    "tool_server": tool_name.split('.')[0] if is_mcp else None,
                    "params": decision.get('params', {}),
                    "active_specialist": state.active_specialist,
                })

                import time as _time
                _act_start = _time.time()
                result = await self._act(state, decision)
                _act_dur = int((_time.time() - _act_start) * 1000)

                # ---- OBSERVE ----
                state.transition(AgentPhase.OBSERVING)
                state.current_tool = None
                state.add_finding({
                    "type": "tool_result",
                    "tool": tool_name,
                    "params": decision.get('params', {}),
                    "result": result,
                })
                self._refresh_reasoning_outputs(
                    session_id,
                    state,
                    tool_name=tool_name,
                    params=decision.get('params', {}),
                    result=result,
                )
                state.step_count += 1
                self._sync_specialist_progress(session_id, state, reason=f"Completed specialist action via {tool_name}.")

                # Persist findings snapshot
                self.store.update_session_findings(session_id, state.findings)

                # Notify WS with tool result for live display
                self._notify(session_id, {
                    "type": "tool_result",
                    "step": state.step_count - 1,
                    "max_steps": state.max_steps,
                    "tool": tool_name,
                    "tool_source": "mcp" if is_mcp else "local",
                    "tool_server": tool_name.split('.')[0] if is_mcp else None,
                    "duration_ms": _act_dur,
                    "params": decision.get('params', {}),
                    "result": result,
                })

                # ---- AUTO-ENRICH with MCP tools ----
                # After first local tool, automatically run relevant MCP tools
                if (tool_name in ('investigate_ioc', 'analyze_malware', 'analyze_email')
                        and state.step_count <= 3
                        and state.step_count < state.max_steps - 1):
                    mcp_calls = self._get_enrichment_mcp_tools(
                        tool_name, decision.get('params', {}), state.goal,
                    )
                    logger.warning(
                        "[AGENT] Auto-enrich: %d MCP tools queued for %s",
                        len(mcp_calls), tool_name,
                    )
                    for mcp_tool, mcp_params in mcp_calls:
                        if state.step_count >= state.max_steps - 1:
                            break
                        try:
                            logger.warning(
                                "[AGENT] Auto-enrich: calling %s",
                                mcp_tool,
                            )
                            state.current_tool = mcp_tool
                            state.phase = AgentPhase.ACTING
                            mcp_server = mcp_tool.split('.')[0] if '.' in mcp_tool else None
                            self._notify(session_id, {
                                "type": "phase", "phase": "acting",
                                "step": state.step_count, "max_steps": state.max_steps,
                                "tool": mcp_tool,
                                "tool_source": "mcp",
                                "tool_server": mcp_server,
                                "params": mcp_params,
                                "active_specialist": state.active_specialist,
                            })
                            mcp_decision = {
                                "action": "use_tool",
                                "tool": mcp_tool,
                                "params": mcp_params,
                                "reasoning": "Auto-enrichment with MCP tool",
                            }
                            _mcp_start = _time.time()
                            try:
                                mcp_result = await asyncio.wait_for(
                                    self._act(state, mcp_decision),
                                    timeout=self.auto_enrich_timeout_seconds,
                                )
                            except asyncio.TimeoutError:
                                mcp_result = {
                                    "error": (
                                        f"Auto-enrichment timed out after "
                                        f"{self.auto_enrich_timeout_seconds}s"
                                    ),
                                    "timed_out": True,
                                }
                            _mcp_dur = int((_time.time() - _mcp_start) * 1000)
                            state.phase = AgentPhase.OBSERVING
                            state.current_tool = None
                            state.add_finding({
                                "type": "tool_result",
                                "tool": mcp_tool,
                                "params": mcp_params,
                                "result": mcp_result,
                            })
                            self._refresh_reasoning_outputs(
                                session_id,
                                state,
                                tool_name=mcp_tool,
                                params=mcp_params,
                                result=mcp_result,
                            )
                            state.step_count += 1
                            self._sync_specialist_progress(session_id, state, reason=f"Auto-enrichment completed via {mcp_tool}.")
                            self.store.update_session_findings(
                                session_id, state.findings,
                            )
                            # Notify WS with MCP tool result
                            self._notify(session_id, {
                                "type": "tool_result",
                                "step": state.step_count - 1,
                                "max_steps": state.max_steps,
                                "tool": mcp_tool,
                                "tool_source": "mcp",
                                "tool_server": mcp_server,
                                "duration_ms": _mcp_dur,
                                "params": mcp_params,
                                "result": mcp_result,
                            })
                            logger.warning(
                                "[AGENT] Auto-enrich: %s done (%dms)", mcp_tool, _mcp_dur,
                            )
                        except Exception as enrich_exc:
                            logger.warning(
                                "[AGENT] Auto-enrich %s failed: %s",
                                mcp_tool, enrich_exc,
                            )
                            state.step_count += 1
                            self._sync_specialist_progress(session_id, state, reason=f"Auto-enrichment failed for {mcp_tool}; specialist team progressed.")

                self._notify(session_id, {
                    "type": "observation",
                    "step": state.step_count,
                    "tool": tool_name,
                    "result_preview": _truncate(json.dumps(result, default=str), 500),
                })

                # Transition back to THINKING for next iteration
                state.transition(AgentPhase.THINKING)

            # ---- Loop finished ----
            if not state.is_terminal():
                if state.step_count >= state.max_steps:
                    state.errors.append(f"Step limit ({state.max_steps}) reached")
                state.phase = AgentPhase.COMPLETED
            final_status = 'completed' if state.phase == AgentPhase.COMPLETED else 'failed'
            self._refresh_reasoning_outputs(session_id, state)
            self._persist_specialist_metadata(session_id, state, terminal_status=final_status, reason="Workflow session finished.")
            self._sync_case_reasoning_checkpoint(session_id, state, terminal_status=final_status)
            summary = await self._generate_summary(state)
            self.store.update_session_status(session_id, final_status, summary)
            self.store.update_session_findings(session_id, state.findings)
            if summary and not any(
                finding.get("type") == "final_answer"
                for finding in state.findings
                if isinstance(finding, dict)
            ):
                self._record_thread_assistant_message(state, summary)

            self._notify(session_id, {
                "type": "completed",
                "status": final_status,
                "summary": summary,
                "steps": state.step_count,
            })

        except Exception as exc:
            logger.error(f"[AGENT] Loop error for {session_id}: {exc}", exc_info=True)
            state.errors.append(str(exc))
            state.phase = AgentPhase.FAILED
            self.store.update_session_status(session_id, 'failed', str(exc))
            self._notify(session_id, {"type": "failed", "error": str(exc)})

        finally:
            # Clean up
            self._approval_events.pop(session_id, None)

    # ================================================================== #
    #  THINK - ask LLM for next action
    # ================================================================== #

    async def _think(self, state: AgentState) -> Optional[Dict]:
        """Build context and call the LLM to decide the next action."""
        tools_block = self._build_tools_block()
        findings_block = self._build_findings_block(state)
        response_style_block = self._build_response_style_block(state)
        chat_decision_block = self._build_chat_decision_block(state)
        reasoning_block = self._build_reasoning_block(state)
        profile_block = self._build_profile_block(state)
        workflow_block = self._build_workflow_block(state)
        playbooks_block = self._build_playbooks_block()
        all_tools = self.tools.get_tools_for_llm()
        # Filter tools to a manageable set for the LLM
        tools_json = self._filter_tools_for_goal(all_tools, state.goal, state)
        allowed_tool_names = {
            str(tool.get("function", {}).get("name", "")).strip()
            for tool in tools_json
            if str(tool.get("function", {}).get("name", "")).strip()
        }
        request_tools_json = list(tools_json)
        model_only_chat = self._chat_should_force_model_answer_without_tools(state)
        if model_only_chat:
            tools_json = []
            request_tools_json = []
            if self._provider_is_recently_unavailable(self.provider):
                logger.info(
                    "[AGENT] Skipping direct chat retry because %s is still marked unavailable within the cooldown window.",
                    self._provider_display_name(self.provider),
                )
                return self._fallback_decision_without_llm(state)
        has_native_tools = len(request_tools_json) > 0 and not self._provider_prefers_json_decision_mode(self.provider)
        if not has_native_tools:
            request_tools_json = []

        prompt_payload = self.prompt_composer.build_think_payload(
            state=state,
            tools_block=tools_block,
            findings_block=findings_block,
            response_style_block=response_style_block,
            chat_decision_block=chat_decision_block,
            reasoning_block=reasoning_block,
            profile_block=profile_block,
            workflow_block=workflow_block,
            playbooks_block=playbooks_block,
            model_only_chat=model_only_chat,
            has_native_tools=has_native_tools,
        )
        messages = prompt_payload["messages"]
        request_metadata = {
            "prompt_mode": prompt_payload.get("prompt_mode"),
            "provider_context_block": prompt_payload.get("provider_context_block"),
            "prompt_envelope": prompt_payload.get("prompt_envelope"),
            "model_only_chat": prompt_payload.get("model_only_chat"),
            "uses_native_tools": prompt_payload.get("uses_native_tools"),
            "planned_next_step_summary": self.session_response_builder.build_planned_next_step_summary(
                decision=self._chat_short_circuit_decision(state)
            ),
        }

        # Attempt tool-calling API first, fall back to plain chat
        try:
            if model_only_chat:
                raw = await asyncio.wait_for(
                    self._chat_with_tools(
                        messages,
                        tools_json=request_tools_json,
                        request_metadata=request_metadata,
                    ),
                    timeout=max(1.0, self.chat_response_timeout_seconds),
                )
            else:
                raw = await self._chat_with_tools(
                    messages,
                    tools_json=request_tools_json,
                    request_metadata=request_metadata,
                )
        except asyncio.TimeoutError:
            self._record_llm_runtime_status(
                provider=self.provider,
                model=self._active_model_name(self.provider),
                available=False,
                error=(
                    f"{self._provider_display_name(self.provider)} direct chat request timed out "
                    f"after {self.chat_response_timeout_seconds:.0f}s"
                ),
            )
            raw = None
        logger.info(f"[AGENT] LLM raw response type={type(raw).__name__}, "
                     f"preview={str(raw)[:500] if raw else 'None'}")
        if raw is None:
            return self._fallback_decision_without_llm(state)

        # If the LLM used native tool_call, convert to our decision dict
        if isinstance(raw, dict) and 'tool_calls' in raw:
            decision = self._parse_tool_call_response(raw)
            return self._sanitize_llm_tool_decision(
                state,
                decision,
                allowed_tool_names=allowed_tool_names,
            )

        # Otherwise parse the text as JSON
        if isinstance(raw, str):
            parsed = self._extract_json(raw)
            if parsed is not None:
                # Normalise non-standard JSON formats into our decision dict
                parsed = self._normalise_decision(parsed, state)
                return self._sanitize_llm_tool_decision(
                    state,
                    parsed,
                    allowed_tool_names=allowed_tool_names,
                )
            if raw.strip():
                if state.findings or not has_native_tools or model_only_chat:
                    return {
                        "action": "final_answer",
                        "answer": raw.strip(),
                        "verdict": self._extract_verdict(raw),
                        "reasoning": "LLM provided direct text response",
                    }
                logger.warning(
                    "[AGENT] LLM gave text instead of tool call. "
                    "Auto-dispatching tool based on goal."
                )
                decision = self._build_next_action_from_context(state)
                decision["reasoning"] = (
                    "Auto-dispatched after non-tool LLM text. "
                    + str(decision.get("reasoning") or "")
                ).strip()
                return decision
            return None

        # Already a dict (from JSON-mode response)
        if isinstance(raw, dict):
            return self._sanitize_llm_tool_decision(
                state,
                raw,
                allowed_tool_names=allowed_tool_names,
            )

        return None

    def _sanitize_llm_tool_decision(
        self,
        state: AgentState,
        decision: Optional[Dict[str, Any]],
        *,
        allowed_tool_names: set[str],
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(decision, dict):
            return decision
        if decision.get("action") != "use_tool":
            return decision

        tool_name = str(decision.get("tool") or "").strip()
        if not tool_name or not allowed_tool_names or tool_name in allowed_tool_names:
            return decision

        logger.warning(
            "[AGENT] LLM selected hidden tool %s outside the allowed prompt tool set. Replacing it with a reasoning-guided pivot.",
            tool_name,
        )
        replacement = self._build_next_action_from_context(
            state,
            exclude_tools={tool_name},
        )
        replacement["reasoning"] = (
            "Sanitized an out-of-policy LLM tool selection. "
            + str(replacement.get("reasoning") or "")
        ).strip()
        return replacement

    def _fallback_decision_without_llm(self, state: AgentState) -> Dict[str, Any]:
        """Return a safe evidence-first fallback when the LLM gives no decision.

        The agent should continue investigating with real tools when possible
        instead of failing immediately at step 0.
        """
        return self.session_response_builder.build_fallback_decision_without_llm(
            state=state,
            chat_prefers_direct_response=self._chat_prefers_direct_response(state),
            build_direct_chat_fallback_answer=self._build_direct_chat_fallback_answer,
            goal=state.goal,
            build_next_action_from_context=self._build_next_action_from_context,
            has_tool=lambda tool_name: self.tools.get_tool(tool_name) is not None,
            resolve_authoritative_outcome=self._resolve_authoritative_outcome,
            is_chat_session=self._is_chat_session,
            provider_is_currently_unavailable=self._provider_is_currently_unavailable,
            provider_name=self.provider,
            build_chat_model_unavailable_answer=self._build_chat_model_unavailable_answer,
            build_fallback_answer=self._build_fallback_answer,
        )

    @staticmethod
    def _extract_verdict(text: str) -> str:
        """Extract verdict keyword from text."""
        text_upper = text.upper()
        if 'MALICIOUS' in text_upper:
            return 'MALICIOUS'
        if 'SUSPICIOUS' in text_upper:
            return 'SUSPICIOUS'
        if 'CLEAN' in text_upper:
            return 'CLEAN'
        return 'UNKNOWN'

    def _normalise_decision(self, parsed: Dict, state) -> Dict:
        """Normalise various JSON formats the LLM might return into our
        standard decision dict ``{action, tool, params, reasoning}``.

        Handles:
        - Ollama text tool-call: ``{"name": "...", "parameters": {...}}``
        - Ollama text tool-call: ``{"name": "...", "arguments": {...}}``
        - Decision with nested params: ``{"action": "use_tool", "tool": "...",
          "params": {"action": "...", ...}}``
        - Standard format (pass through)
        - ``final_answer`` with no findings → auto-dispatch to tool
        """
        # --- Ollama text tool-call format ---
        # LLM writes JSON like {"name": "investigate_ioc", "parameters": {"ioc": "..."}}
        if 'name' in parsed and 'action' not in parsed:
            tool_name = parsed['name']
            params = parsed.get('parameters', parsed.get('arguments', {}))
            if isinstance(params, str):
                try:
                    params = json.loads(params)
                except json.JSONDecodeError:
                    params = {}
            logger.info(
                f"[AGENT] Normalised Ollama text tool-call: "
                f"tool={tool_name}, params={params}"
            )
            return {
                "action": "use_tool",
                "tool": tool_name,
                "params": params if isinstance(params, dict) else {},
                "reasoning": parsed.get("reasoning", "LLM text tool-call"),
            }

        # --- final_answer with no findings → force tool use ---
        if parsed.get('action') == 'final_answer' and not state.findings:
            if self._chat_prefers_direct_response(state):
                answer = str(parsed.get("answer") or "").strip() or self._build_direct_chat_fallback_answer(state.goal)
                return {
                    "action": "final_answer",
                    "answer": answer,
                    "verdict": parsed.get("verdict", "UNKNOWN"),
                    "reasoning": parsed.get("reasoning", "LLM provided direct analyst-chat answer"),
                }
            logger.warning(
                "[AGENT] LLM tried final_answer with no findings. "
                "Auto-dispatching tool."
            )
            decision = self._build_next_action_from_context(state)
            decision["reasoning"] = (
                "Auto-dispatched because the LLM skipped evidence collection. "
                + str(decision.get("reasoning") or "")
            ).strip()
            return decision

        # --- Bare params dict (no action/name/tool key) → auto-dispatch ---
        # LLM returned just the params like {"ioc": "..."} without wrapping
        if 'action' not in parsed and 'name' not in parsed and 'tool' not in parsed:
            logger.warning(
                "[AGENT] LLM returned bare params without action/name. "
                "Auto-dispatching tool. parsed=%s", parsed,
            )
            guessed_tool = self._guess_first_tool(state.goal)
            guessed_params = self._guess_tool_params(state.goal)
            decision = self._build_next_action_from_context(state)
            if decision.get("action") == "use_tool":
                final_params = {**guessed_params, **decision.get("params", {}), **parsed}
                decision["params"] = final_params
            decision["reasoning"] = (
                "Auto-dispatched after bare LLM params. "
                + str(decision.get("reasoning") or "")
            ).strip()
            return decision

        # --- Standard format: pass through ---
        return parsed

    def _build_next_action_from_context(
        self,
        state: AgentState,
        *,
        exclude_tools: Optional[set] = None,
    ) -> Dict[str, Any]:
        guided = self._reasoning_guided_next_action(state, exclude_tools=exclude_tools)
        if guided is not None:
            return guided
        return {
            "action": "use_tool",
            "tool": self._guess_first_tool(state.goal),
            "params": self._guess_tool_params(state.goal),
            "reasoning": "Heuristic bootstrap: no stronger reasoning-guided pivot was available.",
        }

    def _reasoning_guided_next_action(
        self,
        state: AgentState,
        *,
        exclude_tools: Optional[set] = None,
    ) -> Optional[Dict[str, Any]]:
        return self.next_action_planner.reasoning_guided_next_action(
            state,
            exclude_tools=exclude_tools,
        )

    def _build_reasoning_search_request(self, state: AgentState, questions: List[str]) -> Dict[str, Any]:
        plan = self.log_query_planner.build_plan(
            query=None,
            focus=self._latest_focus_candidate(state),
            analyst_request=self._latest_analyst_message(state),
            lane=str((state.investigation_plan or {}).get("lane") or ""),
            unresolved_questions=questions,
            entity_state=state.entity_state,
            timerange="24h",
            max_results=200,
        )
        if isinstance(state.reasoning_state, dict):
            state.reasoning_state["last_log_query_plan"] = copy.deepcopy(plan)
        return {
            "query": self._build_reasoning_search_query(state, questions, plan=plan),
            "timerange": str(plan.get("timerange") or "24h"),
            "reasoning": str(plan.get("reasoning") or "").strip(),
            "plan": plan,
        }

    def _build_reasoning_search_query(
        self,
        state: AgentState,
        questions: List[str],
        *,
        plan: Optional[Dict[str, Any]] = None,
    ) -> str:
        subject = (
            str((plan or {}).get("focus") or "").strip()
            or self._latest_focus_candidate(state)
            or self._latest_analyst_message(state)
            or state.goal
        )
        lead_question = str(questions[0]).strip() if questions else ""
        if lead_question:
            return f"Investigate {subject}. {lead_question}"
        return f"Investigate follow-on telemetry for {subject}"

    def _filter_tools_for_goal(
        self, all_tools: List[Dict], goal: str, state,
    ) -> List[Dict]:
        """Return a filtered subset of tools relevant to the investigation goal.

        Small LLMs (8B-14B) can't handle 90+ tool definitions effectively.
        We keep all 10 local tools + the most relevant MCP tools, capped
        at ~30 total to stay within the model's effective context.
        """
        max_tools = self.chat_tool_cap if self._is_lightweight_chat_session(state) else 30
        goal_lower = goal.lower()

        # Always include all local tools (10)
        local_tools = [
            t for t in all_tools
            if not t.get('function', {}).get('name', '').count('.')
        ]
        if self._is_lightweight_chat_session(state):
            local_tools = [
                t
                for t in local_tools
                if self._lightweight_chat_allows_local_tool(
                    str(t.get("function", {}).get("name", "")),
                    goal,
                    state,
                )
            ]

        # Categorize MCP tools by relevance to the goal
        mcp_tools = [
            t for t in all_tools
            if t.get('function', {}).get('name', '').count('.')
        ]

        if len(local_tools) + len(mcp_tools) <= max_tools:
            if self._is_lightweight_chat_session(state):
                return local_tools + mcp_tools
            return all_tools  # Small enough, send all

        # Score MCP tools by relevance
        is_ip = any(kw in goal_lower for kw in ('ip', 'address', '185.', '10.', '192.'))
        is_domain = any(kw in goal_lower for kw in ('domain', 'dns', '.com', '.org', '.net'))
        is_file = any(kw in goal_lower for kw in ('file', 'malware', 'exe', 'dll', 'binary', 'sample', 'pe '))
        is_email = any(kw in goal_lower for kw in ('email', 'eml', 'phish'))
        is_url = any(kw in goal_lower for kw in ('url', 'http', 'link'))
        is_hash = any(kw in goal_lower for kw in ('hash', 'sha256', 'md5', 'sha1'))
        is_vuln = any(kw in goal_lower for kw in ('cve', 'vuln', 'exploit'))

        # Define relevant server prefixes per category
        ioc_servers = {
            'threat-intel-free', 'malwoverview', 'free-osint',
            'network-analysis', 'osint-tools',
        }
        file_servers = {
            'remnux', 'flare', 'ghidra', 'forensics-tools',
            'malwoverview',
        }
        email_servers = {
            'osint-tools', 'threat-intel-free', 'free-osint',
        }
        vuln_servers = {'vulnerability-tools'}

        # Build set of wanted server prefixes
        wanted = set()
        if is_ip or is_domain or is_url:
            wanted |= ioc_servers
        if is_file or is_hash:
            wanted |= file_servers
        if is_email:
            wanted |= email_servers
        if is_vuln:
            wanted |= vuln_servers
        # If nothing specific, include the most useful general ones
        if not wanted:
            wanted = ioc_servers | {'forensics-tools'}

        # Filter MCP tools
        relevant_mcp = []
        other_mcp = []
        for t in mcp_tools:
            name = t.get('function', {}).get('name', '')
            server = name.split('.')[0] if '.' in name else ''
            if server in wanted:
                relevant_mcp.append(t)
            else:
                other_mcp.append(t)

        # Fill remaining slots with other MCP tools
        remaining = max_tools - len(local_tools) - len(relevant_mcp)
        selected = local_tools + relevant_mcp
        if remaining > 0:
            selected += other_mcp[:remaining]

        logger.info(
            "[AGENT] Filtered tools: %d local + %d relevant MCP + %d other = %d total "
            "(from %d available)",
            len(local_tools), len(relevant_mcp),
            min(remaining, len(other_mcp)) if remaining > 0 else 0,
            len(selected), len(all_tools),
        )
        return selected

    def _lightweight_chat_allows_local_tool(
        self,
        tool_name: str,
        goal: str,
        state: AgentState,
    ) -> bool:
        """Keep lightweight analyst chat on investigative tools unless case work is explicit."""
        focused_goal = self._focus_goal_text(goal).lower()
        metadata = self._session_metadata(state.session_id)
        has_case_context = bool(
            self._session_case_id(state.session_id)
            or metadata.get("chat_context_restored")
        )
        allowed = {
            "investigate_ioc",
            "analyze_malware",
            "analyze_email",
            "extract_iocs",
            "correlate_findings",
            "search_logs",
            "search_threat_intel",
        }
        if any(
            phrase in focused_goal
            for phrase in (
                "seen before",
                "seen previously",
                "history",
                "historical",
                "recall",
                "known indicator",
                "related indicator",
                "overlap",
            )
        ):
            allowed.add("recall_ioc")
        if has_case_context or any(
            phrase in focused_goal
            for phrase in (
                "case context",
                "case status",
                "case note",
                "open case",
                "create case",
                "update case",
                "link case",
            )
        ):
            allowed.update(
                {
                    "get_case_context",
                    "add_case_note",
                    "create_case",
                    "link_case_analysis",
                    "update_case_status",
                }
            )
        return tool_name in allowed

    def _get_enrichment_mcp_tools(
        self, primary_tool: str, params: dict, goal: str,
    ) -> List[tuple]:
        """Return a list of (mcp_tool_name, params) for auto-enrichment.

        After the primary local tool runs, these MCP tools provide
        additional context without relying on the LLM to pick them.
        """
        import re
        result = []
        simple_chat = self._is_simple_chat_goal(goal, primary_tool)

        if primary_tool == 'investigate_ioc':
            ioc_val = params.get('ioc', '')
            # Check if it's an IP
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_val):
                if simple_chat:
                    result.extend([
                        ('network-analysis.geoip_lookup', {'ip': ioc_val}),
                    ])
                else:
                    result.extend([
                        ('network-analysis.whois_lookup', {'target': ioc_val}),
                        ('network-analysis.geoip_lookup', {'ip': ioc_val}),
                        ('free-osint.shodan_internetdb_lookup', {'ip': ioc_val}),
                    ])
            elif re.match(r'[a-zA-Z0-9]', ioc_val) and '.' in ioc_val:
                # Domain
                if simple_chat:
                    result.extend([
                        ('osint-tools.whois_lookup', {'target': ioc_val}),
                        ('osint-tools.dns_resolve', {'domain': ioc_val}),
                    ])
                else:
                    result.extend([
                        ('osint-tools.whois_lookup', {'target': ioc_val}),
                        ('osint-tools.dns_resolve', {'domain': ioc_val}),
                        ('osint-tools.ssl_certificate_info', {'host': ioc_val}),
                    ])
            elif re.match(r'^[a-fA-F0-9]{32,64}$', ioc_val):
                # Hash
                if simple_chat:
                    result.extend([
                        ('malwoverview.malwoverview_hash_lookup', {'hash_value': ioc_val}),
                    ])
                else:
                    result.extend([
                        ('malwoverview.malwoverview_hash_lookup', {'hash_value': ioc_val}),
                        ('threat-intel-free.malwarebazaar_hash_lookup', {'hash_value': ioc_val}),
                    ])

        elif primary_tool == 'analyze_malware':
            file_path = params.get('file_path', params.get('ioc', ''))
            if file_path:
                if simple_chat:
                    result.extend([
                        ('forensics-tools.file_metadata', {'file_path': file_path}),
                    ])
                else:
                    result.extend([
                        ('remnux.hash_file', {'file_path': file_path}),
                        ('remnux.file_entropy', {'file_path': file_path}),
                        ('flare.strings_analysis', {'file_path': file_path}),
                        ('forensics-tools.file_metadata', {'file_path': file_path}),
                    ])

        elif primary_tool == 'analyze_email':
            file_path = params.get('file_path', params.get('eml_path', ''))
            # Extract IOCs from goal for enrichment
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', goal)
            domain_match = re.search(
                r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})',
                goal,
            )
            if file_path:
                result.append(
                    ('forensics-tools.string_analysis', {'file_path': file_path}),
                )
            if ip_match:
                result.append(
                    ('network-analysis.geoip_lookup', {'ip': ip_match.group(1)}),
                )
            if domain_match:
                result.append(
                    ('osint-tools.email_security_check', {'domain': domain_match.group(1)}),
                )

        # Only include MCP tools that are actually registered
        available = []
        for tool_name, tool_params in result:
            if self.tools.get_tool(tool_name) is not None:
                available.append((tool_name, tool_params))
        max_calls = self.chat_auto_enrich_limit if simple_chat else 4
        return available[:max_calls]

    def _guess_first_tool(self, goal: str) -> str:
        """Pick the most appropriate tool name based on the investigation goal."""
        goal_lower = self._focus_goal_text(goal).lower()

        # File / malware analysis keywords
        if any(kw in goal_lower for kw in ('file', 'malware', 'sample', 'binary',
                                            'exe', 'dll', 'pdf', 'macro', '.eml')):
            if any(kw in goal_lower for kw in ('.eml', 'email', 'phish')):
                return 'analyze_email'
            return 'analyze_malware'

        # Default: treat as IOC investigation
        return 'investigate_ioc'

    def _guess_tool_params(self, goal: str) -> dict:
        """Extract the most likely tool parameter from the goal text."""
        import re

        focused_goal = self._focus_goal_text(goal)
        tool = self._guess_first_tool(focused_goal)

        # Try to extract a file path first (for file/email analysis)
        path_match = re.search(r'([A-Z]:[/\\][\w/\\.\- ]+|/[\w/.\- ]+)', focused_goal)
        if path_match:
            path_val = path_match.group(1)
            if tool in ('analyze_malware', 'analyze_email'):
                return {"file_path": path_val}
            return {"ioc": path_val}

        # Try to extract an IP address
        ip_match = re.search(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', focused_goal,
        )
        if ip_match:
            return {"ioc": ip_match.group(1)}

        # Try to extract a domain
        domain_match = re.search(
            r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b',
            focused_goal,
        )
        if domain_match:
            candidate = domain_match.group(1)
            # Filter out common non-domain words
            if '.' in candidate and candidate.lower() not in ('e.g', 'i.e', 'vs.'):
                return {"ioc": candidate}

        # Try to extract a hash (MD5/SHA1/SHA256)
        hash_match = re.search(r'\b([a-fA-F0-9]{32,64})\b', focused_goal)
        if hash_match:
            return {"ioc": hash_match.group(1)}

        # Try to extract a URL
        url_match = re.search(r'(https?://\S+)', focused_goal)
        if url_match:
            return {"ioc": url_match.group(1)}

        # Fallback: use the full goal text as input
        return {"ioc": focused_goal}

    @staticmethod
    def _focus_goal_text(goal: str) -> str:
        """Prefer the newest analyst instruction when follow-up context is embedded."""
        marker = "New analyst request:"
        if marker not in goal:
            return goal

        _, _, tail = goal.rpartition(marker)
        focused = tail.strip()
        if "\n\nUse prior evidence" in focused:
            focused = focused.split("\n\nUse prior evidence", 1)[0].strip()
        return focused or goal

    def _resolve_thread_id(self, session_id: str, case_id: Optional[str], metadata: Dict[str, Any]) -> Optional[str]:
        return self.session_context_service.resolve_thread_id(
            session_id=session_id,
            case_id=case_id,
            metadata=metadata,
        )

    def _maybe_record_thread_user_message(self, state: AgentState, metadata: Dict[str, Any]) -> None:
        self.session_context_service.maybe_record_thread_user_message(
            state=state,
            metadata=metadata,
        )

    def _record_thread_assistant_message(self, state: AgentState, content: str) -> None:
        self.session_context_service.record_thread_assistant_message(
            state=state,
            content=content,
        )

    def _build_thread_snapshot(self, state: AgentState) -> Dict[str, Any]:
        return self.thread_sync_service.build_thread_snapshot(state)

    def _sync_thread_snapshot(self, session_id: str, state: AgentState) -> Optional[str]:
        return self.thread_sync_service.sync_thread_snapshot(
            session_id=session_id,
            state=state,
        )

    def _consume_pending_thread_command(self, session_id: str, state: AgentState) -> bool:
        return self.thread_sync_service.consume_pending_thread_command(
            session_id=session_id,
            state=state,
            dedupe_text=self._dedupe_text,
        )

    @staticmethod
    def _merge_fact_snapshots(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for item in [*(existing or []), *(incoming or [])]:
            if not isinstance(item, dict):
                continue
            key = str(item.get("observation_id") or item.get("summary") or "").strip().lower()
            if not key:
                continue
            merged[key] = item
        return list(merged.values())[-24:]

    @staticmethod
    def _combine_evidence_quality_summary(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        base = dict(existing or {})
        if not incoming:
            return base
        existing_count = int(base.get("observation_count", 0) or 0)
        incoming_count = int(incoming.get("observation_count", 0) or 0)
        total_count = existing_count + incoming_count
        existing_avg = float(base.get("average_quality", 0.0) or 0.0)
        incoming_avg = float(incoming.get("average_quality", 0.0) or 0.0)
        weighted_avg = 0.0
        if total_count:
            weighted_avg = ((existing_avg * existing_count) + (incoming_avg * incoming_count)) / total_count
        typed = dict(base.get("typed_observations", {}) or {})
        for key, value in (incoming.get("typed_observations", {}) or {}).items():
            typed[str(key)] = int(typed.get(str(key), 0) or 0) + int(value or 0)
        return {
            "observation_count": total_count,
            "average_quality": round(weighted_avg, 3),
            "strong_observation_count": int(base.get("strong_observation_count", 0) or 0) + int(incoming.get("strong_observation_count", 0) or 0),
            "typed_observations": typed,
        }

    @staticmethod
    def _dedupe_text(values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            clean = str(value or "").strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(clean)
        return ordered

    def _latest_analyst_message(self, state: AgentState) -> str:
        metadata = self._session_metadata(state.session_id)
        message = str(metadata.get("chat_user_message") or "").strip()
        return message or self._focus_goal_text(state.goal).strip()

    def _latest_focus_candidate(self, state: AgentState) -> str:
        latest_message = self._latest_analyst_message(state)
        if latest_message and self._goal_has_observable(latest_message):
            params = self._guess_tool_params(latest_message)
            for key in ("ioc", "file_path"):
                candidate = str(params.get(key) or "").strip()
                if candidate:
                    return candidate

        reasoning_state = state.reasoning_state if isinstance(state.reasoning_state, dict) else {}
        candidate = str(reasoning_state.get("goal_focus") or "").strip()
        if candidate and self._goal_has_observable(candidate):
            return candidate

        entity_state = state.entity_state if isinstance(state.entity_state, dict) else {}
        entities = entity_state.get("entities", {}) if isinstance(entity_state.get("entities"), dict) else {}
        for entity in entities.values():
            if not isinstance(entity, dict):
                continue
            if str(entity.get("type") or "").lower() not in {"ip", "domain", "url", "hash", "email", "cve"}:
                continue
            candidate = str(entity.get("value") or "").strip()
            if candidate:
                return candidate

        return ""

    def _session_metadata(self, session_id: str) -> Dict[str, Any]:
        session = self.store.get_session(session_id) if self.store is not None else None
        metadata = session.get("metadata", {}) if isinstance(session, dict) else {}
        return metadata if isinstance(metadata, dict) else {}

    def _is_chat_session(self, state: AgentState) -> bool:
        metadata = self._session_metadata(state.session_id)
        return bool(
            metadata.get("chat_mode")
            or metadata.get("ui_mode") == "chat"
            or str(metadata.get("response_style") or "").strip().lower() == "conversational"
        )

    def _chat_follow_up_requires_fresh_evidence(self, state: AgentState) -> bool:
        metadata = self._session_metadata(state.session_id)
        return bool(metadata.get("chat_follow_up_requires_fresh_evidence"))

    def _chat_follow_up_can_answer_from_context(self, state: AgentState) -> bool:
        return self.session_response_builder.chat_follow_up_can_answer_from_context(
            is_chat_session=self._is_chat_session(state),
            metadata=self._session_metadata(state.session_id),
            requires_fresh_evidence=self._chat_follow_up_requires_fresh_evidence(state),
            has_context_state=bool(state.active_observations or state.reasoning_state or state.accepted_facts),
            latest_message=self._latest_analyst_message(state),
            goal_has_observable=self._goal_has_observable,
        )

    def _is_lightweight_chat_session(self, state: AgentState) -> bool:
        return self._is_chat_session(state) and self._is_simple_chat_goal(
            state.goal,
            self._guess_first_tool(state.goal),
        )

    @staticmethod
    def _goal_has_observable(goal: str) -> bool:
        focused_goal = str(goal or "")
        patterns = (
            r'([A-Z]:[/\\][\w/\\.\- ]+|/[\w/.\- ]+)',
            r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
            r'https?://\S+',
            r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b',
            r'\b[a-fA-F0-9]{32,64}\b',
            r'\b[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,}\b',
            r'\bCVE-\d{4}-\d{4,}\b',
        )
        return any(re.search(pattern, focused_goal) for pattern in patterns)

    @staticmethod
    def _looks_like_artifact_submission(goal: str) -> bool:
        focused_goal = str(goal or "").strip()
        lower_goal = focused_goal.lower()
        if not focused_goal:
            return False
        if len(focused_goal) > 280 or focused_goal.count("\n") >= 3:
            return True
        artifact_markers = (
            "subject:",
            "from:",
            "to:",
            "received:",
            "return-path:",
            "message-id:",
            "alert:",
            "event id",
            "siem",
            "powershell",
            "cmd.exe",
            "user-agent:",
            "pcap",
            "mail header",
            "email header",
            "log snippet",
            "ioc list",
        )
        return any(marker in lower_goal for marker in artifact_markers)

    def _chat_prefers_direct_response(self, state: AgentState) -> bool:
        return self.session_response_builder.chat_prefers_direct_response(
            is_chat_session=self._is_chat_session(state),
            has_findings=bool(state.findings),
            focused_goal=self._focus_goal_text(state.goal),
            goal_has_observable=self._goal_has_observable,
            looks_like_artifact_submission=self._looks_like_artifact_submission,
        )

    def _is_simple_chat_goal(self, goal: str, primary_tool: str) -> bool:
        if primary_tool != "investigate_ioc":
            return False

        focused_goal = self._focus_goal_text(goal).lower()
        if len(focused_goal) > 180:
            return False
        if any(
            term in focused_goal
            for term in (
                "playbook", "threat hunt", "campaign", "actor", "timeline",
                "correlate", "compare", "generate rule",
                "detection", "att&ck", "mitre", "full investigation",
                "deep dive", "comprehensive", "all related", "blast radius",
            )
        ):
            return False

        simple_patterns = (
            "tell me if",
            "is it malicious",
            "is this malicious",
            "is this bad",
            "is it bad",
            "investigate whether",
            "determine whether",
            "quick check",
            "what is this ip",
            "what is this domain",
            "what organization",
            "which organization",
            "what hostname",
            "what host name",
            "who owns this ip",
            "check this ip",
            "check this domain",
            "reputation of",
        )
        has_simple_intent = any(pattern in focused_goal for pattern in simple_patterns) or bool(
            re.search(r"\bis\s+.+\s+malicious\b", focused_goal)
        )

        observable_count = 0
        if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', focused_goal):
            observable_count += 1
        if re.search(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b', focused_goal):
            observable_count += 1
        if re.search(r'https?://\S+', focused_goal):
            observable_count += 1
        if re.search(r'\b[a-fA-F0-9]{32,64}\b', focused_goal):
            observable_count += 1

        return has_simple_intent and observable_count <= 2

    def _build_response_style_block(self, state: AgentState) -> str:
        if not self._is_chat_session(state):
            return ""
        block = (
            "Response style for analyst chat:\n"
            "- When you have enough evidence, answer the analyst's question directly in the first sentence.\n"
            "- Use plain, practical SOC language instead of stiff report boilerplate.\n"
            "- After the direct answer, briefly explain the evidence and why it matters.\n"
            "- End with concrete next steps only if they add value."
        )
        if self._session_metadata(state.session_id).get("chat_context_restored"):
            block += "\n- Treat carried-over findings as live investigation context, not as a stale summary."
        return block

    def _build_chat_decision_block(self, state: AgentState) -> str:
        if not self._is_chat_session(state):
            return ""
        block = (
            "Chat decision policy:\n"
            "- If the analyst is greeting you, asking what you can do, asking how you would investigate, or has not provided a concrete IOC/file/email/log artifact yet, answer directly in conversation and ask for the missing input instead of forcing a tool call.\n"
            "- If the analyst's question can already be answered from the current findings, reason over those findings and answer directly.\n"
            "- Use tools when the analyst asks for fresh investigation, new evidence collection, or when the current findings are insufficient."
        )
        metadata = self._session_metadata(state.session_id)
        if metadata.get("chat_context_restored"):
            if metadata.get("chat_follow_up_requires_fresh_evidence"):
                block += (
                    "\n- This is a follow-up chat turn with carried-over findings. Continue from that context and gather fresh evidence only for the new pivot the analyst requested."
                )
            else:
                block += (
                    "\n- This is a follow-up chat turn with carried-over findings. Prefer answering from that restored evidence before starting new tool calls."
                )
        return block

    def _build_direct_chat_fallback_answer(self, goal: str) -> str:
        return self.session_response_builder.build_direct_chat_fallback_answer(
            llm_unavailable_notice=self._llm_unavailable_notice(),
        )

    def _build_chat_model_unavailable_answer(self, state: AgentState) -> str:
        return self.session_response_builder.build_chat_model_unavailable_answer(
            state=state,
            build_direct_chat_fallback_answer=self._build_direct_chat_fallback_answer,
            goal=state.goal,
            authoritative_outcome=self._resolve_authoritative_outcome(state),
            fallback_evidence_points=lambda current_state, limit: self._fallback_evidence_points(current_state, limit=limit),
            build_fallback_answer=self._build_fallback_answer,
            llm_unavailable_notice=self._llm_unavailable_notice(),
        )

    def _build_tools_block(self) -> str:
        """Format registered tools into a readable list for the prompt."""
        return self.prompt_composer.build_tools_block(self.tools.list_tools())

    def _build_playbooks_block(self) -> str:
        """Format available playbooks into a readable list for the prompt."""
        if not hasattr(self, "_playbook_engine") or self._playbook_engine is None:
            return ""
        try:
            return self.prompt_composer.build_playbooks_block(
                self._playbook_engine.list_playbooks()
            )
        except Exception:
            return ""

    def _build_profile_block(self, state: AgentState) -> str:
        """Return specialist-agent guidance for the current session."""
        if self.agent_profiles is None:
            return ""
        return self.prompt_composer.build_profile_block(
            state,
            profile_prompt_block=self.agent_profiles.get_prompt_block(
                state.agent_profile_id
            ),
        )

    def _build_workflow_block(self, state: AgentState) -> str:
        """Return workflow guardrails for the current session."""
        if self.workflow_registry is None or not state.workflow_id:
            return ""
        workflow = self.workflow_registry.get_workflow(state.workflow_id)
        if not workflow:
            return ""
        latest_handoff = (
            state.specialist_handoffs[-1] if state.specialist_handoffs else None
        )
        return self.prompt_composer.build_workflow_block(
            state,
            workflow=workflow,
            latest_handoff=latest_handoff,
        )

    @staticmethod
    def _section_excerpt(section_text: str, limit: int = 3) -> str:
        parts: List[str] = []
        for raw_line in section_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("- "):
                parts.append(line[2:].strip())
            elif re.match(r"^\d+\.\s+", line):
                parts.append(re.sub(r"^\d+\.\s+", "", line))
            elif not parts:
                parts.append(line)
            if len(parts) >= limit:
                break
        return " | ".join(parts[:limit])

    def _build_findings_block(self, state: AgentState) -> str:
        """Summarise findings so far (capped to keep context manageable)."""
        return self.prompt_composer.build_findings_block(
            state,
            is_chat_session=self._is_chat_session(state),
            chat_prompt_findings_limit=self.chat_prompt_findings_limit,
            describe_fallback_evidence=self._describe_fallback_evidence,
        )

    def _build_reasoning_block(self, state: AgentState) -> str:
        """Return a compact structured reasoning snapshot for the prompt."""
        return self.prompt_composer.build_reasoning_block(
            state,
            is_chat_session=self._is_chat_session(state),
        )

    @staticmethod
    def _has_tool_result(state: AgentState, tool_name: str) -> bool:
        return any(
            finding.get("type") == "tool_result" and finding.get("tool") == tool_name
            for finding in state.findings
        )

    @staticmethod
    def _simple_chat_has_strong_evidence(state: AgentState) -> bool:
        tool_results = [
            finding
            for finding in state.findings
            if finding.get("type") == "tool_result"
        ]
        if len(tool_results) < 2:
            return False

        for finding in tool_results:
            result = finding.get("result")
            payload = result.get("result") if isinstance(result, dict) and isinstance(result.get("result"), dict) else result
            if not isinstance(payload, dict):
                continue
            verdict = str(payload.get("verdict") or "").upper()
            severity = str(payload.get("severity") or "").upper()
            threat_score = payload.get("threat_score", payload.get("score"))
            if verdict in {"MALICIOUS", "SUSPICIOUS"}:
                return True
            if verdict in {"CLEAN", "BENIGN"}:
                return True
            if severity in {"HIGH", "CRITICAL"}:
                return True
            if severity in {"LOW", "INFO"}:
                return True
            if isinstance(threat_score, (int, float)) and threat_score >= 80:
                return True
            if isinstance(threat_score, (int, float)) and threat_score <= 20:
                return True
        return False

    def _chat_short_circuit_decision(self, state: AgentState) -> Optional[Dict[str, Any]]:
        """Skip extra LLM turns when a simple analyst chat already has enough evidence."""
        if not state.findings:
            bootstrap = self._build_initial_chat_tool_decision(state)
            if bootstrap is not None:
                return bootstrap

        if not self._is_lightweight_chat_session(state):
            return None
        if not state.findings:
            return None

        authoritative_outcome = self._resolve_authoritative_outcome(state)
        if authoritative_outcome is None:
            return None

        reasoning_status = (
            str(state.reasoning_state.get("status") or "")
            if isinstance(state.reasoning_state, dict)
            else ""
        )

        if not self._has_tool_result(state, "correlate_findings"):
            if (
                reasoning_status == "sufficient_evidence"
                or self._simple_chat_has_strong_evidence(state)
            ) and self.tools.get_tool("correlate_findings") is not None:
                return {
                    "action": "use_tool",
                    "tool": "correlate_findings",
                    "params": {"findings": state.findings[-8:]},
                    "reasoning": "Short-circuit: enough evidence is already available, so correlate before answering the analyst.",
                }
            return None

        root_cause = (
            state.agentic_explanation.get("root_cause_assessment", {})
            if isinstance(state.agentic_explanation, dict)
            else {}
        )
        if (
            reasoning_status == "sufficient_evidence"
            or (
                isinstance(root_cause, dict)
                and root_cause.get("status") == "supported"
                and root_cause.get("supporting_evidence_refs")
            )
            or self._simple_chat_has_strong_evidence(state)
        ):
            return None
        return None

    def _chat_should_force_model_answer_without_tools(self, state: AgentState) -> bool:
        """Use the model for the wording when evidence is already sufficient."""
        if not self._is_chat_session(state):
            return False
        if self._chat_prefers_direct_response(state):
            return True
        if self._chat_follow_up_can_answer_from_context(state):
            return True
        if not self._is_lightweight_chat_session(state):
            return False
        if not state.findings:
            return False

        authoritative_outcome = self._resolve_authoritative_outcome(state)
        if authoritative_outcome is None:
            return False
        if not self._has_tool_result(state, "correlate_findings"):
            return False

        reasoning_status = (
            str(state.reasoning_state.get("status") or "")
            if isinstance(state.reasoning_state, dict)
            else ""
        )
        root_cause = (
            state.agentic_explanation.get("root_cause_assessment", {})
            if isinstance(state.agentic_explanation, dict)
            else {}
        )
        return bool(
            reasoning_status == "sufficient_evidence"
            or (
                isinstance(root_cause, dict)
                and root_cause.get("status") == "supported"
                and root_cause.get("supporting_evidence_refs")
            )
            or self._simple_chat_has_strong_evidence(state)
        )

    def _session_case_id(self, session_id: str) -> Optional[str]:
        session = self.store.get_session(session_id)
        if not session:
            return None
        return session.get('case_id')

    def _log_decision(
        self,
        session_id: str,
        state: AgentState,
        *,
        decision_type: str,
        summary: str,
        rationale: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if self.governance_store is None or not summary:
            return
        try:
            self.governance_store.log_ai_decision(
                session_id=session_id,
                case_id=self._session_case_id(session_id),
                workflow_id=state.workflow_id,
                profile_id=state.agent_profile_id,
                decision_type=decision_type,
                summary=summary,
                rationale=rationale,
                metadata=metadata or {},
            )
        except Exception:
            logger.debug("[AGENT] Failed to log AI decision", exc_info=True)

    # ================================================================== #
    #  ACT - execute a tool
    # ================================================================== #

    async def _act(self, state: AgentState, decision: Dict) -> Dict:
        """Execute the tool specified in *decision*."""
        tool_name = decision.get('tool', '')
        params = decision.get('params', {})
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                params = {}

        logger.info(f"[AGENT] _act: tool={tool_name}, params={params}")

        start = time.time()
        try:
            tool_def = self.tools.get_tool(tool_name)
            if tool_def is None:
                result = {"error": f"Tool not found: {tool_name}"}
            elif tool_def.source == 'local':
                result = await self.tools.execute_local_tool(
                    tool_name,
                    _execution_context={
                        "session_id": state.session_id,
                        "case_id": self._session_case_id(state.session_id),
                        "workflow_id": state.workflow_id,
                        "agent_profile_id": state.agent_profile_id,
                        "goal": state.goal,
                        "thread_id": state.thread_id,
                        "chat_intent": self._session_metadata(state.session_id).get("chat_intent"),
                        "goal_focus": self._latest_focus_candidate(state),
                        "unresolved_questions": list(state.unresolved_questions),
                        "log_query_plan": (
                            copy.deepcopy(state.reasoning_state.get("last_log_query_plan", {}))
                            if isinstance(state.reasoning_state, dict)
                            else {}
                        ),
                    },
                    **params,
                )
            elif self.mcp_client is not None:
                # MCP remote tool call
                result = await self.mcp_client.call_tool(
                    tool_def.source, tool_name.split(".", 1)[-1], params,
                )
                if not isinstance(result, dict):
                    result = {"result": result}
            else:
                result = {"error": f"MCP client not available for tool: {tool_name}"}
        except Exception as exc:
            logger.error(f"[AGENT] Tool {tool_name} failed: {exc}", exc_info=True)
            result = {"error": str(exc)}

        duration_ms = int((time.time() - start) * 1000)

        # Persist step
        self.store.add_step(
            state.session_id,
            state.step_count,
            'tool_call',
            json.dumps(decision, default=str),
            tool_name,
            json.dumps(params, default=str),
            json.dumps(result, default=str),
            duration_ms,
        )

        return result

    # ================================================================== #
    #  Approval wait
    # ================================================================== #

    async def _wait_for_approval(
        self, session_id: str, state: AgentState,
    ) -> bool:
        """Block until the analyst approves/rejects or the session is cancelled.

        Returns True if approved, False if rejected or cancelled.
        """
        evt = self._approval_events.get(session_id)
        if evt is None:
            return False

        evt.clear()
        # Wait up to 30 minutes for human response
        try:
            await asyncio.wait_for(evt.wait(), timeout=1800)
        except asyncio.TimeoutError:
            state.errors.append("Approval timed out (30 min)")
            state.phase = AgentPhase.FAILED
            return False

        approval = state.clear_approval()
        if approval is None:
            return False
        return approval.get("approved", False)

    # ================================================================== #
    #  Summary generation
    # ================================================================== #

    @staticmethod
    def _resolve_authoritative_outcome(state: AgentState) -> Optional[Dict[str, str]]:
        """Return the best evidence-backed outcome seen in tool results."""
        for finding in reversed(state.findings):
            if finding.get("type") != "tool_result":
                continue
            result = finding.get("result")
            if not isinstance(result, dict):
                continue

            verdict = result.get("verdict")
            if verdict:
                return {
                    "kind": "verdict",
                    "label": str(verdict).upper(),
                    "source": str(finding.get("tool") or "tool_result"),
                }

        for finding in reversed(state.findings):
            if finding.get("type") != "tool_result":
                continue
            result = finding.get("result")
            if not isinstance(result, dict):
                continue

            severity = result.get("severity")
            if severity:
                return {
                    "kind": "severity",
                    "label": f"SEVERITY:{str(severity).upper()}",
                    "source": str(finding.get("tool") or "tool_result"),
                }

        return None

    def _build_evidence_backed_answer(
        self,
        state: AgentState,
        authoritative_outcome: Optional[Dict[str, str]],
        *,
        include_runtime_notice: bool,
    ) -> str:
        return self.session_response_builder.build_evidence_backed_answer(
            state=state,
            authoritative_outcome=authoritative_outcome,
            include_runtime_notice=include_runtime_notice,
            llm_unavailable_notice=self._llm_unavailable_notice,
            build_chat_specific_fallback=self._build_chat_specific_fallback,
            fallback_evidence_points=self._fallback_evidence_points,
        )

    def _build_fallback_answer(
        self, state: AgentState, authoritative_outcome: Optional[Dict[str, str]],
    ) -> str:
        """Build a deterministic evidence-backed answer when LLM calls fail."""
        return self.session_response_builder.build_fallback_answer(
            state=state,
            authoritative_outcome=authoritative_outcome,
            build_evidence_backed_answer=self._build_evidence_backed_answer,
        )

    def _build_chat_specific_fallback(self, state: AgentState) -> str:
        """Answer simple analyst lookup questions directly from collected evidence."""
        if not self._is_chat_session(state):
            return ""

        focused_goal = self._focus_goal_text(state.goal).lower()
        wants_org = any(
            phrase in focused_goal
            for phrase in ("what organization", "which organization", "who owns this ip")
        )
        wants_host = any(
            phrase in focused_goal
            for phrase in ("what hostname", "what host name", "hostname", "host name")
        )
        if not wants_org and not wants_host:
            return ""

        organization = ""
        hostname = ""
        for finding in reversed(state.findings):
            if finding.get("type") != "tool_result":
                continue
            result = finding.get("result")
            payload = result.get("result") if isinstance(result, dict) and isinstance(result.get("result"), dict) else result
            if not isinstance(payload, dict):
                continue
            if not organization:
                organization = str(
                    payload.get("organization")
                    or payload.get("org_name")
                    or payload.get("registrant_org")
                    or ""
                ).strip()
                parsed_fields = payload.get("parsed_fields", {}) if isinstance(payload.get("parsed_fields"), dict) else {}
                if not organization:
                    registrant_org = parsed_fields.get("registrant_org")
                    if isinstance(registrant_org, list) and registrant_org:
                        organization = str(registrant_org[0]).strip()
                    elif registrant_org:
                        organization = str(registrant_org).strip()
            if not hostname:
                hostnames = payload.get("hostnames")
                if isinstance(hostnames, list) and hostnames:
                    hostname = str(hostnames[0]).strip()
                elif payload.get("reverse_dns"):
                    hostname = str(payload.get("reverse_dns")).strip()
                elif payload.get("hostname"):
                    hostname = str(payload.get("hostname")).strip()
            if organization and hostname:
                break

        if not organization and not hostname:
            return ""

        subject = ""
        if isinstance(state.reasoning_state, dict):
            subject = str(state.reasoning_state.get("goal_focus") or "").strip()
        subject = subject or "the investigation target"

        details: List[str] = []
        if wants_org and organization:
            details.append(f"organization {organization}")
        if wants_host and hostname:
            details.append(f"hostname {hostname}")
        if not details:
            return ""
        if len(details) == 1:
            return f"For {subject}, the strongest current mapping is {details[0]}."
        return f"For {subject}, the strongest current mapping is {details[0]} and {details[1]}."

    def _llm_unavailable_notice(self) -> str:
        status = self.provider_runtime_status if isinstance(self.provider_runtime_status, dict) else {}
        return self.session_response_builder.llm_unavailable_notice(
            status=status,
            provider_name=self.provider,
            active_model_name=self._active_model_name,
            provider_display_name=self._provider_display_name,
            provider_runtime_error_excerpt=self._provider_runtime_error_excerpt,
        )

    def _provider_display_name(self, provider: Optional[str] = None) -> str:
        return self.session_response_builder.provider_display_name(
            self._normalize_provider(provider),
        )

    def _provider_runtime_error_excerpt(self) -> str:
        status = self.provider_runtime_status if isinstance(self.provider_runtime_status, dict) else {}
        return self.session_response_builder.provider_runtime_error_excerpt(
            status=status,
            provider_display_name=self._provider_display_name,
        )

    @classmethod
    def _fallback_evidence_points(cls, state: AgentState, limit: int = 3) -> List[str]:
        evidence: List[str] = []
        for finding in state.findings:
            if finding.get("type") != "tool_result":
                continue
            tool_name = str(finding.get("tool") or "tool_result")
            point = cls._describe_fallback_evidence(tool_name, finding.get("result"))
            if point and point not in evidence:
                evidence.append(point)
            if len(evidence) >= limit:
                break
        return evidence[:limit]

    @staticmethod
    def _describe_fallback_evidence(tool_name: str, result: Any) -> str:
        if not isinstance(result, dict):
            return ""

        payload = result.get("result") if isinstance(result.get("result"), dict) else result
        if not isinstance(payload, dict):
            return ""

        error = payload.get("error")
        if error:
            return f"{tool_name} reported error={str(error)[:120]}."
        if payload.get("timed_out"):
            return f"{tool_name} timed out while gathering enrichment."

        if tool_name == "investigate_ioc":
            ioc = str(payload.get("ioc") or "IOC")
            verdict = str(payload.get("verdict") or "UNKNOWN").upper()
            threat_score = payload.get("threat_score")
            domain_enrichment = payload.get("domain_enrichment", {})
            domain_age = domain_enrichment.get("domain_age", {}) if isinstance(domain_enrichment, dict) else {}
            if isinstance(domain_age, dict) and domain_age.get("is_newly_registered"):
                age_days = domain_age.get("age_days")
                return (
                    f"{ioc} classified as {verdict} with threat_score={threat_score}; "
                    f"domain age is {age_days} days."
                )
            return f"{ioc} classified as {verdict} with threat_score={threat_score}."

        if tool_name.endswith("whois_lookup"):
            target = str(payload.get("target") or "domain")
            creation_date = str(payload.get("creation_date") or "").strip()
            registrar = payload.get("registrar")
            registrar_name = ""
            if isinstance(registrar, list) and registrar:
                registrar_name = str(registrar[0]).strip()
            elif registrar:
                registrar_name = str(registrar).strip()
            details = ", ".join(
                part
                for part in [
                    f"created={creation_date}" if creation_date else "",
                    f"registrar={registrar_name}" if registrar_name else "",
                ]
                if part
            )
            if details:
                return f"WHOIS for {target}: {details}."
            return f"WHOIS data collected for {target}."

        if tool_name.endswith("dns_resolve"):
            domain = str(payload.get("domain") or "domain")
            records = payload.get("records", {}) if isinstance(payload.get("records"), dict) else {}
            a_records = records.get("A") if isinstance(records.get("A"), list) else []
            if a_records:
                return f"DNS for {domain} resolved to {', '.join(str(ip) for ip in a_records[:3])}."
            return f"DNS data collected for {domain}."

        if tool_name.endswith("ssl_certificate_info"):
            host = str(payload.get("host") or "host")
            issuer = payload.get("issuer", {}) if isinstance(payload.get("issuer"), dict) else {}
            issuer_cn = str(issuer.get("commonName") or "").strip()
            not_after = str(payload.get("not_after") or "").strip()
            details = ", ".join(
                part
                for part in [
                    f"issuer={issuer_cn}" if issuer_cn else "",
                    f"expires={not_after}" if not_after else "",
                ]
                if part
            )
            if details:
                return f"TLS certificate for {host}: {details}."
            return f"TLS certificate metadata collected for {host}."

        if tool_name == "correlate_findings":
            severity = str(payload.get("severity") or "").upper()
            stats = payload.get("statistics", {}) if isinstance(payload.get("statistics"), dict) else {}
            unique_iocs = stats.get("unique_iocs")
            if severity:
                return f"Correlation rated the case severity={severity} across {unique_iocs or 0} unique IOCs."
            return "Correlation completed across collected findings."

        verdict = payload.get("verdict")
        if verdict:
            return f"{tool_name} reported verdict={str(verdict).upper()}."

        severity = payload.get("severity")
        if severity:
            return f"{tool_name} reported severity={str(severity).upper()}."

        return ""

    async def _generate_summary(self, state: AgentState) -> str:
        """Ask the LLM to produce a concise investigation summary."""
        authoritative_outcome = self._resolve_authoritative_outcome(state)

        findings_json = json.dumps(state.findings[-15:], default=str, indent=1)
        prompt = self.prompt_composer.build_summary_prompt(
            goal=state.goal,
            response_style_block=self._build_response_style_block(state),
            reasoning_block=self._build_reasoning_block(state),
            step_count=state.step_count,
            findings_json=findings_json,
        )

        try:
            return await self.session_response_builder.generate_summary(
                state=state,
                authoritative_outcome=authoritative_outcome,
                prompt=prompt,
                call_llm_text=self._call_llm_text,
                is_chat_session=self._is_chat_session,
                provider_is_currently_unavailable=self._provider_is_currently_unavailable,
                provider_name=self.provider,
                build_chat_model_unavailable_answer=self._build_chat_model_unavailable_answer,
                build_fallback_answer=self._build_fallback_answer,
            )
        except Exception as exc:
            logger.warning(f"[AGENT] Summary generation failed: {exc}")
            if self._is_chat_session(state) and self._provider_is_currently_unavailable(self.provider):
                return self._build_chat_model_unavailable_answer(state)
            return self._build_fallback_answer(state, authoritative_outcome)

    # ================================================================== #
    #  LLM communication
    # ================================================================== #

    async def _chat_with_tools(
        self,
        messages: List[Dict],
        tools_json: Optional[List[Dict]] = None,
        request_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        """Call the LLM with a messages list and available tools.

        Supports both Ollama /api/chat and Anthropic /v1/messages.
        Returns raw response text/dict or None on failure.
        """
        tools_payload = tools_json if tools_json is not None else self.tools.get_tools_for_llm()
        return await self.provider_gateway.chat_with_failover(
            invoke_provider_chat=self._chat_with_tools_via_provider,
            messages=messages,
            tools_payload=tools_payload,
            request_metadata=request_metadata,
        )

    async def _call_llm_text(self, prompt: str) -> Optional[str]:
        """Simple single-prompt call returning plain text (for summaries)."""
        return await self.provider_gateway.text_with_failover(
            invoke_provider_text=self._call_llm_text_via_provider,
            prompt=prompt,
        )

    async def _chat_with_tools_via_provider(
        self,
        provider_name: str,
        messages: List[Dict],
        tools_json: List[Dict],
        request_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        metadata = dict(request_metadata or {})
        request = self.provider_chat_gateway.build_chat_request(
            provider_name=provider_name,
            messages=messages,
            tools_json=tools_json,
            model_only_chat=bool(metadata.get("model_only_chat")) or not bool(tools_json),
            prompt_envelope=metadata.get("prompt_envelope"),
        )
        return await self.provider_gateway.dispatch_chat_provider(
            provider_name=request.get("provider", provider_name),
            request=request,
            extract_chat_messages=self.provider_chat_gateway.extract_chat_messages,
            extract_chat_tools=self.provider_chat_gateway.extract_chat_tools,
            invoke_ollama=self._ollama_chat,
            invoke_anthropic=self._anthropic_chat,
            invoke_groq=self._groq_chat,
            invoke_gemini=self._gemini_chat,
            invoke_nvidia=self._nvidia_chat,
            invoke_openrouter=self._openrouter_chat,
            logger=logger,
            normalize_provider=self._normalize_provider,
        )

    def _build_direct_chat_opening_answer(self, state: AgentState) -> str:
        """Return an immediate conversational answer for chat turns without artifacts."""
        return self.session_response_builder.build_direct_chat_opening_answer(
            prefers_direct_response=self._chat_prefers_direct_response(state),
            latest_message=self._latest_analyst_message(state),
        )

    def _build_initial_chat_tool_decision(self, state: AgentState) -> Optional[Dict[str, Any]]:
        """Start artifact-based chat with the primary investigation tool immediately."""
        return self.session_response_builder.build_initial_chat_tool_decision(
            is_chat_session=self._is_chat_session(state),
            has_findings=bool(state.findings),
            prefers_direct_response=self._chat_prefers_direct_response(state),
            latest_message=self._latest_analyst_message(state),
            goal_has_observable=self._goal_has_observable,
            looks_like_artifact_submission=self._looks_like_artifact_submission,
            build_next_action_from_context=self._build_next_action_from_context,
            state=state,
        )

    async def _call_llm_text_via_provider(self, provider_name: str, prompt: str) -> Optional[str]:
        request = self.provider_chat_gateway.build_text_request(
            provider_name=provider_name,
            prompt=prompt,
        )
        return await self.provider_gateway.dispatch_text_provider(
            provider_name=request.get("provider", provider_name),
            request=request,
            extract_text_prompt=self.provider_chat_gateway.extract_text_prompt,
            invoke_ollama=self._ollama_generate,
            invoke_anthropic=self._anthropic_generate,
            invoke_groq=self._groq_generate,
            invoke_gemini=self._gemini_generate,
            invoke_nvidia=self._nvidia_generate,
            invoke_openrouter=self._openrouter_generate,
            logger=logger,
            normalize_provider=self._normalize_provider,
        )

    def _provider_failure_message(self) -> str:
        """Return a provider-aware troubleshooting hint."""
        return self.session_response_builder.provider_failure_message(
            provider=self.provider,
            groq_endpoint=self.groq_endpoint,
            groq_model=self.groq_model,
            anthropic_model=self.anthropic_model,
            gemini_endpoint=self.gemini_endpoint,
            gemini_model=self.gemini_model,
            nvidia_endpoint=self.nvidia_endpoint,
            nvidia_model=self.nvidia_model,
            openrouter_endpoint=self.openrouter_endpoint,
            openrouter_model=self.openrouter_model,
            ollama_endpoint=self.ollama_endpoint,
            ollama_model=self.ollama_model,
        )

    # ---- Ollama ---- #

    async def _ollama_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Ollama /api/chat with optional tool definitions.

        IMPORTANT: ``format: "json"`` is intentionally NOT used when tools
        are provided because it prevents Ollama from generating native
        ``tool_calls`` in its response.  JSON-mode is only enabled for
        tool-less requests where we need structured text output.
        """
        try:
            # Convert tools to Ollama format
            ollama_tools = []
            for t in tools:
                func = t.get("function", t)
                ollama_tools.append({
                    "type": "function",
                    "function": {
                        "name": func.get("name", ""),
                        "description": func.get("description", ""),
                        "parameters": func.get("parameters", {}),
                    },
                })

            payload: Dict[str, Any] = {
                "model": self.ollama_model,
                "messages": messages,
                "stream": False,
            }

            if ollama_tools:
                # When tools are available, let the model decide to use
                # tool_calls OR respond with JSON text.  Do NOT force
                # format: json – it suppresses native tool calling.
                payload["tools"] = ollama_tools
            else:
                # No tools → force JSON for structured answers
                payload["format"] = "json"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.ollama_endpoint}/api/chat", json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Ollama chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()

                    # Check for tool_calls in response
                    msg = data.get("message", {})
                    if msg.get("tool_calls"):
                        return {"tool_calls": msg["tool_calls"]}

                    # Plain content
                    content = msg.get("content", "")
                    return content

        except aiohttp.ClientConnectorError:
            logger.error(
                f"[AGENT] Cannot connect to Ollama at {self.ollama_endpoint}. "
                "Is Ollama running? Start it with: ollama serve"
            )
            return None
        except Exception as exc:
            logger.error(f"[AGENT] Ollama chat failed: {exc}", exc_info=True)
            return None

    async def _ollama_generate(self, prompt: str) -> Optional[str]:
        """Ollama /api/generate for plain text responses."""
        try:
            payload = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False,
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.ollama_endpoint}/api/generate", json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Ollama generate error {resp.status}: {body[:200]}")
                        return None
                    data = await resp.json()
                    return data.get("response", "")
        except aiohttp.ClientConnectorError:
            logger.error(
                f"[AGENT] Cannot connect to Ollama at {self.ollama_endpoint}. "
                "Is Ollama running? Start it with: ollama serve"
            )
            return None
        except Exception as exc:
            logger.error(f"[AGENT] Ollama generate failed: {exc}")
            return None

    # ---- Anthropic ---- #

    async def _anthropic_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Anthropic /v1/messages with tool_use support."""
        if not self.anthropic_key:
            logger.warning("[AGENT] No Anthropic API key configured")
            return None

        try:
            # Convert tools to Anthropic format
            anthropic_tools = []
            for t in tools:
                func = t.get("function", t)
                anthropic_tools.append({
                    "name": func.get("name", ""),
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {}),
                })

            # Extract system message and user messages
            system_text = ""
            api_messages = []
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                if role == "system":
                    system_text = content
                else:
                    api_messages.append({"role": role, "content": content})

            if not api_messages:
                # If everything was in "user" role, use as-is
                api_messages = [{"role": "user", "content": messages[0].get("content", "")}]

            headers = {
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                "x-api-key": self.anthropic_key,
            }

            payload: Dict[str, Any] = {
                "model": self.anthropic_model,
                "max_tokens": 4096,
                "messages": api_messages,
            }
            if system_text:
                payload["system"] = system_text
            if anthropic_tools:
                payload["tools"] = anthropic_tools

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Anthropic chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()
                    content_blocks = data.get("content", [])

                    # Check for tool_use blocks
                    tool_calls = []
                    text_parts = []
                    for block in content_blocks:
                        if block.get("type") == "tool_use":
                            tool_calls.append({
                                "function": {
                                    "name": block.get("name", ""),
                                    "arguments": block.get("input", {}),
                                },
                            })
                        elif block.get("type") == "text":
                            text_parts.append(block.get("text", ""))

                    if tool_calls:
                        return {"tool_calls": tool_calls}

                    return "\n".join(text_parts)

        except Exception as exc:
            logger.error(f"[AGENT] Anthropic chat failed: {exc}", exc_info=True)
            return None

    async def _anthropic_generate(self, prompt: str) -> Optional[str]:
        """Anthropic /v1/messages for plain text responses."""
        if not self.anthropic_key:
            return None

        try:
            headers = {
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                "x-api-key": self.anthropic_key,
            }
            payload = {
                "model": self.anthropic_model,
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}],
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    content = data.get("content", [])
                    if content and content[0].get("type") == "text":
                        return content[0].get("text", "")
                    return None
        except Exception as exc:
            logger.error(f"[AGENT] Anthropic generate failed: {exc}")
            return None

    # ---- Groq ---- #

    async def _groq_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Groq OpenAI-compatible /chat/completions with tool calling."""
        if not self.groq_key:
            self._record_llm_runtime_status(
                provider='groq',
                model=self._active_model_name('groq'),
                available=False,
                error="Groq API key not configured.",
            )
            logger.warning("[AGENT] No Groq API key configured")
            return None

        try:
            headers = {
                "Authorization": f"Bearer {self.groq_key}",
                "Content-Type": "application/json",
            }
            payload: Dict[str, Any] = {
                "model": self.groq_model,
                "messages": messages,
                "temperature": 0.2,
                "stream": False,
            }
            if tools:
                payload["tools"] = tools

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.groq_endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='groq',
                            model=self._active_model_name('groq'),
                            available=False,
                            error=f"Groq HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] Groq chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='groq',
                        model=self._active_model_name('groq'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}

                    if message.get("tool_calls"):
                        return {"tool_calls": message["tool_calls"]}

                    return message.get("content", "")

        except Exception as exc:
            self._record_llm_runtime_status(
                provider='groq',
                model=self._active_model_name('groq'),
                available=False,
                error=f"Groq request failed: {exc}",
            )
            logger.error(f"[AGENT] Groq chat failed: {exc}", exc_info=True)
            return None

    async def _groq_generate(self, prompt: str) -> Optional[str]:
        """Groq /chat/completions for plain text responses."""
        if not self.groq_key:
            self._record_llm_runtime_status(
                provider='groq',
                model=self._active_model_name('groq'),
                available=False,
                error="Groq API key not configured.",
            )
            return None

        try:
            headers = {
                "Authorization": f"Bearer {self.groq_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.groq_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "stream": False,
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.groq_endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='groq',
                            model=self._active_model_name('groq'),
                            available=False,
                            error=f"Groq HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] Groq generate error {resp.status}: {body[:200]}")
                        return None
                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='groq',
                        model=self._active_model_name('groq'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}
                    return message.get("content", "")
        except Exception as exc:
            self._record_llm_runtime_status(
                provider='groq',
                model=self._active_model_name('groq'),
                available=False,
                error=f"Groq request failed: {exc}",
            )
            logger.error(f"[AGENT] Groq generate failed: {exc}")
            return None

    async def _nvidia_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """NVIDIA Build OpenAI-compatible /chat/completions with tool calling."""
        if not self.nvidia_key:
            self._record_llm_runtime_status(
                provider='nvidia',
                model=self._active_model_name('nvidia'),
                available=False,
                error="NVIDIA Build API key not configured.",
            )
            logger.warning("[AGENT] No NVIDIA Build API key configured")
            return None

        try:
            headers = {
                "Authorization": f"Bearer {self.nvidia_key}",
                "Content-Type": "application/json",
            }
            payload: Dict[str, Any] = {
                "model": self.nvidia_model,
                "messages": messages,
                "temperature": 0.2,
                "stream": False,
            }
            if tools:
                payload["tools"] = tools

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.nvidia_endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='nvidia',
                            model=self._active_model_name('nvidia'),
                            available=False,
                            error=f"NVIDIA Build HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] NVIDIA Build chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='nvidia',
                        model=self._active_model_name('nvidia'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}

                    if message.get("tool_calls"):
                        return {"tool_calls": message["tool_calls"]}

                    return message.get("content", "")

        except Exception as exc:
            self._record_llm_runtime_status(
                provider='nvidia',
                model=self._active_model_name('nvidia'),
                available=False,
                error=f"NVIDIA Build request failed: {exc}",
            )
            logger.error(f"[AGENT] NVIDIA Build chat failed: {exc}", exc_info=True)
            return None

    async def _nvidia_generate(self, prompt: str) -> Optional[str]:
        """NVIDIA Build /chat/completions for plain text responses."""
        if not self.nvidia_key:
            self._record_llm_runtime_status(
                provider='nvidia',
                model=self._active_model_name('nvidia'),
                available=False,
                error="NVIDIA Build API key not configured.",
            )
            return None

        try:
            headers = {
                "Authorization": f"Bearer {self.nvidia_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.nvidia_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "stream": False,
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.nvidia_endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='nvidia',
                            model=self._active_model_name('nvidia'),
                            available=False,
                            error=f"NVIDIA Build HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] NVIDIA Build generate error {resp.status}: {body[:200]}")
                        return None
                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='nvidia',
                        model=self._active_model_name('nvidia'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}
                    return message.get("content", "")
        except Exception as exc:
            self._record_llm_runtime_status(
                provider='nvidia',
                model=self._active_model_name('nvidia'),
                available=False,
                error=f"NVIDIA Build request failed: {exc}",
            )
            logger.error(f"[AGENT] NVIDIA Build generate failed: {exc}")
            return None

    async def _openrouter_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """OpenRouter OpenAI-compatible /chat/completions with tool calling."""
        if not self.openrouter_key:
            self._record_llm_runtime_status(
                provider='openrouter',
                model=self._active_model_name('openrouter'),
                available=False,
                error="OpenRouter API key not configured.",
            )
            logger.warning("[AGENT] No OpenRouter API key configured")
            return None

        try:
            headers = {
                "Authorization": f"Bearer {self.openrouter_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://localhost",
                "X-Title": "CABTA",
            }
            payload: Dict[str, Any] = {
                "model": self.openrouter_model,
                "messages": messages,
                "temperature": 0.2,
                "stream": False,
            }
            if tools:
                payload["tools"] = tools

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.openrouter_endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='openrouter',
                            model=self._active_model_name('openrouter'),
                            available=False,
                            error=f"OpenRouter HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] OpenRouter chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='openrouter',
                        model=self._active_model_name('openrouter'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}

                    if message.get("tool_calls"):
                        return {"tool_calls": message["tool_calls"]}

                    return message.get("content", "")

        except Exception as exc:
            self._record_llm_runtime_status(
                provider='openrouter',
                model=self._active_model_name('openrouter'),
                available=False,
                error=f"OpenRouter request failed: {exc}",
            )
            logger.error(f"[AGENT] OpenRouter chat failed: {exc}", exc_info=True)
            return None

    async def _openrouter_generate(self, prompt: str) -> Optional[str]:
        """OpenRouter /chat/completions for plain text responses."""
        if not self.openrouter_key:
            self._record_llm_runtime_status(
                provider='openrouter',
                model=self._active_model_name('openrouter'),
                available=False,
                error="OpenRouter API key not configured.",
            )
            return None

        try:
            headers = {
                "Authorization": f"Bearer {self.openrouter_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://localhost",
                "X-Title": "CABTA",
            }
            payload = {
                "model": self.openrouter_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "stream": False,
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.openrouter_endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='openrouter',
                            model=self._active_model_name('openrouter'),
                            available=False,
                            error=f"OpenRouter HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] OpenRouter generate error {resp.status}: {body[:200]}")
                        return None
                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='openrouter',
                        model=self._active_model_name('openrouter'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}
                    return message.get("content", "")
        except Exception as exc:
            self._record_llm_runtime_status(
                provider='openrouter',
                model=self._active_model_name('openrouter'),
                available=False,
                error=f"OpenRouter request failed: {exc}",
            )
            logger.error(f"[AGENT] OpenRouter generate failed: {exc}")
            return None

    # ---- Gemini ---- #

    async def _gemini_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Gemini OpenAI-compatible /chat/completions with tool calling."""
        if not self.gemini_key:
            self._record_llm_runtime_status(
                provider='gemini',
                model=self._active_model_name('gemini'),
                available=False,
                error="Gemini API key not configured.",
            )
            logger.warning("[AGENT] No Gemini API key configured")
            return None

        try:
            headers = {
                "Authorization": f"Bearer {self.gemini_key}",
                "Content-Type": "application/json",
            }
            payload: Dict[str, Any] = {
                "model": self.gemini_model,
                "messages": messages,
                "temperature": 1.0,
                "stream": False,
            }
            if tools:
                payload["tools"] = tools

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.gemini_endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='gemini',
                            model=self._active_model_name('gemini'),
                            available=False,
                            error=f"Gemini HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] Gemini chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='gemini',
                        model=self._active_model_name('gemini'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}

                    if message.get("tool_calls"):
                        return {"tool_calls": message["tool_calls"]}

                    return message.get("content", "")

        except Exception as exc:
            self._record_llm_runtime_status(
                provider='gemini',
                model=self._active_model_name('gemini'),
                available=False,
                error=f"Gemini request failed: {exc}",
            )
            logger.error(f"[AGENT] Gemini chat failed: {exc}", exc_info=True)
            return None

    async def _gemini_generate(self, prompt: str) -> Optional[str]:
        """Gemini OpenAI-compatible /chat/completions for plain text responses."""
        if not self.gemini_key:
            self._record_llm_runtime_status(
                provider='gemini',
                model=self._active_model_name('gemini'),
                available=False,
                error="Gemini API key not configured.",
            )
            return None

        try:
            headers = {
                "Authorization": f"Bearer {self.gemini_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.gemini_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 1.0,
                "stream": False,
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.gemini_endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='gemini',
                            model=self._active_model_name('gemini'),
                            available=False,
                            error=f"Gemini HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] Gemini generate error {resp.status}: {body[:200]}")
                        return None
                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='gemini',
                        model=self._active_model_name('gemini'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}
                    return message.get("content", "")
        except Exception as exc:
            self._record_llm_runtime_status(
                provider='gemini',
                model=self._active_model_name('gemini'),
                available=False,
                error=f"Gemini request failed: {exc}",
            )
            logger.error(f"[AGENT] Gemini generate failed: {exc}")
            return None

    # ================================================================== #
    #  Response parsing helpers
    # ================================================================== #

    def _parse_tool_call_response(self, raw: Dict) -> Optional[Dict]:
        """Convert native tool_call response into our standard decision dict.

        Handles the common case where the LLM merges the system prompt's
        JSON format into the tool_call arguments, producing::

            arguments: {
                "params": {"ioc": "8.8.8.8"},
                "action": "use_tool",
                "tool": "investigate_ioc",
                "reasoning": "..."
            }

        instead of the expected ``{"ioc": "8.8.8.8"}``.
        """
        calls = raw.get("tool_calls", [])
        if not calls:
            return None
        first = calls[0]
        func = first.get("function", first)
        name = func.get("name", "")
        args = func.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if not isinstance(args, dict):
            args = {}

        # ---- Unwrap nested params ----
        # If the LLM stuffed the full decision JSON into tool_call arguments,
        # the REAL tool parameters live under args["params"].
        if "params" in args and isinstance(args["params"], dict):
            nested = args["params"]
            # Verify this looks like the system-prompt JSON leak
            # (has 'action' or 'tool' or 'reasoning' alongside 'params')
            has_decision_keys = any(
                k in args for k in ("action", "tool", "reasoning")
            )
            if has_decision_keys or len(nested) > 0:
                reasoning = args.get("reasoning", "Selected by LLM tool_call")
                # Use the tool name from the native call (more reliable)
                # but fall back to args["tool"] if the native name is empty
                if not name and args.get("tool"):
                    name = args["tool"]
                args = nested
                logger.info(
                    f"[AGENT] Unwrapped nested params for {name}: {args}"
                )

        logger.info(
            f"[AGENT] Parsed tool_call: tool={name}, args={args}, "
            f"raw_first={json.dumps(first, default=str)[:300]}"
        )
        return {
            "action": "use_tool",
            "tool": name,
            "params": args,
            "reasoning": args.pop("reasoning", "Selected by LLM tool_call")
                         if "reasoning" in args else "Selected by LLM tool_call",
        }

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict]:
        """Best-effort extraction of a JSON object from LLM text output."""
        if not text:
            return None

        # 1. Try parsing entire text as JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2. Try extracting from code blocks
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

        # 3. Find first { ... } block
        start = text.find('{')
        if start >= 0:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except json.JSONDecodeError:
                            break

        return None


# -------------------------------------------------------------------- #
#  Utility
# -------------------------------------------------------------------- #

def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[:max_len] + "..."
