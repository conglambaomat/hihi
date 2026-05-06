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
import os
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
from .capability_plan import CapabilityPlanBuilder
from .capability_resolver import CapabilityResolver
from .capability_plugin_registry import CapabilityPluginRegistry
from .capability_executor import CapabilityActionExecutor
from .tool_policy import ToolPolicyEngine
from .case_sync_service import CaseSyncService
from .chat_intent_router import ChatIntentRouter
from .entity_resolver import EntityResolver
from .context import ContextOrchestrator, ContextRequest, SubInvestigationContextManager, append_capped_ledger
from .evidence_graph import EvidenceGraph
from .events import AgentEvent
from .decision_aggregator import DecisionAggregator
from .final_answer_gate import FinalAnswerGate
from .final_investigation_reviewer import FinalInvestigationReviewer
from .agentic_investigation_loop import InvestigationPlannerExecutorReflector
from .hypothesis_generator import HypothesisGenerator
from .hypothesis_manager import HypothesisManager
from .investigation_planner import InvestigationPlanner
from .investigation_dag import InvestigationDAG, InvestigationDAGBuilder, StrictDAGExecutor
from .capability_actions import CapabilityAction
from .clarification_gate import ClarificationGate
from .parameter_binder import ParameterBinder
from .preflight_validator import PreflightValidator
from .llm_request_interpreter import LLMRequestInterpreter
from .request_understanding import RequestUnderstandingExtractor, SOCRequestInterpreter
from .log_query_planner import LogQueryPlanner
from .coverage import CoverageEvaluator
from .reflection_engine import PlanRepair, ReflectionEngine
from .query_planning import InvestigationQueryPlanner, LLMQueryAssistant, QueryResultEvaluator
from .retry import BacktrackingEngine, RetryPolicy, ToolResultClassifier
from .next_action_planner import NextActionPlanner
from .observation_normalizer import ObservationNormalizer
from .profiles import AgentProfileRegistry
from .prompt_composer import PromptComposer
from .provider_chat_gateway import ProviderChatGateway
from .provider_gateway import ProviderGateway, ProviderGatewayError
from .provider_health_service import ProviderHealthService
from .root_cause_engine import RootCauseEngine
from .runtime_policy import is_production_mode, is_strict_runtime, legacy_runtime_allowed, strict_only_production, truthy
from .runtime_supervisor import AgentRuntimeSupervisor
from .session_context_service import SessionContextService
from .session_response_builder import SessionResponseBuilder
from .specialist_router import SpecialistRouter
from .specialist_supervisor import SpecialistSupervisor
from .thread_store import ThreadStore
from .thread_sync_service import ThreadSyncService
from .tool_registry import ToolRegistry
from .universal_input_compiler import UniversalInputCompiler
from .soc_task_state import SOCTaskState
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
        investigation_workdir_service=None,
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
        self.investigation_workdir_service = investigation_workdir_service
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
        self.request_understanding = RequestUnderstandingExtractor()
        llm_interpreter_cfg = dict((config.get("agent", {}) or {}).get("llm_request_interpreter", {}) or {})
        configured_llm_mode = str(llm_interpreter_cfg.get("mode") or "").strip().lower()
        llm_interpreter_enabled = bool(
            llm_interpreter_cfg.get(
                "enabled",
                configured_llm_mode in {"shadow", "primary"},
            )
        )
        llm_interpreter_mode = str(
            llm_interpreter_cfg.get("mode")
            or ("shadow" if llm_interpreter_enabled else "disabled")
        )
        self.llm_request_interpreter = LLMRequestInterpreter(
            provider=self._llm_schema_interpretation_provider,
            deterministic_extractor=self.request_understanding,
            mode=llm_interpreter_mode if llm_interpreter_enabled else "disabled",
            max_repair_attempts=int(llm_interpreter_cfg.get("max_repair_attempts", 1)),
            min_accept_confidence=float(llm_interpreter_cfg.get("min_accept_confidence", 0.75)),
            min_clarify_confidence=float(llm_interpreter_cfg.get("min_clarify_confidence", 0.50)),
        )
        self.soc_request_interpreter = SOCRequestInterpreter(
            self.request_understanding,
            llm_interpreter=self.llm_request_interpreter,
            mode=self.llm_request_interpreter.mode,
        )
        self.universal_input_compiler = UniversalInputCompiler()
        self.capability_plan_builder = CapabilityPlanBuilder()
        self.investigation_dag_builder = InvestigationDAGBuilder()
        self.parameter_binder = ParameterBinder()
        self.preflight_validator = PreflightValidator()
        self.clarification_gate = ClarificationGate()
        execution_cfg = dict((config.get("agent", {}) or {}).get("execution", {}) or {})
        plugin_cfg = dict((config.get("agent", {}) or {}).get("capability_plugins", {}) or {})
        self.production_mode = is_production_mode(config)
        self.allow_legacy_runtime_in_production = legacy_runtime_allowed(config, execution_cfg)
        self.strict_only_production = strict_only_production(config, execution_cfg)
        self.strict_dag_mode = self._resolve_strict_dag_mode(config, execution_cfg)
        if self.strict_only_production:
            self.strict_dag_mode = True
            execution_cfg["allow_legacy_direct_tool_fallback"] = False
            plugin_cfg["allow_static_catalog_fallback"] = False
        self.capability_plugin_registry = CapabilityPluginRegistry.bootstrap_builtin()
        self.capability_resolver = CapabilityResolver(
            get_tool=self.tools.get_tool,
            plugin_registry=self.capability_plugin_registry,
            allow_static_fallback=bool(plugin_cfg.get("allow_static_catalog_fallback", False)),
        )
        self.require_capability_boundary = True if self.strict_only_production else bool(execution_cfg.get("require_capability_boundary", True))
        self.allow_legacy_direct_tool_fallback = False if self.strict_only_production else bool(execution_cfg.get("allow_legacy_direct_tool_fallback", not self.strict_dag_mode))
        self.tool_policy_engine = ToolPolicyEngine(config)
        self.capability_action_executor = CapabilityActionExecutor(
            binder=self.parameter_binder,
            preflight_validator=self.preflight_validator,
            policy_engine=self.tool_policy_engine,
            capability_resolver=self.capability_resolver,
            tool_registry=self.tools,
        )
        self.strict_dag_executor = StrictDAGExecutor(
            capability_executor=self.capability_action_executor,
            tool_registry=self.tools,
            max_retries=int(execution_cfg.get("strict_dag_max_retries", 0) or 0),
        )
        self.strict_dag_timeout_seconds = float(execution_cfg.get("strict_dag_timeout_seconds", 55) or 55)
        runtime_cfg = dict((config.get("runtime", {}) or {}).get("supervisor", {}) or execution_cfg.get("runtime_supervisor", {}) or {})
        self.runtime_supervisor_enabled = False if self.strict_only_production else bool(runtime_cfg.get("enabled", True))
        self.runtime_supervisor = AgentRuntimeSupervisor(
            max_queue_size=int(runtime_cfg.get("max_queue_size", 100) or 100),
            worker_count=int(runtime_cfg.get("worker_count", 1) or 1),
            task_timeout_seconds=float(runtime_cfg.get("task_timeout_seconds", 0) or 0),
            max_retries=int(runtime_cfg.get("max_retries", 0) or 0),
        )
        self.log_query_planner = LogQueryPlanner()
        self.coverage_evaluator = CoverageEvaluator()
        self.reflection_engine = ReflectionEngine()
        self.plan_repair = PlanRepair()
        self.decision_aggregator = DecisionAggregator()
        self.final_answer_gate = FinalAnswerGate(reflection_engine=self.reflection_engine)
        self.agentic_investigation_loop = InvestigationPlannerExecutorReflector()
        self.investigation_query_planner = InvestigationQueryPlanner(config=config, llm_provider=self._llm_query_assist_provider)
        self.query_result_evaluator = QueryResultEvaluator()
        self.retry_policy = RetryPolicy.from_config(config)
        self.llm_query_assistant = LLMQueryAssistant(config=config, provider=self._llm_query_assist_provider)
        self.backtracking_engine = BacktrackingEngine(policy=self.retry_policy, llm_assistant=self.llm_query_assistant)
        self.tool_result_classifier = ToolResultClassifier()
        self.hypothesis_manager = HypothesisManager()
        self.hypothesis_generator = HypothesisGenerator()
        self.observation_normalizer = ObservationNormalizer()
        self.entity_resolver = EntityResolver()
        self.evidence_graph = EvidenceGraph()
        self.case_sync_service.entity_resolver = self.entity_resolver
        self.case_sync_service.evidence_graph = self.evidence_graph
        self.root_cause_engine = RootCauseEngine()
        self.chat_intent_router = ChatIntentRouter()
        self.prompt_composer = PromptComposer()
        self.context_orchestrator = ContextOrchestrator(
            config=config,
            model_resolver=lambda: self._active_model_name(self.provider),
        )
        self.sub_investigation_context_manager = SubInvestigationContextManager()
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
            retry_policy=self.retry_policy,
            backtracking_engine=self.backtracking_engine,
            tool_result_classifier=self.tool_result_classifier,
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
        self.max_steps = agent_cfg.get('max_steps', 1000)
        self.auto_enrich_timeout_seconds = int(agent_cfg.get('auto_enrich_timeout_seconds', 12))
        self.chat_tool_cap = int(agent_cfg.get('chat_tool_cap', 14))
        self.chat_prompt_findings_limit = int(agent_cfg.get('chat_prompt_findings_limit', 5))
        self.chat_auto_enrich_limit = int(agent_cfg.get('chat_auto_enrich_limit', 1))
        self.chat_response_timeout_seconds = float(agent_cfg.get('chat_response_timeout_seconds', 15))
        self.llm_unavailable_cooldown_seconds = float(agent_cfg.get('llm_unavailable_cooldown_seconds', 30))

        # LLM connection settings. Router remains the canonical default, while
        # legacy provider attributes are kept as compatibility bridges for
        # runtime settings, health checks, and provider-specific tests.
        llm_cfg = config.get('llm', {})
        api_keys_cfg = config.get('api_keys', {})
        self.provider = llm_cfg.get('provider', 'router')
        self.router_base_url = str(llm_cfg.get('base_url', llm_cfg.get('router_endpoint', 'http://localhost:20128/v1'))).rstrip('/')
        self.router_model = str(llm_cfg.get('model', llm_cfg.get('router_model', 'cx/gpt-5.4'))).strip() or 'cx/gpt-5.4'
        self.router_api_key = (
            get_valid_key(api_keys_cfg, 'router')
            or (llm_cfg.get('api_key', '') if is_valid_api_key(llm_cfg.get('api_key', '')) else '')
        )
        self.ollama_base_url = str(llm_cfg.get('ollama_endpoint', llm_cfg.get('ollama_base_url', 'http://localhost:11434'))).rstrip('/')
        self.ollama_endpoint = self.ollama_base_url
        self.ollama_model = str(llm_cfg.get('ollama_model', 'llama3.1')).strip()
        self.anthropic_base_url = str(llm_cfg.get('anthropic_endpoint', 'https://api.anthropic.com/v1')).rstrip('/')
        self.anthropic_endpoint = self.anthropic_base_url
        self.anthropic_model = str(llm_cfg.get('anthropic_model', 'claude-3-5-sonnet-latest')).strip()
        self.anthropic_key = get_valid_key(api_keys_cfg, 'anthropic') or ''
        self.groq_base_url = str(llm_cfg.get('groq_endpoint', 'https://api.groq.com/openai/v1')).rstrip('/')
        self.groq_endpoint = self.groq_base_url
        self.groq_model = str(llm_cfg.get('groq_model', 'llama-3.1-8b-instant')).strip()
        self.groq_key = get_valid_key(api_keys_cfg, 'groq') or ''
        self.gemini_base_url = str(llm_cfg.get('gemini_endpoint', 'https://generativelanguage.googleapis.com/v1beta')).rstrip('/')
        self.gemini_endpoint = self.gemini_base_url
        self.gemini_model = str(llm_cfg.get('gemini_model', 'gemini-1.5-flash')).strip()
        self.gemini_key = get_valid_key(api_keys_cfg, 'gemini') or ''
        self.openrouter_base_url = str(llm_cfg.get('openrouter_endpoint', 'https://openrouter.ai/api/v1')).rstrip('/')
        self.openrouter_endpoint = self.openrouter_base_url
        self.openrouter_model = str(llm_cfg.get('openrouter_model', 'openai/gpt-oss-20b')).strip()
        self.openrouter_key = get_valid_key(api_keys_cfg, 'openrouter') or ''
        self.openrouter_force_json_decision_mode = bool(llm_cfg.get('openrouter_force_json_decision_mode', False))
        self.nvidia_base_url = str(llm_cfg.get('nvidia_endpoint', 'https://integrate.api.nvidia.com/v1')).rstrip('/')
        self.nvidia_endpoint = self.nvidia_base_url
        self.nvidia_model = str(llm_cfg.get('nvidia_model', 'deepseek-ai/deepseek-v3.2')).strip()
        self.nvidia_key = get_valid_key(api_keys_cfg, 'nvidia') or ''
        self.auto_failover = bool(llm_cfg.get('auto_failover', False))
        self.fallback_providers = list(llm_cfg.get('fallback_providers', []) or [])
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
            auto_failover=bool(llm_cfg.get('auto_failover', False)),
            fallback_providers=list(llm_cfg.get('fallback_providers', []) or []),
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

    @staticmethod
    def _truthy(value: Any) -> bool:
        return truthy(value)

    def _resolve_strict_dag_mode(self, config: Dict[str, Any], execution_cfg: Dict[str, Any]) -> bool:
        return is_strict_runtime(config, execution_cfg)

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
        previous_soc_task_state = metadata.get("previous_soc_task_state")
        compiled_input = self.universal_input_compiler.compile(goal, metadata)
        metadata["compiled_input"] = compiled_input.to_dict()
        previous_soc_task_state = metadata.get("previous_soc_task_state")
        soc_task_state = await self.soc_request_interpreter.interpret_async(goal, {**metadata, "previous_soc_task_state": previous_soc_task_state})
        self.universal_input_compiler.apply_to_task_state(soc_task_state, compiled_input)
        objective_contract = self.request_understanding.objective_builder.build(
            self.request_understanding.extract(goal, metadata),
            runtime=metadata,
        )
        objective_contract_dict = soc_task_state.objective_contract or objective_contract.to_dict()
        capability_plan = self.capability_plan_builder.build(soc_task_state, objective_contract_dict)
        soc_task_state.capability_plan = capability_plan.to_dict()
        soc_task_state.actions = list(capability_plan.actions)
        investigation_dag = self.investigation_dag_builder.build(soc_task_state, objective_contract_dict, capability_plan.to_dict())
        soc_task_state.investigation_dag = investigation_dag.to_dict()
        objective_contract_dict["capability_plan_ref"] = capability_plan.plan_id
        objective_contract_dict["investigation_dag_ref"] = investigation_dag.dag_id
        metadata.setdefault("soc_task_state", soc_task_state.to_dict())
        metadata.setdefault("objective_contract", objective_contract_dict)
        metadata.setdefault("capability_plan", capability_plan.to_dict())
        metadata.setdefault("investigation_dag", investigation_dag.to_dict())
        metadata.setdefault("capabilities_required", list(soc_task_state.required_capabilities or objective_contract.capabilities_required))
        metadata.setdefault("effective_timerange", (soc_task_state.timerange or {}).get("effective") or objective_contract.effective_timerange)
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
        investigation_dag.session_id = session_id
        soc_task_state.investigation_dag = investigation_dag.to_dict()
        metadata["investigation_dag"] = investigation_dag.to_dict()
        thread_id = self._resolve_thread_id(session_id, case_id, metadata)
        metadata["thread_id"] = thread_id
        workdir_summary = self._initialize_investigation_workdir(
            session_id=session_id,
            goal=goal,
            case_id=case_id,
            thread_id=thread_id,
            metadata=metadata,
            investigation_plan=investigation_plan,
        )
        workdir_metadata = {"investigation_workdir": workdir_summary} if workdir_summary else {}
        self.store.update_session_metadata(
            session_id,
            {
                "thread_id": thread_id,
                "executor_path": "strict_dag" if self.strict_dag_mode else "legacy_react",
                "strict_dag_mode": self.strict_dag_mode,
                "capability_registry_status": self.capability_plugin_registry.status(),
                "strict_only_production": self.strict_only_production,
                "legacy_fallback_allowed": not self.strict_only_production and self.allow_legacy_direct_tool_fallback,
                "investigation_plan": investigation_plan,
                "investigation_dag": investigation_dag.to_dict(),
                **workdir_metadata,
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
        soc_task_state.session_id = session_id
        soc_task_state.investigation_dag = investigation_dag.to_dict()
        state.reasoning_state["compiled_input"] = compiled_input.to_dict()
        state.reasoning_state["capability_plan"] = capability_plan.to_dict()
        state.reasoning_state["investigation_dag"] = investigation_dag.to_dict()
        state.reasoning_state["soc_task_state"] = soc_task_state.to_dict()
        state.reasoning_state["objective_contract"] = objective_contract_dict
        state.reasoning_state["capabilities_required"] = list(soc_task_state.required_capabilities or objective_contract.capabilities_required)
        state.reasoning_state["effective_timerange"] = (soc_task_state.timerange or {}).get("effective") or objective_contract.effective_timerange
        state.reasoning_state["progress_events"] = list(soc_task_state.progress_events)
        latest_focus = self._latest_focus_candidate(state)
        existing_focus = str(state.reasoning_state.get("goal_focus") or "").strip() if isinstance(state.reasoning_state, dict) else ""
        if latest_focus and (not existing_focus or not self._goal_has_observable(existing_focus)):
            state.reasoning_state["goal_focus"] = latest_focus
        state.unresolved_questions = list(state.reasoning_state.get("open_questions", [])) if isinstance(state.reasoning_state, dict) else []
        self._refresh_reasoning_outputs(session_id, state)
        self._active_sessions[session_id] = state
        self._approval_events[session_id] = asyncio.Event()

        direct_help_decision = self._build_direct_help_decision(state)
        if direct_help_decision is not None:
            summary = str(direct_help_decision.get("answer") or "")
            gate_payload = {
                "status": "skipped_direct_help",
                "allowed": True,
                "reason": "Capability/help chat answer does not make investigation claims.",
                "answer_mode": "direct_help",
            }
            state.add_finding({
                "type": "final_answer",
                "answer": summary,
                "verdict": direct_help_decision.get("verdict", "UNKNOWN"),
                "final_answer_gate": gate_payload,
                "reasoning": direct_help_decision.get("reasoning", ""),
            })
            state.phase = AgentPhase.COMPLETED
            self.store.add_step(session_id, state.step_count, 'thinking', json.dumps(direct_help_decision, default=str))
            self.store.add_step(session_id, state.step_count, 'final_answer', json.dumps(direct_help_decision, default=str))
            self._record_thread_assistant_message(state, summary)
            self._refresh_reasoning_outputs(session_id, state)
            self._persist_reasoning_metadata(session_id, state)
            self.store.update_session_status(session_id, 'completed', summary)
            self.store.update_session_findings(session_id, state.findings)
            self._notify(session_id, {"type": "completed", "status": "completed", "summary": summary, "steps": state.step_count})
            self._emit_agent_event(session_id, "direct_help.completed", state=state, payload={"capability_id": "config.capability.explain"}, refs=[])
            logger.info(f"[AGENT] Direct capability/help answer completed: {session_id} - {goal[:80]}")
            return session_id

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

        if self.runtime_supervisor_enabled:
            task = self.runtime_supervisor.enqueue(session_id=session_id, runner=_run)
            self.store.update_session_metadata(session_id, {"runtime_supervisor": task}, merge=True)
            self._notify(session_id, {"type": "runtime_supervisor", "event": "queued", "task": task})
        else:
            t = threading.Thread(target=_run, daemon=True, name=f"agent-{session_id}")
            t.start()

        self._emit_agent_event(session_id, "compile.plan.created", state=state, payload={"compiled_input": compiled_input.to_dict(), "capability_plan": capability_plan.to_dict(), "investigation_dag": investigation_dag.to_dict()}, refs=[])
        logger.info(f"[AGENT] Investigation started: {session_id} - {goal[:80]}")
        return session_id

    async def resume_from_workdir(
        self,
        investigation_id: str,
        *,
        goal: Optional[str] = None,
        case_id: Optional[str] = None,
        max_steps: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a new session from a validated non-authoritative workdir payload."""
        service = self.investigation_workdir_service
        if service is None:
            raise RuntimeError("Investigation workdir service not initialized")
        payload = service.build_session_resume_payload(investigation_id)
        resume_goal = str(goal or payload.get("resume_goal") or "Resume AISA investigation from workdir").strip()
        metadata = dict(payload.get("metadata") or {})
        state_payload = payload.get("state_payload") if isinstance(payload.get("state_payload"), dict) else {}
        source_workdir_id = str(payload.get("source_workdir_id") or payload.get("investigation_id") or "").strip() or None
        source_session_id = str(payload.get("source_session_id") or payload.get("session_id") or "").strip() or None
        source_case_id = str(payload.get("source_case_id") or payload.get("case_id") or "").strip() or None
        explicit_case_id = str(case_id or "").strip() or None
        linked_case_id = explicit_case_id or self._validated_workdir_source_case_id(source_case_id)
        metadata.update({
            "resume_payload_version": payload.get("schema_version", "1.0"),
            "workdir_resume_payload": state_payload,
            "workdir_resume_validated": True,
            "chat_context_restored": True,
            "chat_context_restored_source": "workdir_resume",
            "chat_context_restored_memory_scope": "working",
            "chat_context_restored_memory_is_authoritative": False,
            "chat_follow_up_requires_fresh_evidence": True,
            "source_workdir_id": source_workdir_id,
            "source_session_id": source_session_id,
            "source_case_id": linked_case_id,
            "source_case_id_present": bool(linked_case_id),
            "source_case_id_unvalidated": source_case_id if source_case_id and not linked_case_id else None,
            "workdir_resume_case_context_available": bool(linked_case_id),
            "workdir_resume_context_authority": "non_authoritative_requires_fresh_tool_validation",
            "investigation_id": f"resume-{payload.get('investigation_id')}-{int(time.time())}",
        })
        session_id = await self.investigate(
            resume_goal,
            case_id=linked_case_id,
            max_steps=max_steps,
            metadata=metadata,
        )
        state = self._active_sessions.get(session_id)
        restored = False
        if state is not None:
            snapshot = {
                "reasoning_state": state_payload.get("reasoning_state") or {},
                "entity_state": state_payload.get("entity_state") or {},
                "evidence_state": state_payload.get("evidence_state") or {},
                "unresolved_questions": state_payload.get("unresolved_questions") or [],
                "memory_boundary": {"case_id": linked_case_id, "thread_id": getattr(state, "thread_id", None)},
                "snapshot_lifecycle": "working",
            }
            restored_scope = self.session_context_service.restore_state_from_snapshot(
                state,
                snapshot,
                expected_case_id=linked_case_id,
                expected_thread_id=getattr(state, "thread_id", None),
            )
            restored = restored_scope is not None or bool(state.reasoning_state or state.entity_state or state.evidence_state)
            if isinstance(state.reasoning_state, dict):
                state.reasoning_state["workdir_resume_warning"] = metadata.get("workdir_resume_warning")
                state.reasoning_state["requires_fresh_evidence"] = True
            self._refresh_reasoning_outputs(session_id, state)
        self.store.update_session_metadata(
            session_id,
            {
                "workdir_resume_restored": restored,
                "workdir_resume_source_payload": {
                    "source_workdir_id": metadata.get("source_workdir_id"),
                    "source_session_id": metadata.get("source_session_id"),
                    "source_case_id": metadata.get("source_case_id"),
                    "source_case_id_present": metadata.get("source_case_id_present"),
                    "source_workdir_investigation_id": metadata.get("source_workdir_investigation_id"),
                    "source_workdir_session_id": metadata.get("source_workdir_session_id"),
                    "source_artifact_hashes": metadata.get("source_artifact_hashes", []),
                    "deterministic_verdict_boundary": metadata.get("deterministic_verdict_boundary"),
                },
            },
            merge=True,
        )
        return {"session_id": session_id, "status": "active", "resume_payload": payload, "restored": restored}

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
        provider_name = str(provider or self.provider or "router").strip().lower()
        legacy_status = self.provider_runtime_status if isinstance(self.provider_runtime_status, dict) else {}
        if isinstance(legacy_status, dict) and str(legacy_status.get("provider") or "").strip().lower() == provider_name:
            return {**legacy_status, "_legacy_runtime_status": True}

        status = self.provider_health_service.provider_runtime_statuses.get(provider_name)
        if not status:
            status = self.provider_health_service.runtime_status_for_provider(provider_name)
        if status:
            return status
        return {}

    def _provider_is_currently_unavailable(self, provider: Optional[str] = None) -> bool:
        status = self._runtime_status_for_provider(provider)
        return bool(status) and status.get("available") is False

    def _provider_is_recently_unavailable(self, provider: Optional[str] = None) -> bool:
        status = self._runtime_status_for_provider(provider)
        if not status or status.get("available") is not False or status.get("_legacy_runtime_status"):
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
        provider_name = str(provider_name or self.provider or "router").strip().lower()
        return {
            "router": self.router_model,
            "ollama": self.ollama_model,
            "anthropic": self.anthropic_model,
            "groq": self.groq_model,
            "gemini": self.gemini_model,
            "openrouter": self.openrouter_model,
            "nvidia": self.nvidia_model,
        }.get(provider_name, self.router_model)

    def _provider_is_configured(self, provider: Optional[str]) -> bool:
        return self._provider_is_configured_from_config(self._normalize_provider(provider))

    def _provider_is_configured_from_config(self, provider_name: str) -> bool:
        provider_name = str(provider_name or self.provider or "router").strip().lower()
        if provider_name == "ollama":
            return True
        return bool({
            "router": self.router_api_key,
            "anthropic": self.anthropic_key,
            "groq": self.groq_key,
            "gemini": self.gemini_key,
            "openrouter": self.openrouter_key,
            "nvidia": self.nvidia_key,
        }.get(provider_name, ""))

    def _provider_prefers_json_decision_mode(self, provider: Optional[str] = None) -> bool:
        """Return True only when a provider should avoid native tool calling."""
        normalized = str(provider or self.provider or "router").strip().lower()
        if normalized == "openrouter" and self.openrouter_force_json_decision_mode:
            return True
        return self.provider_health_service.provider_prefers_json_decision_mode(provider)

    def _candidate_providers(self) -> List[str]:
        current_provider = str(self.provider or "router").strip().lower()
        if hasattr(self.provider_health_service, "primary_provider"):
            self.provider_health_service.primary_provider = current_provider
        setattr(self.provider_health_service, "auto_failover", bool(getattr(self, "auto_failover", (self.config.get('llm', {}) or {}).get('auto_failover', False))))
        fallbacks = list(getattr(self, "fallback_providers", (self.config.get('llm', {}) or {}).get('fallback_providers', []) or []) or [])
        setattr(self.provider_health_service, "fallback_providers", list(dict.fromkeys([*[str(item or '').strip().lower() for item in fallbacks if str(item or '').strip()], current_provider])))
        if current_provider == "nvidia":
            fallbacks = []
        candidates = [current_provider, *[str(item or "").strip().lower() for item in fallbacks]]
        return list(dict.fromkeys(item for item in candidates if item))

    async def approve_action(self, session_id: str) -> bool:
        """Approve the pending action so the loop can resume."""
        return await self._review_approval(session_id, approved=True)

    async def reject_action(self, session_id: str) -> bool:
        """Reject the pending action; the loop will skip it and re-think."""
        return await self._review_approval(session_id, approved=False)

    async def _review_approval(self, session_id: str, *, approved: bool) -> bool:
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        evt = self._approval_events.get(session_id)
        if evt:
            self.session_response_builder.apply_approval_review(
                state=state,
                approved=approved,
                reviewed_at=datetime.now(timezone.utc).isoformat(),
            )
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

        tool_name = self.tools.resolve_tool_name(tool_name)
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

    def start_bounded_sub_investigation_context(
        self,
        state: AgentState,
        *,
        scope: str,
        allowed_tools: Optional[List[str]] = None,
        max_steps: int = 3,
        return_contract: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create and merge a bounded child investigation context without claiming verdict authority."""
        context_pack = getattr(state, "context_pack_latest", None) if isinstance(getattr(state, "context_pack_latest", None), dict) else {}
        manager = self.sub_investigation_context_manager
        if context_pack:
            child_context = manager.build_handoff_packet(context_pack, child_objective=scope, allowed_tools=allowed_tools or [])
        else:
            inherited_refs: List[Dict[str, Any]] = []
            for finding in list(getattr(state, "findings", []) or [])[-8:]:
                if isinstance(finding, dict) and finding.get("type") == "tool_result":
                    inherited_refs.append({
                        "session_id": state.session_id,
                        "step_number": finding.get("step"),
                        "tool_name": finding.get("tool"),
                        "authority": "tool_observation",
                    })
            child_context = manager.build_child_context(
                parent_session_id=state.session_id,
                child_objective=scope,
                allowed_tools=allowed_tools or [],
                inherited_evidence_refs=inherited_refs,
                max_steps=max_steps,
            )
        if isinstance(return_contract, dict):
            child_context["return_contract"] = {**child_context.get("return_contract", {}), **return_contract, "authoritative_for_verdict": False}
        child_result = manager.build_child_result_contract(
            child_context,
            summary=f"Child context initialized for bounded scope: {scope}",
            evidence_refs=[],
            new_entities=[],
            coverage_delta={},
            hypothesis_updates=[],
        )
        merge_metadata = manager.merge_child_result_into_reasoning_state(state.reasoning_state if isinstance(state.reasoning_state, dict) else {}, child_result)
        state.reasoning_state = merge_metadata["reasoning_state"]
        return {"child_context": child_context, "child_result": child_result, "parent_merge_metadata": merge_metadata["merge_metadata"]}

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
        """Return contradiction-aware deterministic decision aggregate."""
        reasoning_state = state.reasoning_state if isinstance(state.reasoning_state, dict) else {}
        decision = self.decision_aggregator.aggregate(
            findings=list(state.findings or []),
            evidence_graph=getattr(state, "evidence_state", {}) if isinstance(getattr(state, "evidence_state", {}), dict) else {},
            coverage=reasoning_state.get("coverage_matrix", {}),
            objective=reasoning_state.get("objective_contract", {}),
        )
        if str(decision.get("verdict") or "UNKNOWN").upper() == "UNKNOWN":
            for finding in reversed(list(state.findings or [])):
                if not isinstance(finding, dict) or finding.get("type") != "tool_result":
                    continue
                payload = finding.get("result") if isinstance(finding.get("result"), dict) else {}
                verdict = str(payload.get("verdict") or "").upper()
                if verdict in {"MALICIOUS", "SUSPICIOUS", "CLEAN"}:
                    decision = {**decision, "verdict": verdict, "authoritative_for_verdict": True, "source": finding.get("tool") or "tool_result"}
                    break
        if isinstance(state.reasoning_state, dict):
            state.reasoning_state["decision_aggregate"] = decision
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
            if isinstance(state.reasoning_state, dict) and normalized_observations:
                audit = state.reasoning_state.get("capability_action_audit", [])
                last_protocol = audit[-1].get("protocol", {}) if isinstance(audit, list) and audit and isinstance(audit[-1], dict) else {}
                protocol_action = last_protocol.get("action", {}) if isinstance(last_protocol, dict) else {}
                capability_id = protocol_action.get("capability_id") if isinstance(protocol_action, dict) else None
                action_id = protocol_action.get("action_id") if isinstance(protocol_action, dict) else None
                if capability_id or action_id:
                    for observation in normalized_observations:
                        if isinstance(observation, dict):
                            observation.setdefault("capability_id", capability_id)
                            observation.setdefault("action_ref", action_id)
                            observation.setdefault("task_ref", (state.reasoning_state.get("soc_task_state") or {}).get("task_id") if isinstance(state.reasoning_state.get("soc_task_state"), dict) else None)
                            observation.setdefault("backend", (params or {}).get("backend"))
                            observation.setdefault("timerange", (params or {}).get("timerange"))
            latest_quality_summary = dict(normalization.get("evidence_quality_summary", {}))
            latest_fact_family_schemas = dict(normalization.get("fact_family_schemas", {}))
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
            state.fact_family_schemas = {
                **(state.fact_family_schemas if isinstance(state.fact_family_schemas, dict) else {}),
                **latest_fact_family_schemas,
            }
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
            dag_payload = state.reasoning_state.get("investigation_dag", {}) if isinstance(state.reasoning_state, dict) else {}
            if isinstance(dag_payload, dict):
                dag = InvestigationDAG.from_dict(dag_payload).update_with_observations(normalized_observations)
                state.reasoning_state["investigation_dag"] = dag.to_dict()
                soc_task_payload = state.reasoning_state.get("soc_task_state", {})
                if isinstance(soc_task_payload, dict):
                    soc_task_payload["investigation_dag"] = dag.to_dict()
                    state.reasoning_state["soc_task_state"] = soc_task_payload
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
            if not isinstance(getattr(state, "fact_family_schemas", None), dict):
                state.fact_family_schemas = {}

        generation = self.hypothesis_generator.generate(
            goal=state.goal,
            session_id=session_id,
            reasoning_state=state.reasoning_state,
            investigation_plan=state.investigation_plan,
            active_observations=state.active_observations,
            entity_state=state.entity_state,
            evidence_state=state.evidence_state,
            deterministic_decision=getattr(state, "deterministic_decision", None),
        )
        state.reasoning_state = self.hypothesis_manager.merge_candidates(
            state.reasoning_state,
            generation.get("candidates", []),
            session_id=session_id,
            entity_state=state.entity_state,
            evidence_state=state.evidence_state,
            generation_events=generation.get("events", []),
            generation_summary=generation.get("summary", {}),
        )

        latest_log_coverage = None
        if isinstance(result, dict) and isinstance(result.get("coverage_matrix"), dict):
            latest_log_coverage = result.get("coverage_matrix")
        elif isinstance(state.reasoning_state, dict) and isinstance(state.reasoning_state.get("last_log_result_coverage"), dict):
            latest_log_coverage = state.reasoning_state.get("last_log_result_coverage")
        if isinstance(state.reasoning_state, dict):
            lane = str((state.investigation_plan or {}).get("lane") or state.reasoning_state.get("investigation_lane") or "ioc")
            coverage_matrix = self.coverage_evaluator.evaluate(
                active_observations=state.active_observations,
                entity_state=state.entity_state,
                evidence_state=state.evidence_state,
                reasoning_state=state.reasoning_state,
                lane=lane,
                log_coverage=latest_log_coverage,
            )
            state.reasoning_state["coverage_matrix"] = coverage_matrix
            state.reasoning_state["coverage_summary"] = coverage_matrix.get("summary")
            if latest_log_coverage:
                state.reasoning_state["last_log_result_coverage"] = copy.deepcopy(latest_log_coverage)

        self._refresh_reflection_state(state)

        state.unresolved_questions = self._dedupe_text(
            [
                *(state.reasoning_state.get("open_questions", []) if isinstance(state.reasoning_state, dict) else []),
                *(state.reasoning_state.get("missing_evidence", []) if isinstance(state.reasoning_state, dict) else []),
            ]
        )[:10]
        state.deterministic_decision = self._build_deterministic_decision_output(state)
        if tool_name == "search_logs" and isinstance(state.reasoning_state, dict) and isinstance(result, dict):
            coverage_for_attempt = result.get("coverage_matrix") if isinstance(result.get("coverage_matrix"), dict) else state.reasoning_state.get("coverage_matrix", {})
            if isinstance(coverage_for_attempt, dict) and coverage_for_attempt:
                state.reasoning_state["coverage_matrix"] = copy.deepcopy(coverage_for_attempt)
                state.reasoning_state["last_log_result_coverage"] = copy.deepcopy(coverage_for_attempt)
            result_diagnosis = self.tool_result_classifier.diagnose(result)
            investigation_query_plan = result.get("investigation_query_plan") if isinstance(result.get("investigation_query_plan"), dict) else state.reasoning_state.get("last_investigation_query_plan", {})
            if isinstance(investigation_query_plan, dict) and investigation_query_plan:
                state.reasoning_state["last_investigation_query_plan"] = copy.deepcopy(investigation_query_plan)
            expected_facets = list((investigation_query_plan or {}).get("expected_facets") or (investigation_query_plan or {}).get("coverage_targets") or (coverage_for_attempt or {}).get("required_facets") or [])
            query_evaluation = self.query_result_evaluator.evaluate(result=result, expected_facets=expected_facets)
            state.reasoning_state["last_query_result_evaluation"] = query_evaluation
            result_class = query_evaluation.get("result_class") or self.tool_result_classifier.classify(result)
            attempts = list(state.reasoning_state.get("query_attempts", []))
            attempt_id = f"query-attempt-{len(attempts) + 1}"
            covered_cells = query_evaluation.get("covered_facets") or (coverage_for_attempt.get("covered_facets", []) if isinstance(coverage_for_attempt, dict) else [])
            remaining_gaps = query_evaluation.get("remaining_facets") or (coverage_for_attempt.get("missing_facets", []) if isinstance(coverage_for_attempt, dict) else [])
            previous_coverage = attempts[-1].get("coverage_after", {}) if attempts and isinstance(attempts[-1], dict) else state.reasoning_state.get("previous_log_result_coverage", {})
            coverage_delta = self._coverage_delta(previous_coverage if isinstance(previous_coverage, dict) else {}, coverage_for_attempt if isinstance(coverage_for_attempt, dict) else {})
            rewrite_strategy = None
            executed_variants = result.get("executed_query_variants") if isinstance(result.get("executed_query_variants"), list) else []
            if executed_variants and isinstance(executed_variants[0], dict):
                rewrite_strategy = executed_variants[0].get("strategy") or executed_variants[0].get("variant_id")
            attempt_entry = {
                "attempt_id": attempt_id,
                "parent_id": attempts[-1].get("attempt_id") if attempts else None,
                "tool": "search_logs",
                "result_class": result_class,
                "gap": remaining_gaps[0] if remaining_gaps else None,
                "objective": str((investigation_query_plan or {}).get("objective") or "log_hunt"),
                "covered_cells": covered_cells,
                "remaining_gaps": remaining_gaps,
                "query_result_evaluation": query_evaluation,
                "diagnosis": result_diagnosis,
                "diagnosis_confidence": result_diagnosis.get("diagnosis_confidence"),
                "rewrite_strategy": rewrite_strategy,
                "coverage_before": self._compact_coverage_snapshot(previous_coverage if isinstance(previous_coverage, dict) else {}),
                "coverage_after": self._compact_coverage_snapshot(coverage_for_attempt if isinstance(coverage_for_attempt, dict) else {}),
                "coverage_delta": coverage_delta,
                "newly_covered_facets": coverage_delta.get("newly_covered_facets", []),
                "still_missing_facets": coverage_delta.get("still_missing_facets", remaining_gaps),
                "retry_reason": (coverage_for_attempt or {}).get("retry_reason") or (coverage_for_attempt or {}).get("summary"),
                "stop_reason": None if result_class in {"empty_result", "success_partial", "low_quality_evidence", "transient_error"} else result_class,
            }
            attempts.append(attempt_entry)
            state.reasoning_state["query_attempts"] = attempts[-12:]
            state.reasoning_state["previous_log_result_coverage"] = copy.deepcopy(coverage_for_attempt if isinstance(coverage_for_attempt, dict) else {})
            retry_state = dict(state.reasoning_state.get("retry_state") or {})
            retry_state["attempts"] = attempts[-12:]
            retry_state["last_result_class"] = result_class
            retry_state["last_remaining_gaps"] = remaining_gaps
            retry_state["last_query_result_evaluation"] = query_evaluation
            retry_state["last_diagnosis"] = result_diagnosis
            retry_state["last_coverage_delta"] = coverage_delta
            retry_state["newly_covered_facets"] = coverage_delta.get("newly_covered_facets", [])
            retry_state["still_missing_facets"] = coverage_delta.get("still_missing_facets", remaining_gaps)
            retry_state["diagnosis_confidence"] = result_diagnosis.get("diagnosis_confidence")
            retry_state["rewrite_strategy"] = rewrite_strategy
            state.reasoning_state["retry_state"] = retry_state
            state.reasoning_state["latest_coverage_delta"] = coverage_delta
            self._record_retry_audit_event(session_id, state, attempt_entry)

        root_cause_assessment = self.root_cause_engine.assess(
            goal=state.goal,
            reasoning_state=state.reasoning_state,
            deterministic_decision=state.deterministic_decision,
            evidence_state=state.evidence_state,
            entity_state=state.entity_state,
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
        self._mirror_reasoning_to_workdir(session_id, state)

    def _refresh_reflection_state(self, state: AgentState) -> None:
        if not isinstance(state.reasoning_state, dict):
            return
        objective = state.reasoning_state.get("objective_contract", {})
        reflection = self.reflection_engine.reflect(
            objective=objective,
            findings=list(state.findings or []),
            observations=list(state.active_observations or []),
            coverage=state.reasoning_state.get("coverage_matrix", {}),
            reasoning_state=state.reasoning_state,
        )
        state.reasoning_state["reflection"] = reflection.to_dict()
        state.reasoning_state["plan_repair"] = self.plan_repair.repair(
            state.investigation_plan if isinstance(state.investigation_plan, dict) else {},
            reflection,
            state,
        )

    def _record_investigation_runtime_snapshot(self, session_id: str, state: AgentState, candidate_answer: str = "") -> Dict[str, Any]:
        if not isinstance(state.reasoning_state, dict) or not hasattr(self, "agentic_investigation_loop"):
            return {}
        snapshot = self.agentic_investigation_loop.plan(state, candidate_answer).to_dict()
        state.reasoning_state["investigation_state"] = snapshot.get("investigation_state", {})
        state.reasoning_state["investigation_loop"] = snapshot
        completion = snapshot.get("completion", {}) if isinstance(snapshot.get("completion"), dict) else {}
        inv_state = snapshot.get("investigation_state", {}) if isinstance(snapshot.get("investigation_state"), dict) else {}
        if hasattr(self.tools, "resolve_action_connector"):
            connectors = [self.tools.resolve_action_connector(action) for action in inv_state.get("next_actions", []) if isinstance(action, dict)]
            inv_state["connector_registry"] = {
                "schema_version": "investigation-connectors/v1",
                "actions": connectors,
                "available_count": sum(1 for item in connectors if item.get("status") == "available"),
                "unavailable_count": sum(1 for item in connectors if item.get("status") != "available"),
            }
            snapshot["investigation_state"] = inv_state
        telemetry = state.reasoning_state.setdefault("investigation_telemetry", {})
        metrics = telemetry.setdefault("metrics", {})
        metrics["investigation_loop_iterations"] = int(getattr(state, "step_count", 0) or 0)
        metrics["investigation_evidence_items_total"] = len((snapshot.get("investigation_state") or {}).get("evidence_items") or [])
        metrics["investigation_open_gaps_total"] = len(completion.get("missing_milestones") or []) + len(completion.get("pending_actions") or [])
        telemetry["latest_progress"] = {
            "completion_status": completion.get("status"),
            "missing_milestones": completion.get("missing_milestones", []),
            "pending_required_actions": completion.get("pending_actions", []),
            "milestone_statuses": inv_state.get("milestone_statuses", []),
            "connector_registry": inv_state.get("connector_registry", {}),
            "planned_actions": snapshot.get("planned_actions", []),
            "executable_actions": snapshot.get("executable_actions", []),
            "reflection": snapshot.get("reflection", {}),
        }
        self._emit_agent_event(session_id, "investigation.loop.iteration", state=state, payload=telemetry["latest_progress"], authoritative=False)
        return snapshot

    def _evaluate_final_answer_gate(self, state: AgentState, draft_answer: str):
        objective = state.reasoning_state.get("objective_contract", {}) if isinstance(state.reasoning_state, dict) else {}
        gate_decision = self.final_answer_gate.evaluate(
            objective=objective,
            state=state,
            draft_answer=draft_answer,
        )
        gate_payload = gate_decision.to_dict()
        if isinstance(state.reasoning_state, dict):
            structured = dict(gate_payload.get("structured_verdict") or {})
            if structured:
                coverage = state.reasoning_state.get("coverage_matrix", {}) if isinstance(state.reasoning_state.get("coverage_matrix"), dict) else {}
                structured.setdefault("coverage", {"lane": coverage.get("lane"), "status": coverage.get("overall_status")})
                state.reasoning_state["structured_verdict"] = structured
            state.reasoning_state["final_answer_gate"] = gate_payload
            state.reasoning_state["evidence_chips"] = list(gate_payload.get("evidence_chips") or [])
            state.reasoning_state["verified_claims"] = list(gate_payload.get("verified_claims") or [])
            state.reasoning_state["unsupported_claims"] = list(gate_payload.get("downgraded_claims") or [])
            state.reasoning_state["claim_evidence_map"] = dict(gate_payload.get("claim_evidence_map") or {})
            self._record_investigation_runtime_snapshot(state.session_id, state, draft_answer)
            soc_task = state.reasoning_state.get("soc_task_state", {}) if isinstance(state.reasoning_state.get("soc_task_state"), dict) else {}
            if soc_task:
                soc_task["final_answer_gate"] = gate_payload
                soc_task["structured_verdict"] = state.reasoning_state.get("structured_verdict", {})
                soc_task["evidence_chips"] = list(gate_payload.get("evidence_chips") or [])
                soc_task["claim_evidence_map"] = dict(gate_payload.get("claim_evidence_map") or {})
                state.reasoning_state["soc_task_state"] = soc_task
        return gate_decision

    @staticmethod
    def _compact_coverage_snapshot(coverage: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(coverage, dict):
            return {}
        return {
            "coverage_status": coverage.get("coverage_status") or coverage.get("overall_status"),
            "overall_score": coverage.get("overall_score"),
            "covered_facets": list(coverage.get("covered_facets") or [])[:12],
            "missing_facets": list(coverage.get("missing_facets") or [])[:12],
            "partial_facets": list(coverage.get("partial_facets") or [])[:12],
        }

    def _coverage_delta(self, before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
        before_snapshot = self._compact_coverage_snapshot(before)
        after_snapshot = self._compact_coverage_snapshot(after)
        before_covered = set(before_snapshot.get("covered_facets") or [])
        after_covered = set(after_snapshot.get("covered_facets") or [])
        before_missing = set(before_snapshot.get("missing_facets") or [])
        after_missing = set(after_snapshot.get("missing_facets") or [])
        return {
            "schema_version": "coverage-delta/v1",
            "before_status": before_snapshot.get("coverage_status"),
            "after_status": after_snapshot.get("coverage_status"),
            "before_score": before_snapshot.get("overall_score"),
            "after_score": after_snapshot.get("overall_score"),
            "score_delta": round(float(after_snapshot.get("overall_score") or 0.0) - float(before_snapshot.get("overall_score") or 0.0), 3),
            "newly_covered_facets": sorted(after_covered - before_covered),
            "newly_missing_facets": sorted(after_missing - before_missing),
            "still_missing_facets": sorted(after_missing),
            "resolved_missing_facets": sorted(before_missing - after_missing),
            "authoritative": False,
        }

    @staticmethod
    def _compact_hypothesis_requirement_coverage(coverage_matrix: Dict[str, Any]) -> Dict[str, Any]:
        cells = coverage_matrix.get("cells", []) if isinstance(coverage_matrix, dict) else []
        hypothesis_cells = []
        for cell in cells if isinstance(cells, list) else []:
            if not isinstance(cell, dict):
                continue
            metadata = cell.get("metadata") if isinstance(cell.get("metadata"), dict) else {}
            if metadata.get("cell_type") != "hypothesis_required_evidence":
                continue
            hypothesis_cells.append({
                "facet": cell.get("facet"),
                "status": cell.get("status"),
                "missing_fields": list(cell.get("missing_fields") or [])[:12],
                "confidence": cell.get("confidence"),
                "hypothesis_id": metadata.get("hypothesis_id"),
                "hypothesis_type": metadata.get("hypothesis_type"),
                "contract_id": metadata.get("contract_id"),
                "relation_basis": dict(metadata.get("relation_basis") or {}),
                "strongest_relation_basis": metadata.get("strongest_relation_basis"),
                "authoritative": False,
            })
        return {
            "schema_version": "hypothesis-requirement-coverage/v1",
            "authoritative": False,
            "cell_count": len(hypothesis_cells),
            "cells": hypothesis_cells[:24],
        }

    def _record_retry_audit_event(self, session_id: str, state: AgentState, attempt_entry: Dict[str, Any]) -> None:
        event = {
            "event_type": "retry_backtracking_decision",
            "session_id": session_id,
            "tool": "search_logs",
            "attempt_id": attempt_entry.get("attempt_id"),
            "result_class": attempt_entry.get("result_class"),
            "diagnosis": attempt_entry.get("diagnosis"),
            "coverage_delta": attempt_entry.get("coverage_delta"),
            "rewrite_strategy": attempt_entry.get("rewrite_strategy"),
            "authoritative": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if isinstance(state.reasoning_state, dict):
            events = list(state.reasoning_state.get("retry_audit_events", []))
            events.append(event)
            state.reasoning_state["retry_audit_events"] = events[-24:]
        if self.governance_store is not None:
            try:
                self.governance_store.log_ai_decision(
                    session_id=session_id,
                    case_id=self._session_case_id(session_id),
                    workflow_id=getattr(state, "workflow_id", None),
                    decision_type="retry_backtracking_decision",
                    summary=f"Recorded log retry diagnosis {attempt_entry.get('result_class')} with coverage delta metadata.",
                    rationale=str((attempt_entry.get("diagnosis") or {}).get("reason") or ""),
                    metadata=event,
                )
            except Exception:
                logger.debug("[AGENT] Failed to log retry/backtracking decision", exc_info=True)

    def _normalize_terminal_snapshot_publication(self, state: AgentState) -> str:
        return self.thread_sync_service.finalize_lifecycle_for_state(state)

    def _persist_reasoning_metadata(self, session_id: str, state: AgentState) -> None:
        state.deterministic_decision = self._build_deterministic_decision_output(state)
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
                "candidate_hypotheses": (state.reasoning_state or {}).get("candidate_hypotheses", []),
                "suppressed_hypotheses": (state.reasoning_state or {}).get("suppressed_hypotheses", []),
                "hypothesis_events": (state.reasoning_state or {}).get("hypothesis_events", []),
                "hypothesis_generation_summary": (state.reasoning_state or {}).get("hypothesis_generation_summary", {}),
                "retry_audit_events": (state.reasoning_state or {}).get("retry_audit_events", []),
                "latest_coverage_delta": (state.reasoning_state or {}).get("latest_coverage_delta", {}),
                "evidence_chips": (state.reasoning_state or {}).get("evidence_chips", []),
                "verified_claims": (state.reasoning_state or {}).get("verified_claims", []),
                "unsupported_claims": (state.reasoning_state or {}).get("unsupported_claims", []),
                "claim_evidence_map": (state.reasoning_state or {}).get("claim_evidence_map", {}),
                "active_observations": state.active_observations[-24:],
                "accepted_facts": state.accepted_facts[-16:],
                "accepted_facts_delta": state.accepted_facts[-12:],
                "unresolved_questions": state.unresolved_questions,
                "evidence_quality_summary": state.evidence_quality_summary,
                "fact_family_schemas": state.fact_family_schemas,
                "restored_memory_scope": state.restored_memory_scope,
                "chat_context_restored_memory_scope": state.chat_context_restored_memory_scope,
                "context_pack_latest": getattr(state, "context_pack_latest", None),
                "context_pack_summary_latest": getattr(state, "context_pack_summary_latest", None),
                "context_ledger_latest": getattr(state, "context_ledger_latest", None),
                "context_budget_latest": getattr(state, "context_budget_latest", None),
                "context_ledgers": append_capped_ledger(
                    (self._session_metadata(session_id) or {}).get("context_ledgers", []),
                    getattr(state, "context_ledger_latest", {}) if isinstance(getattr(state, "context_ledger_latest", {}), dict) else {},
                    max_items=12,
                ) if getattr(state, "context_ledger_latest", None) else (self._session_metadata(session_id) or {}).get("context_ledgers", []),
            },
            merge=True,
        )

    def _workdir_investigation_id(self, session_id: str) -> str:
        metadata = self._session_metadata(session_id)
        workdir = metadata.get("investigation_workdir") if isinstance(metadata, dict) else None
        if isinstance(workdir, dict) and workdir.get("investigation_id"):
            return str(workdir.get("investigation_id"))
        return str(metadata.get("investigation_id") or session_id)

    def _initialize_investigation_workdir(
        self,
        *,
        session_id: str,
        goal: str,
        case_id: Optional[str],
        thread_id: Optional[str],
        metadata: Dict[str, Any],
        investigation_plan: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        service = self.investigation_workdir_service
        if service is None:
            return None
        try:
            investigation_id = str(metadata.get("investigation_id") or session_id)
            root = service.create_or_get(
                investigation_id,
                case_id=case_id,
                session_id=session_id,
                thread_id=thread_id,
            )
            safe_id = service.normalize_investigation_id(investigation_id)
            service.write_json(safe_id, "plan.json", investigation_plan)
            service.write_text(safe_id, "plan.md", self._render_workdir_plan(goal, investigation_plan))
            service.write_text(safe_id, "context.md", self._render_workdir_context(goal, case_id, session_id, thread_id, metadata))
            service.sync_state(safe_id, phase="initialized", last_step=0, latest_tool=None)
            summary = service.summarize(safe_id)
            return {
                "investigation_id": safe_id,
                "path": str(root),
                "manifest_ref": "manifest.json",
                "artifact_count": summary.get("artifact_count", 0),
                "last_event_type": summary.get("last_event_type"),
                "verdict_boundary": "deterministic_scoring_remains_authoritative",
            }
        except Exception:
            logger.warning("[AGENT] Investigation workdir initialization failed", exc_info=True)
            return None

    @staticmethod
    def _render_workdir_plan(goal: str, investigation_plan: Dict[str, Any]) -> str:
        return "\n".join([
            "# AISA Investigation Plan",
            "",
            f"Goal: {goal}",
            "",
            "Deterministic AISA scoring remains authoritative for verdicts and scores.",
            "",
            "```json",
            json.dumps(investigation_plan or {}, indent=2, default=str),
            "```",
            "",
        ])

    @staticmethod
    def _render_workdir_context(goal: str, case_id: Optional[str], session_id: str, thread_id: Optional[str], metadata: Dict[str, Any]) -> str:
        safe_metadata = {k: v for k, v in (metadata or {}).items() if "key" not in str(k).lower() and "token" not in str(k).lower() and "secret" not in str(k).lower()}
        return "\n".join([
            "# AISA Investigation Context",
            "",
            f"Goal: {goal}",
            f"Case ID: {case_id or ''}",
            f"Session ID: {session_id}",
            f"Thread ID: {thread_id or ''}",
            "",
            "Metadata snapshot:",
            "```json",
            json.dumps(safe_metadata, indent=2, default=str),
            "```",
            "",
        ])

    def _mirror_reasoning_to_workdir(self, session_id: str, state: AgentState) -> None:
        service = self.investigation_workdir_service
        if service is None:
            return
        try:
            investigation_id = self._workdir_investigation_id(session_id)
            service.write_json(investigation_id, "hypotheses.json", state.reasoning_state or {})
            service.write_json(investigation_id, "coverage_matrix.json", (state.reasoning_state or {}).get("coverage_matrix", {}))
            service.write_json(investigation_id, "investigation_query_plan.json", (state.reasoning_state or {}).get("last_investigation_query_plan", {}))
            service.write_json(investigation_id, "query_attempts.json", (state.reasoning_state or {}).get("query_attempts", []))
            service.write_json(investigation_id, "retry_state.json", (state.reasoning_state or {}).get("retry_state", {}))
            service.write_json(investigation_id, "retry_audit_events.json", (state.reasoning_state or {}).get("retry_audit_events", []))
            service.write_json(investigation_id, "latest_coverage_delta.json", (state.reasoning_state or {}).get("latest_coverage_delta", {}))
            service.write_json(investigation_id, "last_log_result_coverage.json", (state.reasoning_state or {}).get("last_log_result_coverage", {}))
            service.write_json(investigation_id, "last_query_result_evaluation.json", (state.reasoning_state or {}).get("last_query_result_evaluation", {}))
            service.write_json(investigation_id, "hypothesis_requirement_coverage.json", self._compact_hypothesis_requirement_coverage((state.reasoning_state or {}).get("coverage_matrix", {})))
            service.write_json(investigation_id, "entities.json", state.entity_state or {})
            service.write_json(investigation_id, "evidence_graph.json", state.evidence_state or {})
            service.write_json(investigation_id, "candidate_hypotheses.json", (state.reasoning_state or {}).get("candidate_hypotheses", []))
            service.write_json(investigation_id, "hypothesis_events.json", (state.reasoning_state or {}).get("hypothesis_events", []))
            service.write_json(investigation_id, "hypothesis_generation_summary.json", (state.reasoning_state or {}).get("hypothesis_generation_summary", {}))
            service.write_json(investigation_id, "deterministic_decision.json", {
                "schema_version": "1.0",
                "verdict_boundary": "deterministic_aisa_scoring",
                "decision": state.deterministic_decision or {},
            })
            service.write_json(investigation_id, "agentic_explanation.json", {
                "schema_version": "1.0",
                "verdict_boundary": "non_authoritative",
                "explanation": state.agentic_explanation or {},
            })
            if getattr(state, "context_pack_latest", None):
                service.write_json(investigation_id, "context_pack_latest.json", getattr(state, "context_pack_latest", {}), artifact_kind="context_orchestration_metadata")
            if getattr(state, "context_ledger_latest", None):
                service.write_json(investigation_id, "context_ledger_latest.json", getattr(state, "context_ledger_latest", {}), artifact_kind="context_orchestration_metadata")
            if getattr(state, "context_budget_latest", None):
                service.write_json(investigation_id, "context_budget_latest.json", getattr(state, "context_budget_latest", {}), artifact_kind="context_orchestration_metadata")
            if getattr(state, "context_ledger_latest", None):
                metadata = self._session_metadata(session_id) or {}
                service.write_json(
                    investigation_id,
                    "context_ledgers.json",
                    {
                        "schema_version": "context-ledger-history/v1",
                        "authority": "orchestration_metadata_non_authoritative",
                        "authoritative_for_verdict": False,
                        "items": metadata.get("context_ledgers", []),
                    },
                    artifact_kind="context_orchestration_metadata",
                )
            service.sync_state(
                investigation_id,
                phase=str(getattr(state.phase, "value", state.phase)).lower(),
                last_step=state.step_count,
                latest_tool=state.current_tool,
                state={"open_questions": list(state.unresolved_questions or [])},
            )
            summary = service.summarize(investigation_id)
            self.store.update_session_metadata(session_id, {"investigation_workdir": summary}, merge=True)
        except Exception:
            logger.warning("[AGENT] Investigation workdir reasoning mirror failed", exc_info=True)

    def _mirror_observation_to_workdir(
        self,
        *,
        session_id: str,
        state: AgentState,
        tool_name: str,
        params: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        service = self.investigation_workdir_service
        if service is None:
            return
        try:
            investigation_id = self._workdir_investigation_id(session_id)
            service.persist_observation(
                investigation_id,
                step_number=state.step_count,
                tool_name=tool_name,
                params=params,
                result=result,
            )
        except Exception:
            logger.warning("[AGENT] Investigation workdir observation mirror failed", exc_info=True)

    def _write_terminal_review_to_workdir(self, session_id: str, state: AgentState, terminal_payload: Dict[str, Any]) -> None:
        service = self.investigation_workdir_service
        if service is None:
            return
        try:
            investigation_id = self._workdir_investigation_id(session_id)
            service.generate_review(
                investigation_id,
                summary=str(terminal_payload.get("summary") or ""),
                status=str(terminal_payload.get("status") or "completed"),
            )
            service.sync_state(
                investigation_id,
                phase=str(terminal_payload.get("status") or "completed"),
                last_step=state.step_count,
                latest_tool=None,
            )
            self.store.update_session_metadata(session_id, {"investigation_workdir": service.summarize(investigation_id)}, merge=True)
        except Exception:
            logger.warning("[AGENT] Investigation workdir terminal review failed", exc_info=True)

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

    def _build_execution_guidance(self, state: AgentState, tool_name: str) -> Dict[str, Any]:
        plan = state.investigation_plan if isinstance(state.investigation_plan, dict) else {}
        root_cause = (
            state.agentic_explanation.get("root_cause_assessment", {})
            if isinstance(state.agentic_explanation, dict)
            else {}
        )
        causal_support = (
            state.evidence_state.get("causal_support", {})
            if isinstance(state.evidence_state, dict)
            else {}
        )
        triage_contracts = plan.get("triage_contracts", []) if isinstance(plan, dict) else []
        matched_contracts = [
            dict(item)
            for item in triage_contracts
            if isinstance(item, dict)
            and str(item.get("lane") or plan.get("lane") or "generic").strip().lower() == str(plan.get("lane") or "generic").strip().lower()
        ]
        return {
            "lane": str(plan.get("lane") or "generic"),
            "tool": tool_name,
            "deterministic_verdict": str((state.deterministic_decision or {}).get("verdict") or "UNKNOWN").upper(),
            "deterministic_verdict_owner": str(plan.get("deterministic_verdict_owner") or "AISA deterministic core"),
            "reasoning_status": str((state.reasoning_state or {}).get("status") or ""),
            "root_cause_status": str(root_cause.get("status") or ""),
            "root_cause_summary": str(root_cause.get("summary") or ""),
            "top_missing_evidence": list(state.unresolved_questions[:3]),
            "required_evidence_fields": sorted(
                {
                    str(field).strip()
                    for contract in matched_contracts
                    for field in contract.get("required_fields", [])
                    if str(field).strip()
                }
            ),
            "escalation_hooks": [
                str(hook).strip()
                for contract in matched_contracts
                for hook in contract.get("escalation_hooks", [])
                if str(hook).strip()
            ][:6],
            "causal_path_summaries": [
                str(item.get("path_summary") or "")
                for item in causal_support.get("root_path_summaries", [])
                if isinstance(item, dict) and str(item.get("path_summary") or "").strip()
            ][:3],
        }

    def _record_execution_blocker(
        self,
        state: AgentState,
        *,
        tool_name: str,
        blocker_status: str,
        approval_context: Dict[str, Any],
    ) -> None:
        blocker = {
            "type": "approval_blocker",
            "tool": tool_name,
            "status": blocker_status,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "approval_context": dict(approval_context or {}),
            "execution_guidance": dict((approval_context or {}).get("execution_guidance", {})),
        }
        if isinstance(state.reasoning_state, dict):
            blockers = list(state.reasoning_state.get("execution_blockers", []))
            blockers.append(blocker)
            state.reasoning_state["execution_blockers"] = blockers[-6:]
            state.reasoning_state["approval_status"] = blocker_status
            if blocker_status in {"rejected", "timed_out"}:
                follow_up = f"Approval-gated action '{tool_name}' is {blocker_status}; analyst decision or a safer alternate pivot is required."
                missing = list(state.reasoning_state.get("missing_evidence", []))
                if follow_up not in missing:
                    state.reasoning_state["missing_evidence"] = [*missing, follow_up][-8:]
        state.last_approval_outcome = {
            "tool": tool_name,
            "status": blocker_status,
            "context": dict(approval_context or {}),
            "recorded_at": blocker["captured_at"],
        }

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

    def _pop_forced_next_decision(self, state: AgentState) -> Optional[Dict[str, Any]]:
        if not isinstance(getattr(state, "reasoning_state", None), dict):
            return None
        forced_next = state.reasoning_state.pop("_forced_next_decision", None)
        return forced_next if isinstance(forced_next, dict) else None

    def _tool_available_for_auto_pivot(self, name: str) -> bool:
        tools = getattr(self, "tools", None)
        if tools is not None and getattr(tools, "get_tool", None):
            return tools.get_tool(name) is not None
        legacy_get_tool = getattr(self, "_get_tool", None)
        return bool(legacy_get_tool and legacy_get_tool(name) is not None)

    def _safe_investigation_continuation_answer(self, gate_payload: Dict[str, Any], auto_pivot: Optional[Dict[str, Any]] = None) -> str:
        if auto_pivot is not None:
            tool = str(auto_pivot.get("tool") or "next SOC pivot")
            return f"Continuing investigation; AISA queued the next evidence pivot with `{tool}` instead of finalizing prematurely."
        pending = [item for item in ((gate_payload.get("structured_verdict") or {}).get("pending_actions") or []) if isinstance(item, dict)]
        missing_items = list(gate_payload.get("missing_evidence") or [])
        if pending:
            for item in pending[:5]:
                action_type = str(item.get("action_type") or item.get("tool_hint") or "follow_up")
                tool_hint = str(item.get("tool_hint") or "").strip() or "no tool hint"
                missing_items.append(f"{action_type} ({tool_hint} unavailable or duplicate params exhausted)")
        missing = "; ".join(str(item) for item in missing_items[:8])
        suffix = f" Missing capability/evidence: {missing}." if missing else " No executable follow-up capability is currently available."
        return "partial_safe_stop blocked_missing_capability." + suffix

    def _decision_from_investigation_pending_action(self, state: AgentState, pending_actions: List[Dict[str, Any]], prev_tool_calls: List[Any]) -> Optional[Dict[str, Any]]:
        """Turn completeness-gate follow-ups into one safe executable pivot."""
        if not pending_actions:
            return None
        excluded = self._auto_pivot_call_signatures(prev_tool_calls)
        for action in pending_actions:
            if not isinstance(action, dict):
                continue
            preferred_tool = str(action.get("tool_hint") or "search_logs").strip()
            tool_candidates = [preferred_tool]
            action_type = str(action.get("action_type") or "").strip()
            if action_type in {"build_timeline", "host_timeline"}:
                tool_candidates.extend(["splunk.get_host_timeline", "search_logs"])
            elif action_type in {"pivot_hash_enrichment", "hash_enrichment"}:
                focus_value = self._hash_for_investigation_action(state, action)
                if focus_value:
                    params = action.setdefault("params", {})
                    if isinstance(params, dict):
                        params.setdefault("ioc", focus_value)
                    tool_candidates.extend(["investigate_ioc", "search_threat_intel", "search_logs"])
                else:
                    tool_candidates = ["search_logs"]
            elif action_type in {"pivot_file_registry", "file_registry"}:
                tool_candidates = [preferred_tool, "search_logs"]
                action.setdefault("query_focus", "file registry process persistence artifacts")
            elif action_type in {"derive_root_cause", "write_threat_story", "assess_scope", "assess_impact", "root_cause", "threat_story", "scope", "impact"}:
                tool_candidates.extend(["correlate_findings", "search_logs"])
            else:
                tool_candidates.append("search_logs")
            tool = ""
            for candidate in dict.fromkeys(t for t in tool_candidates if t and t != "none"):
                if not self._tool_available_for_auto_pivot(candidate):
                    continue
                preview_query = self._query_for_investigation_action(state, action, candidate)
                preview_params = self._params_for_investigation_action(candidate, action, preview_query, "all_time", state)
                if self._auto_pivot_signature(candidate, preview_params) not in excluded:
                    tool = candidate
                    break
            if not tool:
                continue
            focus = str(action.get("query_focus") or action.get("action_type") or action.get("rationale") or "investigation pivot")
            query = self._query_for_investigation_action(state, action, tool)
            if hasattr(self, "_build_reasoning_search_request") and tool == "search_logs":
                try:
                    request_focus = query if action_type in {"pivot_file_registry", "file_registry", "pivot_hash_enrichment", "hash_enrichment"} else focus
                    request = self._build_reasoning_search_request(state, [request_focus])
                    query = request.get("query", request_focus)
                    timerange = request.get("timerange", "all_time")
                except Exception:
                    timerange = "all_time"
            else:
                timerange = "all_time"
            if isinstance(state.reasoning_state, dict):
                inv = state.reasoning_state.get("investigation_state") if isinstance(state.reasoning_state.get("investigation_state"), dict) else {}
                actions = inv.get("next_actions", []) if isinstance(inv.get("next_actions"), list) else []
                for existing in actions:
                    if isinstance(existing, dict) and existing.get("dedupe_key") == action.get("dedupe_key"):
                        existing["status"] = "executed"
                inv["next_actions"] = actions
                state.reasoning_state["investigation_state"] = inv
            return {
                "action": "use_tool",
                "tool": tool,
                "params": self._params_for_investigation_action(tool, action, query, timerange, state),
                "reasoning": "Completeness gate blocked final answer and scheduled required SOC pivot: " + str(action.get("rationale") or action.get("action_type") or "follow-up"),
                "decision_source": "investigation_completeness_auto_pivot",
                "investigation_action_id": action.get("action_id"),
            }
        return None

    @staticmethod
    def _auto_pivot_signature(tool: str, params: Dict[str, Any]) -> tuple:
        return (str(tool or ""), json.dumps(params or {}, sort_keys=True, default=str))

    def _auto_pivot_call_signatures(self, prev_tool_calls: List[Any]) -> set:
        signatures = set()
        for item in prev_tool_calls or []:
            if isinstance(item, dict) and item.get("tool"):
                signatures.add(self._auto_pivot_signature(str(item.get("tool")), dict(item.get("params") or {})))
            elif isinstance(item, tuple) and len(item) >= 2:
                signatures.add((str(item[0]), str(item[1])))
            elif isinstance(item, tuple) and item:
                signatures.add((str(item[0]), "{}"))
        return signatures

    def _query_for_investigation_action(self, state: AgentState, action: Dict[str, Any], tool: str) -> str:
        action_type = str(action.get("action_type") or "").strip()
        if action_type in {"pivot_file_registry", "file_registry"}:
            return "file registry process persistence artifacts OR file write OR registry autorun OR run key OR scheduled task OR service install"
        if action_type in {"pivot_hash_enrichment", "hash_enrichment"}:
            hash_value = self._hash_for_investigation_action(state, action)
            return hash_value or "hash sha256 md5 indicator enrichment"
        return str(action.get("query_focus") or action.get("action_type") or action.get("rationale") or "investigation pivot")

    def _hash_for_investigation_action(self, state: AgentState, action: Dict[str, Any]) -> str:
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        candidates = [params.get("sha256"), params.get("hash"), params.get("ioc"), action.get("sha256"), action.get("hash")]
        for finding in getattr(state, "findings", []) or []:
            if isinstance(finding, dict):
                candidates.extend([finding.get("sha256"), finding.get("hash"), finding.get("ioc")])
                result = finding.get("result")
                if isinstance(result, dict):
                    candidates.extend([result.get("sha256"), result.get("hash"), result.get("Hashes"), result.get("hashes")])
        for candidate in candidates:
            text = str(candidate or "")
            match = re.search(r"\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b", text)
            if match:
                return match.group(1)
        return ""

    def _params_for_investigation_action(self, tool: str, action: Dict[str, Any], query: Any, timerange: str, state: AgentState) -> Dict[str, Any]:
        params = dict(action.get("params") or {}) if isinstance(action, dict) else {}
        focus = str(action.get("query_focus") or action.get("rationale") or query or "investigation pivot")
        if tool == "search_logs":
            return {"query": query, "timerange": timerange}
        if tool == "splunk.get_host_timeline":
            host = params.get("host") or self._latest_focus_candidate(state) or "unknown-host"
            return {"host": str(host), "timerange": params.get("timerange") or timerange or "24h"}
        if tool in {"investigate_ioc", "search_threat_intel"}:
            ioc = params.get("ioc") or params.get("sha256") or params.get("hash") or self._hash_for_investigation_action(state, action) or params.get("query") or focus
            if not re.fullmatch(r"[A-Fa-f0-9]{32,64}|\d{1,3}(?:\.\d{1,3}){3}|https?://\S+|[A-Za-z0-9-]+(?:\.[A-Za-z]{2,})+", str(ioc).strip()):
                return {"query": query, "timerange": timerange}
            return {"ioc": str(ioc)} if tool == "investigate_ioc" else {"query": str(ioc)}
        if tool == "correlate_findings":
            return {"findings": list(getattr(state, "findings", []) or [])[-10:], "objective": focus}
        return params

    # ================================================================== #
    #  Main ReAct Loop
    # ================================================================== #

    async def _run_loop(self, session_id: str) -> None:
        state = self._active_sessions.get(session_id)
        if state is None:
            return
        if self.strict_dag_mode:
            await self._run_strict_dag_loop(session_id, state)
            return
        if self.strict_only_production:
            error = "Strict-only production requires the strict DAG executor; legacy ReAct runtime is disabled."
            state.errors.append(error)
            state.phase = AgentPhase.FAILED
            self.store.update_session_status(session_id, "failed", error)
            self.store.update_session_metadata(session_id, {"executor_path": "blocked_legacy_react", "legacy_fallback_blocked": True}, merge=True)
            self._notify(session_id, {"type": "failed", "error": error, "executor_path": "blocked_legacy_react"})
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
                    decision = self._pop_forced_next_decision(state)

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
                    summary = decision.get('answer', '')
                    verdict = decision.get('verdict', 'UNKNOWN')
                    self._refresh_reasoning_outputs(session_id, state)
                    if decision.get("skip_final_answer_gate") and decision.get("answer_mode") == "direct_help":
                        gate_decision = type("DirectHelpGateDecision", (), {
                            "allowed": True,
                            "provisional_answer": summary,
                            "to_dict": lambda _self: {
                                "status": "skipped_direct_help",
                                "allowed": True,
                                "reason": "Capability/help chat answer does not make investigation claims.",
                                "answer_mode": "direct_help",
                            },
                        })()
                    else:
                        gate_decision = self._evaluate_final_answer_gate(state, summary)
                    self._emit_agent_event(session_id, "answer.final_gate", state=state, payload=gate_decision.to_dict(), authoritative=False)
                    if not gate_decision.allowed:
                        gate_payload = gate_decision.to_dict()
                        pending_actions = list(((gate_payload.get("structured_verdict") or {}).get("pending_actions") or []))
                        auto_pivot = self._decision_from_investigation_pending_action(state, pending_actions, _prev_tool_calls)
                        if auto_pivot is not None:
                            if isinstance(state.reasoning_state, dict):
                                telemetry = state.reasoning_state.setdefault("investigation_telemetry", {})
                                telemetry["final_blocked_total"] = int(telemetry.get("final_blocked_total") or 0) + 1
                                telemetry["last_block_reason"] = gate_payload.get("blocking_reasons", [])
                                telemetry.setdefault("metrics", {})["investigation_final_blocked_total"] = telemetry["final_blocked_total"]
                                state.reasoning_state["_forced_next_decision"] = auto_pivot
                            self.store.add_step(
                                session_id, state.step_count, 'final_blocked_auto_pivot',
                                json.dumps({"gate": gate_payload, "next_action": auto_pivot}, default=str),
                            )
                            self._emit_agent_event(session_id, "investigation.final_blocked_auto_pivot", state=state, payload={"gate": gate_payload, "next_action": auto_pivot}, authoritative=False)
                            self._sync_specialist_progress(session_id, state, reason="Final answer gate blocked completion; scheduled required SOC pivot without consuming the execution budget.")
                            continue
                        else:
                            summary = self._safe_investigation_continuation_answer(gate_payload)
                            verdict = str(decision.get('verdict') or 'UNKNOWN').upper() if self._resolve_authoritative_outcome(state) else 'UNKNOWN'
                            decision = {
                                **decision,
                                "answer": summary,
                                "verdict": verdict,
                                "final_answer_gate": gate_payload,
                                "reasoning": "Final answer gate converted unsupported conclusion to provisional evidence-gap response because no safe executable pivot is available.",
                            }
                    self._log_decision(
                        session_id,
                        state,
                        decision_type='final_answer',
                        summary=str(summary)[:500],
                        rationale=decision.get('reasoning', ''),
                        metadata={'verdict': verdict, 'final_answer_gate': gate_decision.to_dict()},
                    )
                    authoritative_outcome = self._resolve_authoritative_outcome(state)
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
                        "final_answer_gate": gate_decision.to_dict(),
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

                # ---- Capability bridge / execution boundary ----
                if decision.get('action') == 'use_capability':
                    decision = self._bridge_capability_decision(state, decision)
                    if decision.get('action') in {'degraded_capability', 'ask_clarification', 'request_approval'}:
                        self._record_degraded_capability(session_id, state, decision)
                        state.step_count += 1
                        self._sync_specialist_progress(session_id, state, reason="Capability protocol gate blocked execution; no unsafe fallback tool was executed.")
                        continue
                elif decision.get('action') == 'use_tool' and self.require_capability_boundary:
                    normalized = self._normalize_legacy_tool_decision(state, decision)
                    if normalized.get('action') in {'degraded_capability', 'ask_clarification', 'request_approval'}:
                        self._record_degraded_capability(session_id, state, normalized)
                        if not self.allow_legacy_direct_tool_fallback:
                            state.step_count += 1
                            self._sync_specialist_progress(session_id, state, reason="Direct tool call blocked by capability execution boundary.")
                            continue
                    elif normalized.get('action') == 'use_tool':
                        decision = normalized

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
                    approval_context = self.session_response_builder.build_approval_context(
                        session_id=session_id,
                        state=state,
                        tool_name=tool_name,
                        params=decision.get('params', {}),
                        approval_id=approval_id,
                        case_id=self._session_case_id(session_id),
                        execution_guidance=self._build_execution_guidance(state, tool_name),
                    )
                    approval_reason = f"Tool '{tool_name}' requires analyst approval before execution."
                    state.request_approval(
                        self.session_response_builder.build_approval_pending_payload(
                            decision=decision,
                            approval_id=approval_id,
                        ),
                        approval_reason,
                        context=approval_context,
                    )
                    state.phase = AgentPhase.WAITING_HUMAN
                    self._notify(
                        session_id,
                        self.session_response_builder.build_approval_required_event(
                            tool_name=tool_name,
                            params=decision.get('params', {}),
                            reason=approval_reason,
                            approval_context=approval_context,
                        ),
                    )

                    # Wait until approve/reject/cancel
                    approved = await self._wait_for_approval(session_id, state)
                    if state.is_terminal():
                        break
                    if not approved:
                        rejection_transition = self.session_response_builder.build_approval_rejection_transition(
                            tool_name=tool_name,
                            approval_outcome=state.last_approval_outcome,
                        )
                        state.add_finding(rejection_transition["finding"])
                        self._record_execution_blocker(
                            state,
                            tool_name=tool_name,
                            blocker_status=rejection_transition["blocker_status"],
                            approval_context=rejection_transition["approval_context"],
                        )
                        state.step_count += 1
                        self._sync_specialist_progress(session_id, state, reason="Approval was rejected or timed out; ownership moved to the next specialist.")
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
                self._emit_agent_event(session_id, "tool.start", state=state, payload={"tool": tool_name, "params": decision.get('params', {}), "capability_id": decision.get("capability_id")}, refs=[])
                if decision.get("decision_source") == "investigation_completeness_auto_pivot":
                    self._emit_agent_event(session_id, "investigation.action.started", state=state, payload={"tool": tool_name, "action_id": decision.get("investigation_action_id"), "params": decision.get("params", {})}, refs=[])
                result = await self._act(state, decision)
                _act_dur = int((_time.time() - _act_start) * 1000)

                # ---- OBSERVE ----
                state.transition(AgentPhase.OBSERVING)
                self._record_tool_observation(
                    session_id=session_id,
                    state=state,
                    tool_name=tool_name,
                    params=decision.get('params', {}),
                    result=result,
                    duration_ms=_act_dur,
                    specialist_progress_reason=f"Completed specialist action via {tool_name}.",
                )
                if decision.get("decision_source") == "investigation_completeness_auto_pivot":
                    self._emit_agent_event(session_id, "investigation.action.completed", state=state, payload={"tool": tool_name, "action_id": decision.get("investigation_action_id"), "duration_ms": _act_dur, "result_status": "error" if isinstance(result, dict) and result.get("error") else "completed"}, refs=[])
                    self._record_investigation_runtime_snapshot(session_id, state)

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
                            self._record_tool_observation(
                                session_id=session_id,
                                state=state,
                                tool_name=mcp_tool,
                                params=mcp_params,
                                result=mcp_result,
                                duration_ms=_mcp_dur,
                                specialist_progress_reason=f"Auto-enrichment completed via {mcp_tool}.",
                            )
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
            self._refresh_reasoning_outputs(session_id, state)
            summary = await self._generate_summary(state)
            terminal_payload = self.session_response_builder.build_terminal_status_payload(
                state=state,
                summary=summary,
            )
            self._write_terminal_review_to_workdir(session_id, state, terminal_payload)
            self._persist_specialist_metadata(
                session_id,
                state,
                terminal_status=terminal_payload["status"],
                reason="Workflow session finished.",
            )
            self._sync_case_reasoning_checkpoint(
                session_id,
                state,
                terminal_status=terminal_payload["status"],
            )
            self.store.update_session_status(
                session_id,
                terminal_payload["status"],
                terminal_payload["summary"],
            )
            self.store.update_session_findings(session_id, state.findings)
            if terminal_payload["record_thread_message"]:
                self._record_thread_assistant_message(state, terminal_payload["summary"])

            self._notify(session_id, {
                "type": "completed",
                "status": terminal_payload["status"],
                "summary": terminal_payload["summary"],
                "steps": terminal_payload["steps"],
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

    async def _run_strict_dag_loop(self, session_id: str, state: AgentState) -> None:
        """Production path: execute the compiled capability DAG and fail closed."""
        try:
            if state.phase == AgentPhase.IDLE:
                state.transition(AgentPhase.THINKING)
            if state.phase != AgentPhase.ACTING:
                state.transition(AgentPhase.ACTING)
            reasoning = state.reasoning_state if isinstance(state.reasoning_state, dict) else {}
            objective = dict(reasoning.get("objective_contract") or {})
            objective["execution_mode"] = "strict_production"
            task_state = SOCTaskState.from_legacy_reasoning_state(reasoning, session_id=session_id, raw_request=state.goal)
            task_state.session_id = session_id
            dag_payload = reasoning.get("investigation_dag", {}) if isinstance(reasoning.get("investigation_dag"), dict) else {}
            self.store.update_session_metadata(session_id, {"executor_path": "strict_dag", "legacy_fallback_allowed": False}, merge=True)
            self._emit_agent_event(session_id, "executor.path", state=state, payload={"executor_path": "strict_dag", "strict_dag_mode": True, "legacy_fallback_allowed": False}, refs=[])
            result = await asyncio.wait_for(
                self.strict_dag_executor.execute(
                    dag_payload,
                    task_state=task_state,
                    objective_contract=objective,
                    context={"session_id": session_id, "executor_path": "strict_dag"},
                ),
                timeout=max(1.0, self.strict_dag_timeout_seconds),
            )
            payload = result.to_dict()
            for node_result in payload.get("node_results", []):
                if not isinstance(node_result, dict) or node_result.get("status") != "completed":
                    continue
                envelope = node_result.get("envelope") if isinstance(node_result.get("envelope"), dict) else {}
                observation = node_result.get("observation") if isinstance(node_result.get("observation"), dict) else {}
                self._record_tool_observation(
                    session_id=session_id,
                    state=state,
                    tool_name=str(observation.get("tool_name") or envelope.get("tool_name") or "strict_dag_node"),
                    params=dict(envelope.get("params") or {}),
                    result=dict(observation.get("result") or observation),
                    duration_ms=0,
                    specialist_progress_reason="Strict DAG capability node completed.",
                )
            if isinstance(state.reasoning_state, dict):
                state.reasoning_state["strict_dag_execution"] = payload
                state.reasoning_state["investigation_dag"] = payload.get("dag", {})
            self._refresh_reasoning_outputs(session_id, state)
            if not result.allowed:
                state.errors.extend(payload.get("blocking_reasons") or ["Strict DAG execution blocked."])
                state.phase = AgentPhase.FAILED
            else:
                state.phase = AgentPhase.COMPLETED
            summary = await self._generate_summary(state)
            gate_decision = self._evaluate_final_answer_gate(state, summary)
            gate_payload = gate_decision.to_dict()
            self._emit_agent_event(session_id, "answer.final_gate", state=state, payload=gate_payload, authoritative=False)
            if not gate_decision.allowed:
                executed_auto_pivots: list = []
                while not gate_decision.allowed:
                    pending_actions = list(((gate_payload.get("structured_verdict") or {}).get("pending_actions") or []))
                    auto_pivot = self._decision_from_investigation_pending_action(state, pending_actions, executed_auto_pivots)
                    if auto_pivot is None:
                        summary = self._safe_investigation_continuation_answer(gate_payload)
                        state.errors.extend(gate_payload.get("blocking_reasons") or ["Strict DAG final answer gate blocked unsupported claims."])
                        break

                    self.store.add_step(session_id, state.step_count, 'final_blocked_auto_pivot', json.dumps({"gate": gate_payload, "next_action": auto_pivot}, default=str))
                    self._emit_agent_event(session_id, "investigation.final_blocked_auto_pivot", state=state, payload={"gate": gate_payload, "next_action": auto_pivot}, authoritative=False)
                    result_payload = await self._act(state, auto_pivot)
                    executed_auto_pivots.append((auto_pivot.get("tool", ""), json.dumps(auto_pivot.get("params", {}), sort_keys=True, default=str)))
                    self._record_tool_observation(
                        session_id=session_id,
                        state=state,
                        tool_name=str(auto_pivot.get("tool") or "auto_pivot"),
                        params=dict(auto_pivot.get("params") or {}),
                        result=result_payload if isinstance(result_payload, dict) else {"result": result_payload},
                        duration_ms=0,
                        specialist_progress_reason="Strict DAG final gate blocked completion; executed required SOC pivot.",
                    )
                    self._emit_agent_event(session_id, "investigation.action.completed", state=state, payload={"tool": auto_pivot.get("tool"), "action_id": auto_pivot.get("investigation_action_id"), "result_status": "error" if isinstance(result_payload, dict) and result_payload.get("error") else "completed"}, refs=[])
                    self._refresh_reasoning_outputs(session_id, state)
                    summary = await self._generate_summary(state)
                    gate_decision = self._evaluate_final_answer_gate(state, summary)
                    gate_payload = gate_decision.to_dict()
                    self._emit_agent_event(session_id, "answer.final_gate", state=state, payload=gate_payload, authoritative=False)
                state.phase = AgentPhase.COMPLETED
            state.add_finding({
                "type": "final_answer",
                "answer": summary,
                "verdict": (gate_payload.get("structured_verdict") or {}).get("verdict", "inconclusive"),
                "final_answer_gate": gate_payload,
                "evidence_chips": gate_payload.get("evidence_chips", []),
                "claim_evidence_map": gate_payload.get("claim_evidence_map", {}),
                "structured_verdict": gate_payload.get("structured_verdict", {}),
            })
            terminal_payload = self.session_response_builder.build_terminal_status_payload(state=state, summary=summary)
            final_status = terminal_payload["status"]
            self._persist_reasoning_metadata(session_id, state)
            self.store.update_session_metadata(session_id, {"strict_dag_execution": payload, "executor_path": "strict_dag", "final_answer_gate": gate_payload, "evidence_chips": gate_payload.get("evidence_chips", []), "claim_evidence_map": gate_payload.get("claim_evidence_map", {}), "structured_verdict": gate_payload.get("structured_verdict", {})}, merge=True)
            self.store.update_session_status(session_id, final_status, terminal_payload["summary"])
            self.store.update_session_findings(session_id, state.findings)
            self._notify(session_id, {"type": "completed", "status": final_status, "summary": terminal_payload["summary"], "steps": terminal_payload["steps"], "executor_path": "strict_dag", "final_answer_gate": gate_payload, "evidence_chips": gate_payload.get("evidence_chips", []), "claim_evidence_map": gate_payload.get("claim_evidence_map", {}), "structured_verdict": gate_payload.get("structured_verdict", {})})
        except asyncio.TimeoutError:
            timeout_message = f"Strict DAG execution timed out after {self.strict_dag_timeout_seconds:.0f}s before producing evidence; AISA safe-stopped the session instead of leaving it active."
            logger.error("[AGENT] Strict DAG loop timeout for %s: %s", session_id, timeout_message)
            state.errors.append(timeout_message)
            state.phase = AgentPhase.COMPLETED
            degraded_finding = {
                "type": "capability_degraded",
                "capability": "strict_dag_runtime",
                "reasoning": timeout_message,
                "decision": {"action": "safe_stop", "executor_path": "strict_dag"},
            }
            state.add_finding(degraded_finding)
            state.add_finding({
                "type": "final_answer",
                "answer": timeout_message,
                "verdict": "inconclusive",
            })
            self.store.add_step(session_id, state.step_count, "runtime_safe_stop", json.dumps(degraded_finding, default=str))
            state.step_count += 1
            self._refresh_reasoning_outputs(session_id, state)
            self._persist_reasoning_metadata(session_id, state)
            self.store.update_session_status(session_id, "completed", timeout_message)
            self.store.update_session_findings(session_id, state.findings)
            self.store.update_session_metadata(session_id, {"executor_path": "strict_dag", "strict_dag_timeout": True, "strict_dag_error": timeout_message}, merge=True)
            self._notify(session_id, {"type": "completed", "status": "completed", "summary": timeout_message, "steps": state.step_count, "executor_path": "strict_dag", "degraded": True})
        except Exception as exc:
            logger.error("[AGENT] Strict DAG loop error for %s: %s", session_id, exc, exc_info=True)
            state.errors.append(str(exc))
            state.phase = AgentPhase.FAILED
            self.store.update_session_status(session_id, "failed", str(exc))
            self.store.update_session_metadata(session_id, {"executor_path": "strict_dag", "strict_dag_error": str(exc)}, merge=True)
            self._notify(session_id, {"type": "failed", "error": str(exc), "executor_path": "strict_dag"})
        finally:
            self._approval_events.pop(session_id, None)

    def _record_tool_observation(
        self,
        *,
        session_id: str,
        state: AgentState,
        tool_name: str,
        params: Dict[str, Any],
        result: Dict[str, Any],
        duration_ms: int,
        specialist_progress_reason: str,
    ) -> None:
        state.current_tool = None
        state.add_finding({
            "type": "tool_result",
            "tool": tool_name,
            "params": params,
            "result": result,
        })
        self._refresh_reasoning_outputs(
            session_id,
            state,
            tool_name=tool_name,
            params=params,
            result=result,
        )
        state.deterministic_decision = self._build_deterministic_decision_output(state)
        self._mirror_observation_to_workdir(
            session_id=session_id,
            state=state,
            tool_name=tool_name,
            params=params,
            result=result,
        )
        state.step_count += 1
        self._sync_specialist_progress(session_id, state, reason=specialist_progress_reason)
        self.store.update_session_findings(session_id, state.findings)
        is_mcp = '.' in tool_name
        self._emit_agent_event(session_id, "tool.result", state=state, payload={"tool": tool_name, "duration_ms": duration_ms, "has_error": isinstance(result, dict) and bool(result.get("error"))}, refs=[{"tool_name": tool_name, "step_number": state.step_count - 1}])
        self._notify(session_id, {
            "type": "tool_result",
            "step": state.step_count - 1,
            "max_steps": state.max_steps,
            "tool": tool_name,
            "tool_source": "mcp" if is_mcp else "local",
            "tool_server": tool_name.split('.')[0] if is_mcp else None,
            "duration_ms": duration_ms,
            "params": params,
            "result": result,
        })

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
        planned_decision = self._chat_short_circuit_decision(state)
        if isinstance(planned_decision, dict) and planned_decision.get("action") == "use_tool":
            return planned_decision

        model_only_chat = self._chat_should_force_model_answer_without_tools(state)
        if model_only_chat:
            tools_json = []
            request_tools_json = []
            if self._provider_is_recently_unavailable(self.provider):
                logger.info(
                    "[AGENT] Skipping direct chat retry because %s is still marked unavailable within the cooldown window.",
                    self.session_response_builder.provider_display_name(self.provider),
                )
                raise ProviderGatewayError("Direct chat LLM is unavailable within cooldown")
        has_native_tools = len(request_tools_json) > 0 and not self._provider_prefers_json_decision_mode(self.provider)
        if not has_native_tools:
            request_tools_json = []

        context_pack = None
        if self.context_orchestrator is not None and self.context_orchestrator.enabled():
            try:
                objective = "direct_answer" if model_only_chat else "decide_next_tool"
                context_pack_obj = self.context_orchestrator.build_pack(
                    state=state,
                    request=ContextRequest(
                        session_id=state.session_id,
                        step_number=state.step_count,
                        objective=objective,
                        model=self._active_model_name(self.provider),
                        prompt_mode="direct_answer" if model_only_chat else ("native_tooling" if has_native_tools else "json_tool_decision"),
                        analyst_focus=self._latest_analyst_message(state) or self._latest_focus_candidate(state) or state.goal,
                        tools_block=tools_block,
                        findings_block=findings_block,
                        reasoning_block=reasoning_block,
                        workflow_block=workflow_block,
                        playbooks_block=playbooks_block,
                    ),
                )
                context_pack = context_pack_obj.to_dict()
                context_pack["summary"] = context_pack_obj.summary()
                setattr(state, "context_pack_latest", context_pack)
                setattr(state, "context_pack_summary_latest", context_pack_obj.summary())
                setattr(state, "context_ledger_latest", context_pack.get("ledger", {}))
                setattr(state, "context_budget_latest", context_pack.get("budget_report", {}))
            except Exception:
                logger.warning("[AGENT] Context orchestration failed; falling back to legacy prompt blocks", exc_info=True)
                context_pack = None

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
            context_pack=context_pack,
        )
        messages = prompt_payload["messages"]
        request_metadata = self.session_response_builder.build_think_request_metadata(
            prompt_payload=prompt_payload,
            planned_decision=planned_decision,
        )

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
            timeout_status = self.session_response_builder.build_provider_timeout_runtime_status(
                provider=self.provider,
                timeout_seconds=self.chat_response_timeout_seconds,
                provider_display_name=self.session_response_builder.provider_display_name,
            )
            self._record_llm_runtime_status(
                provider=self.provider,
                model=self._active_model_name(self.provider),
                available=False,
                error=timeout_status.get("error"),
            )
            raw = None
        logger.info(f"[AGENT] LLM raw response type={type(raw).__name__}, "
                     f"preview={str(raw)[:500] if raw else 'None'}")
        if raw is None:
            raise ProviderGatewayError("LLM returned no decision")

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
            raise ProviderGatewayError("LLM returned an empty text response")

        # Already a dict (from JSON-mode response)
        if isinstance(raw, dict):
            return self._sanitize_llm_tool_decision(
                state,
                raw,
                allowed_tool_names=allowed_tool_names,
            )

        raise ProviderGatewayError(f"LLM returned unsupported response type: {type(raw).__name__}")

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

    def _llm_query_assist_provider(self, prompt: str) -> Optional[str]:
        """Optional synchronous adapter for non-authoritative query suggestions."""
        if not bool((self.config.get("log_hunting", {}) if isinstance(self.config, dict) else {}).get("llm_query_assist_enabled", False)):
            return None
        if self._provider_is_currently_unavailable(self.provider) or not self._provider_is_configured(self.provider):
            return None

        result: Dict[str, Any] = {"value": None}

        def _run_provider_call() -> None:
            try:
                result["value"] = asyncio.run(self._call_llm_text(prompt))
            except Exception as exc:  # pragma: no cover - defensive runtime boundary
                logger.warning("[AGENT] LLM query assistance provider degraded: %s", exc)
                result["value"] = None

        # Query planning is synchronous and may be called while the main agent
        # loop is already inside an event loop. Run the real router text path in
        # a short-lived thread rather than blocking on the active loop. The LLM
        # response remains advisory and is still validated by QueryValidator.
        worker = threading.Thread(target=_run_provider_call, daemon=True, name="llm-query-assist")
        worker.start()
        timeout_seconds = float((self.config.get("log_hunting", {}) if isinstance(self.config, dict) else {}).get("llm_query_assist_timeout_seconds", 8) or 8)
        worker.join(max(0.5, timeout_seconds))
        if worker.is_alive():
            logger.warning("[AGENT] LLM query assistance timed out after %.1fs", timeout_seconds)
            return None
        value = result.get("value")
        return str(value) if value else None

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
        if self.strict_only_production:
            return {
                "action": "runtime_blocked",
                "reasoning": "Strict-only production blocks heuristic legacy tool bootstrap outside the strict DAG executor.",
            }
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
        requested_timerange, timerange_source = self._reasoning_timerange_hint(state)
        plan = self.log_query_planner.build_plan(
            query=None,
            focus=self._latest_focus_candidate(state),
            analyst_request=self._latest_analyst_message(state),
            lane=str((state.investigation_plan or {}).get("lane") or ""),
            unresolved_questions=questions,
            entity_state=state.entity_state,
            timerange=requested_timerange,
            max_results=200,
        )
        investigation_query_plan = self.investigation_query_planner.build_log_hunt_plan(
            goal=state.goal,
            lane=str((state.investigation_plan or {}).get("lane") or ""),
            focus=plan.get("focus") or self._latest_focus_candidate(state) or "",
            unresolved_questions=questions,
            entity_state=state.entity_state,
            coverage_matrix=(state.reasoning_state or {}).get("coverage_matrix", {}) if isinstance(state.reasoning_state, dict) else {},
            timerange=str(plan.get("timerange") or requested_timerange),
            retry_state=(state.reasoning_state or {}).get("retry_state", {}) if isinstance(state.reasoning_state, dict) else {},
            max_results=int(plan.get("max_results") or 200),
        )
        if isinstance(state.reasoning_state, dict):
            state.reasoning_state["last_log_query_plan"] = copy.deepcopy(plan)
            state.reasoning_state["last_investigation_query_plan"] = copy.deepcopy(investigation_query_plan)
        effective_timerange = str((investigation_query_plan.get("log_query_plan") or {}).get("timerange") or plan.get("timerange") or requested_timerange)
        return {
            "query": plan.get("query_bundle") or self._build_reasoning_search_query(state, questions, plan=plan),
            "timerange": effective_timerange,
            "requested_timerange": requested_timerange,
            "effective_timerange": effective_timerange,
            "timerange_source": timerange_source,
            "reasoning": str(plan.get("reasoning") or "").strip(),
            "plan": plan,
            "investigation_query_plan": investigation_query_plan,
        }

    def _reasoning_timerange_hint(self, state: AgentState) -> tuple[str, str]:
        reasoning_state = state.reasoning_state if isinstance(state.reasoning_state, dict) else {}
        investigation_plan = state.investigation_plan if isinstance(state.investigation_plan, dict) else {}
        candidates = [
            ((reasoning_state.get("last_investigation_query_plan") or {}).get("log_query_plan") or {}).get("timerange") if isinstance(reasoning_state.get("last_investigation_query_plan"), dict) else "",
            (reasoning_state.get("last_investigation_query_plan") or {}).get("timerange") if isinstance(reasoning_state.get("last_investigation_query_plan"), dict) else "",
            (reasoning_state.get("last_log_query_plan") or {}).get("timerange") if isinstance(reasoning_state.get("last_log_query_plan"), dict) else "",
            ((investigation_plan.get("investigation_query_plan") or {}).get("log_query_plan") or {}).get("timerange") if isinstance(investigation_plan.get("investigation_query_plan"), dict) else "",
            (investigation_plan.get("log_query_plan") or {}).get("timerange") if isinstance(investigation_plan.get("log_query_plan"), dict) else "",
            investigation_plan.get("timerange"),
        ]
        for candidate in candidates:
            value = str(candidate or "").strip()
            if value:
                return value, "plan_context"
        return "24h", "default"

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

        if self._should_suppress_case_management_tools(state):
            local_tools = [
                tool for tool in local_tools
                if str(tool.get("function", {}).get("name") or "") not in {
                    "get_case_context",
                    "add_case_note",
                    "create_case",
                    "link_case_analysis",
                    "update_case_status",
                }
            ]

        if len(local_tools) + len(mcp_tools) <= max_tools:
            if self._is_lightweight_chat_session(state):
                return local_tools + mcp_tools
            if self._should_suppress_case_management_tools(state):
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

    def _should_suppress_case_management_tools(self, state: AgentState) -> bool:
        metadata = self._session_metadata(state.session_id)
        if self._session_case_id(state.session_id) or metadata.get("workdir_resume_case_context_available"):
            return False
        if metadata.get("resume_mode") == "workdir_deep_resume":
            return True
        return False

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
            or metadata.get("workdir_resume_case_context_available")
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

        try:
            contract = self.request_understanding.build_objective_contract(goal, {})
            for capability in getattr(contract, "capabilities_required", []) or []:
                resolution = self.capability_resolver.resolve(capability, objective=contract)
                if resolution.availability == "available" and resolution.selected_tool:
                    return resolution.selected_tool
        except Exception:
            pass

        # Log/SIEM/firewall hunt requests must not fall through to IOC enrichment.
        if any(
            kw in goal_lower
            for kw in (
                'splunk', 'siem', 'log', 'logs', 'fortigate', 'fortinet', 'firewall',
                'threat hunt', 'threat-hunt', 'hunt', 'auth event', 'eventcode',
                'sourcetype', 'sessionid', 'srcip', 'dstip', 'traffic',
            )
        ):
            return 'search_logs'

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

    def _validated_workdir_source_case_id(self, source_case_id: Optional[str]) -> Optional[str]:
        candidate = str(source_case_id or "").strip()
        if not candidate:
            return None
        if self.case_store is None:
            return candidate
        try:
            if self.case_store.get_case(candidate) is None:
                logger.info(
                    "[AGENT] Workdir resume source case_id %s is not present in case store; preserving it as source metadata only.",
                    candidate,
                )
                return None
        except Exception:
            logger.warning("[AGENT] Could not validate workdir resume source case_id", exc_info=True)
            return None
        return candidate

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
        if latest_message:
            fortigate_focus = self._focus_from_fortigate_kv(latest_message)
            if fortigate_focus:
                return fortigate_focus
        if latest_message and self._goal_has_observable(latest_message):
            params = self._guess_tool_params(latest_message)
            for key in ("ioc", "file_path"):
                candidate = str(params.get(key) or "").strip()
                if candidate and not self._is_bad_focus_candidate(candidate):
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
            if candidate and not self._is_bad_focus_candidate(candidate):
                return candidate

        return ""

    @staticmethod
    def _focus_from_fortigate_kv(text: str) -> str:
        pairs = dict(
            (key.lower(), value.strip().strip('"'))
            for key, value in re.findall(r'(\w+)=((?:"[^"]*")|\S+)', str(text or ""))
        )
        for key in ("srcip", "dstip", "sessionid", "devname", "devid"):
            value = str(pairs.get(key) or "").strip()
            if value:
                return value
        return ""

    @staticmethod
    def _is_bad_focus_candidate(value: str) -> bool:
        text = str(value or "").strip().lower()
        return not text or text.startswith("/") or "search_logs" in text or "threat logs" in text

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
        metadata = self._session_metadata(state.session_id)
        return self.session_response_builder.chat_follow_up_can_answer_from_context(
            is_chat_session=self._is_chat_session(state),
            metadata=metadata,
            requires_fresh_evidence=self._chat_follow_up_requires_fresh_evidence(state),
            has_context_state=bool(state.active_observations or state.reasoning_state or state.accepted_facts),
            latest_message=self._latest_analyst_message(state),
            goal_has_observable=self._goal_has_observable,
            execution_mode=str(metadata.get("chat_execution_mode") or ""),
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
        metadata = self._session_metadata(state.session_id)
        return self.session_response_builder.chat_prefers_direct_response(
            is_chat_session=self._is_chat_session(state),
            has_findings=bool(state.findings),
            focused_goal=self._focus_goal_text(state.goal),
            goal_has_observable=self._goal_has_observable,
            looks_like_artifact_submission=self._looks_like_artifact_submission,
            execution_mode=str(metadata.get("chat_execution_mode") or ""),
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

    def _chat_context_flags(self, state: AgentState) -> Dict[str, Any]:
        return self.session_context_service.build_chat_context_flags(
            state=state,
            metadata=self._session_metadata(state.session_id),
        )

    def _chat_prompt_policy(self, state: AgentState) -> Dict[str, str]:
        context_flags = self._chat_context_flags(state)
        return self.session_response_builder.build_chat_prompt_policy(
            is_chat_session=self._is_chat_session(state),
            chat_context_restored=bool(context_flags.get("chat_context_restored")),
            requires_fresh_evidence=bool(context_flags.get("requires_fresh_evidence")),
            restored_memory_scope=str(context_flags.get("restored_memory_scope") or ""),
            restored_memory_is_authoritative=bool(context_flags.get("restored_memory_is_authoritative")),
        )

    def _build_response_style_block(self, state: AgentState) -> str:
        return str(self._chat_prompt_policy(state).get("response_style_block") or "")

    def _build_chat_decision_block(self, state: AgentState) -> str:
        return str(self._chat_prompt_policy(state).get("chat_decision_block") or "")

    def _build_direct_chat_fallback_answer(self, goal: str) -> str:
        return self.session_response_builder.build_direct_chat_fallback_answer_with_runtime_status(
            provider_runtime_status=self.provider_runtime_status,
            provider_name=self.provider,
            normalize_provider=self._normalize_provider,
            active_model_name=self._active_model_name,
            provider_display_name=self.session_response_builder.provider_display_name,
            provider_runtime_error_excerpt=self.session_response_builder.provider_runtime_error_excerpt,
        )

    def _build_chat_model_unavailable_answer(self, state: AgentState) -> str:
        return self.session_response_builder.build_chat_model_unavailable_answer_with_runtime_status(
            state=state,
            provider_runtime_status=self.provider_runtime_status,
            provider_name=self.provider,
            normalize_provider=self._normalize_provider,
            active_model_name=self._active_model_name,
            build_direct_chat_fallback_answer=self._build_direct_chat_fallback_answer,
            goal=state.goal,
            authoritative_outcome=self._resolve_authoritative_outcome(state),
            fallback_evidence_points=lambda current_state, limit: self._fallback_evidence_points(current_state, limit=limit),
            build_chat_specific_fallback=self._build_chat_specific_fallback,
            provider_display_name=self.session_response_builder.provider_display_name,
            provider_runtime_error_excerpt=self.session_response_builder.provider_runtime_error_excerpt,
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

    def _describe_fallback_evidence(self, tool_name: str, result: Any) -> str:
        return self.session_response_builder.describe_fallback_evidence(
            tool_name=tool_name,
            result=result,
        )

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
            direct_help = self._build_direct_help_decision(state)
            if direct_help is not None:
                return direct_help
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

        reasoning_status, root_cause, has_strong_evidence = self._chat_evidence_summary(state)
        if not self._has_tool_result(state, "correlate_findings"):
            if self.session_response_builder.chat_evidence_allows_answer_without_tools(
                reasoning_status=reasoning_status,
                root_cause=root_cause,
                has_strong_evidence=has_strong_evidence,
                require_supported_root_cause_refs=False,
            ) and self.tools.get_tool("correlate_findings") is not None:
                return {
                    "action": "use_tool",
                    "tool": "correlate_findings",
                    "params": {"findings": state.findings[-8:]},
                    "reasoning": "Short-circuit: enough evidence is already available, so correlate before answering the analyst.",
                }
            return None

        if self.session_response_builder.chat_evidence_allows_answer_without_tools(
            reasoning_status=reasoning_status,
            root_cause=root_cause,
            has_strong_evidence=has_strong_evidence,
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

        reasoning_status, root_cause, has_strong_evidence = self._chat_evidence_summary(state)
        return self.session_response_builder.chat_evidence_allows_answer_without_tools(
            reasoning_status=reasoning_status,
            root_cause=root_cause,
            has_strong_evidence=has_strong_evidence,
        )

    def _chat_evidence_summary(self, state: AgentState) -> tuple[str, Dict[str, Any], bool]:
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
        has_strong_evidence = self._simple_chat_has_strong_evidence(state)
        return reasoning_status, root_cause, has_strong_evidence

    def _session_case_id(self, session_id: str) -> Optional[str]:
        session = self.store.get_session(session_id)
        if not session:
            return None
        return session.get('case_id')

    def _emit_agent_event(
        self,
        session_id: str,
        event_type: str,
        *,
        state: Optional[AgentState] = None,
        payload: Optional[Dict[str, Any]] = None,
        severity: str = "info",
        authoritative: bool = False,
        refs: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        event = AgentEvent.create(
            session_id=session_id,
            event_type=event_type,
            case_id=self._session_case_id(session_id),
            task_id=((state.reasoning_state or {}).get("soc_task_state", {}) or {}).get("task_id") if state and isinstance(state.reasoning_state, dict) else None,
            payload=payload or {},
            severity=severity,
            refs=refs or [],
            authoritative=authoritative,
        ).to_dict()
        if state is not None and isinstance(state.reasoning_state, dict):
            events = list(state.reasoning_state.get("agent_events", []))
            events.append(event)
            state.reasoning_state["agent_events"] = events[-100:]
        if self.governance_store is not None:
            try:
                self.governance_store.record_agent_event(**event)
            except Exception:
                logger.debug("[AGENT] Failed to persist agent event", exc_info=True)
        return event

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

    def _soc_task_for_execution(self, state: AgentState):
        from .soc_task_state import SOCTaskState
        objective = (state.reasoning_state or {}).get("objective_contract", {}) if isinstance(state.reasoning_state, dict) else {}
        soc_task_payload = (state.reasoning_state or {}).get("soc_task_state", {}) if isinstance(state.reasoning_state, dict) else {}
        soc_task = SOCTaskState.from_dict(soc_task_payload if isinstance(soc_task_payload, dict) else {})
        if not soc_task.raw_request:
            soc_task.raw_request = self._latest_analyst_message(state) or state.goal
        if not soc_task.objective_contract:
            soc_task.objective_contract = dict(objective)
        return soc_task, objective

    def _record_execution_envelope(self, state: AgentState, envelope: Dict[str, Any], original_decision: Dict[str, Any], bridged_decision: Dict[str, Any]) -> None:
        if not isinstance(state.reasoning_state, dict):
            return
        soc_task, _objective = self._soc_task_for_execution(state)
        action_record = {
            **dict(envelope.get("action") or {}),
            "binding": dict(envelope.get("binding") or {}),
            "preflight": dict(envelope.get("preflight") or {}),
            "policy": dict(envelope.get("policy") or {}),
            "execution_envelope_ref": envelope.get("schema_version"),
        }
        soc_task.actions = [*list(soc_task.actions or []), action_record][-12:]
        preflight = envelope.get("preflight") if isinstance(envelope.get("preflight"), dict) else {}
        policy = envelope.get("policy") if isinstance(envelope.get("policy"), dict) else {}
        for event in (preflight.get("progress_event"), {"event_type": "tool_policy_decision", "status": policy.get("status"), "capability_id": envelope.get("capability_id"), "tool_name": envelope.get("tool_name"), "reasons": policy.get("reasons", []), "warnings": policy.get("warnings", [])}):
            if isinstance(event, dict) and event.get("event_type"):
                soc_task.add_progress(**event)
        state.reasoning_state["soc_task_state"] = soc_task.to_dict()
        state.reasoning_state["progress_events"] = list(soc_task.progress_events)
        audit = list(state.reasoning_state.get("capability_action_audit", []))
        audit.append({"original_action": dict(original_decision), "bridged_action": dict(bridged_decision), "protocol": envelope, "authoritative_for_verdict": False})
        state.reasoning_state["capability_action_audit"] = audit[-20:]

    def _normalize_legacy_tool_decision(self, state: AgentState, decision: Dict[str, Any]) -> Dict[str, Any]:
        try:
            soc_task, objective = self._soc_task_for_execution(state)
            envelope = self.capability_action_executor.from_legacy_decision(
                decision=decision,
                task_state=soc_task,
                objective_contract=objective,
                context={"session_id": state.session_id, "legacy_direct_tool": True},
            )
            payload = envelope.to_dict()
            if not envelope.allowed:
                blocked = {
                    "action": "request_approval" if payload.get("policy", {}).get("approval_required") else "ask_clarification" if payload.get("preflight", {}).get("clarification_required") else "degraded_capability",
                    "capability": envelope.capability_id,
                    "capability_id": envelope.capability_id,
                    "tool": envelope.tool_name or decision.get("tool"),
                    "params": envelope.params,
                    "execution_envelope": payload,
                    "preflight": payload.get("preflight", {}),
                    "policy": payload.get("policy", {}),
                    "reasoning": envelope.reason or "Capability execution boundary blocked direct tool execution.",
                }
                self._record_execution_envelope(state, payload, decision, blocked)
                return blocked
            normalized = {**decision, "tool": envelope.tool_name, "params": envelope.params, "capability": envelope.capability_id, "capability_id": envelope.capability_id, "execution_envelope": payload}
            self._record_execution_envelope(state, payload, decision, normalized)
            return normalized
        except Exception as exc:
            logger.debug("[AGENT] Capability boundary normalization failed", exc_info=True)
            if self.allow_legacy_direct_tool_fallback:
                return {**decision, "execution_boundary_warning": str(exc)}
            return {"action": "degraded_capability", "tool": decision.get("tool"), "params": decision.get("params", {}), "reasoning": str(exc)}

    def _soc_alert_file_analysis_blocker(self, state: AgentState, capability: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        reasoning = state.reasoning_state if isinstance(getattr(state, "reasoning_state", None), dict) else {}
        soc_task = reasoning.get("soc_task_state", {}) if isinstance(reasoning.get("soc_task_state"), dict) else {}
        compiled = soc_task.get("compiled_input", {}) if isinstance(soc_task.get("compiled_input"), dict) else reasoning.get("compiled_input", {})
        if capability != "file.analyze.static" or not isinstance(compiled, dict) or compiled.get("input_kind") != "soc_alert_text":
            return None
        if params.get("file_path") or params.get("hash") or params.get("sha256"):
            return None
        return {
            "action": "ask_clarification",
            "capability": capability,
            "capability_id": capability,
            "params": {},
            "reasoning": "SOC alert text must route to log.search/correlation; file analysis needs an explicit file path or hash artifact.",
            "preferred_capability": "log.search",
        }

    def _bridge_capability_decision(self, state: AgentState, decision: Dict[str, Any]) -> Dict[str, Any]:
        objective = (state.reasoning_state or {}).get("objective_contract", {}) if isinstance(state.reasoning_state, dict) else {}
        soc_task_payload = (state.reasoning_state or {}).get("soc_task_state", {}) if isinstance(state.reasoning_state, dict) else {}
        capability = str(decision.get("capability") or decision.get("capability_id") or "").strip()
        alert_block = self._soc_alert_file_analysis_blocker(state, capability, dict(decision.get("params") or {}))
        if alert_block is not None:
            return alert_block
        protocol_record: Dict[str, Any] = {}
        if capability:
            try:
                from .soc_task_state import SOCTaskState
                soc_task = SOCTaskState.from_dict(soc_task_payload if isinstance(soc_task_payload, dict) else {})
                if not soc_task.raw_request:
                    soc_task.raw_request = self._latest_analyst_message(state) or state.goal
                if not soc_task.objective_contract:
                    soc_task.objective_contract = dict(objective)
                action = CapabilityAction(
                    task_ref=soc_task.task_id,
                    objective_ref=str(objective.get("contract_id") or ""),
                    capability_id=capability,
                    action_type="collect_evidence",
                    bound_params=dict(decision.get("params") or {}),
                    rationale=str(decision.get("reasoning") or "Capability-first bridge."),
                    legacy_tool_hint=decision.get("tool"),
                )
                binding = self.parameter_binder.bind(action, soc_task, objective, {})
                action.bound_params = dict(binding.params)
                preflight = self.preflight_validator.validate(action, binding, soc_task, self.tools, self.capability_resolver)
                protocol_record = {"action": action.to_dict(), "binding": binding.to_dict(), "preflight": preflight.to_dict()}
                if preflight.progress_event:
                    events = list(soc_task.progress_events)
                    events.append(preflight.progress_event)
                    soc_task.progress_events = events[-50:]
                soc_task.actions = [*list(soc_task.actions or []), {**action.to_dict(), "binding": binding.to_dict(), "preflight": preflight.to_dict()}][-12:]
                soc_task.pending_clarifications = self.clarification_gate.evaluate(soc_task, soc_task.actions).to_dict().get("payloads", [])
                state.reasoning_state["soc_task_state"] = soc_task.to_dict()
                state.reasoning_state["progress_events"] = list(soc_task.progress_events)
                if not preflight.allowed:
                    blocked = {
                        "action": "request_approval" if preflight.approval_required else "ask_clarification" if preflight.clarification_required else "degraded_capability",
                        "capability": capability,
                        "capability_id": capability,
                        "params": preflight.normalized_params,
                        "preflight": preflight.to_dict(),
                        "reasoning": "; ".join(preflight.blocking_reasons or preflight.warnings) or "Preflight blocked execution.",
                    }
                    return blocked
                decision = {**decision, "params": preflight.normalized_params}
            except Exception as exc:
                protocol_record = {"protocol_error": str(exc)}
        bridged = self.capability_resolver.decision_to_tool_action(decision, objective=objective, state=state)
        bridged_block = self._soc_alert_file_analysis_blocker(state, str(bridged.get("capability_id") or capability), dict(bridged.get("params") or {}))
        if bridged_block is not None:
            return bridged_block
        if bridged.get("action") == "use_tool" and "execution_envelope" not in bridged:
            bridged["execution_envelope"] = {
                "allowed": True,
                "capability_id": bridged.get("capability_id") or capability,
                "source": "capability_resolver_bridge",
            }
        if isinstance(state.reasoning_state, dict):
            audit = list(state.reasoning_state.get("capability_action_audit", []))
            audit.append({
                "original_action": dict(decision),
                "bridged_action": dict(bridged),
                "protocol": protocol_record,
                "authoritative_for_verdict": False,
            })
            state.reasoning_state["capability_action_audit"] = audit[-12:]
        return bridged

    def _record_degraded_capability(self, session_id: str, state: AgentState, decision: Dict[str, Any]) -> None:
        finding = {
            "type": "capability_degraded",
            "capability": decision.get("capability") or decision.get("capability_id"),
            "availability": decision.get("availability"),
            "message": decision.get("degradation_reason") or "Capability could not be resolved to an available tool.",
            "resolution": decision.get("resolution", {}),
            "params": decision.get("params", {}),
        }
        state.add_finding(finding)
        if isinstance(state.reasoning_state, dict):
            degraded = list(state.reasoning_state.get("degraded_capabilities", []))
            degraded.append(finding)
            state.reasoning_state["degraded_capabilities"] = degraded[-8:]
        self.store.add_step(session_id, state.step_count, 'capability_degraded', json.dumps(finding, default=str))
        self.store.update_session_findings(session_id, state.findings)

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
        envelope = decision.get("execution_envelope") if isinstance(decision.get("execution_envelope"), dict) else {}
        if self.require_capability_boundary and decision.get("capability_id") and self.capability_action_executor.capability_for_tool(tool_name) and not envelope.get("allowed"):
            return {"error": "Capability execution envelope is required before tool execution.", "error_type": "policy_blocked", "tool": tool_name}

        start = time.time()
        try:
            tool_def = self.tools.get_tool(tool_name)
            if tool_def is None:
                result = {"error": f"Tool not found: {tool_name}"}
            elif tool_def.source == 'local':
                result = await self.tools.execute_local_tool(
                    tool_name,
                    _execution_context={
                        "capability_enforced": bool(envelope.get("allowed")),
                        "capability_id": envelope.get("capability_id") or decision.get("capability_id"),
                        "execution_envelope": envelope,
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
                        "investigation_query_plan": (
                            copy.deepcopy(state.reasoning_state.get("last_investigation_query_plan", {}))
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
        try:
            await asyncio.wait_for(evt.wait(), timeout=1800)
        except asyncio.TimeoutError:
            self.session_response_builder.mark_approval_timeout(
                state=state,
                reviewed_at=datetime.now(timezone.utc).isoformat(),
            )

        approval = self.session_response_builder.consume_approval_outcome(state=state)
        if approval is None:
            return False
        return approval.get("approved", False)

    # ================================================================== #
    #  Summary generation
    # ================================================================== #

    @staticmethod
    def _resolve_authoritative_outcome(state: AgentState) -> Optional[Dict[str, str]]:
        """Return the best evidence-backed outcome seen in aggregated decisions."""
        aggregate = getattr(state, "deterministic_decision", None)
        if isinstance(aggregate, dict) and aggregate.get("authoritative_for_verdict") and aggregate.get("verdict"):
            return {
                "kind": "verdict",
                "label": str(aggregate.get("verdict") or "UNKNOWN").upper(),
                "source": str(aggregate.get("source") or "decision_aggregator"),
            }
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
        self,
        state: AgentState,
        authoritative_outcome: Optional[Dict[str, str]],
        include_runtime_notice: bool = True,
    ) -> str:
        """Build a deterministic evidence-backed answer when LLM calls fail."""
        return self.session_response_builder.build_fallback_answer(
            state=state,
            authoritative_outcome=authoritative_outcome,
            build_evidence_backed_answer=self._build_evidence_backed_answer,
            include_runtime_notice=include_runtime_notice,
        )

    def _build_chat_specific_fallback(self, state: AgentState) -> str:
        """Answer simple analyst lookup questions directly from collected evidence."""
        return self.session_response_builder.build_chat_specific_fallback(
            is_chat_session=self._is_chat_session(state),
            focused_goal=self._focus_goal_text(state.goal),
            findings=list(state.findings or []),
            reasoning_state=state.reasoning_state if isinstance(state.reasoning_state, dict) else None,
        )

    def _llm_unavailable_notice(self) -> str:
        return self.session_response_builder.build_runtime_unavailable_notice(
            provider_runtime_status=self.provider_runtime_status,
            provider_name=self.provider,
            normalize_provider=self._normalize_provider,
            active_model_name=self._active_model_name,
            provider_display_name=self.session_response_builder.provider_display_name,
            provider_runtime_error_excerpt=self.session_response_builder.provider_runtime_error_excerpt,
        )

    def _fallback_evidence_points(self, state: AgentState, limit: int = 3) -> List[str]:
        return self.session_response_builder.build_fallback_evidence_points(
            findings=list(state.findings or []),
            describe_fallback_evidence=lambda tool_name, result: self.session_response_builder.describe_fallback_evidence(
                tool_name=tool_name,
                result=result,
            ),
            limit=limit,
        )

    async def _generate_summary(self, state: AgentState) -> str:
        """Ask the LLM to produce a concise investigation summary."""
        authoritative_outcome = self._resolve_authoritative_outcome(state)

        findings_json = json.dumps(state.findings[-15:], default=str, indent=1)
        summary_context_pack = None
        if self.context_orchestrator is not None and self.context_orchestrator.enabled():
            try:
                pack_obj = self.context_orchestrator.build_pack(
                    state=state,
                    request=ContextRequest(
                        session_id=state.session_id,
                        step_number=state.step_count,
                        objective="summary",
                        model=self._active_model_name(self.provider),
                        prompt_mode="summary_explanation",
                        analyst_focus=self._latest_analyst_message(state) or self._latest_focus_candidate(state) or state.goal,
                        tools_block="",
                        findings_block=self._build_findings_block(state),
                        reasoning_block=self._build_reasoning_block(state),
                    ),
                )
                summary_context_pack = pack_obj.to_dict()
                summary_context_pack["summary"] = pack_obj.summary()
                setattr(state, "context_pack_latest", summary_context_pack)
                setattr(state, "context_pack_summary_latest", pack_obj.summary())
                setattr(state, "context_ledger_latest", summary_context_pack.get("ledger", {}))
                setattr(state, "context_budget_latest", summary_context_pack.get("budget_report", {}))
            except Exception:
                logger.warning("[AGENT] Summary context orchestration failed; falling back to legacy summary prompt", exc_info=True)
        payload = self.prompt_composer.build_summary_payload(
            state=state,
            response_style_block=self._build_response_style_block(state),
            reasoning_block=self._build_reasoning_block(state),
            step_count=state.step_count,
            findings_json=findings_json,
            context_pack=summary_context_pack,
        )
        prompt = str(payload["prompt"])

        try:
            return await self.session_response_builder.generate_summary_with_runtime_fallback(
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
            return self.session_response_builder.build_summary_fallback_answer(
                state=state,
                authoritative_outcome=authoritative_outcome,
                is_chat_session=self._is_chat_session,
                provider_is_currently_unavailable=self._provider_is_currently_unavailable,
                provider_name=self.provider,
                build_chat_model_unavailable_answer=self._build_chat_model_unavailable_answer,
                build_fallback_answer=self._build_fallback_answer,
            )

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
        return await self.provider_gateway.chat(
            invoke_provider_chat=self._chat_with_tools_via_provider,
            messages=messages,
            tools_payload=tools_payload,
            request_metadata=request_metadata,
        )

    async def _call_llm_text(self, prompt: str) -> Optional[str]:
        """Simple single-prompt call returning plain text (for summaries)."""
        return await self.provider_gateway.text(
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
        if str(provider_name or "").strip().lower() == "openrouter" and not self.router_api_key:
            return await self._openrouter_chat(request.get("messages", messages), request.get("tools", tools_json))
        return await self.provider_gateway.dispatch_chat_provider(
            provider_name=request.get("provider", provider_name),
            request=request,
            extract_chat_messages=self.provider_chat_gateway.extract_chat_messages,
            extract_chat_tools=self.provider_chat_gateway.extract_chat_tools,
            invoke_router=self._router_chat,
            logger=logger,
            normalize_provider=self._normalize_provider,
        )

    def _build_direct_chat_opening_answer(self, state: AgentState) -> str:
        """Return an immediate conversational answer for chat turns without artifacts."""
        return self.session_response_builder.build_direct_chat_opening_answer(
            prefers_direct_response=self._chat_prefers_direct_response(state),
            latest_message=self._latest_analyst_message(state),
        )

    def _is_capability_help_request(self, state: AgentState) -> bool:
        """Return True for direct capability/help chat turns that should not enter investigation gating."""
        if not self._is_chat_session(state):
            return False
        if state.findings:
            return False
        metadata = self._session_metadata(state.session_id)
        execution_mode = str(metadata.get("chat_execution_mode") or "").strip().lower()
        chat_intent = str(metadata.get("chat_intent") or "").strip().lower()
        if execution_mode != ChatIntentRouter.DIRECT_RESPONSE_MODE:
            return False
        if bool(metadata.get("chat_has_observable")) or bool(metadata.get("chat_looks_like_artifact")):
            return False
        soc_task = state.reasoning_state.get("soc_task_state", {}) if isinstance(state.reasoning_state, dict) else {}
        soc_intent = str(soc_task.get("intent") or "").strip().lower() if isinstance(soc_task, dict) else ""
        soc_lane = str(soc_task.get("lane") or "").strip().lower() if isinstance(soc_task, dict) else ""
        required_capabilities = list(soc_task.get("required_capabilities") or []) if isinstance(soc_task, dict) else []
        if chat_intent in {"capability_question", "greeting"}:
            return True
        if soc_intent == "config_capability_question":
            return True
        return soc_lane == "config" and "config.capability.explain" in required_capabilities

    def _build_direct_help_decision(self, state: AgentState) -> Optional[Dict[str, Any]]:
        """Build deterministic capability-help answer before investigation or final-answer evidence gates."""
        if not self._is_capability_help_request(state):
            return None
        soc_task = state.reasoning_state.get("soc_task_state", {}) if isinstance(state.reasoning_state, dict) else {}
        if isinstance(soc_task, dict):
            soc_task["lane"] = "config"
            soc_task["intent"] = "config_capability_question"
            soc_task["required_capabilities"] = ["config.capability.explain"]
            soc_task["answer_mode"] = "direct_help"
            progress_events = list(soc_task.get("progress_events") or [])
            progress_events.append({
                "event": "direct_help_short_circuit",
                "answer_mode": "direct_help",
                "lane": "config",
                "capability_id": "config.capability.explain",
                "status": "answered_without_investigation",
            })
            soc_task["progress_events"] = progress_events[-50:]
            state.reasoning_state["soc_task_state"] = soc_task
            state.reasoning_state["progress_events"] = list(soc_task["progress_events"])
            state.reasoning_state["answer_mode"] = "direct_help"
            state.reasoning_state["direct_help"] = {
                "answer_mode": "direct_help",
                "lane": "config",
                "capability_id": "config.capability.explain",
            }
        return {
            "action": "final_answer",
            "answer": self._build_direct_chat_opening_answer(state),
            "verdict": "UNKNOWN",
            "answer_mode": "direct_help",
            "lane": "config",
            "capability_id": "config.capability.explain",
            "skip_final_answer_gate": True,
            "reasoning": "Direct capability/help chat turn answered without investigation tools or evidence-gated verdict synthesis.",
        }

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

    async def _llm_schema_interpretation_provider(self, messages: List[Dict[str, Any]], metadata: Dict[str, Any]) -> Optional[Any]:
        provider_name = self._normalize_provider(self.provider)
        request = self.provider_chat_gateway.build_interpretation_request(
            provider_name=provider_name,
            messages=messages,
            prompt_envelope=metadata,
        )
        return await self.provider_gateway.dispatch_chat_provider(
            provider_name=request.get("provider", provider_name),
            request=request,
            extract_chat_messages=self.provider_chat_gateway.extract_chat_messages,
            extract_chat_tools=self.provider_chat_gateway.extract_chat_tools,
            invoke_router=self._router_chat,
            logger=logger,
            normalize_provider=self._normalize_provider,
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
            invoke_router=self._router_generate,
            logger=logger,
            normalize_provider=self._normalize_provider,
        )

    def _provider_failure_message(self) -> str:
        """Return a provider-aware troubleshooting hint."""
        return self.session_response_builder.provider_failure_message(
            provider=self.provider,
            base_url=self.router_base_url,
            model=self.router_model,
        )

    async def _router_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Canonical router /chat/completions with optional tool calling."""
        if not self.router_api_key:
            self._record_llm_runtime_status(
                provider='router',
                model=self._active_model_name('router'),
                available=False,
                error="Router API key not configured.",
            )
            logger.warning("[AGENT] No router API key configured")
            raise ProviderGatewayError("Router API key not configured")

        try:
            headers = {
                "Authorization": f"Bearer {self.router_api_key}",
                "Content-Type": "application/json",
            }
            payload: Dict[str, Any] = {
                "model": self.router_model,
                "messages": messages,
                "temperature": 0.2,
                "stream": False,
            }
            if tools:
                payload["tools"] = tools

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.router_base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='router',
                            model=self._active_model_name('router'),
                            available=False,
                            error=f"Router HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] Router chat error {resp.status}: {body[:300]}")
                        raise ProviderGatewayError(f"Router chat HTTP {resp.status}: {body[:200]}")

                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='router',
                        model=self._active_model_name('router'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}

                    if message.get("tool_calls"):
                        return {"tool_calls": message["tool_calls"]}

                    return message.get("content", "")

        except Exception as exc:
            error_detail = str(exc).strip() or type(exc).__name__
            self._record_llm_runtime_status(
                provider='router',
                model=self._active_model_name('router'),
                available=False,
                error=f"Router request failed: {error_detail}",
            )
            logger.error("[AGENT] Router chat failed: %s", error_detail, exc_info=True)
            raise ProviderGatewayError(f"Router chat request failed: {error_detail}") from exc

    async def _router_generate(self, prompt: str) -> Optional[str]:
        """Canonical router /chat/completions for plain text responses."""
        if not self.router_api_key:
            self._record_llm_runtime_status(
                provider='router',
                model=self._active_model_name('router'),
                available=False,
                error="Router API key not configured.",
            )
            raise ProviderGatewayError("Router API key not configured")

        try:
            headers = {
                "Authorization": f"Bearer {self.router_api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.router_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "stream": False,
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.router_base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        self._record_llm_runtime_status(
                            provider='router',
                            model=self._active_model_name('router'),
                            available=False,
                            error=f"Router HTTP {resp.status}: {body[:200]}",
                            http_status=resp.status,
                        )
                        logger.error(f"[AGENT] Router generate error {resp.status}: {body[:200]}")
                        raise ProviderGatewayError(f"Router generate HTTP {resp.status}: {body[:200]}")
                    data = await resp.json()
                    self._record_llm_runtime_status(
                        provider='router',
                        model=self._active_model_name('router'),
                        available=True,
                        http_status=resp.status,
                    )
                    choices = data.get("choices", [])
                    message = choices[0].get("message", {}) if choices else {}
                    return message.get("content", "")
        except Exception as exc:
            self._record_llm_runtime_status(
                provider='router',
                model=self._active_model_name('router'),
                available=False,
                error=f"Router request failed: {exc}",
            )
            logger.error(f"[AGENT] Router generate failed: {exc}")
            raise ProviderGatewayError(f"Router generate request failed: {exc}") from exc

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
        name = self.tools.resolve_tool_name(func.get("name", ""))
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
