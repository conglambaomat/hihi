"""Workflow execution helpers and dependency validation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class WorkflowService:
    """Bridge workflow definitions to existing CABTA sessions and playbooks."""

    def __init__(self, workflow_registry, agent_store, case_store=None, governance_store=None):
        self.workflow_registry = workflow_registry
        self.agent_store = agent_store
        self.case_store = case_store
        self.governance_store = governance_store

    @staticmethod
    def _default_plan_contract() -> Dict[str, Any]:
        return {
            "required": True,
            "planner": "InvestigationPlanner",
            "pivot_signals_supported": True,
            "resume_signals_supported": True,
        }

    @staticmethod
    def _default_evidence_contract() -> Dict[str, Any]:
        return {
            "required": True,
            "require_typed_observations": False,
            "require_triage_contract_evidence": False,
            "minimum_required_fields": 0,
        }

    @staticmethod
    def _normalize_contracts(value: Any) -> List[Dict[str, Any]]:
        return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    @staticmethod
    def _runtime_truth_contract(*, dependency_status: Any = "unknown") -> Dict[str, Any]:
        return {
            "contract_version": "workflow-runtime-contract/v2",
            "deterministic_verdict_owner": "CABTA deterministic core",
            "dependency_status": str(dependency_status or "unknown"),
            "runtime_truth": "workflow_registry_plus_runtime_enforcement",
            "governance_contract_version": "governance-contract/v2",
        }

    def _triage_contract_runtime(self, plan_payload: Dict[str, Any], typed_observations: List[Any]) -> Dict[str, Any]:
        contracts = self._normalize_contracts(plan_payload.get("triage_contracts"))
        observation_text = " ".join(str(item).lower() for item in typed_observations)
        contract_statuses: List[Dict[str, Any]] = []
        satisfied_count = 0
        blocked_contract_ids: List[str] = []
        for contract in contracts:
            contract_id = str(contract.get("contract_id") or "").strip()
            required_fields = self._normalized_list(contract.get("required_fields"))
            observed_fields = [field for field in required_fields if field.lower() in observation_text]
            ready = len(observed_fields) == len(required_fields) if required_fields else bool(typed_observations)
            if ready:
                satisfied_count += 1
            elif contract_id:
                blocked_contract_ids.append(contract_id)
            contract_statuses.append(
                {
                    "contract_id": contract_id,
                    "title": str(contract.get("title") or contract_id).strip(),
                    "required_fields": required_fields,
                    "observed_fields": observed_fields,
                    "ready": ready,
                    "deterministic_verdict_owner": str(
                        contract.get("deterministic_verdict_owner") or "CABTA deterministic core"
                    ).strip()
                    or "CABTA deterministic core",
                }
            )
        return {
            "declared": bool(contracts),
            "contract_count": len(contracts),
            "satisfied_count": satisfied_count,
            "blocked_contract_ids": blocked_contract_ids,
            "contracts": contract_statuses,
            "ready": bool(contracts) and satisfied_count == len(contracts) if contracts else True,
        }

    @staticmethod
    def _goal_present(goal: Any) -> bool:
        return bool(str(goal or "").strip())

    @staticmethod
    def _normalized_list(value: Any) -> List[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]

    def _execution_contracts(self, workflow: Dict[str, Any], workflow_contract: Optional[Dict[str, Any]] = None) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        contract_source = workflow_contract if isinstance(workflow_contract, dict) else workflow
        execution_contract = contract_source.get("execution_contract", {}) if isinstance(contract_source, dict) else {}
        plan_contract = execution_contract.get("plan_contract", self._default_plan_contract())
        governance_contract = execution_contract.get("governance_contract", {}) if isinstance(execution_contract, dict) else {}
        return execution_contract, plan_contract, governance_contract

    @staticmethod
    def _count_list(value: Any) -> int:
        return len(value) if isinstance(value, list) else 0

    @staticmethod
    def _supports_headless_execution(workflow: Dict[str, Any], execution_contract: Dict[str, Any]) -> bool:
        return bool(
            execution_contract.get(
                "supports_headless_execution",
                workflow.get("headless_ready") and workflow.get("approval_mode", "inherited") != "analyst",
            )
        )

    @staticmethod
    def _execution_surface_contract(
        workflow: Dict[str, Any],
        execution_contract: Dict[str, Any],
        dependency_status: Dict[str, Any],
    ) -> Dict[str, Any]:
        supports_headless_execution = WorkflowService._supports_headless_execution(workflow, execution_contract)
        headless_declared = bool(workflow.get("headless_ready"))
        dependency_state = str(dependency_status.get("status") or "unknown")
        optional_runtime = dict(dependency_status.get("optional_runtime") or {})
        degraded_optional = list(optional_runtime.get("degraded_dependencies") or [])

        headless_blockers: List[str] = []
        if not headless_declared:
            headless_blockers.append("workflow_not_declared_headless_ready")
        if not supports_headless_execution:
            headless_blockers.append("approval_checkpoints_require_interactive_runtime")

        return {
            "headless_declared": headless_declared,
            "headless_ready": headless_declared and dependency_state != "blocked",
            "supports_headless_execution": supports_headless_execution,
            "interactive_runtime_required": not supports_headless_execution,
            "headless_blockers": headless_blockers,
            "runtime_mode": "interactive_only" if not supports_headless_execution else "headless_or_interactive",
            "optional_runtime_degraded": bool(optional_runtime.get("degraded")),
            "optional_runtime_blockers": degraded_optional,
            "dependency_status": dependency_state,
            "runtime_status": "blocked" if headless_blockers or dependency_state == "blocked" else dependency_state,
            "case_truth_ready": dependency_state in {"ready", "degraded"},
            "headless_execution_eligible": supports_headless_execution and headless_declared and dependency_state != "blocked",
            "capability_scope": "workflow_runtime_contract",
            "runtime_truth": "workflow_registry_plus_runtime_enforcement",
            "contract_version": "workflow-runtime-contract/v2",
        }

    def evaluate_runtime_readiness(
        self,
        app: Any,
        workflow_id: str,
        *,
        goal: str = "",
        params: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        include_dependency_status: bool = True,
        dependency_status_override: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        workflow = self.workflow_registry.get_workflow(workflow_id)
        if workflow is None:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        registry_describe = getattr(self.workflow_registry, "describe_workflow", None)
        workflow_contract = (
            registry_describe(workflow_id)
            if callable(registry_describe)
            else dict(workflow)
        )
        execution_contract, plan_contract, governance_contract = self._execution_contracts(workflow, workflow_contract)
        dependency_status = (
            dict(dependency_status_override)
            if isinstance(dependency_status_override, dict)
            else (self.validate_dependencies(app, workflow_id) if include_dependency_status else {"status": "unknown"})
        )
        dependency_status_for_surface = dependency_status
        params = dict(params or {})
        metadata = dict(metadata or {})

        plan_payload = params.get("investigation_plan") or metadata.get("investigation_plan") or {}
        if not isinstance(plan_payload, dict):
            plan_payload = {}
        goal_present = self._goal_present(goal) or self._goal_present(params.get("workflow_goal"))
        plan_signal_count = self._count_list(plan_payload.get("next_action_signals")) + self._count_list(plan_payload.get("resume_signals"))
        plan_signals_ready = plan_signal_count > 0
        plan_ready = bool(plan_payload) or goal_present or bool(params)

        evidence_contract = execution_contract.get("evidence_contract", self._default_evidence_contract()) if isinstance(execution_contract, dict) else self._default_evidence_contract()
        evidence_refs = params.get("evidence_refs") or metadata.get("evidence_refs") or []
        typed_observations = params.get("typed_observations") or metadata.get("typed_observations") or []
        triage_contract_runtime = self._triage_contract_runtime(plan_payload, typed_observations if isinstance(typed_observations, list) else [])
        requires_triage_contract_evidence = bool(
            isinstance(evidence_contract, dict) and evidence_contract.get("require_triage_contract_evidence")
        )
        if requires_triage_contract_evidence and not triage_contract_runtime["declared"]:
            triage_contract_runtime = {
                **triage_contract_runtime,
                "ready": False,
                "blocked_contract_ids": [*triage_contract_runtime["blocked_contract_ids"], "missing_triage_contract"],
            }
        evidence_ready = bool(evidence_refs or typed_observations or params.get("observable_summary") or goal_present or params)
        if isinstance(evidence_contract, dict) and evidence_contract.get("require_typed_observations"):
            evidence_ready = bool(typed_observations)
        if requires_triage_contract_evidence:
            evidence_ready = evidence_ready and triage_contract_runtime["ready"]
        minimum_required_fields = int(evidence_contract.get("minimum_required_fields", 0) or 0) if isinstance(evidence_contract, dict) else 0
        if minimum_required_fields > 0:
            evidence_ready = evidence_ready and sum(
                len(item.get("observed_fields", [])) for item in triage_contract_runtime["contracts"]
            ) >= minimum_required_fields

        fallback_paths = self._normalized_list(execution_contract.get("fallback_paths"))
        stop_conditions = self._normalized_list(execution_contract.get("stop_conditions"))
        fallback_contract = {
            "declared": bool(fallback_paths),
            "paths": fallback_paths,
            "available": dependency_status.get("status") in {"ready", "degraded"},
            "active": bool(fallback_paths) and dependency_status.get("status") == "degraded",
        }
        stop_condition_contract = {
            "declared": bool(stop_conditions),
            "conditions": stop_conditions,
            "triggered": [],
        }
        if dependency_status.get("status") == "blocked":
            stop_condition_contract["triggered"].append("dependencies_blocked")
        if plan_contract.get("required", True) and not plan_ready:
            stop_condition_contract["triggered"].append("missing_plan")
        if plan_contract.get("required", True) and not plan_signals_ready and not goal_present:
            stop_condition_contract["triggered"].append("missing_plan_signals")
        if evidence_contract.get("required", True) and not evidence_ready:
            stop_condition_contract["triggered"].append("missing_evidence")
        if not triage_contract_runtime["ready"] and (
            requires_triage_contract_evidence or triage_contract_runtime["declared"]
        ):
            stop_condition_contract["triggered"].append("missing_triage_contract_evidence")

        governance_store = self.governance_store or getattr(app.state, "governance_store", None)
        governance_ready = governance_store is not None
        approval_mode = str(workflow.get("approval_mode") or "inherited").strip().lower()
        if governance_contract.get("approvals_required") and not governance_contract.get("decision_logging_supported", True):
            governance_ready = False

        blocking_reasons: List[str] = list(stop_condition_contract["triggered"])
        if governance_contract.get("decision_logging_supported", True) and not governance_ready:
            blocking_reasons.append("missing_governance_store")
            stop_condition_contract["triggered"].append("missing_governance_store")

        execution_surface = self._execution_surface_contract(
            workflow,
            execution_contract,
            dependency_status_for_surface,
        )
        interactive_runtime_blocked = bool(execution_surface.get("interactive_runtime_required"))
        if interactive_runtime_blocked:
            blocking_reasons.append("interactive_runtime_required")
            stop_condition_contract["triggered"].append("interactive_runtime_required")

        status = "blocked" if blocking_reasons else dependency_status.get("status", "ready")
        if status == "unknown":
            status = "ready"
        dependency_case_truth_ready = dependency_status.get("status") in {"ready", "degraded"}
        return {
            "workflow_id": workflow_id,
            "status": status,
            "ready": not blocking_reasons and dependency_status.get("status") != "blocked",
            "case_truth_ready": dependency_case_truth_ready,
            "blocking_reasons": blocking_reasons,
            "runtime_truth_contract": self._runtime_truth_contract(
                dependency_status=dependency_status.get("status", "unknown")
            ),
            "plan_contract": {
                **plan_contract,
                "ready": plan_ready,
                "signal_count": plan_signal_count,
                "goal_present": goal_present,
            },
            "evidence_contract": {
                "required": evidence_contract.get("required", True),
                "require_typed_observations": bool(evidence_contract.get("require_typed_observations", False)),
                "require_triage_contract_evidence": bool(evidence_contract.get("require_triage_contract_evidence", False)),
                "minimum_required_fields": minimum_required_fields,
                "evidence_refs_count": len(evidence_refs) if isinstance(evidence_refs, list) else 0,
                "typed_observation_count": len(typed_observations) if isinstance(typed_observations, list) else 0,
                "triage_contract_runtime": triage_contract_runtime,
                "ready": evidence_ready,
            },
            "fallback_contract": fallback_contract,
            "stop_condition_contract": stop_condition_contract,
            "governance_contract": {
                "contract_version": governance_contract.get("contract_version", "governance-contract/v2"),
                "deterministic_verdict_owner": governance_contract.get("deterministic_verdict_owner", "CABTA deterministic core"),
                "decision_logging_supported": bool(governance_contract.get("decision_logging_supported", True)),
                "feedback_logging_supported": bool(governance_contract.get("feedback_logging_supported", True)),
                "approvals_required": bool(
                    governance_contract.get("approvals_required", False)
                    or approval_mode in {"analyst", "analyst-gated"}
                ),
                "approval_mode": approval_mode or "inherited",
                "governance_store_ready": governance_ready,
            },
            "execution_surface": execution_surface,
            "interactive_runtime_blocked": interactive_runtime_blocked,
            "dependency_status": dependency_status,
        }

    def describe_workflow_runtime(self, app: Any, workflow_id: str) -> Dict[str, Any]:
        workflow = self.workflow_registry.get_workflow(workflow_id)
        if workflow is None:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        registry_describe = getattr(self.workflow_registry, "describe_workflow", None)
        workflow_contract = (
            registry_describe(workflow_id)
            if callable(registry_describe)
            else dict(workflow)
        )
        dependency_status = self.validate_dependencies(app, workflow_id)

        runs = self.list_runs(limit=20, workflow_id=workflow_id)
        recent_statuses = [run.get("status") for run in runs if run.get("status")]
        active_runs = sum(1 for status in recent_statuses if status in {"active", "running", "waiting_approval"})
        completed_runs = sum(1 for status in recent_statuses if status == "completed")

        execution_contract, plan_contract, governance_contract = self._execution_contracts(workflow, workflow_contract)
        runtime_enforcement = self.evaluate_runtime_readiness(app, workflow_id)
        governance_hooks = {
            "approvals_supported": True,
            "decision_logging_supported": True,
            "feedback_logging_supported": True,
            "deterministic_verdict_owner": "CABTA deterministic core",
            "contract_version": "governance-contract/v2",
        }
        runtime_truth_contract = self._runtime_truth_contract(
            dependency_status=dependency_status.get("status", "unknown")
        )
        fact_contract = {
            "contract_version": "workflow-runtime-contract/v2",
            "deterministic_verdict_owner": "CABTA deterministic core",
            "typed_observation_contract": "observation-contract/v2",
            "fact_family_schema_count": len(workflow_contract.get("fact_family_schemas", {}) or {}),
            "required_soc_lanes": list(workflow.get("required_soc_lanes", []) or []),
            "plan_driven_investigation": True,
            "plan_contract": plan_contract,
            "governance_hooks": governance_hooks,
        }

        return {
            "workflow": workflow_contract,
            "dependency_status": dependency_status,
            "runtime_enforcement": runtime_enforcement,
            "runtime_truth_contract": runtime_truth_contract,
            "run_contract": {
                "supports_headless": bool(workflow.get("headless_ready")),
                "supports_headless_execution": self._supports_headless_execution(workflow, execution_contract),
                "approval_mode": workflow.get("approval_mode", "inherited"),
                "execution_backend": workflow.get("execution_backend", "agent"),
                "requires_playbook": bool(workflow.get("playbook_id")),
                "dependency_count": int(
                    execution_contract.get(
                        "dependency_count",
                        len(workflow.get("required_tools", []))
                        + len(workflow.get("required_mcp_servers", []))
                        + len(workflow.get("required_features", [])),
                    )
                ),
                "dependency_status_label": dependency_status.get("status", "unknown"),
                "is_dependency_blocked": dependency_status.get("status") == "blocked",
                "is_dependency_degraded": dependency_status.get("status") == "degraded",
                "recent_run_count": len(runs),
                "active_run_count": active_runs,
                "completed_run_count": completed_runs,
                "recent_statuses": recent_statuses[:10],
                "fact_contract": fact_contract,
                "governance_hooks": governance_hooks,
                "runtime_enforcement": runtime_enforcement,
                "fallback_paths": list(execution_contract.get("fallback_paths", []) or []),
                "stop_conditions": list(execution_contract.get("stop_conditions", []) or []),
                "is_runtime_blocked": runtime_enforcement.get("status") == "blocked",
            },
        }

    def validate_dependencies(self, app: Any, workflow_id: str) -> Dict[str, Any]:
        workflow = self.workflow_registry.get_workflow(workflow_id)
        if workflow is None:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        tool_registry = getattr(app.state, "tool_registry", None)
        mcp_client = getattr(app.state, "mcp_client", None)
        playbook_engine = getattr(app.state, "playbook_engine", None)
        provider = getattr(app.state, "web_provider", None)
        feature_status = provider.feature_status(app) if provider else {}
        mcp_status = mcp_client.get_connection_status() if mcp_client else {}

        missing_required_tools = []
        available_required_tools = []
        for tool_name in workflow.get("required_tools", []):
            if tool_registry and tool_registry.get_tool(tool_name):
                available_required_tools.append(tool_name)
            else:
                missing_required_tools.append(tool_name)

        missing_required_servers = []
        connected_required_servers = []
        for server_name in workflow.get("required_mcp_servers", []):
            if mcp_status.get(server_name, {}).get("connected"):
                connected_required_servers.append(server_name)
            else:
                missing_required_servers.append(server_name)

        missing_features = []
        ready_features = []
        for feature_name in workflow.get("required_features", []):
            meta = feature_status.get(feature_name, {})
            if meta.get("status") in {"available", "configured", "enabled"}:
                ready_features.append(feature_name)
            else:
                missing_features.append(feature_name)

        optional_servers = [
            {
                "name": server_name,
                "connected": bool(mcp_status.get(server_name, {}).get("connected")),
                "capability_scope": "optional_enrichment",
            }
            for server_name in workflow.get("optional_mcp_servers", [])
        ]
        degraded_optional_servers = [item["name"] for item in optional_servers if not item["connected"]]

        playbook_dependency = None
        if str(workflow.get("execution_backend") or "agent").lower() == "playbook":
            playbook_id = workflow.get("playbook_id")
            playbook_available = bool(
                playbook_id and playbook_engine is not None and playbook_engine.get_playbook(playbook_id)
            )
            playbook_dependency = {
                "id": playbook_id,
                "available": playbook_available,
            }

        if (
            missing_required_tools
            or missing_required_servers
            or missing_features
            or (playbook_dependency is not None and not playbook_dependency["available"])
        ):
            status = "blocked"
        elif any(not item["connected"] for item in optional_servers):
            status = "degraded"
        else:
            status = "ready"

        return {
            "workflow_id": workflow_id,
            "status": status,
            "blocked": status == "blocked",
            "degraded": status == "degraded",
            "dependency_count": len(workflow.get("required_tools", []))
            + len(workflow.get("required_mcp_servers", []))
            + len(workflow.get("required_features", []))
            + (1 if playbook_dependency is not None else 0),
            "required_tools": {
                "available": available_required_tools,
                "missing": missing_required_tools,
            },
            "required_mcp_servers": {
                "connected": connected_required_servers,
                "missing": missing_required_servers,
            },
            "required_features": {
                "ready": ready_features,
                "missing": missing_features,
            },
            "optional_mcp_servers": optional_servers,
            "optional_runtime": {
                "degraded": bool(degraded_optional_servers),
                "degraded_dependencies": degraded_optional_servers,
                "capability_scope": "optional_infrastructure",
                "message": (
                    "Optional MCP infrastructure is degraded; workflow execution can continue with governed fallback paths."
                    if degraded_optional_servers
                    else "Optional MCP infrastructure is ready."
                ),
            },
            "required_playbook": playbook_dependency,
        }

    def list_runs(
        self,
        *,
        limit: int = 50,
        status: Optional[str] = None,
        workflow_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sessions = self.agent_store.list_sessions(limit=limit, status=status)
        results = []
        for session in sessions:
            metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
            resolved_workflow_id = metadata.get("workflow_id")
            if not resolved_workflow_id:
                continue
            if workflow_id and workflow_id != resolved_workflow_id:
                continue
            results.append(self._build_run_summary(session))
        return results

    def get_run(self, session_id: str) -> Optional[Dict[str, Any]]:
        session = self.agent_store.get_session(session_id)
        if session is None:
            return None
        metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
        if not metadata.get("workflow_id"):
            return None
        payload = self._build_run_summary(session)
        payload["steps"] = self.agent_store.get_steps(session_id)
        payload["specialist_tasks"] = self.agent_store.list_specialist_tasks(session_id)
        return payload

    def _build_run_summary(self, session: Dict[str, Any]) -> Dict[str, Any]:
        metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
        workflow_id = metadata.get("workflow_id")
        workflow = self.workflow_registry.get_workflow(workflow_id) or {}
        phases = list(metadata.get("specialist_team") or workflow.get("agents") or ["triage", "investigation", "reporting"])
        max_steps = int(metadata.get("max_steps") or len(phases) or 1)
        current_step = int(metadata.get("current_step") or 0)
        phase_index = min(int((current_step / max(max_steps, 1)) * len(phases)), max(len(phases) - 1, 0)) if phases else 0
        current_phase = metadata.get("active_specialist") or (phases[phase_index] if phases else "workflow")
        evidence_quality_summary = metadata.get("evidence_quality_summary", {}) if isinstance(metadata.get("evidence_quality_summary"), dict) else {}
        fact_family_schemas = metadata.get("fact_family_schemas", {}) if isinstance(metadata.get("fact_family_schemas"), dict) else {}
        investigation_plan = metadata.get("investigation_plan", {}) if isinstance(metadata.get("investigation_plan"), dict) else {}
        execution_contract, _, _ = self._execution_contracts(workflow)
        supports_headless_execution = self._supports_headless_execution(workflow, execution_contract)
        interactive_runtime_required = not supports_headless_execution
        headless_declared = bool(workflow.get("headless_ready"))
        headless_blockers: List[str] = []
        if not headless_declared:
            headless_blockers.append("workflow_not_declared_headless_ready")
        if interactive_runtime_required:
            headless_blockers.append("approval_checkpoints_require_interactive_runtime")

        return {
            "session_id": session["id"],
            "workflow_id": workflow_id,
            "workflow_name": workflow.get("name", workflow_id),
            "status": session.get("status"),
            "case_id": session.get("case_id"),
            "agent_profile_id": metadata.get("active_specialist") or metadata.get("agent_profile_id") or workflow.get("default_agent_profile"),
            "lead_agent_profile_id": metadata.get("lead_agent_profile_id") or workflow.get("default_agent_profile"),
            "active_specialist": metadata.get("active_specialist") or current_phase,
            "specialist_team": phases,
            "specialist_count": len(phases),
            "collaboration_mode": metadata.get("collaboration_mode") or ("multi_agent" if len(phases) > 1 else "single_agent"),
            "specialist_handoffs": list(metadata.get("specialist_handoffs") or []),
            "specialist_task_count": len(self.agent_store.list_specialist_tasks(session["id"])),
            "current_step": current_step,
            "max_steps": max_steps,
            "current_phase": current_phase,
            "phase_index": phase_index,
            "phases": phases,
            "execution_backend": workflow.get("execution_backend", "agent"),
            "headless_ready": headless_declared,
            "approval_mode": workflow.get("approval_mode", "inherited"),
            "requires_playbook": bool(workflow.get("playbook_id")),
            "created_at": session.get("created_at"),
            "completed_at": session.get("completed_at"),
            "summary": session.get("summary"),
            "pending_approval": metadata.get("pending_approval"),
            "runtime_contract": {
                "plan_ready": bool(investigation_plan) or bool(metadata.get("goal")),
                "plan_signal_count": len(list(investigation_plan.get("next_action_signals") or []))
                + len(list(investigation_plan.get("resume_signals") or [])),
                "triage_contract_count": len(list(investigation_plan.get("triage_contracts") or [])),
                "evidence_ready": int(evidence_quality_summary.get("observation_count", 0) or 0) > 0,
                "governed": True,
                "case_truth_ready": int(evidence_quality_summary.get("observation_count", 0) or 0) > 0,
                "deterministic_verdict_owner": str(
                    investigation_plan.get("deterministic_verdict_owner") or "CABTA deterministic core"
                ),
                "runtime_truth": "workflow_registry_plus_session_metadata",
                "contract_version": "workflow-runtime-contract/v2",
                "supports_headless_execution": supports_headless_execution,
                "interactive_runtime_required": interactive_runtime_required,
                "headless_blockers": headless_blockers,
            },
            "typed_fact_contract": {
                "contract_version": "workflow-runtime-contract/v2",
                "observation_contract_version": "observation-contract/v2",
                "deterministic_verdict_owner": "CABTA deterministic core",
                "observation_count": int(evidence_quality_summary.get("observation_count", 0) or 0),
                "observation_lanes": dict(evidence_quality_summary.get("observation_lanes", {}) or {}),
                "fact_family_schemas": sorted(fact_family_schemas.keys()),
                "plan_driven_investigation": True,
                "plan_has_next_action_signals": bool(investigation_plan.get("next_action_signals")),
                "plan_has_resume_signals": bool(investigation_plan.get("resume_signals")),
                "required_soc_lanes": list(workflow.get("required_soc_lanes", []) or []),
                "governance_contract_version": "governance-contract/v2",
            },
        }
