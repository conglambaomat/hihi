"""Model-led SOC investigation planner contracts and guardrail verifier."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .capability_ontology import CapabilityDescriptor
from .capability_resolver import CapabilityResolver
from .tool_policy import ToolPolicyEngine


MODEL_LED_PLANNER_SCHEMA_VERSION = "model-led-investigation-plan/v1"
_ALLOWED_STEP_TYPES = {"tool_call", "capability_action", "clarify", "final_answer"}
_APPROVAL_KEYWORDS = ("sandbox", "detonate", "dynamic", "malware", "external", "submit", "delete", "quarantine", "block")
_BROAD_TIMERANGES = {"all", "*", "forever", "90d", "180d", "365d"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(json.dumps(part, sort_keys=True, default=str) for part in parts if part is not None)
    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


@dataclass
class ModelProposedStep:
    step_id: str = ""
    step_type: str = "capability_action"
    capability_id: str = ""
    tool_name: str = ""
    action_id: str = ""
    title: str = ""
    rationale: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    evidence_gap_refs: List[str] = field(default_factory=list)
    hypothesis_refs: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    timerange: str = ""
    scope: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    approval_reason: str = ""
    resolved_capability: str = ""
    resolved_tool: str = ""
    approval_required: bool = False
    risk_level: str = "low"
    risk_reasons: List[str] = field(default_factory=list)
    policy_reasons: List[str] = field(default_factory=list)
    blocked_reasons: List[str] = field(default_factory=list)
    priority: int = 50
    dedupe_key: str = ""

    def __post_init__(self) -> None:
        if not self.step_id:
            self.step_id = _stable_id("model-step", self.step_type, self.capability_id, self.tool_name, self.params, self.title)
        if not self.action_id:
            self.action_id = self.step_id
        self.params = dict(self.params or {})
        self.scope = dict(self.scope or {})
        self.evidence_gap_refs = [str(item) for item in _as_list(self.evidence_gap_refs) if str(item).strip()]
        self.hypothesis_refs = [str(item) for item in _as_list(self.hypothesis_refs) if str(item).strip()]
        self.expected_evidence = [str(item) for item in _as_list(self.expected_evidence) if str(item).strip()]
        self.risk_reasons = [str(item) for item in _as_list(self.risk_reasons) if str(item).strip()]
        self.policy_reasons = [str(item) for item in _as_list(self.policy_reasons) if str(item).strip()]
        self.blocked_reasons = [str(item) for item in _as_list(self.blocked_reasons) if str(item).strip()]
        if not self.dedupe_key:
            self.dedupe_key = _stable_id("dedupe", self.capability_id or self.tool_name, self.params)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "ModelProposedStep":
        data = dict(payload or {})
        valid = set(cls.__dataclass_fields__.keys())
        if "tool" in data and "tool_name" not in data:
            data["tool_name"] = data.get("tool")
        return cls(**{key: value for key, value in data.items() if key in valid})

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ModelLedInvestigationPlan:
    planning_intent: str = "continue_investigation"
    soc_lane: str = "generic"
    lane_transition_reason: str = ""
    hypotheses_to_test: List[str] = field(default_factory=list)
    evidence_gaps: List[str] = field(default_factory=list)
    proposed_steps: List[ModelProposedStep] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    stop_conditions: List[str] = field(default_factory=list)
    risk_notes: List[str] = field(default_factory=list)
    approval_notes: List[str] = field(default_factory=list)
    confidence: float = 0.0
    schema_version: str = MODEL_LED_PLANNER_SCHEMA_VERSION
    plan_id: str = ""
    created_at: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        self.hypotheses_to_test = [str(item) for item in _as_list(self.hypotheses_to_test) if str(item).strip()]
        self.evidence_gaps = [str(item) for item in _as_list(self.evidence_gaps) if str(item).strip()]
        self.expected_evidence = [str(item) for item in _as_list(self.expected_evidence) if str(item).strip()]
        self.stop_conditions = [str(item) for item in _as_list(self.stop_conditions) if str(item).strip()]
        self.risk_notes = [str(item) for item in _as_list(self.risk_notes) if str(item).strip()]
        self.approval_notes = [str(item) for item in _as_list(self.approval_notes) if str(item).strip()]
        self.proposed_steps = [step if isinstance(step, ModelProposedStep) else ModelProposedStep.from_dict(step) for step in _as_list(self.proposed_steps) if isinstance(step, (dict, ModelProposedStep))]
        if not self.plan_id:
            self.plan_id = _stable_id("model-plan", self.planning_intent, self.soc_lane, self.hypotheses_to_test, [step.to_dict() for step in self.proposed_steps])

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "ModelLedInvestigationPlan":
        data = dict(payload or {})
        valid = set(cls.__dataclass_fields__.keys())
        if "risk_approval_notes" in data:
            notes = _as_list(data.get("risk_approval_notes"))
            data.setdefault("risk_notes", notes)
            data.setdefault("approval_notes", notes)
        return cls(**{key: value for key, value in data.items() if key in valid})

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["proposed_steps"] = [step.to_dict() for step in self.proposed_steps]
        return payload


@dataclass
class ModelPlannerContext:
    objective: str = ""
    alert: Dict[str, Any] = field(default_factory=dict)
    raw_input: str = ""
    current_dag: Dict[str, Any] = field(default_factory=dict)
    adaptive_mutations: List[Dict[str, Any]] = field(default_factory=list)
    evidence_graph: Dict[str, Any] = field(default_factory=dict)
    evidence_briefs: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    coverage_gaps: List[Any] = field(default_factory=list)
    failed_queries: List[Dict[str, Any]] = field(default_factory=list)
    tool_failures: List[Dict[str, Any]] = field(default_factory=list)
    analyst_follow_up: str = ""
    available_capabilities: List[Dict[str, Any]] = field(default_factory=list)
    available_tools: List[Dict[str, Any]] = field(default_factory=list)
    policy_boundaries: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlanVerificationResult:
    status: str
    allowed_steps: List[Dict[str, Any]] = field(default_factory=list)
    blocked_reasons: List[str] = field(default_factory=list)
    needs_approval: List[Dict[str, Any]] = field(default_factory=list)
    clarification_requests: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    step_verifications: List[Dict[str, Any]] = field(default_factory=list)
    plan_id: str = ""
    schema_version: str = "model-plan-verification/v1"
    created_at: str = field(default_factory=_now_iso)

    @property
    def allowed(self) -> bool:
        return self.status == "allowed" and not self.blocked_reasons

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ModelLedPlanVerifier:
    """Deterministic policy boundary for model-authored investigation plans."""

    def __init__(
        self,
        *,
        get_tool: Optional[Callable[[str], Any]] = None,
        capability_exists: Optional[Callable[[str], bool]] = None,
        max_steps: int = 4,
        capability_resolver: Optional[CapabilityResolver] = None,
        policy_engine: Optional[ToolPolicyEngine] = None,
    ) -> None:
        self.get_tool = get_tool
        self.capability_exists = capability_exists
        self.max_steps = max(1, int(max_steps or 4))
        self.capability_resolver = capability_resolver or CapabilityResolver(get_tool=get_tool)
        self.policy_engine = policy_engine or ToolPolicyEngine()

    def verify(self, plan: ModelLedInvestigationPlan | Dict[str, Any], context: ModelPlannerContext | Dict[str, Any]) -> PlanVerificationResult:
        try:
            plan_obj = plan if isinstance(plan, ModelLedInvestigationPlan) else ModelLedInvestigationPlan.from_dict(plan)
        except Exception as exc:
            return PlanVerificationResult(status="blocked", blocked_reasons=[f"invalid_schema:{exc}"])
        ctx = context if isinstance(context, ModelPlannerContext) else ModelPlannerContext(**{k: v for k, v in dict(context or {}).items() if k in ModelPlannerContext.__dataclass_fields__})
        blocked: List[str] = []
        warnings: List[str] = []
        approvals: List[Dict[str, Any]] = []
        clarifications: List[str] = []
        allowed_steps: List[Dict[str, Any]] = []
        step_verifications: List[Dict[str, Any]] = []

        if plan_obj.schema_version != MODEL_LED_PLANNER_SCHEMA_VERSION:
            warnings.append(f"schema_version:{plan_obj.schema_version}")
        if not plan_obj.planning_intent:
            blocked.append("missing_planning_intent")
        if not plan_obj.proposed_steps and plan_obj.planning_intent not in {"stop", "request_clarification", "final_answer"}:
            clarifications.append("model_planner_returned_no_steps")

        valid_gap_refs = self._valid_refs(ctx.coverage_gaps, prefix="gap") | set(plan_obj.evidence_gaps)
        valid_hypothesis_refs = self._valid_refs(ctx.hypotheses, prefix="hypothesis") | set(plan_obj.hypotheses_to_test)
        seen_dedupe: set[str] = set()
        existing_dedupe = self._existing_dedupe(ctx.current_dag)

        for index, step in enumerate(plan_obj.proposed_steps[: self.max_steps]):
            step_reasons: List[str] = []
            policy_reasons: List[str] = []
            descriptor: Optional[CapabilityDescriptor] = None
            risk_reasons: List[str] = []
            if step.step_type not in _ALLOWED_STEP_TYPES:
                step_reasons.append(f"invalid_step_type:{step.step_type}")
            if not isinstance(step.params, dict):
                step_reasons.append("params_must_be_object")

            resolved_capability, resolved_tool, resolution_meta, descriptor = self._resolve_step(step)
            risk_reasons = self._risk_reasons(step, descriptor)
            if step.step_type in {"tool_call", "capability_action"}:
                if not step.capability_id and not step.tool_name:
                    step_reasons.append("missing_capability_or_tool")
                if not resolved_capability:
                    step_reasons.append(f"unknown_capability:{step.capability_id or step.tool_name}")
                if step.tool_name and resolved_tool and step.tool_name != resolved_tool:
                    step_reasons.append(f"tool_capability_mismatch:{step.tool_name}:{resolved_capability}")
                if step.tool_name and not resolved_tool and self.get_tool is not None and self.get_tool(step.tool_name) is None:
                    step_reasons.append(f"unknown_tool:{step.tool_name}")
                if step.capability_id and self.capability_exists is not None and not self.capability_exists(resolved_capability or step.capability_id):
                    step_reasons.append(f"unknown_capability:{step.capability_id}")

            if step.evidence_gap_refs and valid_gap_refs and not any(ref in valid_gap_refs for ref in step.evidence_gap_refs):
                warnings.append(f"step_{index}_unmatched_gap_refs")
            if step.hypothesis_refs and valid_hypothesis_refs and not any(ref in valid_hypothesis_refs for ref in step.hypothesis_refs):
                warnings.append(f"step_{index}_unmatched_hypothesis_refs")
            if self._needs_scope_timerange(step) and not (step.timerange or step.params.get("timerange") or step.scope.get("timerange")):
                step_reasons.append("missing_timerange_for_log_scope")
            dedupe_key = step.dedupe_key or _stable_id("dedupe", step.capability_id or step.tool_name, step.params)
            if dedupe_key in seen_dedupe or dedupe_key in existing_dedupe:
                step_reasons.append("duplicate_or_budget_exhausted_step")
            seen_dedupe.add(dedupe_key)

            approval_required = step.requires_approval or self._step_implies_approval(step, descriptor) or self._high_risk_needs_approval(resolved_capability, resolved_tool, risk_reasons, descriptor)
            if resolved_capability and resolved_tool:
                policy = self.policy_engine.evaluate(
                    tool_name=resolved_tool,
                    capability_id=resolved_capability,
                    params={**step.params, **({"timerange": step.timerange} if step.timerange and "timerange" not in step.params else {})},
                    action={"capability_id": resolved_capability, "allowed_tools": [resolved_tool], "approval_policy": (descriptor.approval_policy if descriptor else {"approval_required": approval_required})},
                    context=ctx.to_dict(),
                )
                policy_reasons.extend(policy.reasons)
                warnings.extend(f"step_{index}_policy_warning:{item}" for item in policy.warnings)
                approval_required = approval_required or policy.approval_required
                if policy.status == "blocked":
                    step_reasons.extend(policy.reasons)
            elif step.step_type in {"tool_call", "capability_action"} and resolved_capability and not resolved_tool:
                if not (descriptor and descriptor.approval_required and not descriptor.compatible_tools):
                    step_reasons.append(f"unavailable_tool_for_capability:{resolved_capability}")

            if approval_required:
                approvals.append({"step_id": step.step_id, "reason": step.approval_reason or "; ".join(risk_reasons or policy_reasons) or "approval_required_by_policy", "step": step.to_dict(), "resolved_capability": resolved_capability, "resolved_tool": resolved_tool, "risk_reasons": risk_reasons, "policy_reasons": policy_reasons})
            if step.step_type == "final_answer" and not self._final_answer_evidence_ready(ctx):
                step_reasons.append("final_answer_evidence_gate_not_satisfied")

            verified = step.to_dict()
            verified.update({
                "resolved_capability": resolved_capability,
                "resolved_tool": resolved_tool,
                "approval_required": approval_required,
                "risk_level": self._risk_level(risk_reasons, approval_required, descriptor),
                "capability_metadata": descriptor.to_dict() if descriptor else {},
                "risk_reasons": list(dict.fromkeys(risk_reasons)),
                "policy_reasons": list(dict.fromkeys(policy_reasons)),
                "blocked_reasons": list(dict.fromkeys(step_reasons)),
                "resolution": resolution_meta,
            })
            step_verifications.append(verified)
            if step_reasons:
                blocked.extend(step_reasons)
                continue
            if approval_required:
                continue
            allowed_steps.append(verified)

        if approvals and not allowed_steps:
            status = "needs_approval"
        elif blocked:
            status = "blocked" if not allowed_steps else "partial"
        elif clarifications:
            status = "request_clarification"
        else:
            status = "allowed"
        return PlanVerificationResult(
            status=status,
            allowed_steps=allowed_steps,
            blocked_reasons=blocked,
            needs_approval=approvals,
            clarification_requests=clarifications,
            warnings=list(dict.fromkeys(warnings)),
            step_verifications=step_verifications,
            plan_id=plan_obj.plan_id,
        )

    def _resolve_step(self, step: ModelProposedStep) -> tuple[str, str, Dict[str, Any], Optional[CapabilityDescriptor]]:
        descriptor = self._descriptor_for(step.capability_id or step.tool_name or step.title)
        capability = descriptor.capability_id if descriptor else str(step.capability_id or "").strip()
        if not descriptor and step.tool_name:
            capability = self._capability_for_tool(step.tool_name)
            descriptor = self.capability_resolver.ontology.get(capability) if capability else None
        if not capability:
            return "", "", {}, None
        resolution = self.capability_resolver.resolve(capability)
        meta = resolution.to_dict() if hasattr(resolution, "to_dict") else {}
        if descriptor:
            meta["descriptor"] = descriptor.to_dict()
        if resolution.availability == "unknown_capability":
            return "", "", meta, None
        selected = str(resolution.selected_tool or "").strip()
        if step.tool_name and selected and step.tool_name != selected:
            return capability, selected, meta, descriptor
        return capability, step.tool_name or selected, meta, descriptor

    def _descriptor_for(self, value: str) -> Optional[CapabilityDescriptor]:
        ontology = self.capability_resolver.ontology
        if hasattr(ontology, "find_by_alias"):
            return ontology.find_by_alias(value)
        return ontology.get(str(value or "").strip())

    def _capability_for_tool(self, tool_name: str) -> str:
        wanted = str(tool_name or "").strip()
        for capability in self.capability_resolver.ontology.all():
            for contract in capability.compatible_tools:
                if contract.tool_name == wanted:
                    return capability.capability_id
        # Minimal compatibility fallback for older tool-only model plans.
        aliases = {"splunk.search": "log.search", "search_logs": "log.search", "investigate_ioc": "ioc.enrich", "analyze_malware": "file.analyze.static", "extract_iocs": "ioc.extract"}
        return aliases.get(wanted, "")

    @staticmethod
    def _risk_reasons(step: ModelProposedStep, descriptor: Optional[CapabilityDescriptor] = None) -> List[str]:
        reasons: List[str] = list(descriptor.risk_reasons if descriptor else [])
        capability_id = descriptor.capability_id if descriptor else step.capability_id
        if capability_id == "log.search" and str(step.params.get("timerange") or step.timerange).lower() in _BROAD_TIMERANGES:
            reasons.append("broad_or_unbounded_hunt")
        # Compatibility fallback only annotates obvious free-text risk when no descriptor exists.
        if descriptor is None:
            text = " ".join([step.capability_id, step.tool_name, step.title, step.rationale, json.dumps(step.params, default=str)]).lower()
            if step.capability_id.startswith("ir.") or any(word in text for word in ("contain", "quarantine", "disable", "delete", "block host", "block ip")):
                reasons.append("ir_or_containment_action")
            if any(word in text for word in ("sandbox", "detonate", "dynamic analysis")):
                reasons.append("sandbox_execution_or_submission")
            if any(word in text for word in ("external", "http://", "https://", "submit", "virustotal")):
                reasons.append("external_network_or_submission")
        return list(dict.fromkeys(reasons))

    @staticmethod
    def _high_risk_needs_approval(capability: str, tool: str, reasons: List[str], descriptor: Optional[CapabilityDescriptor] = None) -> bool:
        if descriptor and descriptor.approval_required:
            return True
        approval_reasons = {"ir_or_containment_action", "sandbox_execution_or_submission", "external_network_or_submission"}
        return bool(approval_reasons.intersection(reasons)) or str(capability or "").startswith("ir.") or "sandbox" in str(capability or tool).lower()

    @staticmethod
    def _risk_level(reasons: List[str], approval_required: bool, descriptor: Optional[CapabilityDescriptor] = None) -> str:
        if descriptor and descriptor.risk_level:
            return descriptor.risk_level
        if any(r in reasons for r in ("ir_or_containment_action", "sandbox_execution_or_submission")):
            return "high"
        if approval_required or reasons:
            return "medium"
        return "low"

    @staticmethod
    def _valid_refs(items: List[Any], *, prefix: str) -> set[str]:
        refs: set[str] = set()
        for idx, item in enumerate(items or []):
            if isinstance(item, dict):
                for key in ("id", "gap_id", "hypothesis_id", "facet", "statement", "label"):
                    value = str(item.get(key) or "").strip()
                    if value:
                        refs.add(value)
            elif str(item).strip():
                refs.add(str(item).strip())
            refs.add(f"{prefix}:{idx}")
        return refs

    @staticmethod
    def _existing_dedupe(dag: Dict[str, Any]) -> set[str]:
        keys: set[str] = set()
        for node in dag.get("nodes", []) if isinstance(dag, dict) else []:
            if isinstance(node, dict):
                meta = node.get("adaptive_metadata") if isinstance(node.get("adaptive_metadata"), dict) else {}
                key = str(meta.get("model_led_dedupe_key") or "").strip()
                if key:
                    keys.add(key)
        return keys

    @staticmethod
    def _needs_scope_timerange(step: ModelProposedStep) -> bool:
        text = " ".join([step.capability_id, step.tool_name, step.title, step.rationale]).lower()
        return "log" in text or "siem" in text or step.tool_name in {"search_logs", "splunk.search"}

    @staticmethod
    def _step_implies_approval(step: ModelProposedStep, descriptor: Optional[CapabilityDescriptor] = None) -> bool:
        if descriptor:
            return bool(descriptor.approval_required)
        text = " ".join([step.capability_id, step.tool_name, step.title, step.rationale, json.dumps(step.params, default=str)]).lower()
        return any(keyword in text for keyword in _APPROVAL_KEYWORDS)

    @staticmethod
    def _final_answer_evidence_ready(ctx: ModelPlannerContext) -> bool:
        evidence_count = len(ctx.evidence_briefs or [])
        graph_nodes = ctx.evidence_graph.get("nodes") if isinstance(ctx.evidence_graph, dict) else []
        return evidence_count > 0 or bool(graph_nodes)


class ModelLedPlanner:
    """Thin parser/adapter for model-authored SOC plans."""

    def __init__(self, verifier: Optional[ModelLedPlanVerifier] = None) -> None:
        self.verifier = verifier or ModelLedPlanVerifier()

    def parse(self, payload: Any) -> Optional[ModelLedInvestigationPlan]:
        if isinstance(payload, ModelLedInvestigationPlan):
            return payload
        if isinstance(payload, str):
            payload = self._extract_json(payload)
        if not isinstance(payload, dict):
            return None
        try:
            return ModelLedInvestigationPlan.from_dict(payload)
        except Exception:
            return None

    def verify(self, payload: Any, context: ModelPlannerContext | Dict[str, Any]) -> PlanVerificationResult:
        plan = self.parse(payload)
        if plan is None:
            return PlanVerificationResult(status="blocked", blocked_reasons=["invalid_or_unparseable_model_plan"])
        return self.verifier.verify(plan, context)

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict[str, Any]]:
        value = str(text or "").strip()
        if not value:
            return None
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass
        start = value.find("{")
        end = value.rfind("}")
        if start >= 0 and end > start:
            try:
                parsed = json.loads(value[start : end + 1])
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None
