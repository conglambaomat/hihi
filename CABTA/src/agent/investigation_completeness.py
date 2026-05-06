"""Deterministic completeness model for agentic SOC investigations."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class InvestigationBudget:
    max_iterations: int = 12
    max_tool_calls: int = 30
    max_auto_pivots: int = 15
    max_wall_clock_seconds: int = 180
    iterations: int = 0
    tool_calls: int = 0
    auto_pivots: int = 0
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def exhausted_reasons(self) -> List[str]:
        reasons: List[str] = []
        if self.iterations >= self.max_iterations:
            reasons.append("iteration_budget_exhausted")
        if self.tool_calls >= self.max_tool_calls:
            reasons.append("tool_call_budget_exhausted")
        if self.auto_pivots >= self.max_auto_pivots:
            reasons.append("auto_pivot_budget_exhausted")
        return reasons


class NextActionType(str, Enum):
    PROCESS_PARENT_LOOKUP = "PROCESS_PARENT_LOOKUP"
    PROCESS_CHILD_LOOKUP = "PROCESS_CHILD_LOOKUP"
    COMMAND_LINE_DEOBFUSCATE = "COMMAND_LINE_DEOBFUSCATE"
    NETWORK_CONNECTION_LOOKUP = "NETWORK_CONNECTION_LOOKUP"
    FILE_WRITE_LOOKUP = "FILE_WRITE_LOOKUP"
    REGISTRY_LOOKUP = "REGISTRY_LOOKUP"
    USER_SESSION_LOOKUP = "USER_SESSION_LOOKUP"
    HOST_TIMELINE_EXPAND = "HOST_TIMELINE_EXPAND"
    IOC_EXTRACT_ENRICH = "IOC_EXTRACT_ENRICH"
    RELATED_EVENT_SEARCH = "RELATED_EVENT_SEARCH"
    RULE_DETECTION_GENERATE = "RULE_DETECTION_GENERATE"
    REPORT_FINALIZE = "REPORT_FINALIZE"


ACTION_TOOL_HINTS = {
    "process_tree": "search_logs",
    "pivot_process_tree": "search_logs",
    "hash_enrichment": "investigate_ioc",
    "pivot_hash_enrichment": "investigate_ioc",
    "host_timeline": "splunk.get_host_timeline",
    "build_timeline": "splunk.get_host_timeline",
    "user_scope": "search_logs",
    "pivot_user_host_scope": "search_logs",
    "network_pivot": "search_logs",
    "pivot_network": "search_logs",
    "file_registry": "search_logs",
    "pivot_file_registry": "search_logs",
    "root_cause": "correlate_findings",
    "derive_root_cause": "correlate_findings",
    "threat_story": "correlate_findings",
    "write_threat_story": "correlate_findings",
    "scope": "correlate_findings",
    "assess_scope": "correlate_findings",
    "impact": "correlate_findings",
    "assess_impact": "correlate_findings",
}


@dataclass
class NextActionSignal:
    action_id: str
    action_type: str
    rationale: str
    tool_hint: str = ""
    query_focus: str = ""
    required: bool = True
    priority: int = 0
    status: str = "pending"
    dedupe_key: str = ""
    params: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def default_tool_hint(action_type: str) -> str:
        return ACTION_TOOL_HINTS.get(str(action_type or "").strip(), "search_logs")

    def __post_init__(self) -> None:
        if not self.tool_hint:
            self.tool_hint = self.default_tool_hint(self.action_type)
        if not self.dedupe_key:
            self.dedupe_key = f"{self.action_type}:{self.query_focus or self.rationale}".lower()
        if not self.action_id:
            self.action_id = "act-" + hashlib.sha1(self.dedupe_key.encode()).hexdigest()[:10]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CompletionDecision:
    allowed: bool
    status: str
    stop_reason: str
    blocking_reasons: List[str] = field(default_factory=list)
    missing_milestones: List[str] = field(default_factory=list)
    pending_actions: List[NextActionSignal] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)
    budget_exhausted: bool = False
    provisional_answer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["pending_actions"] = [a.to_dict() if hasattr(a, "to_dict") else dict(a) for a in self.pending_actions]
        return payload


@dataclass
class MilestoneStatus:
    milestone_id: str
    name: str
    status: str = "not_started"
    evidence_ids: List[str] = field(default_factory=list)
    blocker_reason: str = ""
    required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationState:
    investigation_id: str
    input_type: str = "unknown"
    threat_story: str = ""
    milestones: List[str] = field(default_factory=list)
    completed_milestones: List[str] = field(default_factory=list)
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    next_actions: List[NextActionSignal] = field(default_factory=list)
    budget: InvestigationBudget = field(default_factory=InvestigationBudget)
    completion: Optional[CompletionDecision] = None
    milestone_statuses: List[MilestoneStatus] = field(default_factory=list)
    connector_registry: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["next_actions"] = [a.to_dict() if hasattr(a, "to_dict") else dict(a) for a in self.next_actions]
        payload["completion"] = self.completion.to_dict() if self.completion else None
        payload["milestone_statuses"] = [m.to_dict() if hasattr(m, "to_dict") else dict(m) for m in self.milestone_statuses]
        return payload


RAW_LOG_MILESTONES = [
    "process_tree",
    "command_line",
    "network",
    "file_registry",
    "user_host_scope",
    "timeline",
    "root_cause",
    "threat_story",
    "scope",
    "impact",
]


class InvestigationCompletenessGate:
    """Blocks final answers until required SOC pivots have evidence or explicit gaps."""

    def build_state(self, agent_state: Any) -> InvestigationState:
        reasoning = getattr(agent_state, "reasoning_state", {}) if agent_state is not None else {}
        reasoning = reasoning if isinstance(reasoning, dict) else {}
        existing = reasoning.get("investigation_state") if isinstance(reasoning.get("investigation_state"), dict) else {}
        input_type = str(existing.get("input_type") or reasoning.get("input_type") or reasoning.get("compiled_input_kind") or "unknown")
        objective = reasoning.get("objective_contract", {}) if isinstance(reasoning.get("objective_contract"), dict) else {}
        lane = str(objective.get("lane") or "").lower()
        goal = str(getattr(agent_state, "goal", "") or "")
        if input_type == "unknown" and self._looks_like_raw_log(goal, reasoning):
            input_type = "raw_log"
        milestones = list(existing.get("milestones") or [])
        if not milestones and (input_type == "raw_log" or "log" in lane):
            milestones = list(RAW_LOG_MILESTONES)
        completed = set(existing.get("completed_milestones") or [])
        evidence_items = self._collect_evidence(agent_state)
        completed.update(self._infer_completed_milestones(evidence_items, reasoning))
        actions = self._merge_actions(existing.get("next_actions") or [], self.required_actions(input_type, evidence_items, completed, goal))
        budget_data = existing.get("budget") if isinstance(existing.get("budget"), dict) else {}
        budget = InvestigationBudget(**{k: v for k, v in budget_data.items() if k in InvestigationBudget.__dataclass_fields__})
        budget.iterations = max(int(budget.iterations or 0), int(getattr(agent_state, "step_count", 0) or 0))
        budget.tool_calls = len([f for f in getattr(agent_state, "findings", []) or [] if isinstance(f, dict) and f.get("type") == "tool_result"])
        budget.auto_pivots = len([a for a in actions if a.status in {"pending", "planned", "executed"}])
        milestone_statuses = self._milestone_statuses(milestones, completed, evidence_items, actions)
        return InvestigationState(
            investigation_id=str(getattr(agent_state, "session_id", "investigation") or "investigation"),
            input_type=input_type,
            threat_story=str(existing.get("threat_story") or reasoning.get("threat_story") or ""),
            milestones=milestones,
            completed_milestones=sorted(completed),
            evidence_items=evidence_items,
            next_actions=actions,
            budget=budget,
            milestone_statuses=milestone_statuses,
            connector_registry=dict(existing.get("connector_registry") or reasoning.get("connector_registry") or {}),
        )

    def evaluate(self, agent_state: Any, candidate_answer: str = "") -> CompletionDecision:
        state = self.build_state(agent_state)
        pending = [a for a in state.next_actions if a.required and a.status not in {"done", "executed", "blocked", "skipped"}]
        missing = [m for m in state.milestones if m not in set(state.completed_milestones)]
        budget_reasons = state.budget.exhausted_reasons()
        report_shape = self._final_report_shape(candidate_answer, state)
        blocking: List[str] = []
        if pending:
            blocking.append("Required investigation pivots remain pending: " + ", ".join(a.action_type for a in pending[:6]))
        if missing:
            blocking.append("Required SOC milestones are incomplete: " + ", ".join(missing[:6]))
        if self._authoritative_no_findings(candidate_answer) and (pending or missing):
            blocking.append("No-findings or clean verdict requires completed coverage or an explicit incomplete label.")
        if budget_reasons:
            return CompletionDecision(
                allowed=True,
                status="incomplete_budget_exhausted",
                stop_reason="budget_exhausted",
                blocking_reasons=blocking + budget_reasons,
                missing_milestones=missing,
                pending_actions=pending,
                coverage={**self._coverage(state), "final_report_shape": report_shape},
                budget_exhausted=True,
                provisional_answer=self._incomplete_answer(blocking + budget_reasons, missing, pending),
            )
        missing_report_sections = report_shape["missing_sections"] if not blocking else []
        if missing_report_sections:
            blocking.append("Final SOC report is missing required sections: " + ", ".join(missing_report_sections))
        allowed = not blocking
        return CompletionDecision(
            allowed=allowed,
            status="complete" if allowed else "blocked_incomplete",
            stop_reason="complete" if allowed else "pending_required_pivots",
            blocking_reasons=blocking,
            missing_milestones=missing,
            pending_actions=pending,
            coverage={**self._coverage(state), "final_report_shape": report_shape},
            provisional_answer="" if allowed else self._incomplete_answer(blocking, missing, pending),
        )

    def required_actions(self, input_type: str, evidence: List[Dict[str, Any]], completed: set, goal: str) -> List[NextActionSignal]:
        if input_type != "raw_log" and "sysmon" not in goal.lower():
            return []
        specs = [
            ("process_tree", "pivot_process_tree", "Trace parent and child process lineage", "process parent child lineage"),
            ("command_line", "decode_command_line", "Decode and review command-line/script content", "powershell command line encoded command"),
            ("network", "pivot_network", "Check network connections and DNS around the process", "network dns connections"),
            ("file_registry", "pivot_file_registry", "Check file writes, persistence and registry activity", "file registry persistence writes"),
            ("user_host_scope", "pivot_user_host_scope", "Scope affected user, host and session", "user host session scope"),
            ("timeline", "build_timeline", "Build a host timeline around the suspicious chain", "host timeline process network file"),
            ("root_cause", "derive_root_cause", "Explain the most likely initiating cause from evidence", "root cause initial access execution chain"),
            ("threat_story", "write_threat_story", "Connect evidence into a coherent threat story", "threat story kill chain narrative"),
            ("scope", "assess_scope", "Determine affected hosts, users and related indicators", "scope affected hosts users indicators"),
            ("impact", "assess_impact", "Assess business/security impact and containment urgency", "impact containment severity blast radius"),
            ("hash_enrichment", "pivot_hash_enrichment", "Enrich hashes or extracted indicators seen in the chain", "hash sha256 md5 indicator enrichment"),
        ]
        actions = []
        for milestone, action_type, rationale, focus in specs:
            if milestone in completed:
                continue
            actions.append(NextActionSignal("", action_type, rationale, query_focus=focus, priority=10))
        return actions

    def _collect_evidence(self, agent_state: Any) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for idx, finding in enumerate(getattr(agent_state, "findings", []) or [], start=1):
            if isinstance(finding, dict):
                if self._looks_like_prompt_injection(finding):
                    items.append({"evidence_id": f"E{idx}", "type": "security_note", "summary": "Potential prompt-injection text ignored for coverage inference."})
                    continue
                item = dict(finding)
                item.setdefault("evidence_id", f"E{idx}")
                items.append(item)
        return items

    def _infer_completed_milestones(self, evidence: List[Dict[str, Any]], reasoning: Dict[str, Any]) -> List[str]:
        text = " ".join(str(item).lower() for item in evidence)
        completed = []
        mapping = {
            "process_tree": ["parent", "child", "process", "stage2.exe", "powershell.exe"],
            "command_line": ["command", "powershell", "encoded", "script"],
            "network": ["network", "dns", "connection", "destination_ip"],
            "file_registry": ["registry", "file write", "persistence", "autorun"],
            "user_host_scope": ["user", "host", "session", "computer"],
            "timeline": ["timeline", "event_id", "timestamp", "utc"],
            "root_cause": ["root cause", "initial access", "spawned", "initiating", "cause"],
            "threat_story": ["threat story", "kill chain", "attack narrative", "execution chain"],
            "scope": ["scope", "affected", "blast radius", "related host", "related user"],
            "impact": ["impact", "severity", "containment", "business impact", "risk"],
        }
        for milestone, tokens in mapping.items():
            if any(token in text for token in tokens):
                completed.append(milestone)
        coverage = reasoning.get("coverage_matrix") if isinstance(reasoning.get("coverage_matrix"), dict) else {}
        completed.extend(str(f) for f in coverage.get("covered_facets", []) if str(f).strip())
        return completed

    def _merge_actions(self, raw_actions: List[Any], generated: List[NextActionSignal]) -> List[NextActionSignal]:
        merged: Dict[str, NextActionSignal] = {}
        for item in [*raw_actions, *generated]:
            if isinstance(item, NextActionSignal):
                action = item
            elif isinstance(item, dict):
                action = NextActionSignal(
                    action_id=str(item.get("action_id") or ""),
                    action_type=str(item.get("action_type") or item.get("signal_type") or "pivot"),
                    rationale=str(item.get("rationale") or item.get("reason") or "Required investigation pivot"),
                    tool_hint=str(item.get("tool_hint") or item.get("tool") or NextActionSignal.default_tool_hint(str(item.get("action_type") or item.get("signal_type") or "pivot"))),
                    query_focus=str(item.get("query_focus") or item.get("focus") or ""),
                    required=bool(item.get("required", True)),
                    priority=int(item.get("priority") or 0),
                    status=str(item.get("status") or "pending"),
                    dedupe_key=str(item.get("dedupe_key") or ""),
                    params=dict(item.get("params") or {}),
                )
            else:
                continue
            merged.setdefault(action.dedupe_key, action)
        return sorted(merged.values(), key=lambda a: (-a.priority, a.action_type))

    def _milestone_statuses(self, milestones: List[str], completed: set, evidence: List[Dict[str, Any]], actions: List[NextActionSignal]) -> List[MilestoneStatus]:
        evidence_ids = [str(item.get("evidence_id")) for item in evidence if isinstance(item, dict) and item.get("evidence_id")]
        statuses: List[MilestoneStatus] = []
        for milestone in milestones:
            status = "satisfied" if milestone in completed else "not_started"
            blocker = ""
            for action in actions:
                focus = f"{action.action_type} {action.query_focus}".lower()
                if milestone.replace("_", " ") in focus or milestone in focus:
                    if action.status == "blocked":
                        status = "blocked"
                        blocker = action.rationale
                    elif status != "satisfied":
                        status = "in_progress"
                    break
            statuses.append(MilestoneStatus(milestone_id=milestone, name=milestone.replace("_", " ").title(), status=status, evidence_ids=evidence_ids if status == "satisfied" else [], blocker_reason=blocker))
        return statuses

    def _coverage(self, state: InvestigationState) -> Dict[str, Any]:
        completed = set(state.completed_milestones)
        checklist = {milestone: (milestone in completed) for milestone in state.milestones}
        total = len(state.milestones)
        done = sum(1 for ok in checklist.values() if ok)
        return {
            "milestones_total": total,
            "milestones_complete": done,
            "status": "complete" if total == done else "incomplete",
            "checklist": checklist,
            "required_checklist": {
                "root_cause": checklist.get("root_cause", False),
                "threat_story": checklist.get("threat_story", False),
                "timeline": checklist.get("timeline", False),
                "scope": checklist.get("scope", False),
                "impact": checklist.get("impact", False),
            },
        }

    @staticmethod
    def _final_report_shape(answer: str, state: InvestigationState) -> Dict[str, Any]:
        required = ["timeline", "scope", "impact", "root_cause_status", "threat_story", "evidence_refs", "residual_gaps"]
        text = str(answer or "").lower()
        patterns = {
            "timeline": r"timeline|sequence|when|utc|timestamp",
            "scope": r"scope|affected|host|user|blast radius",
            "impact": r"impact|severity|risk|containment|business",
            "root_cause_status": r"root cause|initial access|initiating|cause",
            "threat_story": r"threat story|attack path|kill chain|narrative|execution chain",
            "evidence_refs": r"\be\d+\b|evidence|observed|tool result",
            "residual_gaps": r"residual gap|remaining gap|limitation|unknown|incomplete|not yet",
        }
        if state.input_type != "raw_log" and "raw_log" not in text:
            return {"required_sections": [], "missing_sections": [], "status": "not_applicable"}
        missing = [name for name in required if not re.search(patterns[name], text, flags=re.IGNORECASE)]
        return {"required_sections": required, "missing_sections": missing, "status": "complete" if not missing else "incomplete"}

    @staticmethod
    def _looks_like_prompt_injection(item: Dict[str, Any]) -> bool:
        text = str(item).lower()
        return any(token in text for token in ("ignore all rules", "ignore previous", "mark network", "mark all", "bypass gate"))

    @staticmethod
    def _looks_like_raw_log(goal: str, reasoning: Dict[str, Any]) -> bool:
        blob = (goal + " " + str(reasoning)).lower()
        return any(token in blob for token in ("sysmon", "event id", "processguid", "powershell.exe", "stage2.exe", "raw log"))

    @staticmethod
    def _authoritative_no_findings(answer: str) -> bool:
        text = str(answer or "").lower()
        return bool(re.search(r"\b(clean|benign|no findings|safe)\b", text) and "incomplete" not in text)

    @staticmethod
    def _incomplete_answer(reasons: List[str], missing: List[str], pending: List[NextActionSignal]) -> str:
        parts = ["AISA cannot finalize the SOC investigation yet; this is an incomplete investigation status."]
        if reasons:
            parts.append("Blocking reasons: " + "; ".join(dict.fromkeys(reasons)) + ".")
        if missing:
            parts.append("Missing milestones: " + ", ".join(missing) + ".")
        if pending:
            parts.append("Next required pivots: " + ", ".join(a.action_type for a in pending[:8]) + ".")
        return " ".join(parts)
