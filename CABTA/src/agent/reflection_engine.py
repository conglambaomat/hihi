"""Reflection and bounded repair recommendations for objective/capability evidence gaps."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any, Dict, List, Optional


@dataclass
class RepairRecommendation:
    capability: str
    reason: str
    action: str = "use_capability"
    params: Dict[str, Any] = field(default_factory=dict)
    priority: int = 50

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReflectionResult:
    status: str
    covered_facets: List[str] = field(default_factory=list)
    missing_facets: List[str] = field(default_factory=list)
    blocking_reasons: List[str] = field(default_factory=list)
    repair_recommendations: List[RepairRecommendation] = field(default_factory=list)
    degraded_reason: str = ""
    schema_version: str = "reflection-result/v1"
    reflection_id: str = ""
    objective_ref: str = ""
    blocking_gaps: List[Dict[str, Any]] = field(default_factory=list)
    repair_actions: List[Dict[str, Any]] = field(default_factory=list)
    max_repair_attempts_reached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["repair_recommendations"] = [item.to_dict() for item in self.repair_recommendations]
        payload["repair_actions"] = self.repair_actions or [{"capability": item.capability, "rationale": item.reason, "action": item.action, "params": dict(item.params)} for item in self.repair_recommendations]
        payload["blocking_gaps"] = self.blocking_gaps or [{"reason": item, "missing": list(self.missing_facets)} for item in self.blocking_reasons]
        payload["reflection_id"] = self.reflection_id or ("refl-" + hashlib.sha1((self.objective_ref + self.status + ",".join(self.missing_facets)).encode()).hexdigest()[:10])
        return payload


class ReflectionEngine:
    """Compare recent observations/tool findings against objective evidence requirements."""

    _CAPABILITY_TO_TOOL = {
        "log.search": "search_logs",
        "log.analyze.inline": "inline_log_artifact",
        "ioc.enrich": "investigate_ioc",
        "ioc.extract": "extract_iocs",
        "email.analyze": "analyze_email",
        "file.analyze.static": "analyze_malware",
        "file.analyze.sandbox": "analyze_malware",
        "findings.correlate": "correlate_findings",
        "threat_intel.search": "search_threat_intel",
    }

    def reflect(
        self,
        *,
        objective: Dict[str, Any] | Any,
        findings: Optional[List[Dict[str, Any]]] = None,
        observations: Optional[List[Dict[str, Any]]] = None,
        coverage: Optional[Dict[str, Any]] = None,
        reasoning_state: Optional[Dict[str, Any]] = None,
    ) -> ReflectionResult:
        objective_dict = self._as_dict(objective)
        findings = [item for item in (findings or []) if isinstance(item, dict)]
        observations = [item for item in (observations or []) if isinstance(item, dict)]
        coverage = coverage if isinstance(coverage, dict) else {}
        reasoning_state = reasoning_state if isinstance(reasoning_state, dict) else {}

        required_capabilities = self._required_capabilities(objective_dict)
        covered_facets = self._coverage_list(coverage, "covered_facets")
        missing_facets = self._coverage_list(coverage, "missing_facets")
        blocking_reasons: List[str] = []
        recommendations: List[RepairRecommendation] = []
        degraded_reasons: List[str] = []

        for capability in required_capabilities:
            expected_tool = self._CAPABILITY_TO_TOOL.get(capability, "")
            matching = self._findings_for_capability(findings, capability, expected_tool)
            if not matching and capability == "log.analyze.inline" and self._has_inline_log_artifact(reasoning_state):
                matching = [{"type": "tool_result", "tool": "inline_log_artifact", "capability_id": capability, "result": {"status": "available", "source": "pasted_inline_log"}}]
            if not matching:
                reason = f"No executed tool result satisfied required capability {capability}."
                blocking_reasons.append(reason)
                recommendations.append(self._recommend(capability, objective_dict, reason))
                continue

            wrong_or_degraded = [item for item in matching if self._finding_degraded(item)]
            if wrong_or_degraded:
                reason = f"Required capability {capability} is degraded or approval/manual blocked."
                blocking_reasons.append(reason)
                degraded_reasons.append(reason)
                recommendations.append(self._recommend(capability, objective_dict, reason))

            if capability == "log.search":
                log_reason = self._evaluate_log_search(objective_dict, matching, coverage, reasoning_state)
                if log_reason:
                    blocking_reasons.append(log_reason)
                    recommendations.append(self._recommend(capability, objective_dict, log_reason))

        if missing_facets:
            reason = "Coverage still has missing required facets: " + ", ".join(missing_facets[:8])
            blocking_reasons.append(reason)
            first_capability = required_capabilities[0] if required_capabilities else "findings.correlate"
            recommendations.append(self._recommend(first_capability, objective_dict, reason))

        status = "satisfied"
        if blocking_reasons:
            status = "blocked" if any("No executed tool" in item or "missing" in item.lower() for item in blocking_reasons) else "degraded"

        return ReflectionResult(
            status=status,
            objective_ref=str(objective_dict.get("contract_id") or objective_dict.get("objective_ref") or ""),
            covered_facets=covered_facets,
            missing_facets=self._dedupe(missing_facets),
            blocking_reasons=self._dedupe(blocking_reasons),
            repair_recommendations=self._dedupe_recommendations(recommendations),
            degraded_reason="; ".join(self._dedupe(degraded_reasons)),
        )

    def _evaluate_log_search(self, objective: Dict[str, Any], findings: List[Dict[str, Any]], coverage: Dict[str, Any], reasoning_state: Dict[str, Any]) -> str:
        expected_timerange = str(objective.get("effective_timerange") or (objective.get("timerange") or {}).get("effective") or "").strip()
        for finding in reversed(findings):
            params = finding.get("params") if isinstance(finding.get("params"), dict) else {}
            result = finding.get("result") if isinstance(finding.get("result"), dict) else {}
            effective = str(result.get("effective_timerange") or result.get("timerange") or params.get("timerange") or "").strip()
            if expected_timerange and effective and expected_timerange != effective:
                return f"Log search timerange mismatch: expected {expected_timerange}, observed {effective}."
            count = self._result_count(result)
            if count == 0:
                facets = self._coverage_list(result.get("coverage_matrix") if isinstance(result.get("coverage_matrix"), dict) else coverage, "missing_facets")
                if facets:
                    return "Log search returned empty results while required facets remain missing: " + ", ".join(facets[:8])
                return "Log search returned empty results; this is an evidence gap, not a benign verdict."
        return ""

    def _recommend(self, capability: str, objective: Dict[str, Any], reason: str) -> RepairRecommendation:
        params: Dict[str, Any] = {}
        if capability == "log.search":
            params["query"] = objective.get("summary") or "security log investigation"
            timerange = str(objective.get("effective_timerange") or (objective.get("timerange") or {}).get("effective") or "")
            if timerange:
                params["timerange"] = timerange
        return RepairRecommendation(capability=capability, reason=reason, params=params)

    def _findings_for_capability(self, findings: List[Dict[str, Any]], capability: str, expected_tool: str) -> List[Dict[str, Any]]:
        matches = []
        for finding in findings:
            if finding.get("type") not in {"tool_result", "capability_degraded", "approval_rejected"}:
                continue
            if str(finding.get("capability") or finding.get("capability_id") or "") == capability:
                matches.append(finding)
                continue
            if expected_tool and str(finding.get("tool") or "") == expected_tool:
                matches.append(finding)
        return matches

    @staticmethod
    def _finding_degraded(finding: Dict[str, Any]) -> bool:
        if finding.get("type") in {"capability_degraded", "approval_rejected"}:
            return True
        result = finding.get("result") if isinstance(finding.get("result"), dict) else {}
        status = str(result.get("status") or result.get("availability") or "").lower()
        return bool(result.get("error") or result.get("approval_required") or status in {"degraded", "unavailable", "approval_required"})

    @staticmethod
    def _has_inline_log_artifact(reasoning_state: Dict[str, Any]) -> bool:
        soc_task = reasoning_state.get("soc_task_state", {}) if isinstance(reasoning_state, dict) else {}
        artifacts = soc_task.get("artifacts", []) if isinstance(soc_task, dict) else []
        return any(isinstance(item, dict) and item.get("type") == "inline_log_event" for item in artifacts if isinstance(artifacts, list))

    @staticmethod
    def _result_count(result: Dict[str, Any]) -> Optional[int]:
        for key in ("results_count", "count", "total"):
            if isinstance(result.get(key), int):
                return int(result.get(key))
        rows = result.get("results")
        if isinstance(rows, list):
            return len(rows)
        return None

    @staticmethod
    def _required_capabilities(objective: Dict[str, Any]) -> List[str]:
        caps = [str(item).strip() for item in objective.get("capabilities_required", []) if str(item).strip()]
        for req in objective.get("evidence_requirements", []) if isinstance(objective.get("evidence_requirements"), list) else []:
            if isinstance(req, dict) and str(req.get("capability") or "").strip():
                caps.append(str(req.get("capability")).strip())
        return list(dict.fromkeys(caps))

    @staticmethod
    def _coverage_list(coverage: Any, key: str) -> List[str]:
        if not isinstance(coverage, dict):
            return []
        values = coverage.get(key)
        if isinstance(values, list):
            return [str(item) for item in values if str(item).strip()]
        if key == "missing_facets":
            cells = coverage.get("cells") if isinstance(coverage.get("cells"), list) else []
            return [str(cell.get("facet")) for cell in cells if isinstance(cell, dict) and cell.get("status") in {"missing", "unknown"}]
        return []

    @staticmethod
    def _as_dict(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if hasattr(value, "to_dict"):
            try:
                return value.to_dict()
            except Exception:
                return {}
        return {}

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        return list(dict.fromkeys(str(item) for item in values if str(item).strip()))

    def _dedupe_recommendations(self, items: List[RepairRecommendation]) -> List[RepairRecommendation]:
        seen = set()
        result = []
        for item in items:
            key = (item.capability, item.reason)
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result[:8]


class PlanRepair:
    """Small adapter that converts reflections into bounded next-action hints."""

    def repair(self, plan: Dict[str, Any], reflection: ReflectionResult, state: Any = None) -> Dict[str, Any]:
        repaired = dict(plan or {})
        repaired["reflection_status"] = reflection.status
        repaired["repair_recommendations"] = [item.to_dict() for item in reflection.repair_recommendations]
        repaired["repair_authoritative_for_verdict"] = False
        return repaired
