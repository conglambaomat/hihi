"""Final answer evidence gate for AISA investigation responses."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional

from .claim_verifier import ClaimVerification, ClaimVerifier
from .reflection_engine import ReflectionEngine
from .investigation_completeness import InvestigationCompletenessGate
from .final_investigation_reviewer import FinalInvestigationReviewer


@dataclass
class GateDecision:
    allowed: bool
    mode: str
    blocking_reasons: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    downgraded_claims: List[ClaimVerification] = field(default_factory=list)
    verified_claims: List[ClaimVerification] = field(default_factory=list)
    provisional_answer: str = ""
    schema_version: str = "final-answer-gate-result/v1"
    gate_id: str = ""
    objective_ref: str = ""
    status: str = ""
    required_answer_constraints: List[str] = field(default_factory=list)
    structured_verdict: Dict[str, Any] = field(default_factory=dict)
    evidence_chips: List[Dict[str, Any]] = field(default_factory=list)
    claim_evidence_map: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["downgraded_claims"] = [item.to_dict() for item in self.downgraded_claims]
        payload["verified_claims"] = [item.to_dict() for item in self.verified_claims]
        payload["evidence_chips"] = self.evidence_chips or _evidence_chips_from_claims(payload["verified_claims"], payload["downgraded_claims"])
        payload["claim_evidence_map"] = self.claim_evidence_map or {chip["claim_id"]: chip for chip in payload["evidence_chips"] if isinstance(chip, dict) and chip.get("claim_id")}
        payload["gate_id"] = self.gate_id or ("gate-" + hashlib.sha1((self.objective_ref + self.mode + str(self.allowed)).encode()).hexdigest()[:10])
        payload["status"] = self.status or ("allowed" if self.allowed else "blocked")
        payload["required_answer_constraints"] = self.required_answer_constraints or list(self.blocking_reasons)
        payload["structured_verdict"] = self.structured_verdict or _structured_verdict_from_gate(payload)
        return payload


def _evidence_chips_from_claims(verified: List[Dict[str, Any]], downgraded: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    chips: List[Dict[str, Any]] = []
    for item in [*(verified or []), *(downgraded or [])]:
        if not isinstance(item, dict):
            continue
        refs = list(item.get("evidence_refs") or [])
        chips.append({
            "schema_version": "evidence-chip/v1",
            "claim_id": item.get("claim_id"),
            "sentence": item.get("claim"),
            "status": item.get("status"),
            "reason": item.get("reason") or item.get("limitation"),
            "evidence_refs": refs,
            "provenance_spans": list(item.get("provenance_spans") or []),
            "tool_names": sorted({str(ref.get("tool_name")) for ref in refs if isinstance(ref, dict) and ref.get("tool_name")}),
            "score": item.get("score"),
        })
    return chips


def _structured_verdict_from_gate(gate: Dict[str, Any]) -> Dict[str, Any]:
    allowed = bool(gate.get("allowed"))
    downgraded = gate.get("downgraded_claims", []) if isinstance(gate.get("downgraded_claims"), list) else []
    verified = gate.get("verified_claims", []) if isinstance(gate.get("verified_claims"), list) else []
    blocking = list(gate.get("blocking_reasons") or [])
    verdict = "inconclusive" if allowed else "blocked"
    return {
        "schema_version": "structured-verdict/v1",
        "verdict": verdict,
        "scope": "investigation",
        "allowed_final": allowed,
        "summary": "Final response is evidence-gated; unsupported verdict-like claims are not authoritative.",
        "supported_claims": [{"claim": item.get("claim"), "evidence_refs": item.get("evidence_refs", [])} for item in verified if isinstance(item, dict)],
        "unsupported_claims": [{"claim": item.get("claim"), "reason": item.get("limitation") or "Unsupported by deterministic evidence."} for item in downgraded if isinstance(item, dict)],
        "limitations": blocking or list(gate.get("missing_evidence") or []),
        "coverage": {},
        "ui_badge": verdict,
        "authority": "deterministic_evidence_gate",
    }


class FinalAnswerGate:
    """Gate final answers where an investigation objective requires real evidence."""

    _DIRECT_OBJECTIVE_TYPES = {"direct", "direct_response", "config", "capability_explanation", "general_explanation"}
    _DIRECT_CAPABILITIES = {"config.capability.explain"}

    @staticmethod
    def _is_inconclusive_inline_log_status(state: Any, draft_answer: str) -> bool:
        text = str(draft_answer or "").lower()
        if "inconclusive" not in text or any(token in text for token in ("confirmed malicious", "confirmed clean", "benign confirmed")):
            return False
        findings = list(getattr(state, "findings", []) or []) if state is not None else []
        return any(isinstance(item, dict) and item.get("tool") == "analyze_log_artifact" for item in findings)

    def __init__(self, reflection_engine: Optional[ReflectionEngine] = None, claim_verifier: Optional[ClaimVerifier] = None, final_reviewer: Optional[FinalInvestigationReviewer] = None):
        self.reflection_engine = reflection_engine or ReflectionEngine()
        self.claim_verifier = claim_verifier or ClaimVerifier()
        self.investigation_completeness = InvestigationCompletenessGate()
        self.final_reviewer = final_reviewer

    def evaluate(self, *, objective: Dict[str, Any] | Any, state: Any, draft_answer: str = "") -> GateDecision:
        objective_dict = self._as_dict(objective)
        if self._allows_without_evidence(objective_dict, state):
            return GateDecision(allowed=True, mode="direct_or_explanation_allowed", objective_ref=str(objective_dict.get("contract_id") or ""), status="allowed")

        reasoning_state = getattr(state, "reasoning_state", {}) if state is not None else {}
        if self._agentic_investigation_gate_enabled(objective_dict, state, reasoning_state):
            if self._is_inconclusive_inline_log_status(state, draft_answer):
                coverage = reasoning_state.get("coverage_matrix", {}) if isinstance(reasoning_state, dict) else {}
                missing = list(coverage.get("missing_facets") or []) if isinstance(coverage, dict) else []
                return GateDecision(
                    allowed=True,
                    mode="pasted_log_artifact_inconclusive_allowed",
                    objective_ref=str(objective_dict.get("contract_id") or ""),
                    status="allowed",
                    missing_evidence=missing,
                    structured_verdict={
                        "schema_version": "structured-verdict/v1",
                        "scope": "pasted_log_artifact",
                        "verdict": "inconclusive",
                        "allowed_final": True,
                        "completion_status": "inconclusive_inline_log_status",
                        "authority": "deterministic_inline_log_boundary",
                    },
                )
            completion = self.investigation_completeness.evaluate(state, draft_answer)
            if isinstance(reasoning_state, dict):
                inv_state = self.investigation_completeness.build_state(state)
                inv_state.completion = completion
                reasoning_state["investigation_state"] = inv_state.to_dict()
                reasoning_state["investigation_completion"] = completion.to_dict()
            reviewer_decision = None
            if completion.allowed and completion.status == "complete" and self._llm_final_reviewer_enabled(reasoning_state):
                reviewer = self.final_reviewer or FinalInvestigationReviewer()
                inv_state = self.investigation_completeness.build_state(state)
                reviewer_decision = reviewer.review(investigation_state=inv_state, completion=completion, candidate_answer=draft_answer)
                if isinstance(reasoning_state, dict):
                    reasoning_state["final_reviewer"] = reviewer_decision.to_dict()
                    if not reviewer_decision.approved:
                        inv = reasoning_state.get("investigation_state") if isinstance(reasoning_state.get("investigation_state"), dict) else inv_state.to_dict()
                        existing_actions = inv.get("next_actions", []) if isinstance(inv.get("next_actions"), list) else []
                        inv["next_actions"] = [*existing_actions, *[a.to_dict() for a in reviewer_decision.required_followups]]
                        reasoning_state["investigation_state"] = inv
                if not reviewer_decision.approved:
                    return GateDecision(
                        allowed=False,
                        mode="reviewer_rejected",
                        objective_ref=str(objective_dict.get("contract_id") or ""),
                        status="reviewer_rejected",
                        blocking_reasons=[reviewer_decision.rationale],
                        missing_evidence=[a.action_type for a in reviewer_decision.required_followups],
                        provisional_answer="AISA cannot finalize yet; the final reviewer found remaining evidence or write-up gaps.",
                        structured_verdict={
                            "schema_version": "structured-verdict/v1",
                            "verdict": "blocked",
                            "scope": "investigation",
                            "allowed_final": False,
                            "completion_status": "reviewer_rejected",
                            "reviewer": reviewer_decision.to_dict(),
                            "pending_actions": [a.to_dict() for a in reviewer_decision.required_followups],
                            "authority": "llm_final_reviewer_and_deterministic_gate",
                        },
                    )
            if not completion.allowed or completion.status == "incomplete_budget_exhausted":
                return GateDecision(
                    allowed=completion.allowed,
                    mode=completion.status,
                    objective_ref=str(objective_dict.get("contract_id") or ""),
                    status=completion.status,
                    blocking_reasons=self._dedupe(completion.blocking_reasons),
                    missing_evidence=self._dedupe([*completion.missing_milestones, *[a.action_type for a in completion.pending_actions]]),
                    provisional_answer=completion.provisional_answer,
                    required_answer_constraints=self._dedupe(completion.blocking_reasons),
                    structured_verdict={
                        "schema_version": "structured-verdict/v1",
                        "verdict": "incomplete" if completion.allowed else "blocked",
                        "scope": "investigation",
                        "allowed_final": completion.allowed,
                        "completion_status": completion.status,
                        "stop_reason": completion.stop_reason,
                        "coverage": completion.coverage,
                        "pending_actions": [a.to_dict() for a in completion.pending_actions],
                        "limitations": completion.blocking_reasons,
                        "authority": "deterministic_investigation_completeness_gate",
                    },
                )
        coverage = reasoning_state.get("coverage_matrix", {}) if isinstance(reasoning_state, dict) else {}
        findings = list(getattr(state, "findings", []) or []) if state is not None else []
        observations = list(getattr(state, "active_observations", []) or []) if state is not None else []
        reflection = self.reflection_engine.reflect(
            objective=objective_dict,
            findings=findings,
            observations=observations,
            coverage=coverage,
            reasoning_state=reasoning_state if isinstance(reasoning_state, dict) else {},
        )
        strict_mode = self._is_strict_production(objective_dict, state)
        verifications = self.claim_verifier.verify(draft_answer=draft_answer, state=state, objective=objective_dict, strict=strict_mode)
        downgraded = [item for item in verifications if item.status in {"downgraded", "contradicted", "unsupported", "insufficient"}]
        inline_verdict = self._allowed_inline_inconclusive_verdict(state, reasoning_state if isinstance(reasoning_state, dict) else {})
        inline_scope_allows_gap_answer = bool(inline_verdict) and not self._draft_requests_authoritative_verdict(draft_answer)
        blocking = [] if inline_scope_allows_gap_answer else list(reflection.blocking_reasons)
        missing = list(reflection.missing_facets)

        degraded_capabilities = []
        if isinstance(reasoning_state, dict):
            degraded_capabilities.extend(reasoning_state.get("degraded_capabilities", []) if isinstance(reasoning_state.get("degraded_capabilities"), list) else [])
            soc_task = reasoning_state.get("soc_task_state", {}) if isinstance(reasoning_state.get("soc_task_state"), dict) else {}
            if soc_task.get("pending_clarifications"):
                blocking.append("Task is waiting for analyst clarification; final answer must be provisional.")
            if soc_task.get("pending_approvals"):
                blocking.append("Task is waiting for analyst approval; response actions are not executed.")
            for action in soc_task.get("actions", []) or []:
                if isinstance(action, dict):
                    preflight = action.get("preflight") if isinstance(action.get("preflight"), dict) else {}
                    if preflight and not preflight.get("allowed"):
                        blocking.extend(str(item) for item in preflight.get("blocking_reasons", []) if str(item).strip())
        degraded_capabilities.extend([item for item in findings if isinstance(item, dict) and item.get("type") in {"capability_degraded", "approval_rejected"}])
        if degraded_capabilities:
            blocking.append("Required capability or backend is degraded/approval-blocked and must be stated explicitly.")

        if downgraded and not inline_scope_allows_gap_answer:
            blocking.extend(item.limitation for item in downgraded if item.limitation)

        if inline_scope_allows_gap_answer:
            return GateDecision(
                allowed=True,
                mode="pasted_log_artifact_inconclusive_allowed",
                objective_ref=str(objective_dict.get("contract_id") or ""),
                status="allowed",
                blocking_reasons=[],
                missing_evidence=self._dedupe([*missing, *list(inline_verdict.get("limitations") or [])]),
                verified_claims=[item for item in verifications if item.status == "verified"],
                downgraded_claims=[],
                provisional_answer=draft_answer,
                structured_verdict=inline_verdict,
                required_answer_constraints=[],
            )

        if not blocking:
            return GateDecision(
                allowed=True,
                mode="investigation_grounded",
                objective_ref=str(objective_dict.get("contract_id") or ""),
                status="allowed",
                verified_claims=[item for item in verifications if item.status == "verified"],
                downgraded_claims=downgraded,
            )

        provisional = self.build_provisional_answer(blocking_reasons=blocking, missing_evidence=missing, draft_answer=draft_answer)
        return GateDecision(
            allowed=False,
            mode="provisional_evidence_gap",
            objective_ref=str(objective_dict.get("contract_id") or ""),
            status="blocked",
            blocking_reasons=self._dedupe(blocking),
            missing_evidence=self._dedupe(missing),
            downgraded_claims=downgraded,
            verified_claims=[item for item in verifications if item.status == "verified"],
            provisional_answer=provisional,
            required_answer_constraints=self._dedupe(blocking),
        )

    @staticmethod
    def _llm_final_reviewer_enabled(reasoning_state: Any) -> bool:
        if not isinstance(reasoning_state, dict):
            return False
        flags = reasoning_state.get("agentic_investigation") if isinstance(reasoning_state.get("agentic_investigation"), dict) else {}
        return bool(flags.get("llm_final_reviewer_enabled", reasoning_state.get("llm_final_reviewer_enabled", False)))

    @staticmethod
    def _agentic_investigation_gate_enabled(objective: Dict[str, Any], state: Any, reasoning_state: Any) -> bool:
        if not isinstance(reasoning_state, dict):
            reasoning_state = {}
        flags = reasoning_state.get("agentic_investigation") if isinstance(reasoning_state.get("agentic_investigation"), dict) else {}
        explicit = flags.get("gate_enabled", reasoning_state.get("agentic_investigation_gate_enabled"))
        if explicit is False:
            return False
        input_type = str(reasoning_state.get("input_type") or reasoning_state.get("compiled_input_kind") or "").lower()
        lane = str(objective.get("lane") or "").lower()
        goal = str(getattr(state, "goal", "") or "").lower()
        return explicit is True or input_type == "raw_log" or any(token in goal for token in ("sysmon", "stage2.exe", "powershell.exe", "raw log"))

    def build_provisional_answer(self, *, blocking_reasons: List[str], missing_evidence: List[str], draft_answer: str = "") -> str:
        parts = [
            "AISA cannot support a final verdict from the current evidence yet.",
            "This is a provisional evidence-gap response, not a malicious/clean conclusion.",
        ]
        if blocking_reasons:
            parts.append("Blocking gaps: " + "; ".join(self._dedupe(blocking_reasons)[:4]) + ".")
        if missing_evidence:
            parts.append("Missing evidence: " + ", ".join(self._dedupe(missing_evidence)[:8]) + ".")
        if draft_answer:
            parts.append("Any prior draft conclusion was downgraded until the missing deterministic evidence is collected.")
        return " ".join(parts)

    def _allowed_inline_inconclusive_verdict(self, state: Any, reasoning_state: Dict[str, Any]) -> Dict[str, Any]:
        candidates: List[Dict[str, Any]] = []
        structured = reasoning_state.get("structured_verdict") if isinstance(reasoning_state, dict) else None
        if isinstance(structured, dict):
            candidates.append(structured)
        for finding in getattr(state, "findings", []) or []:
            if not isinstance(finding, dict):
                continue
            result = finding.get("result") if isinstance(finding.get("result"), dict) else finding
            verdict = result.get("structured_verdict") if isinstance(result, dict) else None
            if isinstance(verdict, dict):
                candidates.append(verdict)
        for observation in getattr(state, "active_observations", []) or []:
            if not isinstance(observation, dict):
                continue
            result = observation.get("result") if isinstance(observation.get("result"), dict) else observation
            verdict = result.get("structured_verdict") if isinstance(result, dict) else None
            if isinstance(verdict, dict):
                candidates.append(verdict)
        for verdict in candidates:
            if (
                str(verdict.get("scope") or "").lower() == "pasted_log_artifact"
                and str(verdict.get("verdict") or "").lower() == "inconclusive"
                and verdict.get("allowed_final") is True
            ):
                return dict(verdict)
        return {}

    @staticmethod
    def _draft_requests_authoritative_verdict(draft_answer: str) -> bool:
        text = str(draft_answer or "").lower()
        if re.search(r"\b(is|was|are|were|definitely|confirmed|verdict[: ]+)\b.{0,40}\b(malicious|clean|benign|safe|compromised)\b", text):
            return True
        return bool(re.search(r"\b(malicious|clean|benign|safe|compromised)\b", text) and not re.search(r"\b(cannot|can't|not enough|insufficient|inconclusive|khong|không)\b", text))

    def _is_strict_production(self, objective: Dict[str, Any], state: Any) -> bool:
        mode = str(objective.get("execution_mode") or objective.get("mode") or "").strip().lower()
        if state is not None:
            mode = mode or str(getattr(state, "execution_mode", "") or "").strip().lower()
            runtime = getattr(state, "runtime_mode", "")
            mode = mode or str(runtime or "").strip().lower()
        return mode in {"strict", "production", "prod", "strict_production"} or bool(objective.get("require_provenance"))

    def _allows_without_evidence(self, objective: Dict[str, Any], state: Any) -> bool:
        objective_type = str(objective.get("objective_type") or objective.get("intent") or "").strip().lower()
        capabilities = {str(item).strip() for item in objective.get("capabilities_required", []) if str(item).strip()}
        if objective_type in self._DIRECT_OBJECTIVE_TYPES or (capabilities and capabilities.issubset(self._DIRECT_CAPABILITIES)):
            return True
        metadata_mode = ""
        if state is not None:
            metadata_mode = str(getattr(state, "execution_mode", "") or "").strip().lower()
        return metadata_mode == "direct_response"

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
