"""Deterministic decision aggregation for Vibe SOC investigations."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


_VERDICT_ORDER = {"UNKNOWN": 0, "CLEAN": 1, "BENIGN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class DecisionEvidence:
    source: str
    verdict: str = "UNKNOWN"
    severity: Optional[str] = None
    score: Optional[float] = None
    confidence: Optional[float] = None
    authority: float = 0.5
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DecisionAggregator:
    """Fuse deterministic tool verdicts with provenance and contradiction handling."""

    _AUTHORITY_BY_SOURCE = {
        "correlate_findings": 1.0,
        "analyze_malware": 0.95,
        "analyze_email": 0.9,
        "investigate_ioc": 0.85,
        "search_logs": 0.75,
    }

    def aggregate(
        self,
        *,
        findings: List[Dict[str, Any]],
        evidence_graph: Optional[Dict[str, Any]] = None,
        coverage: Optional[Dict[str, Any]] = None,
        objective: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        evidences = self.collect_evidence(findings)
        if not evidences:
            return self._empty(coverage=coverage, objective=objective)

        contradictions = self._detect_contradictions(evidences)
        selected = self._select(evidences, contradictions)
        confidence = self._aggregate_confidence(selected, evidences, contradictions, coverage)
        severity = self._select_severity(evidences)
        aggregate_id = "decision-" + hashlib.sha1(
            (selected.source + selected.verdict + str(len(evidences))).encode("utf-8")
        ).hexdigest()[:10]
        reason = self._reason(selected, contradictions, coverage)
        return {
            "schema_version": "decision-aggregate/v1",
            "aggregate_id": aggregate_id,
            "verdict": selected.verdict,
            "severity": severity or selected.severity,
            "score": selected.score,
            "confidence": confidence,
            "source": selected.source,
            "authority": "deterministic_decision_aggregator",
            "authoritative_for_verdict": bool(selected.verdict in {"MALICIOUS", "SUSPICIOUS", "CLEAN", "BENIGN"} and not contradictions),
            "contradiction_status": "contradicted" if contradictions else "none",
            "contradictions": contradictions,
            "aggregation_reason": reason,
            "evidence_refs": selected.evidence_refs,
            "source_refs": [item.to_dict() for item in evidences],
            "coverage": self._compact_coverage(coverage),
            "objective_ref": str((objective or {}).get("contract_id") or ""),
            "policy_flags": self._collect_policy_flags(evidences),
        }

    def collect_evidence(self, findings: List[Dict[str, Any]]) -> List[DecisionEvidence]:
        collected: List[DecisionEvidence] = []
        for index, finding in enumerate(findings or []):
            if not isinstance(finding, dict) or finding.get("type") != "tool_result":
                continue
            payload = finding.get("result")
            payload = payload.get("result") if isinstance(payload, dict) and isinstance(payload.get("result"), dict) else payload
            if not isinstance(payload, dict):
                continue
            normalized = self._normalize_payload(payload)
            if not any(normalized.get(key) is not None for key in ("verdict", "severity", "score", "confidence")):
                continue
            source = str(finding.get("tool") or "tool_result")
            collected.append(DecisionEvidence(
                source=source,
                verdict=str(normalized.get("verdict") or "UNKNOWN").upper(),
                severity=str(normalized.get("severity")).lower() if normalized.get("severity") is not None else None,
                score=normalized.get("score"),
                confidence=normalized.get("confidence"),
                authority=self._AUTHORITY_BY_SOURCE.get(source, 0.6),
                evidence_refs=[{
                    "tool_name": source,
                    "step_number": finding.get("step", index),
                    "finding_index": index,
                    "summary": str(payload)[:240],
                }],
                raw=payload,
            ))
        return collected

    def _normalize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        structured = payload.get("structured_verdict") if isinstance(payload.get("structured_verdict"), dict) else {}
        decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
        sources = [structured, decision, payload]
        result: Dict[str, Any] = {}
        for key in ("verdict", "severity", "score", "confidence"):
            for source in sources:
                if source.get(key) is not None:
                    result[key] = source.get(key)
                    break
        for numeric in ("score", "confidence"):
            if result.get(numeric) is not None:
                try:
                    result[numeric] = float(result[numeric])
                except (TypeError, ValueError):
                    result[numeric] = None
        return result

    def _select(self, evidences: List[DecisionEvidence], contradictions: List[Dict[str, Any]]) -> DecisionEvidence:
        if contradictions:
            strongest = max(evidences, key=lambda item: item.authority)
            return DecisionEvidence(
                source=strongest.source,
                verdict="SUSPICIOUS",
                severity=self._select_severity(evidences) or strongest.severity,
                score=strongest.score,
                confidence=0.5,
                authority=strongest.authority,
                evidence_refs=strongest.evidence_refs,
                raw=strongest.raw,
            )
        return max(evidences, key=lambda item: (item.authority, item.confidence or 0.0, _VERDICT_ORDER.get(item.verdict, 0)))

    def _detect_contradictions(self, evidences: List[DecisionEvidence]) -> List[Dict[str, Any]]:
        strong = [item for item in evidences if item.verdict in {"MALICIOUS", "SUSPICIOUS", "CLEAN", "BENIGN"}]
        contradictions = []
        for left in strong:
            for right in strong:
                if left is right:
                    continue
                if {left.verdict, right.verdict} & {"MALICIOUS", "SUSPICIOUS"} and {left.verdict, right.verdict} & {"CLEAN", "BENIGN"}:
                    key = tuple(sorted([left.source, right.source]))
                    if not any(item.get("sources") == list(key) for item in contradictions):
                        contradictions.append({"sources": list(key), "verdicts": [left.verdict, right.verdict], "status": "conflicting_verdicts"})
        return contradictions

    def _select_severity(self, evidences: List[DecisionEvidence]) -> Optional[str]:
        severities = [item.severity for item in evidences if item.severity]
        if not severities:
            return None
        return max(severities, key=lambda value: _SEVERITY_ORDER.get(str(value).lower(), -1))

    def _aggregate_confidence(self, selected: DecisionEvidence, evidences: List[DecisionEvidence], contradictions: List[Dict[str, Any]], coverage: Optional[Dict[str, Any]]) -> float:
        base = selected.confidence if selected.confidence is not None else selected.authority
        if len(evidences) > 1:
            base += 0.05
        if contradictions:
            base = min(base, 0.55)
        status = str((coverage or {}).get("overall_status") or (coverage or {}).get("coverage_status") or "").lower()
        if "partial" in status or "missing" in status:
            base = min(base, 0.7)
        return round(max(0.0, min(1.0, float(base))), 3)

    def _reason(self, selected: DecisionEvidence, contradictions: List[Dict[str, Any]], coverage: Optional[Dict[str, Any]]) -> str:
        if contradictions:
            return "Conflicting deterministic verdicts were found; aggregator downgraded to a conservative suspicious/needs-review outcome."
        status = (coverage or {}).get("overall_status") or (coverage or {}).get("coverage_status")
        return f"Selected highest-authority deterministic evidence from {selected.source}; coverage={status or 'unknown'}."

    @staticmethod
    def _compact_coverage(coverage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not isinstance(coverage, dict):
            return {}
        return {
            "status": coverage.get("overall_status") or coverage.get("coverage_status"),
            "score": coverage.get("overall_score"),
            "missing_facets": list(coverage.get("missing_facets") or [])[:12],
        }

    @staticmethod
    def _collect_policy_flags(evidences: List[DecisionEvidence]) -> List[str]:
        flags: List[str] = []
        for evidence in evidences:
            flags.extend(str(item) for item in evidence.raw.get("policy_flags", []) if str(item).strip())
        return list(dict.fromkeys(flags))

    def _empty(self, *, coverage: Optional[Dict[str, Any]], objective: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "schema_version": "decision-aggregate/v1",
            "aggregate_id": "decision-empty",
            "verdict": "UNKNOWN",
            "severity": None,
            "score": None,
            "confidence": 0.0,
            "source": None,
            "authority": "deterministic_decision_aggregator",
            "authoritative_for_verdict": False,
            "contradiction_status": "no_evidence",
            "contradictions": [],
            "aggregation_reason": "No deterministic decision evidence was available.",
            "evidence_refs": [],
            "source_refs": [],
            "coverage": self._compact_coverage(coverage),
            "objective_ref": str((objective or {}).get("contract_id") or ""),
            "policy_flags": [],
        }
