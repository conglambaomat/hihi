"""Graph-backed final-answer claim verification."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ClaimVerification:
    claim: str
    status: str
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    limitation: str = ""
    score: float = 0.0
    reason: str = ""
    provenance_spans: List[Dict[str, Any]] = field(default_factory=list)
    claim_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        mapping = {"verified": "supported", "downgraded": "unsupported", "blocked": "unsupported", "insufficient": "insufficient"}
        payload["legacy_status"] = self.status
        payload["status"] = mapping.get(self.status, self.status if self.status in {"supported", "contradicted", "unsupported", "limitation", "insufficient"} else "limitation")
        payload["claim_id"] = self.claim_id or "claim-" + hashlib.sha1(self.claim.encode("utf-8")).hexdigest()[:10]
        payload["reason"] = self.reason or self.limitation
        return payload


class ClaimVerifier:
    """Deterministic verifier that links answer claims to evidence graph nodes."""

    _STRONG_VERDICT_RE = re.compile(
        r"\b(malicious|clean|benign|suspicious|safe|độc hại|doc hai|sạch|sach|an toàn|an toan|đáng ngờ|dang ngo|khả nghi|kha nghi)\b",
        re.IGNORECASE,
    )
    _NEGATION_RE = re.compile(r"\b(no|not|never|without|không|khong|chưa|chua)\b", re.IGNORECASE)
    _TOKEN_RE = re.compile(r"[a-zA-Z0-9_.:/@-]{3,}")

    def __init__(self, *, strict: bool = False, require_provenance: Optional[bool] = None, legacy_mode: bool = False) -> None:
        self.strict = strict
        self.require_provenance = strict if require_provenance is None else bool(require_provenance)
        self.legacy_mode = legacy_mode

    def verify(self, *, draft_answer: str, state: Any, objective: Dict[str, Any], strict: Optional[bool] = None) -> List[ClaimVerification]:
        strict_mode = self.strict if strict is None else bool(strict)
        claims = self._extract_claims(draft_answer)
        if not claims:
            return []
        graph = self._graph_state(state)
        graph_refs = self._graph_evidence(graph)
        legacy_refs = self._legacy_evidence_refs(state)
        if not graph_refs and not strict_mode:
            return self._legacy_verify(claims, state, legacy_refs)

        results: List[ClaimVerification] = []
        for claim in claims:
            support, contradiction = self._match_graph_claim(claim, graph_refs)
            if contradiction:
                results.append(self._result(claim, "contradicted", contradiction[:4], 0.0, "Evidence graph contains contradictory provenance for this claim."))
            elif support:
                score = max(float(item.get("score", 0.0) or 0.0) for item in support)
                status = "verified" if score >= 0.34 else "insufficient"
                reason = "Claim is linked to evidence graph provenance." if status == "verified" else "Claim has weak graph overlap but insufficient provenance confidence."
                results.append(self._result(claim, status, support[:4], score, reason))
            elif self.require_provenance or strict_mode:
                status = "unsupported" if self._STRONG_VERDICT_RE.search(claim) else "insufficient"
                results.append(self._result(claim, status, [], 0.0, "No supporting evidence graph node or provenance span was found."))
            elif legacy_refs:
                results.append(self._result(claim, "verified", legacy_refs[:4], 0.35, "Verified in explicit non-production legacy evidence mode."))
            else:
                results.append(self._result(claim, "unsupported", [], 0.0, "No tool evidence is available for this investigation claim."))
        return results

    def _result(self, claim: str, status: str, refs: List[Dict[str, Any]], score: float, reason: str) -> ClaimVerification:
        return ClaimVerification(
            claim=claim,
            status=status,
            evidence_refs=refs,
            limitation="" if status == "verified" else reason,
            score=round(score, 3),
            reason=reason,
            provenance_spans=[item.get("provenance_span", {}) for item in refs if isinstance(item.get("provenance_span"), dict)],
        )

    def _extract_claims(self, text: str) -> List[str]:
        clean = re.sub(r"\s+", " ", str(text or "").strip())
        if not clean:
            return []
        parts = re.split(r"(?<=[.!?])\s+|\n+", clean)
        claims = [part.strip(" -•") for part in parts if len(part.strip()) >= 8]
        return claims[:12]

    def _graph_state(self, state: Any) -> Dict[str, Any]:
        for name in ("evidence_state", "evidence_graph", "evidence_graph_state", "graph_state"):
            value = getattr(state, name, None) if state is not None else None
            if isinstance(value, dict):
                return value
        metadata = getattr(state, "metadata", None)
        if isinstance(metadata, dict) and isinstance(metadata.get("evidence_graph"), dict):
            return metadata["evidence_graph"]
        return {}

    def _graph_evidence(self, graph: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes = [n for n in graph.get("nodes", []) if isinstance(n, dict)] if isinstance(graph, dict) else []
        edges = [e for e in graph.get("edges", []) if isinstance(e, dict)] if isinstance(graph, dict) else []
        edge_by_target: Dict[str, List[Dict[str, Any]]] = {}
        for edge in edges:
            edge_by_target.setdefault(str(edge.get("target") or ""), []).append(edge)
            edge_by_target.setdefault(str(edge.get("source") or ""), []).append(edge)
        refs: List[Dict[str, Any]] = []
        for node in nodes:
            text = " ".join(str(node.get(k) or "") for k in ("label", "summary", "value", "status"))
            typed = node.get("typed_fact") if isinstance(node.get("typed_fact"), dict) else {}
            text = (text + " " + " ".join(str(v) for v in typed.values())).strip()
            if not text:
                continue
            node_id = str(node.get("id") or "")
            incoming = edge_by_target.get(node_id, [])
            relation = "contradicts" if any(e.get("relation") == "contradicts" for e in incoming) or node.get("relation") == "contradicts" else "supports"
            refs.append({
                "node_id": node_id,
                "summary": text[:360],
                "tool_name": node.get("tool_name"),
                "step_number": node.get("step_number"),
                "relation": relation,
                "confidence": node.get("confidence") or node.get("quality") or 0.6,
                "provenance_span": {"node_id": node_id, "source_paths": list(node.get("source_paths") or []), "timestamp": node.get("timestamp")},
            })
        return refs

    def _match_graph_claim(self, claim: str, refs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        claim_tokens = set(t.lower() for t in self._TOKEN_RE.findall(claim))
        claim_neg = bool(self._NEGATION_RE.search(claim))
        support: List[Dict[str, Any]] = []
        contradiction: List[Dict[str, Any]] = []
        for ref in refs:
            text = str(ref.get("summary") or "")
            tokens = set(t.lower() for t in self._TOKEN_RE.findall(text))
            if not claim_tokens or not tokens:
                continue
            overlap = claim_tokens & tokens
            score = len(overlap) / max(len(claim_tokens), 1)
            if self._STRONG_VERDICT_RE.search(claim) and self._STRONG_VERDICT_RE.search(text):
                score = max(score, 0.55)
            if score < 0.22:
                continue
            item = dict(ref)
            item["score"] = min(1.0, score * float(ref.get("confidence", 0.6) or 0.6))
            ref_neg = bool(self._NEGATION_RE.search(text))
            if ref.get("relation") == "contradicts" or (claim_neg != ref_neg and len(overlap) >= 2):
                contradiction.append(item)
            else:
                support.append(item)
        support.sort(key=lambda item: item.get("score", 0), reverse=True)
        contradiction.sort(key=lambda item: item.get("score", 0), reverse=True)
        return support, contradiction

    @staticmethod
    def _legacy_evidence_refs(state: Any) -> List[Dict[str, Any]]:
        refs = []
        for finding in getattr(state, "findings", []) or []:
            if isinstance(finding, dict) and finding.get("type") == "tool_result":
                refs.append({"tool_name": finding.get("tool"), "step_number": finding.get("step"), "summary": str(finding.get("result") or "")[:240]})
        return refs[-8:]

    def _legacy_verify(self, claims: List[str], state: Any, evidence_refs: List[Dict[str, Any]]) -> List[ClaimVerification]:
        deterministic = getattr(state, "deterministic_decision", {}) if state is not None else {}
        authoritative = bool((deterministic or {}).get("authoritative_for_verdict"))
        contradiction_status = str((deterministic or {}).get("contradiction_status") or "none")
        out: List[ClaimVerification] = []
        for claim in claims:
            if self._STRONG_VERDICT_RE.search(claim) and contradiction_status == "contradicted":
                out.append(self._result(claim, "contradicted", evidence_refs[:4], 0.0, "Deterministic evidence contains contradictory verdicts."))
            elif self._STRONG_VERDICT_RE.search(claim) and not authoritative:
                out.append(self._result(claim, "downgraded", evidence_refs[:4], 0.2, "Strong verdict claim lacks authoritative deterministic verdict evidence."))
            elif evidence_refs:
                out.append(self._result(claim, "verified", evidence_refs[:4], 0.35, "Legacy non-production evidence fixture supports the claim."))
            else:
                out.append(self._result(claim, "downgraded", [], 0.0, "No tool evidence is available for this investigation claim."))
        return out


__all__ = ["ClaimVerification", "ClaimVerifier"]
