"""High-level AISA context pack builder."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .context_budget_manager import ContextBudgetManager
from .context_compressor import ContextCompressor
from .context_ledger import ContextLedger
from .context_map_builder import InvestigationContextMapBuilder
from .context_pack import AUTHORITY_POLICY, ContextRequest, SOCContextPack
from .evidence_retriever import EvidenceRetriever


class ContextOrchestrator:
    """Build prompt-ready SOC context packs while preserving verdict boundaries."""

    def __init__(self, config: Dict[str, Any] | None = None, *, model_resolver=None):
        self.config = config or {}
        self.model_resolver = model_resolver
        self.budget_manager = ContextBudgetManager(self.config)
        self.map_builder = InvestigationContextMapBuilder()
        self.retriever = EvidenceRetriever(self.config)
        self.compressor = ContextCompressor()

    def enabled(self) -> bool:
        return self.budget_manager.enabled()

    def build_pack(self, *, state: Any, request: ContextRequest) -> SOCContextPack:
        model = request.model or (self.model_resolver() if callable(self.model_resolver) else "")
        context_map = self.map_builder.build(state, objective=request.objective, analyst_focus=request.analyst_focus)
        evidence_briefs, excluded_briefs = self.retriever.retrieve(
            context_map,
            objective=request.objective,
            analyst_focus=request.analyst_focus,
        )
        sections = self._build_sections(state=state, request=request, context_map=context_map, evidence_briefs=evidence_briefs)
        budget_report = self.budget_manager.budget_report(sections=sections, objective=request.objective, model=model)
        ledger = ContextLedger(
            ledger_id=f"ctx-ledger-{request.session_id}-{request.step_number}",
            session_id=request.session_id,
            step_number=request.step_number,
            objective=request.objective,
            model=model,
            prompt_mode=request.prompt_mode,
            token_estimate={"total": budget_report.get("estimated_total"), "by_section": budget_report.get("by_section", {})},
        )
        for section, value in sections.items():
            ledger.add_included(
                {
                    "item_id": section,
                    "section": section,
                    "kind": "context_section",
                    "authority": "orchestration_metadata" if section not in {"deterministic_decision"} else "deterministic",
                    "authoritative_for_verdict": section == "deterministic_decision" and bool(value),
                    "token_estimate": (budget_report.get("by_section", {}) or {}).get(section, 0),
                },
                reason="section selected for context pack",
            )
        for brief in evidence_briefs:
            ledger.add_included(brief, reason=brief.get("selected_reason") or "evidence brief selected")
        for brief in excluded_briefs:
            ledger.add_excluded(brief, reason=brief.get("exclude_reason") or "not selected")

        if budget_report.get("over_budget"):
            sections = self.compressor.compress(
                sections,
                target_tokens=int(budget_report.get("compression_target_tokens") or budget_report.get("hard_prompt_budget_tokens") or 1),
                ledger=ledger,
            )
            budget_report = self.budget_manager.budget_report(sections=sections, objective=request.objective, model=model)
            ledger.token_estimate = {"total": budget_report.get("estimated_total"), "by_section": budget_report.get("by_section", {})}

        ledger.add_compression_action(
            "ranking_telemetry",
            item_id="evidence_retrieval",
            reason="Recorded non-authoritative selected item scores and active ranking weights for production tuning.",
            details={
                "ranking_weights_version": self.retriever.ranking_weights_version,
                "ranking_weights": dict(self.retriever.ranking_weights),
                "selected_item_scores": [
                    {
                        "brief_id": item.get("brief_id"),
                        "score": item.get("score"),
                        "why_included": (item.get("ranking_score_detail") or {}).get("why_included"),
                    }
                    for item in evidence_briefs[:24]
                    if isinstance(item, dict)
                ],
                "authoritative_for_verdict": False,
            },
        )
        ledger.context_package_ref = f"ctx-{request.session_id}-{request.step_number}"
        ledger.do_not_claim_constraints = ["Do not claim final compromise or clean verdict without deterministic evidence."]
        ledger_dict = ledger.to_dict(max_items=self.budget_manager.max_ledger_items())
        pack = SOCContextPack(
            pack_id=f"ctx-{request.session_id}-{request.step_number}",
            session_id=request.session_id,
            step_number=request.step_number,
            objective=request.objective,
            sections=sections,
            token_estimate=ledger.token_estimate,
            budget_report=budget_report,
            ledger=ledger_dict,
            ledger_id=ledger.ledger_id,
            context_map_summary=self._context_map_summary(context_map),
            authority_policy=AUTHORITY_POLICY,
            objective_ref=str((getattr(state, "objective_contract", {}) or {}).get("contract_id") if isinstance(getattr(state, "objective_contract", {}), dict) else ""),
        )
        return self._cap_pack(pack)

    def _build_sections(self, *, state: Any, request: ContextRequest, context_map: Dict[str, Any], evidence_briefs: list[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "goal": {"text": getattr(state, "goal", ""), "objective": request.objective},
            "selected_findings": self._selected_findings(getattr(state, "findings", []) or []),
            "reasoning_summary": {
                "legacy_reasoning_block": request.reasoning_block,
                "status": (getattr(state, "reasoning_state", {}) or {}).get("status") if isinstance(getattr(state, "reasoning_state", {}), dict) else None,
                "authority": "agentic_explanation",
                "authoritative_for_verdict": False,
            },
            "evidence_briefs": evidence_briefs,
            "entities": list(context_map.get("ranked_entities", []) or [])[:16],
            "relationships": list(context_map.get("ranked_relationships", []) or [])[:12],
            "hypotheses": list(context_map.get("ranked_hypotheses", []) or [])[:8],
            "coverage_gaps": list(context_map.get("coverage_gaps", []) or [])[:10],
            "root_cause": context_map.get("root_cause_state", {}) or {},
            "deterministic_decision": context_map.get("deterministic_decision", {}) or {},
            "tools": {"tools_block": request.tools_block, "authority": "tool_policy", "authoritative_for_verdict": False},
            "workflow": {"workflow_block": request.workflow_block, "playbooks_block": request.playbooks_block, "authority": "workflow_metadata", "authoritative_for_verdict": False},
            "memory_contract": context_map.get("memory_contract", {}) or {},
            "query_retry": {
                "query_attempts": list(context_map.get("query_attempts", []) or [])[-4:],
                "retry_state": context_map.get("retry_state", {}) or {},
                "authority": "retry_metadata",
                "authoritative_for_verdict": False,
            },
            "authority_policy": AUTHORITY_POLICY,
        }

    @staticmethod
    def _selected_findings(findings: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        selected = []
        for idx, finding in enumerate(findings[-12:]):
            if not isinstance(finding, dict):
                continue
            selected.append({
                "id": f"finding-{finding.get('step', idx)}-{idx}",
                "step": finding.get("step", idx),
                "type": finding.get("type"),
                "tool": finding.get("tool"),
                "summary": str(finding.get("answer") or finding.get("reasoning") or finding.get("tool") or finding.get("type") or "finding"),
                "authority": "tool_observation" if finding.get("type") == "tool_result" else "agentic_explanation",
                "authoritative_for_verdict": False,
            })
        return selected

    @staticmethod
    def _context_map_summary(context_map: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "schema_version": "investigation-context-map-summary/v1",
            "entity_count": len(context_map.get("ranked_entities", []) or []),
            "relationship_count": len(context_map.get("ranked_relationships", []) or []),
            "hypothesis_count": len(context_map.get("ranked_hypotheses", []) or []),
            "evidence_ref_count": len(context_map.get("ranked_evidence_refs", []) or []),
            "contradiction_count": len(context_map.get("contradictions", []) or []),
            "missing_evidence_count": len(context_map.get("missing_evidence", []) or []),
            "coverage_gap_count": len(context_map.get("coverage_gaps", []) or []),
            "authority_policy": context_map.get("authority_policy") or AUTHORITY_POLICY,
            "authoritative_for_verdict": False,
        }

    def _cap_pack(self, pack: SOCContextPack) -> SOCContextPack:
        max_bytes = self.budget_manager.max_context_pack_bytes()
        payload = pack.to_dict()
        try:
            size = len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))
        except TypeError:
            size = 0
        if size <= max_bytes:
            return pack
        sections = dict(pack.sections or {})
        sections["selected_findings"] = list(sections.get("selected_findings", []) or [])[:6]
        sections["evidence_briefs"] = list(sections.get("evidence_briefs", []) or [])[:8]
        sections["entities"] = list(sections.get("entities", []) or [])[:10]
        sections["relationships"] = list(sections.get("relationships", []) or [])[:8]
        sections["hypotheses"] = list(sections.get("hypotheses", []) or [])[:5]
        pack.sections = sections
        if isinstance(pack.ledger, dict):
            pack.ledger["pack_size_capped"] = True
        return pack
