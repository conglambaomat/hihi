"""Safe context compression for AISA orchestration metadata."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .token_estimator import estimate_json_tokens

DO_NOT_FORGET = [
    "deterministic_decision",
    "authority_policy",
    "top_contradictions",
    "blocking_coverage_gaps",
    "root_cause_status",
    "memory_contract",
    "approval_or_degraded_state",
]


class ContextCompressor:
    """Compress prompt-selected context without changing evidence authority."""

    def compress(self, sections: Dict[str, Any], *, target_tokens: int, ledger: Any | None = None) -> Dict[str, Any]:
        compressed = {k: v for k, v in (sections or {}).items()}
        compressed.setdefault("do_not_forget", list(DO_NOT_FORGET))
        before = estimate_json_tokens(compressed)
        compressed["evidence_briefs"] = self._dedupe_briefs(list(compressed.get("evidence_briefs", []) or []), ledger=ledger)
        compressed["selected_findings"] = list(compressed.get("selected_findings", []) or [])[:8]
        compressed["entities"] = list(compressed.get("entities", []) or [])[:16]
        compressed["relationships"] = list(compressed.get("relationships", []) or [])[:12]
        compressed["hypotheses"] = self._trim_hypotheses(list(compressed.get("hypotheses", []) or []), ledger=ledger)
        compressed["coverage_gaps"] = list(compressed.get("coverage_gaps", []) or [])[:10]
        after_stage_one = estimate_json_tokens(compressed)
        if ledger is not None and after_stage_one < before:
            ledger.add_compression_action("trim_duplicate_or_low_rank_context", reason="context exceeded compaction threshold", before_tokens=before, after_tokens=after_stage_one)

        if after_stage_one <= target_tokens:
            return compressed

        # Roll up older/neutral evidence but preserve source refs and authority.
        briefs = list(compressed.get("evidence_briefs", []) or [])
        required = [b for b in briefs if isinstance(b, dict) and b.get("do_not_drop")]
        optional = [b for b in briefs if isinstance(b, dict) and not b.get("do_not_drop")]
        kept_optional = optional[: max(0, 10 - len(required))]
        dropped_optional = optional[len(kept_optional):]
        if dropped_optional:
            rollup_refs = []
            for brief in dropped_optional[:20]:
                rollup_refs.extend(brief.get("source_refs") or ([brief.get("evidence_ref")] if brief.get("evidence_ref") else []))
            compressed["phase_rollups"] = [
                {
                    "summary": f"{len(dropped_optional)} lower-ranked evidence briefs were omitted from prompt detail after ranking.",
                    "source_refs": [ref for ref in rollup_refs if isinstance(ref, dict)][:20],
                    "authority": "tool_observation",
                    "authoritative_for_verdict": False,
                }
            ]
            compressed["evidence_briefs"] = [*required, *kept_optional]
            if ledger is not None:
                for brief in dropped_optional:
                    ledger.add_excluded(brief, reason="compressed into phase rollup; lower-ranked optional evidence")
                ledger.add_compression_action("phase_rollup", reason="preserved refs while reducing prompt detail", before_tokens=after_stage_one, after_tokens=estimate_json_tokens(compressed))
        return compressed

    @staticmethod
    def _dedupe_briefs(briefs: List[Dict[str, Any]], *, ledger: Any | None) -> List[Dict[str, Any]]:
        seen = set()
        out = []
        for brief in briefs:
            if not isinstance(brief, dict):
                continue
            key = (
                str((brief.get("evidence_ref") or {}).get("observation_id") or ""),
                str((brief.get("evidence_ref") or {}).get("tool_name") or ""),
                str((brief.get("evidence_ref") or {}).get("step_number") or ""),
                str(brief.get("summary") or "")[:100],
            )
            if key in seen:
                if ledger is not None:
                    ledger.add_excluded(brief, reason="duplicate evidence brief removed")
                continue
            seen.add(key)
            # Ensure compressed summaries retain refs and labels.
            if brief.get("evidence_ref") and not brief.get("source_refs"):
                brief = {**brief, "source_refs": [brief.get("evidence_ref")]}
            brief.setdefault("authority", "tool_observation")
            brief.setdefault("authoritative_for_verdict", False)
            out.append(brief)
        return out

    @staticmethod
    def _trim_hypotheses(hypotheses: List[Dict[str, Any]], *, ledger: Any | None) -> List[Dict[str, Any]]:
        ranked = [item for item in hypotheses if isinstance(item, dict)]
        ranked.sort(key=lambda item: float(item.get("score") or item.get("ranking_score") or item.get("confidence") or 0.0), reverse=True)
        kept = []
        for item in ranked:
            if len(kept) < 6 or item.get("contradiction_refs"):
                kept.append(item)
            elif ledger is not None:
                ledger.add_excluded(item, reason="low-rank candidate hypothesis trimmed during compression")
        return kept[:8]
