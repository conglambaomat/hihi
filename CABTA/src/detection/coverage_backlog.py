"""Deterministic planning helpers for detection coverage and lifecycle gaps."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

_PHASE_RULE_TYPES = {
    "Initial Access": ["sigma", "spl", "kql"],
    "Execution": ["sigma", "spl", "kql", "yara"],
    "Persistence": ["sigma", "spl", "kql"],
    "Privilege Escalation": ["sigma", "spl", "kql"],
    "Defense Evasion": ["sigma", "spl", "kql", "yara"],
    "Credential Access": ["sigma", "spl", "kql"],
    "Discovery": ["sigma", "spl", "kql"],
    "Lateral Movement": ["sigma", "spl", "kql"],
    "Collection": ["sigma", "spl", "kql"],
    "Command and Control": ["sigma", "spl", "kql", "snort"],
    "Exfiltration": ["sigma", "spl", "kql", "snort"],
    "Impact": ["sigma", "spl", "kql"],
}


def build_detection_backlog(
    *,
    coverage_result: Dict[str, Any],
    techniques: List[Dict[str, Any]],
    target_platforms: Optional[List[str]] = None,
    existing_rule_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Turn ATT&CK coverage analysis into a prioritized engineering backlog."""
    platforms = [str(item).lower() for item in (target_platforms or ["sigma", "spl", "kql", "yara", "snort"])]
    existing = {str(item).lower() for item in (existing_rule_types or [])}
    missing_phases = list(coverage_result.get("missing_phases") or [])
    coverage_ratio_pct = float(coverage_result.get("coverage_ratio_pct") or 0.0)

    backlog: List[Dict[str, Any]] = []
    for phase in missing_phases:
        recommended = [name for name in _PHASE_RULE_TYPES.get(phase, ["sigma", "spl", "kql"]) if name in platforms and name not in existing]
        backlog.append(
            {
                "gap_type": "phase_gap",
                "phase": phase,
                "priority": "high" if phase in {"Initial Access", "Execution", "Command and Control"} else "medium",
                "recommended_rule_types": recommended or [name for name in platforms if name not in existing][:3],
                "rationale": f"Kill-chain phase '{phase}' is not covered by current ATT&CK evidence.",
            }
        )

    for item in techniques[:8]:
        technique_id = str(item.get("technique_id") or "").strip()
        if not technique_id:
            continue
        phase = str(item.get("tactic") or "Unknown").replace("-", " ").title()
        backlog.append(
            {
                "gap_type": "technique_hardening",
                "phase": phase,
                "technique_id": technique_id,
                "technique_name": item.get("technique_name") or technique_id,
                "priority": "high" if coverage_ratio_pct < 50 else "medium",
                "recommended_rule_types": [name for name in _PHASE_RULE_TYPES.get(phase, ["sigma", "spl", "kql"]) if name in platforms][:3],
                "rationale": "Observed ATT&CK evidence should be turned into durable detections and hunt pivots.",
            }
        )

    lifecycle = {
        "coverage_status": "mature" if coverage_ratio_pct >= 70 else "developing" if coverage_ratio_pct >= 35 else "early",
        "next_review_window": "7d" if coverage_ratio_pct < 50 else "30d",
        "actions": [
            "Promote high-priority gaps into detection backlog tickets.",
            "Generate rules only from evidence-backed techniques and indicators.",
            "Review false-positive tuning after first deployment cycle.",
        ],
    }

    priority_summary = {
        "high": sum(1 for item in backlog if item.get("priority") == "high"),
        "medium": sum(1 for item in backlog if item.get("priority") == "medium"),
        "low": sum(1 for item in backlog if item.get("priority") == "low"),
    }
    return {
        "target_platforms": platforms,
        "existing_rule_types": sorted(existing),
        "backlog": backlog,
        "backlog_count": len(backlog),
        "priority_summary": priority_summary,
        "lifecycle": lifecycle,
    }
