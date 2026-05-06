"""Investigation query plan models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class InvestigationQueryPlan:
    objective: str
    hypothesis_ids: List[str] = field(default_factory=list)
    coverage_targets: List[str] = field(default_factory=list)
    queries: Dict[str, List[str]] = field(default_factory=dict)
    query_variants: List[Dict[str, Any]] = field(default_factory=list)
    expected_observation_types: List[str] = field(default_factory=list)
    expected_entities: List[str] = field(default_factory=list)
    expected_facets: List[str] = field(default_factory=list)
    source_coverage: Dict[str, Any] = field(default_factory=dict)
    success_criteria: List[str] = field(default_factory=list)
    fallback_variants: List[Dict[str, Any]] = field(default_factory=list)
    negative_controls: List[str] = field(default_factory=list)
    quality_score: float = 0.0
    risk_score: float = 0.0
    validation_metadata: Dict[str, Any] = field(default_factory=dict)
    fingerprints: List[str] = field(default_factory=list)
    schema_version: str = "investigation-query-plan/v1"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["quality_score"] = round(float(self.quality_score), 3)
        payload["risk_score"] = round(float(self.risk_score), 3)
        return payload
