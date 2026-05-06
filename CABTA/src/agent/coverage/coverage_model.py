"""Dict-safe coverage models for AISA investigation evidence gaps."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class CoverageRequirement:
    lane: str
    facet: str
    required: bool = True
    description: str = ""
    minimum_basis: str = "direct_or_typed_evidence"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageCell:
    facet: str
    status: str = "missing"
    basis: str = "no_evidence"
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    missing_fields: List[str] = field(default_factory=list)
    blocking_gap: bool = True
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(float(payload.get("confidence", 0.0)), 3)
        return payload


@dataclass
class CoverageMatrix:
    lane: str
    cells: List[CoverageCell]
    requirements: List[CoverageRequirement] = field(default_factory=list)
    coverage_targets: List[str] = field(default_factory=list)
    overall_status: str = "missing"
    overall_score: float = 0.0
    blocking_gaps: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    schema_version: str = "coverage-matrix/v1"
    coverage_id: str = ""
    objective_ref: str = ""
    retry_state: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "coverage_id": self.coverage_id or f"cov-{abs(hash((self.lane, tuple(self.coverage_targets)))) % 10000000}",
            "objective_ref": self.objective_ref,
            "lane": self.lane,
            "requirements": [item.to_dict() for item in self.requirements],
            "cells": [item.to_dict() for item in self.cells],
            "coverage_targets": list(self.coverage_targets),
            "overall_status": self.overall_status,
            "coverage_status": self.overall_status,
            "overall_score": round(float(self.overall_score), 3),
            "blocking_gaps": list(self.blocking_gaps),
            "summary": self.summary,
            "retry_state": dict(self.retry_state or {}),
            "required_facets": [item.facet for item in self.requirements],
            "covered_facets": [item.facet for item in self.cells if item.status == "covered"],
            "missing_facets": [item.facet for item in self.cells if item.status in {"missing", "unknown", "unavailable", "degraded"}],
            "partial_facets": [item.facet for item in self.cells if item.status == "partial"],
        }
