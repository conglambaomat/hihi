"""Evaluate investigation coverage from typed observations and evidence state."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .coverage_model import CoverageCell, CoverageMatrix
from .lane_contracts import requirements_for_lane

_FIELD_ALIASES = {
    "user": ["user", "principal", "account", "username"],
    "session": ["session", "session_id", "logon_id"],
    "source_ip": ["source_ip", "src_ip", "client_ip", "ip"],
    "host": ["host", "asset", "hostname", "device"],
    "process": ["process", "process_name", "command_line", "cmdline", "image", "parent_process", "parentimage"],
    "network": ["dest_ip", "destination_ip", "domain", "url", "remote_ip", "network"],
    "sender": ["sender", "from_address", "mail_from"],
    "recipient": ["recipient", "to_address", "delivered_to"],
    "delivery": ["delivery", "delivered", "message_id", "mailbox"],
    "url_or_attachment": ["url", "attachment", "attachments", "file_name"],
    "file_hash": ["hash", "hashes", "sha256", "sha1", "md5"],
    "file_path": ["file_path", "path", "folderpath", "file_name", "image"],
    "ioc": ["ioc", "indicator", "domain", "url", "hash", "ip"],
    "timeline": ["timestamp", "time", "_time", "@timestamp"],
    "timestamp": ["timestamp", "time", "_time", "@timestamp", "raw_event"],
    "destination_ip": ["destination_ip", "dest_ip", "dstip", "dst_ip", "remote_ip"],
    "destination_port": ["destination_port", "dest_port", "dst_port", "dstport", "port"],
    "protocol_app": ["protocol", "app", "application", "transport", "service", "protocol_app"],
    "action": ["action", "event_action", "act", "outcome"],
    "source_sourcetype": ["source", "sourcetype", "index"],
    "certificate": ["certificate", "ssl_subject_common_name", "ssl_issuer_common_name", "tls", "ssl"],
    "raw_event": ["raw_event", "raw_text", "event"],
    "backend": ["backend", "source", "sourcetype"],
}

_ENTITY_FACETS = {
    "user": {"user"},
    "session": {"session"},
    "source_ip": {"ip"},
    "host": {"host", "asset"},
    "process": {"process"},
    "network": {"ip", "domain", "url"},
    "sender": {"sender", "email"},
    "recipient": {"recipient", "email", "user"},
    "url_or_attachment": {"url", "file"},
    "file_hash": {"hash"},
    "file_path": {"file"},
    "ioc": {"ip", "domain", "url", "hash"},
}


class CoverageEvaluator:
    """Build a coverage matrix without treating inferred-only evidence as complete."""

    def evaluate(
        self,
        *,
        active_observations: List[Dict[str, Any]] | None,
        entity_state: Dict[str, Any] | None,
        evidence_state: Dict[str, Any] | None,
        reasoning_state: Dict[str, Any] | None,
        lane: str,
        log_coverage: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        clean_lane = str(lane or (reasoning_state or {}).get("investigation_lane") or "ioc").strip().lower() or "ioc"
        requirements = requirements_for_lane(clean_lane)
        observations = [item for item in (active_observations or []) if isinstance(item, dict)]
        observations.extend(self._inline_log_observations(reasoning_state or {}))
        entities = (entity_state or {}).get("entities", {}) if isinstance(entity_state, dict) else {}
        relationships = (entity_state or {}).get("relationships", []) if isinstance(entity_state, dict) else []
        timeline = (evidence_state or {}).get("timeline", []) if isinstance(evidence_state, dict) else []
        cells: List[CoverageCell] = []

        log_covered = set(log_coverage.get("covered_facets", []) if isinstance(log_coverage, dict) else [])
        log_missing = set(log_coverage.get("missing_facets", []) if isinstance(log_coverage, dict) else [])

        for requirement in requirements:
            facet = requirement.facet
            status, basis, refs, confidence = self._facet_status(facet, observations, entities, relationships, timeline)
            if facet in log_covered and status != "covered":
                status, basis, confidence = "partial", "log_result_metadata", max(confidence, 0.62)
            if facet in log_missing and status == "unknown":
                status = "missing"
            missing_fields = [] if status == "covered" else [facet]
            cells.append(
                CoverageCell(
                    facet=facet,
                    status=status,
                    basis=basis,
                    evidence_refs=refs[:6],
                    missing_fields=missing_fields,
                    blocking_gap=status in {"missing", "unknown"},
                    confidence=confidence,
                )
            )

        hypothesis_cells = self._hypothesis_requirement_cells(
            reasoning_state=reasoning_state or {},
            observations=observations,
            entities=entities,
            relationships=relationships,
        )
        cells.extend(hypothesis_cells)

        covered_weight = sum(1.0 if cell.status == "covered" else 0.5 if cell.status == "partial" else 0.0 for cell in cells)
        overall_score = covered_weight / max(len(cells), 1)
        if overall_score >= 0.95:
            overall_status = "covered"
        elif overall_score > 0.0:
            overall_status = "partial"
        else:
            overall_status = "missing"
        blocking = [
            {"facet": cell.facet, "status": cell.status, "basis": cell.basis, "missing_fields": cell.missing_fields}
            for cell in cells
            if cell.blocking_gap
        ]
        summary = f"Coverage {overall_status} for {clean_lane}: {overall_score:.0%} of required facets covered or partially covered."
        return CoverageMatrix(
            lane=clean_lane,
            requirements=requirements,
            cells=cells,
            coverage_targets=[item.facet for item in requirements],
            overall_status=overall_status,
            overall_score=overall_score,
            blocking_gaps=blocking,
            summary=summary,
        ).to_dict()

    def _inline_log_observations(self, reasoning_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        soc_task = reasoning_state.get("soc_task_state", {}) if isinstance(reasoning_state, dict) else {}
        artifacts = soc_task.get("artifacts", []) if isinstance(soc_task, dict) else []
        observations: List[Dict[str, Any]] = []
        for artifact in artifacts if isinstance(artifacts, list) else []:
            if not isinstance(artifact, dict) or artifact.get("type") != "inline_log_event":
                continue
            fields = artifact.get("fields", {}) if isinstance(artifact.get("fields"), dict) else {}
            facts = {
                "raw_event": artifact.get("raw_text") or artifact.get("raw_event_ref"),
                "backend": artifact.get("backend"),
                "source": artifact.get("source"),
                "sourcetype": artifact.get("sourcetype"),
                **fields,
            }
            if facts.get("src_ip") and not facts.get("source_ip"):
                facts["source_ip"] = facts.get("src_ip")
            if facts.get("dest_ip") and not facts.get("destination_ip"):
                facts["destination_ip"] = facts.get("dest_ip")
            if facts.get("dest_port") and not facts.get("destination_port"):
                facts["destination_port"] = facts.get("dest_port")
            if facts.get("protocol") or facts.get("transport"):
                facts.setdefault("protocol_app", facts.get("protocol") or facts.get("transport"))
            if facts.get("ssl_subject_common_name") or facts.get("ssl_issuer_common_name"):
                facts.setdefault("certificate", facts.get("ssl_subject_common_name") or facts.get("ssl_issuer_common_name"))
            observations.append({
                "observation_id": artifact.get("artifact_id"),
                "tool_name": "inline_log_artifact",
                "observation_type": "log_event",
                "canonical_facts": facts,
                "typed_fact": {"type": "log_event", "quality": 0.86},
                "quality": 0.86,
            })
        return observations

    def _hypothesis_requirement_cells(
        self,
        *,
        reasoning_state: Dict[str, Any],
        observations: List[Dict[str, Any]],
        entities: Dict[str, Any],
        relationships: List[Any],
    ) -> List[CoverageCell]:
        cells: List[CoverageCell] = []
        hypotheses = reasoning_state.get("hypotheses", []) if isinstance(reasoning_state, dict) else []
        present_types = {self._observation_type(item) for item in observations}
        present_entities = {
            str(entity.get("type") or "").strip().lower()
            for entity in entities.values()
            if isinstance(entity, dict) and str(entity.get("type") or "").strip()
        } if isinstance(entities, dict) else set()
        for obs in observations:
            for entity in obs.get("entities", []) if isinstance(obs.get("entities"), list) else []:
                if isinstance(entity, dict) and str(entity.get("type") or "").strip():
                    present_entities.add(str(entity.get("type") or "").strip().lower())
        relation_strengths: Dict[str, str] = {}
        for item in relationships:
            if not isinstance(item, dict) or not str(item.get("relation") or "").strip():
                continue
            relation_name = str(item.get("relation") or "").strip().lower()
            strength = str(item.get("relation_strength") or item.get("basis") or "missing").strip().lower() or "missing"
            current = relation_strengths.get(relation_name, "missing")
            relation_strengths[relation_name] = self._stronger_relation_basis(current, strength)
        present_relations = set(relation_strengths.keys())

        for hypothesis in hypotheses[:7] if isinstance(hypotheses, list) else []:
            if not isinstance(hypothesis, dict):
                continue
            hypothesis_id = str(hypothesis.get("id") or "hypothesis").strip() or "hypothesis"
            hypothesis_type = str(hypothesis.get("hypothesis_type") or hypothesis.get("type") or "generic_incident").strip()
            attack_path = [str(item) for item in (hypothesis.get("attack_path") or []) if str(item).strip()]
            for contract in hypothesis.get("required_evidence", []) or []:
                if not isinstance(contract, dict):
                    continue
                required_obs = [str(item).strip().lower() for item in contract.get("required_observation_types", []) or [] if str(item).strip()]
                required_entities = [str(item).strip().lower() for item in contract.get("required_entities", []) or [] if str(item).strip()]
                required_relations = [str(item).strip().lower() for item in contract.get("required_relations", []) or [] if str(item).strip()]
                missing_obs = [item for item in required_obs if item not in present_types]
                missing_entities = [item for item in required_entities if item not in present_entities]
                relation_basis = {item: relation_strengths.get(item, "missing") for item in required_relations}
                missing_relations = [item for item, basis in relation_basis.items() if basis == "missing"]
                missing_fields = [*missing_obs, *missing_entities, *missing_relations]
                total = max(1, len(required_obs) + len(required_entities) + len(required_relations))
                covered = total - len(missing_fields)
                status = "covered" if not missing_fields else "partial" if covered > 0 else "missing"
                refs = self._refs_for_requirements(observations, required_obs, required_entities)[:6]
                cells.append(CoverageCell(
                    facet=f"hypothesis:{hypothesis_type}:{contract.get('contract_id') or hypothesis_id}",
                    status=status,
                    basis="hypothesis_required_evidence_contract",
                    evidence_refs=refs,
                    missing_fields=missing_fields,
                    blocking_gap=status in {"missing", "partial"},
                    confidence=covered / total,
                    metadata={
                        "cell_type": "hypothesis_required_evidence",
                        "hypothesis_id": hypothesis_id,
                        "hypothesis_type": hypothesis_type,
                        "attack_path": attack_path,
                        "contract_id": contract.get("contract_id"),
                        "required_observation_types": required_obs,
                        "required_entities": required_entities,
                        "required_relations": required_relations,
                        "relation_basis": relation_basis,
                        "strongest_relation_basis": self._strongest_relation_basis(relation_basis),
                    },
                ))
        return cells

    @staticmethod
    def _stronger_relation_basis(current: str, candidate: str) -> str:
        order = {"missing": 0, "co_observed": 1, "inferred": 2, "explicit": 3}
        normalized_current = current if current in order else "missing"
        normalized_candidate = candidate if candidate in order else "inferred"
        return normalized_candidate if order[normalized_candidate] > order[normalized_current] else normalized_current

    @staticmethod
    def _strongest_relation_basis(relation_basis: Dict[str, str]) -> str:
        strongest = "missing"
        for basis in relation_basis.values():
            strongest = CoverageEvaluator._stronger_relation_basis(strongest, str(basis or "missing"))
        return strongest

    @staticmethod
    def _observation_type(observation: Dict[str, Any]) -> str:
        typed = observation.get("typed_fact") if isinstance(observation.get("typed_fact"), dict) else {}
        return str(typed.get("type") or observation.get("observation_type") or "").strip().lower()

    def _refs_for_requirements(self, observations: List[Dict[str, Any]], required_obs: List[str], required_entities: List[str]) -> List[Dict[str, Any]]:
        refs: List[Dict[str, Any]] = []
        for obs in observations:
            obs_type = self._observation_type(obs)
            entity_types = {str(entity.get("type") or "").strip().lower() for entity in obs.get("entities", []) if isinstance(entity, dict)} if isinstance(obs.get("entities"), list) else set()
            if obs_type in required_obs or entity_types.intersection(required_entities):
                refs.append({"observation_id": obs.get("observation_id"), "tool_name": obs.get("tool_name"), "observation_type": obs_type})
        return refs

    def _facet_status(self, facet: str, observations: List[Dict[str, Any]], entities: Dict[str, Any], relationships: List[Any], timeline: List[Any]) -> Tuple[str, str, List[Dict[str, Any]], float]:
        if facet == "timeline" and timeline:
            return "covered", "evidence_timeline", [{"source": "evidence_state.timeline", "count": len(timeline)}], 0.8
        aliases = _FIELD_ALIASES.get(facet, [facet])
        refs: List[Dict[str, Any]] = []
        best_quality = 0.0
        for obs in observations:
            facts = obs.get("canonical_facts") if isinstance(obs.get("canonical_facts"), dict) else obs.get("facts", {})
            typed_fact = obs.get("typed_fact", {}) if isinstance(obs.get("typed_fact"), dict) else {}
            fact_text_keys = {str(key).lower(): value for key, value in (facts or {}).items() if value not in (None, "", [], {})}
            if any(alias.lower() in fact_text_keys for alias in aliases):
                quality = float(typed_fact.get("quality", obs.get("quality", 0.0)) or 0.0)
                refs.append({"observation_id": obs.get("observation_id"), "tool_name": obs.get("tool_name"), "quality": quality})
                best_quality = max(best_quality, quality)
        if refs and best_quality >= 0.68:
            return "covered", "typed_observation", refs, best_quality
        if refs:
            return "partial", "weak_or_low_quality_observation", refs, best_quality

        wanted_types = _ENTITY_FACETS.get(facet, set())
        if wanted_types and isinstance(entities, dict):
            entity_refs = [entity for entity in entities.values() if isinstance(entity, dict) and str(entity.get("type") or "").lower() in wanted_types]
            strong = [entity for entity in entity_refs if float(entity.get("confidence", 0.0) or 0.0) >= 0.75 and entity.get("evidence_refs")]
            if strong:
                return "partial", "entity_observed_without_direct_facet", [{"entity_id": entity.get("id"), "type": entity.get("type")} for entity in strong[:4]], 0.6
        explicit_rel = [rel for rel in relationships if isinstance(rel, dict) and rel.get("relation_strength") == "explicit"]
        if explicit_rel and facet in {"user", "session", "host", "process", "network", "sender", "recipient"}:
            return "partial", "explicit_relation_without_direct_facet", [{"relation": rel.get("relation")} for rel in explicit_rel[:3]], 0.58
        return "missing", "no_direct_evidence", [], 0.0
