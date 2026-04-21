"""Session-friendly evidence graph with typed observations and edge basis."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceGraph:
    """Maintain a lightweight reasoning-support graph in session metadata."""

    def bootstrap(self, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        state = dict(existing or {})
        state.setdefault("schema_version", 2)
        state.setdefault("nodes", [])
        state.setdefault("edges", [])
        state.setdefault("timeline", [])
        state.setdefault("updated_at", _now_iso())
        return state

    def summarize_causal_support(self, graph_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        state = self.bootstrap(graph_state)
        edges = [item for item in state.get("edges", []) if isinstance(item, dict)]
        supports = [item for item in edges if item.get("relation") in {"supports", "derived_from", "caused_by"}]
        contradicts = [item for item in edges if item.get("relation") == "contradicts"]
        strongest_paths = sorted(
            supports,
            key=lambda item: float(item.get("confidence", 0.0) or 0.0),
            reverse=True,
        )[:6]
        root_paths = self._root_path_summaries(state, strongest_paths)
        return {
            "support_count": len(supports),
            "contradiction_count": len(contradicts),
            "strongest_support_paths": strongest_paths,
            "root_path_summaries": root_paths,
        }

    def ingest_observation(
        self,
        graph_state: Optional[Dict[str, Any]],
        *,
        session_id: str,
        tool_name: str,
        step_number: int,
        evidence_ref: Dict[str, Any],
        entity_state: Optional[Dict[str, Any]],
        observations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        state = self.bootstrap(graph_state)
        observation_items = observations or [
            {
                "observation_id": f"obs:{session_id}:{step_number}:{tool_name}:legacy".lower(),
                "observation_type": "correlation_observation",
                "summary": evidence_ref.get("summary", ""),
                "timestamp": evidence_ref.get("created_at") or _now_iso(),
                "quality": 0.4,
                "source_paths": ["result"],
                "entities": [],
                "facts": {},
            }
        ]

        entity_lookup = {}
        if isinstance(entity_state, dict) and isinstance(entity_state.get("entities"), dict):
            entity_lookup = entity_state.get("entities", {})

        for observation in observation_items:
            if not isinstance(observation, dict):
                continue
            observation_id = str(observation.get("observation_id") or f"obs:{session_id}:{step_number}:{tool_name}").lower()
            typed_fact = observation.get("typed_fact", {}) if isinstance(observation.get("typed_fact"), dict) else {}
            node = {
                "id": observation_id,
                "type": "observation",
                "observation_type": observation.get("observation_type", "correlation_observation"),
                "fact_family": observation.get("fact_family") or typed_fact.get("family"),
                "typed_fact": typed_fact,
                "label": observation.get("summary") or observation.get("observation_type") or tool_name,
                "summary": observation.get("summary", ""),
                "tool_name": tool_name,
                "step_number": step_number,
                "timestamp": observation.get("timestamp") or evidence_ref.get("created_at") or _now_iso(),
                "quality": observation.get("quality"),
                "source_paths": list(observation.get("source_paths", [])),
                "entity_count": len(observation.get("entities", []) if isinstance(observation.get("entities"), list) else []),
            }
            self._upsert_node(state, node)

            entity_ids = self._observation_entity_ids(observation, entity_lookup)
            for entity_id in entity_ids:
                entity_payload = entity_lookup.get(entity_id) if isinstance(entity_lookup, dict) else None
                if isinstance(entity_payload, dict):
                    self._upsert_node(
                        state,
                        {
                            "id": entity_id,
                            "type": entity_payload.get("type", "entity"),
                            "label": entity_payload.get("label") or entity_payload.get("value") or entity_id,
                            "value": entity_payload.get("value"),
                            "confidence": entity_payload.get("confidence"),
                        },
                    )
                self._upsert_edge(
                    state,
                    {
                        "source": observation_id,
                        "target": entity_id,
                        "relation": "linked_to",
                        "confidence": max(0.45, float(observation.get("quality", 0.0) or 0.0)),
                        "basis": "normalized_observation",
                        "explicit": True,
                        "timestamp": node["timestamp"],
                        "support_kind": "observation_entity_link",
                    },
                )

            previous_observation = self._previous_observation_id(state, observation_id)
            if previous_observation:
                self._upsert_edge(
                    state,
                    {
                        "source": previous_observation,
                        "target": observation_id,
                        "relation": "precedes",
                        "confidence": 0.75,
                        "basis": "timeline_order",
                        "explicit": True,
                        "timestamp": node["timestamp"],
                    },
                )

            self._append_timeline_event(
                state,
                {
                    "id": f"timeline:{observation_id}",
                    "type": observation.get("observation_type", "correlation_observation"),
                    "timestamp": node["timestamp"],
                    "title": f"{tool_name} observation",
                    "summary": observation.get("summary", ""),
                    "tool_name": tool_name,
                    "step_number": step_number,
                    "observation_id": observation_id,
                    "entity_ids": entity_ids,
                },
            )

        state["updated_at"] = _now_iso()
        return state

    def sync_reasoning(
        self,
        graph_state: Optional[Dict[str, Any]],
        *,
        session_id: str,
        reasoning_state: Optional[Dict[str, Any]],
        root_cause_assessment: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        state = self.bootstrap(graph_state)
        hypotheses = reasoning_state.get("hypotheses", []) if isinstance(reasoning_state, dict) else []

        for hypothesis in hypotheses[:8]:
            if not isinstance(hypothesis, dict):
                continue
            hypothesis_node = {
                "id": f"hypothesis:{hypothesis.get('id')}".lower(),
                "type": "hypothesis",
                "label": hypothesis.get("statement", "Hypothesis"),
                "status": hypothesis.get("status"),
                "confidence": hypothesis.get("confidence"),
                "topics": list(hypothesis.get("topics", [])),
            }
            self._upsert_node(state, hypothesis_node)
            for ref in hypothesis.get("supporting_evidence_refs", []) or []:
                observation_id = self._observation_id_from_ref(session_id, ref)
                if observation_id:
                    self._upsert_edge(
                        state,
                        {
                            "source": observation_id,
                            "target": hypothesis_node["id"],
                            "relation": "supports",
                            "confidence": ref.get("confidence") or ref.get("quality") or 0.7,
                            "basis": ref.get("source_kind") or "structured_evidence",
                            "explicit": True,
                            "timestamp": ref.get("created_at") or _now_iso(),
                        },
                    )
            for ref in hypothesis.get("contradicting_evidence_refs", []) or []:
                observation_id = self._observation_id_from_ref(session_id, ref)
                if observation_id:
                    self._upsert_edge(
                        state,
                        {
                            "source": observation_id,
                            "target": hypothesis_node["id"],
                            "relation": "contradicts",
                            "confidence": ref.get("confidence") or ref.get("quality") or 0.7,
                            "basis": ref.get("source_kind") or "structured_evidence",
                            "explicit": True,
                            "timestamp": ref.get("created_at") or _now_iso(),
                        },
                    )

        if isinstance(root_cause_assessment, dict) and root_cause_assessment:
            root_node = {
                "id": f"root-cause:{session_id}".lower(),
                "type": "root_cause",
                "label": root_cause_assessment.get("primary_root_cause") or "Root cause assessment",
                "status": root_cause_assessment.get("status"),
                "confidence": root_cause_assessment.get("confidence"),
            }
            self._upsert_node(state, root_node)
            for ref in root_cause_assessment.get("supporting_evidence_refs", []) or []:
                observation_id = self._observation_id_from_ref(session_id, ref)
                if observation_id:
                    confidence = ref.get("confidence") or ref.get("quality") or 0.72
                    self._upsert_edge(
                        state,
                        {
                            "source": observation_id,
                            "target": root_node["id"],
                            "relation": "derived_from",
                            "confidence": confidence,
                            "basis": ref.get("source_kind") or "root_cause_support",
                            "explicit": True,
                            "timestamp": ref.get("created_at") or _now_iso(),
                            "support_kind": "root_cause_support",
                        },
                    )
                    for hypothesis in hypotheses[:8]:
                        if not isinstance(hypothesis, dict):
                            continue
                        hypothesis_id = f"hypothesis:{hypothesis.get('id')}".lower()
                        supporting_refs = hypothesis.get("supporting_evidence_refs", [])
                        if any(
                            self._observation_id_from_ref(session_id, item) == observation_id
                            for item in supporting_refs
                            if isinstance(item, dict)
                        ):
                            self._upsert_edge(
                                state,
                                {
                                    "source": hypothesis_id,
                                    "target": root_node["id"],
                                    "relation": "caused_by",
                                    "confidence": min(0.96, float(confidence) + 0.08),
                                    "basis": "hypothesis_root_cause_alignment",
                                    "explicit": False,
                                    "timestamp": ref.get("created_at") or _now_iso(),
                                    "support_kind": "hypothesis_bridge",
                                },
                            )
            self._append_timeline_event(
                state,
                {
                    "id": f"timeline:root-cause:{session_id}".lower(),
                    "type": "root_cause_assessment",
                    "timestamp": root_cause_assessment.get("assessed_at") or _now_iso(),
                    "title": "Root cause assessment updated",
                    "summary": root_cause_assessment.get("summary", ""),
                    "status": root_cause_assessment.get("status"),
                },
            )

        state["causal_support"] = self.summarize_causal_support(state)
        state["updated_at"] = _now_iso()
        return state

    def _root_path_summaries(self, state: Dict[str, Any], support_edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        node_lookup = {
            str(item.get("id") or ""): item
            for item in state.get("nodes", [])
            if isinstance(item, dict) and str(item.get("id") or "")
        }
        summaries: List[Dict[str, Any]] = []
        seen = set()
        for edge in support_edges:
            if not isinstance(edge, dict):
                continue
            source = str(edge.get("source") or "").strip()
            target = str(edge.get("target") or "").strip()
            relation = str(edge.get("relation") or "").strip()
            if not source or not target or not relation:
                continue
            summary = {
                "source": source,
                "source_type": str(node_lookup.get(source, {}).get("type") or "unknown"),
                "target": target,
                "target_type": str(node_lookup.get(target, {}).get("type") or "unknown"),
                "relation": relation,
                "confidence": float(edge.get("confidence", 0.0) or 0.0),
                "basis": str(edge.get("basis") or ""),
                "support_kind": str(edge.get("support_kind") or ""),
                "path_summary": self._describe_path(source, target, relation, node_lookup),
            }
            key = (summary["source"], summary["target"], summary["relation"], summary["basis"])
            if key in seen:
                continue
            seen.add(key)
            summaries.append(summary)
        return summaries[:6]

    @staticmethod
    def _describe_path(source: str, target: str, relation: str, node_lookup: Dict[str, Dict[str, Any]]) -> str:
        source_node = node_lookup.get(source, {})
        target_node = node_lookup.get(target, {})
        source_label = str(source_node.get("label") or source)
        target_label = str(target_node.get("label") or target)
        return f"{source_label} {relation} {target_label}"

    def summarize_for_case_event(self, graph_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        state = self.bootstrap(graph_state)
        causal_support = self.summarize_causal_support(state)
        return {
            "node_count": len(state.get("nodes", [])),
            "edge_count": len(state.get("edges", [])),
            "timeline": list(state.get("timeline", []))[-18:],
            "edges": list(state.get("edges", []))[-40:],
            "causal_support": causal_support,
        }

    def _observation_entity_ids(self, observation: Dict[str, Any], entity_lookup: Dict[str, Any]) -> List[str]:
        entity_ids: List[str] = []
        for entity in observation.get("entities", []) if isinstance(observation.get("entities"), list) else []:
            if not isinstance(entity, dict):
                continue
            entity_type = str(entity.get("type") or "").strip().lower()
            value = str(entity.get("value") or "").strip().lower()
            if not entity_type or not value:
                continue
            entity_id = f"{entity_type}:{value}"
            if entity_id in entity_lookup:
                entity_ids.append(entity_id)
            else:
                entity_ids.append(entity_id)
        return self._dedupe(entity_ids)

    @staticmethod
    def _observation_id_from_ref(session_id: str, ref: Dict[str, Any]) -> Optional[str]:
        observation_id = str(ref.get("observation_id") or "").strip()
        if observation_id:
            return observation_id.lower()
        tool_name = ref.get("tool_name")
        step_number = ref.get("step_number")
        if tool_name is None or step_number is None:
            return None
        return f"obs:{session_id}:{step_number}:0:{tool_name}:legacy".lower()

    def _upsert_node(self, state: Dict[str, Any], node: Dict[str, Any]) -> None:
        nodes = {item.get("id"): item for item in state.get("nodes", []) if isinstance(item, dict)}
        nodes[node["id"]] = {**nodes.get(node["id"], {}), **node}
        state["nodes"] = list(nodes.values())[-180:]

    def _upsert_edge(self, state: Dict[str, Any], edge: Dict[str, Any]) -> None:
        key = "|".join(
            [
                str(edge.get("source") or ""),
                str(edge.get("target") or ""),
                str(edge.get("relation") or ""),
                str(edge.get("basis") or ""),
            ]
        )
        edges = {
            "|".join(
                [
                    str(item.get("source") or ""),
                    str(item.get("target") or ""),
                    str(item.get("relation") or ""),
                    str(item.get("basis") or ""),
                ]
            ): item
            for item in state.get("edges", [])
            if isinstance(item, dict)
        }
        current = dict(edges.get(key, {}))
        merged = {**current, **edge}
        merged["confidence"] = max(float(current.get("confidence", 0.0) or 0.0), float(edge.get("confidence", 0.0) or 0.0))
        edges[key] = merged
        state["edges"] = list(edges.values())[-360:]

    def _append_timeline_event(self, state: Dict[str, Any], event: Dict[str, Any]) -> None:
        events = [item for item in state.get("timeline", []) if item.get("id") != event["id"]]
        events.append(event)
        events.sort(key=lambda item: item.get("timestamp", ""))
        state["timeline"] = events[-120:]

    @staticmethod
    def _previous_observation_id(state: Dict[str, Any], current_id: str) -> Optional[str]:
        observations = [item for item in state.get("nodes", []) if item.get("type") == "observation" and item.get("id") != current_id]
        if not observations:
            return None
        observations.sort(key=lambda item: (item.get("step_number", 0), item.get("timestamp", "")))
        return observations[-1].get("id")

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            clean = str(value or "").strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(clean)
        return ordered
