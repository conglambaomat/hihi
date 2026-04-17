"""Lightweight evidence link and timeline support for investigations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceGraph:
    """Maintain a minimal evidence graph in session metadata."""

    def bootstrap(self, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        state = dict(existing or {})
        state.setdefault("schema_version", 1)
        state.setdefault("nodes", [])
        state.setdefault("edges", [])
        state.setdefault("timeline", [])
        state.setdefault("updated_at", _now_iso())
        return state

    def ingest_observation(
        self,
        graph_state: Optional[Dict[str, Any]],
        *,
        session_id: str,
        tool_name: str,
        step_number: int,
        evidence_ref: Dict[str, Any],
        entity_state: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        state = self.bootstrap(graph_state)
        observation_node = {
            "id": f"observation:{session_id}:{step_number}:{tool_name}".lower(),
            "type": "observation",
            "label": tool_name,
            "summary": evidence_ref.get("summary", ""),
            "tool_name": tool_name,
            "step_number": step_number,
            "timestamp": evidence_ref.get("created_at") or _now_iso(),
        }
        self._upsert_node(state, observation_node)

        entity_lookup = {}
        if isinstance(entity_state, dict):
            entity_lookup = entity_state.get("entities", {}) if isinstance(entity_state.get("entities"), dict) else {}

        recent_entities = self._recent_entity_ids(entity_state, step_number)
        for entity_id in recent_entities:
            entity_payload = entity_lookup.get(entity_id) if isinstance(entity_lookup, dict) else None
            if isinstance(entity_payload, dict):
                self._upsert_node(
                    state,
                    {
                        "id": entity_id,
                        "type": entity_payload.get("type", "entity"),
                        "label": entity_payload.get("label") or entity_payload.get("value") or entity_id,
                        "value": entity_payload.get("value"),
                    },
                )
            self._upsert_edge(
                state,
                {
                    "source": observation_node["id"],
                    "target": entity_id,
                    "relation": "linked_to",
                    "timestamp": observation_node["timestamp"],
                },
            )

        previous_observation = self._previous_observation_id(state, observation_node["id"])
        if previous_observation:
            self._upsert_edge(
                state,
                {
                    "source": previous_observation,
                    "target": observation_node["id"],
                    "relation": "precedes",
                    "timestamp": observation_node["timestamp"],
                },
            )

        state["timeline"] = self._append_timeline_event(
            state.get("timeline", []),
            {
                "id": f"timeline:{observation_node['id']}",
                "type": "observation",
                "timestamp": observation_node["timestamp"],
                "title": f"{tool_name} observation",
                "summary": evidence_ref.get("summary", ""),
                "tool_name": tool_name,
                "step_number": step_number,
                "entity_ids": recent_entities,
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

        for hypothesis in hypotheses[:6]:
            if not isinstance(hypothesis, dict):
                continue
            hypothesis_node = {
                "id": f"hypothesis:{hypothesis.get('id')}".lower(),
                "type": "hypothesis",
                "label": hypothesis.get("statement", "Hypothesis"),
                "status": hypothesis.get("status"),
                "confidence": hypothesis.get("confidence"),
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
                    self._upsert_edge(
                        state,
                        {
                            "source": observation_id,
                            "target": root_node["id"],
                            "relation": "derived_from",
                            "timestamp": ref.get("created_at") or _now_iso(),
                        },
                    )
            state["timeline"] = self._append_timeline_event(
                state.get("timeline", []),
                {
                    "id": f"timeline:root-cause:{session_id}".lower(),
                    "type": "root_cause_assessment",
                    "timestamp": root_cause_assessment.get("assessed_at") or _now_iso(),
                    "title": "Root cause assessment updated",
                    "summary": root_cause_assessment.get("summary", ""),
                    "status": root_cause_assessment.get("status"),
                },
            )

        state["updated_at"] = _now_iso()
        return state

    def summarize_for_case_event(self, graph_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        state = self.bootstrap(graph_state)
        return {
            "node_count": len(state.get("nodes", [])),
            "edge_count": len(state.get("edges", [])),
            "timeline": list(state.get("timeline", []))[-12:],
            "edges": list(state.get("edges", []))[-24:],
        }

    @staticmethod
    def _recent_entity_ids(entity_state: Optional[Dict[str, Any]], step_number: int) -> List[str]:
        if not isinstance(entity_state, dict):
            return []
        observations = entity_state.get("observations", [])
        if not isinstance(observations, list):
            return []
        for observation in reversed(observations):
            if observation.get("step_number") == step_number:
                return list(observation.get("entity_ids", []))
        return []

    @staticmethod
    def _observation_id_from_ref(session_id: str, ref: Dict[str, Any]) -> Optional[str]:
        tool_name = ref.get("tool_name")
        step_number = ref.get("step_number")
        if tool_name is None or step_number is None:
            return None
        return f"observation:{session_id}:{step_number}:{tool_name}".lower()

    def _upsert_node(self, state: Dict[str, Any], node: Dict[str, Any]) -> None:
        nodes = {item.get("id"): item for item in state.get("nodes", []) if isinstance(item, dict)}
        nodes[node["id"]] = {**nodes.get(node["id"], {}), **node}
        state["nodes"] = list(nodes.values())[-120:]

    def _upsert_edge(self, state: Dict[str, Any], edge: Dict[str, Any]) -> None:
        edges = {
            f"{item.get('source')}|{item.get('target')}|{item.get('relation')}": item
            for item in state.get("edges", [])
            if isinstance(item, dict)
        }
        key = f"{edge.get('source')}|{edge.get('target')}|{edge.get('relation')}"
        edges[key] = {**edges.get(key, {}), **edge}
        state["edges"] = list(edges.values())[-240:]

    @staticmethod
    def _append_timeline_event(existing: List[Dict[str, Any]], event: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = [item for item in existing if item.get("id") != event["id"]]
        events.append(event)
        events.sort(key=lambda item: item.get("timestamp", ""))
        return events[-80:]

    @staticmethod
    def _previous_observation_id(state: Dict[str, Any], current_id: str) -> Optional[str]:
        observations = [item for item in state.get("nodes", []) if item.get("type") == "observation" and item.get("id") != current_id]
        if not observations:
            return None
        observations.sort(key=lambda item: (item.get("step_number", 0), item.get("timestamp", "")))
        return observations[-1].get("id")
