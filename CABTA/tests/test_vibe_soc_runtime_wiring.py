from types import SimpleNamespace

import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.capability_plugin_registry import CapabilityPluginRegistry
from src.agent.capability_resolver import CapabilityResolver
from src.agent.final_answer_gate import FinalAnswerGate
from src.agent.runtime_policy import legacy_runtime_allowed, strict_only_production


class _State:
    def __init__(self):
        self.findings = []
        self.active_observations = []
        self.reasoning_state = {"objective_contract": {"execution_mode": "strict_production"}, "coverage_matrix": {}}
        self.evidence_state = {
            "nodes": [
                {
                    "id": "n1",
                    "label": "8.8.8.8 is suspicious from threat intel",
                    "summary": "8.8.8.8 suspicious threat intel verdict",
                    "tool_name": "investigate_ioc",
                    "step_number": 1,
                    "confidence": 0.9,
                    "source_paths": ["findings[0].result"],
                }
            ],
            "edges": [],
        }


def test_builtin_plugin_registry_is_primary_capability_source():
    registry = CapabilityPluginRegistry.bootstrap_builtin()
    resolver = CapabilityResolver(plugin_registry=registry, get_tool=lambda name: object() if name == "investigate_ioc" else None)

    resolution = resolver.resolve("ioc.enrich")

    assert registry.status()["plugins"][0]["state"] == "running"
    assert resolution.availability == "available"
    assert resolution.selected_tool == "investigate_ioc"
    assert resolution.tool_contract.capability == "ioc.enrich"


def test_resolver_without_registry_or_explicit_fallback_fails_closed():
    resolver = CapabilityResolver(get_tool=lambda name: object(), allow_static_fallback=False)

    resolution = resolver.resolve("ioc.enrich")

    assert resolution.availability == "unknown_capability"
    assert "active plugin registry" in resolution.degradation_reason


def test_final_answer_gate_emits_sentence_level_evidence_chips():
    state = _State()
    gate = FinalAnswerGate().evaluate(
        objective={"execution_mode": "strict_production", "require_provenance": True},
        state=state,
        draft_answer="8.8.8.8 is suspicious from threat intel.",
    ).to_dict()

    assert gate["evidence_chips"]
    chip = gate["evidence_chips"][0]
    assert chip["sentence"] == "8.8.8.8 is suspicious from threat intel."
    assert chip["status"] == "supported"
    assert chip["tool_names"] == ["investigate_ioc"]
    assert gate["claim_evidence_map"][chip["claim_id"]]["evidence_refs"]


def _loop(config):
    return AgentLoop(
        config=config,
        tool_registry=SimpleNamespace(get_tool=lambda _name: object()),
        agent_store=SimpleNamespace(),
    )


def test_production_forces_strict_dag_and_blocks_legacy_flags(monkeypatch):
    monkeypatch.delenv("AISA_ALLOW_LEGACY_RUNTIME_IN_PRODUCTION", raising=False)
    loop = _loop({
        "runtime": {"mode": "production", "supervisor": {"enabled": True}},
        "agent": {
            "execution": {"strict_dag_mode": False, "allow_legacy_direct_tool_fallback": True},
            "capability_plugins": {"allow_static_catalog_fallback": True},
        },
    })

    assert loop.strict_only_production is True
    assert loop.strict_dag_mode is True
    assert loop.allow_legacy_direct_tool_fallback is False
    assert loop.runtime_supervisor_enabled is False
    assert loop.capability_resolver.allow_static_fallback is False


def test_dev_config_cannot_enable_legacy_runtime_fallback(monkeypatch):
    monkeypatch.setenv("AISA_ALLOW_LEGACY_RUNTIME_IN_PRODUCTION", "true")
    monkeypatch.setenv("AISA_STRICT_DAG_MODE", "false")
    loop = _loop({
        "runtime": {"mode": "development", "supervisor": {"enabled": True}},
        "agent": {
            "execution": {"strict_dag_mode": False, "allow_legacy_direct_tool_fallback": True},
            "capability_plugins": {"allow_static_catalog_fallback": True},
        },
    })

    assert loop.strict_only_production is True
    assert loop.strict_dag_mode is True
    assert loop.allow_legacy_direct_tool_fallback is False
    assert loop.runtime_supervisor_enabled is False
    assert loop.capability_resolver.allow_static_fallback is False


def test_legacy_escape_hatch_is_removed(monkeypatch):
    monkeypatch.setenv("AISA_ALLOW_LEGACY_RUNTIME_IN_PRODUCTION", "true")
    config = {"runtime": {"mode": "production"}, "agent": {"execution": {"allow_legacy_runtime_in_production": True}}}

    assert legacy_runtime_allowed(config) is False
    assert strict_only_production(config) is True
