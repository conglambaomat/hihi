import sys
from pathlib import Path
from types import SimpleNamespace

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.prompt_composer import PromptComposer


def test_build_think_payload_for_native_tools():
    composer = PromptComposer()
    state = SimpleNamespace(
        goal="Investigate suspicious IP 1.2.3.4",
        active_specialist="network_forensics",
        investigation_plan={"lane": "ioc", "incident_type": "suspected_command_and_control"},
        agentic_explanation={"missing_evidence": ["Need stronger destination infrastructure evidence."]},
        chat_context_restored_memory_scope="accepted",
    )

    payload = composer.build_think_payload(
        state=state,
        tools_block="- investigate_ioc(ioc: string)",
        findings_block="(none yet)",
        response_style_block="",
        chat_decision_block="",
        reasoning_block="Reasoning status: collecting_evidence",
        profile_block="",
        workflow_block="",
        playbooks_block="",
        model_only_chat=False,
        has_native_tools=True,
    )

    assert "Investigate suspicious IP 1.2.3.4" in payload["system_prompt"]
    assert "Active specialist: network_forensics" in payload["system_prompt"]
    assert "Investigation lane: ioc" in payload["system_prompt"]
    assert "Incident type: suspected_command_and_control" in payload["system_prompt"]
    assert "Restored memory scope: accepted" in payload["system_prompt"]
    assert "Top evidence gap: Need stronger destination infrastructure evidence." in payload["system_prompt"]
    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][1]["role"] == "user"
    assert payload["prompt_mode"] == "native_tooling"
    assert payload["uses_native_tools"] is True
    assert payload["model_only_chat"] is False
    assert payload["provider_context_block"].startswith("Active specialist: network_forensics")
    assert payload["prompt_envelope"]["policy_instructions"]["tooling_mode"] == "native_tools"
    assert payload["prompt_envelope"]["investigation_context"]["provider_context"] == {
        "active_specialist": "network_forensics",
        "investigation_lane": "ioc",
        "incident_type": "suspected_command_and_control",
        "memory_scope": "accepted",
        "top_evidence_gap": "Need stronger destination infrastructure evidence.",
    }
    assert payload["prompt_envelope"]["user_intent"]["mode"] == "native_tooling"
    assert "Continue the CABTA investigation" in payload["user_prompt"]


def test_build_think_payload_for_json_mode_without_tools():
    composer = PromptComposer()
    state = SimpleNamespace(goal="Check this domain example.com")

    payload = composer.build_think_payload(
        state=state,
        tools_block="- investigate_ioc(ioc: string)",
        findings_block="Previous IOC lookup complete",
        response_style_block="response-style",
        chat_decision_block="chat-policy",
        reasoning_block="Reasoning status: sufficient_evidence",
        profile_block="profile-guidance",
        workflow_block="workflow-guidance",
        playbooks_block="playbooks-guidance",
        model_only_chat=False,
        has_native_tools=False,
    )

    assert "Respond in JSON" in payload["system_prompt"]
    assert "Available tools:" in payload["system_prompt"]
    assert "Check this domain example.com" in payload["system_prompt"]
    assert payload["prompt_mode"] == "json_tool_decision"
    assert payload["uses_native_tools"] is False
    assert payload["model_only_chat"] is False
    assert payload["provider_context_block"] == "(no additional provider context)"
    assert payload["prompt_envelope"]["policy_instructions"]["tooling_mode"] == "json_tools"
    assert payload["prompt_envelope"]["investigation_context"]["provider_context"]["active_specialist"] == ""
    assert payload["prompt_envelope"]["investigation_context"]["tools_block"] == "- investigate_ioc(ioc: string)"
    assert payload["prompt_envelope"]["user_intent"]["mode"] == "json_tool_decision"


def test_build_think_payload_for_direct_chat():
    composer = PromptComposer()
    state = SimpleNamespace(
        goal="Summarize the evidence so far",
        active_specialist="investigator",
        investigation_plan={"lane": "log_identity"},
        agentic_explanation={"missing_evidence": ["Need explicit session-to-user attribution."]},
    )

    payload = composer.build_think_payload(
        state=state,
        tools_block="",
        findings_block="[1] correlate_findings reported verdict=SUSPICIOUS.",
        response_style_block="chat-style",
        chat_decision_block="chat-policy",
        reasoning_block="Reasoning status: sufficient_evidence",
        profile_block="profile-guidance",
        workflow_block="workflow-guidance",
        playbooks_block="playbooks-guidance",
        model_only_chat=True,
        has_native_tools=False,
    )

    assert "Answer the analyst directly in natural language" in payload["system_prompt"]
    assert "Active specialist: investigator" in payload["system_prompt"]
    assert "Investigation lane: log_identity" in payload["system_prompt"]
    assert "Top evidence gap: Need explicit session-to-user attribution." in payload["system_prompt"]
    assert payload["prompt_mode"] == "direct_answer"
    assert payload["uses_native_tools"] is False
    assert payload["model_only_chat"] is True
    assert payload["prompt_envelope"]["policy_instructions"]["tooling_mode"] == "direct_answer"
    assert payload["prompt_envelope"]["investigation_context"]["provider_context"]["investigation_lane"] == "log_identity"
    assert payload["prompt_envelope"]["user_intent"]["mode"] == "direct_answer"
    assert "Answer the analyst directly from the current structured investigation context." in payload["user_prompt"]


def test_build_summary_payload_exposes_layered_prompt_contract():
    composer = PromptComposer()
    state = SimpleNamespace(
        goal="Investigate 1.2.3.4",
        active_specialist="network_forensics",
        investigation_plan={"lane": "ioc", "incident_type": "c2"},
        agentic_explanation={"missing_evidence": ["Need WHOIS confirmation."]},
        chat_context_restored_memory_scope="accepted",
    )

    payload = composer.build_summary_payload(
        state=state,
        response_style_block="response-style",
        reasoning_block="Reasoning status: supported",
        step_count=4,
        findings_json='{"tool":"investigate_ioc"}',
    )

    assert payload["prompt_mode"] == "summary_explanation"
    assert "Investigate 1.2.3.4" in payload["prompt"]
    assert "Reasoning status: supported" in payload["prompt"]
    assert "Active specialist: network_forensics" in payload["prompt"]
    assert "Top evidence gap: Need WHOIS confirmation." in payload["prompt"]
    assert payload["provider_context_block"].startswith("Active specialist: network_forensics")
    assert payload["prompt_envelope"]["policy_instructions"]["tooling_mode"] == "summary_explanation"
    assert payload["prompt_envelope"]["investigation_context"]["provider_context"] == {
        "active_specialist": "network_forensics",
        "investigation_lane": "ioc",
        "incident_type": "c2",
        "memory_scope": "accepted",
        "top_evidence_gap": "Need WHOIS confirmation.",
    }
    assert payload["prompt_envelope"]["investigation_context"]["step_count"] == 4
    assert payload["prompt_envelope"]["user_intent"]["mode"] == "summary_explanation"


def test_build_summary_prompt():
    composer = PromptComposer()

    prompt = composer.build_summary_prompt(
        goal="Investigate 1.2.3.4",
        response_style_block="response-style",
        reasoning_block="Reasoning status: supported",
        step_count=4,
        findings_json='{"tool":"investigate_ioc"}',
        provider_context_block="Active specialist: network_forensics\nTop evidence gap: Need WHOIS confirmation.",
    )

    assert "Investigate 1.2.3.4" in prompt
    assert "Reasoning status: supported" in prompt
    assert "Active specialist: network_forensics" in prompt
    assert "Top evidence gap: Need WHOIS confirmation." in prompt
    assert "Steps taken: 4" in prompt


def test_build_tools_block_formats_registered_tools():
    composer = PromptComposer()
    tool = SimpleNamespace(
        name="investigate_ioc",
        description="Investigate IOC",
        requires_approval=False,
        parameters={"properties": {"ioc": {"type": "string"}}},
    )

    block = composer.build_tools_block([tool])

    assert block == "- investigate_ioc(ioc: string): Investigate IOC"


def test_build_playbooks_block_formats_playbooks():
    composer = PromptComposer()

    block = composer.build_playbooks_block(
        [{"id": "ioc_triage", "step_count": 3, "description": "IOC playbook"}]
    )

    assert "Available playbooks" in block
    assert "- ioc_triage (3 steps): IOC playbook" in block


def test_build_profile_block_includes_team_and_active_specialist():
    composer = PromptComposer()
    state = SimpleNamespace(
        specialist_team=["workflow_controller", "network_forensics"],
        active_specialist="network_forensics",
        agent_profile_id="network_forensics",
    )

    block = composer.build_profile_block(
        state,
        profile_prompt_block="Focus on network evidence.",
    )

    assert "Specialist profile guidance:" in block
    assert "Focus on network evidence." in block
    assert "Active specialist team: workflow_controller -> network_forensics" in block
    assert "Current active specialist: network_forensics" in block


def test_build_workflow_block_includes_handoff_and_sections():
    composer = PromptComposer()
    state = SimpleNamespace(workflow_id="ioc_workflow")
    workflow = {
        "name": "IOC Workflow",
        "execution_backend": "agent",
        "description": "Investigate IOC evidence",
        "use_case": "IOC triage",
        "agents": ["investigator", "network_forensics"],
        "tools_used": ["investigate_ioc", "correlate_findings"],
        "sections": {
            "operating_model": "- Validate indicator\n- Enrich indicator",
            "phase_sequence": "1. Gather evidence\n2. Correlate findings",
        },
    }
    handoff = {"from_profile": "investigator", "to_profile": "network_forensics"}

    block = composer.build_workflow_block(
        state,
        workflow=workflow,
        latest_handoff=handoff,
    )

    assert "Workflow context: IOC Workflow" in block
    assert "Latest specialist handoff: investigator -> network_forensics" in block
    assert "Workflow operating model: Validate indicator | Enrich indicator" in block
    assert "Workflow phases: Gather evidence | Correlate findings" in block


def test_build_findings_block_summarizes_recent_findings():
    composer = PromptComposer()
    state = SimpleNamespace(
        findings=[
            {
                "step": 2,
                "type": "tool_result",
                "tool": "investigate_ioc",
                "result": {"verdict": "SUSPICIOUS"},
            },
            {
                "step": 3,
                "type": "final_answer",
                "answer": "Suspicious infrastructure observed.",
            },
        ]
    )

    block = composer.build_findings_block(
        state,
        is_chat_session=False,
        chat_prompt_findings_limit=5,
        describe_fallback_evidence=lambda tool, result: f"{tool} summary",
    )

    assert "[2] investigate_ioc summary" in block
    assert "[3] final_answer: Suspicious infrastructure observed." in block


def test_build_reasoning_block_summarizes_reasoning_state():
    composer = PromptComposer()
    state = SimpleNamespace(
        investigation_plan={
            "lane": "ioc",
            "lead_profile": "network_forensics",
            "primary_entities": ["1.2.3.4"],
            "first_pivots": ["whois_lookup"],
        },
        reasoning_state={
            "status": "sufficient_evidence",
            "open_questions": ["Who owns the destination IP?"],
            "hypotheses": [
                {
                    "statement": "The IP is suspicious",
                    "confidence": 0.8,
                    "status": "supported",
                    "supporting_evidence_refs": ["obs-1", "obs-2"],
                    "contradicting_evidence_refs": [],
                }
            ],
        },
        active_observations=[{"id": "obs-1"}],
        evidence_quality_summary={"average_quality": 0.7, "observation_count": 1},
        agentic_explanation={"root_cause_assessment": {"summary": "Malicious infrastructure"}},
        entity_state={"entities": {"ip-1": {"type": "ip", "value": "1.2.3.4"}}},
        unresolved_questions=[],
    )

    block = composer.build_reasoning_block(state, is_chat_session=False)

    assert "Investigation plan: lane=ioc, lead_profile=network_forensics" in block
    assert "Reasoning status: sufficient_evidence" in block
    assert "Normalized observations: 1" in block
    assert "Evidence quality: avg=0.7, observations=1" in block
    assert "Root cause assessment: Malicious infrastructure" in block
    assert "Tracked entities: ip=1.2.3.4" in block
    assert "Open questions:" in block
    assert "- Who owns the destination IP?" in block
    assert "- The IP is suspicious (status=supported, confidence=0.80, support=2, contradict=0)" in block
