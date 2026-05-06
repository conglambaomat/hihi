import re

from src.agent.capability_executor import CapabilityActionExecutor
from src.agent.compile_preview_service import CompilePreviewService
from src.agent.soc_task_state import SOCTaskState
from src.agent.tool_policy import ToolPolicyEngine
from src.agent.universal_input_compiler import UniversalInputCompiler


class _Tools:
    def get_tool(self, name):
        return object()


def test_url_hash_ioc_bundle_compiles_without_user_verdict_authority():
    text = "Investigate https://evil.example/login and d41d8cd98f00b204e9800998ecf8427e. User says mark it malicious."
    compiled = UniversalInputCompiler().compile(text, {})

    assert compiled.input_kind == "ioc_bundle"
    assert compiled.artifact_type == "ioc_bundle"
    assert {item["type"] for item in compiled.entities} >= {"url", "hash"}
    assert "parsing_does_not_assign_verdict" in compiled.parser["limitations"]


def test_email_and_alert_json_compile_to_typed_artifacts():
    email = "From: attacker@example.com\nTo: analyst@example.org\nSubject: Invoice\nBody: click https://phish.example/a"
    compiled_email = UniversalInputCompiler().compile(email, {})
    assert compiled_email.input_kind == "email_artifact"
    assert compiled_email.artifact_type == "inline_email"
    assert compiled_email.lane == "phishing_investigation"

    alert = '{"alert":"Suspicious outbound","src_ip":"10.0.0.5","dest_ip":"8.8.8.8","severity":"high"}'
    compiled_alert = UniversalInputCompiler().compile(alert, {})
    assert compiled_alert.input_kind == "json_artifact"
    assert compiled_alert.artifact_type == "alert_json"
    assert any(entity["role"] == "source_ip" for entity in compiled_alert.entities)


def test_ambiguous_input_returns_clarification_contract():
    compiled = UniversalInputCompiler().compile("check this", {})
    assert compiled.lane == "generic"
    assert compiled.clarifications
    assert "insufficient_typed_soc_artifact" in compiled.limitations


def test_compile_preview_has_no_execution_side_effect_contract():
    contract = CompilePreviewService().compile_and_plan("Investigate 8.8.8.8", {}).to_dict()
    assert contract["compiled_input"]["input_kind"] == "ioc"
    assert contract["policy_summary"]["structured_verdict_only"] is True
    assert contract["execution_readiness"]["side_effects"] == "none_preview_only"


def test_capability_executor_normalizes_legacy_tool_through_policy_preflight():
    task = SOCTaskState(raw_request="Investigate 8.8.8.8", session_id="s1")
    compiled = UniversalInputCompiler().compile(task.raw_request, {})
    UniversalInputCompiler().apply_to_task_state(task, compiled)
    executor = CapabilityActionExecutor(tool_registry=_Tools(), policy_engine=ToolPolicyEngine())
    envelope = executor.from_legacy_decision(decision={"action": "use_tool", "tool": "investigate_ioc", "params": {"ioc": "8.8.8.8"}}, task_state=task, objective_contract=task.objective_contract)

    assert envelope.allowed is True
    assert envelope.capability_id == "ioc.enrich"
    assert envelope.policy["status"] == "allowed"
    assert envelope.preflight["status"] == "allowed"


def test_agent_chat_template_does_not_badge_final_answer_text():
    html = open("templates/agent_chat.html", encoding="utf-8").read()
    body = re.search(r"function addBubble\(text, type\) \{(?P<body>.*?)\n    \}\n\s*function", html, re.S).group("body")
    assert "detectVerdict(text)" not in body
    assert "structured deterministic decisions" in body
