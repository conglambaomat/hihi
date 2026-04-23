"""
Author: Ugur Ates
Chat API routes - Interactive agent conversation.
"""

import json
import logging
import re
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.agent.chat_intent_router import ChatIntentRouter
from src.agent.session_response_builder import SessionResponseBuilder
from src.agent.thread_sync_service import ThreadSyncService

from .agent import _chat_history_messages, _decorate_session_payload

logger = logging.getLogger(__name__)
router = APIRouter()
DEFAULT_CHAT_AGENT_PROFILE = "investigator"
_intent_router = ChatIntentRouter()
_response_builder = SessionResponseBuilder()


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1)
    session_id: Optional[str] = None
    playbook_id: Optional[str] = None


def _coerce_playbook_chat_input(message: str, input_params) -> dict:
    """Map chat text to playbook inputs with a JSON-object escape hatch."""
    raw_message = message.strip()
    input_data = {"query": message, "user_input": message}

    parsed_object = None
    if raw_message.startswith("{") and raw_message.endswith("}"):
        try:
            candidate = json.loads(raw_message)
        except json.JSONDecodeError:
            candidate = None
        if isinstance(candidate, dict):
            parsed_object = candidate
            input_data.update(candidate)

    if parsed_object is None:
        target_param = None
        normalized_items = []
        if isinstance(input_params, list):
            normalized_items = [item for item in input_params if isinstance(item, dict)]
        elif isinstance(input_params, dict):
            normalized_items = [
                {"name": key, **(value if isinstance(value, dict) else {})}
                for key, value in input_params.items()
            ]

        for item in normalized_items:
            if item.get("required") and item.get("name"):
                target_param = item["name"]
                break
        if target_param is None:
            for item in normalized_items:
                if item.get("name"):
                    target_param = item["name"]
                    break
        if target_param:
            input_data[target_param] = message

    return input_data


def _session_metadata(session: dict) -> dict:
    metadata = session.get("metadata", {}) if isinstance(session, dict) else {}
    return metadata if isinstance(metadata, dict) else {}



def _normalize_memory_contract(
    case_memory_context: Optional[dict],
    *,
    snapshot: Optional[dict] = None,
) -> dict:
    return ThreadSyncService.resolve_session_memory_contract(
        case_memory_context,
        snapshot=snapshot,
    )


def _preferred_chat_profile(session: Optional[dict] = None) -> str:
    metadata = _session_metadata(session or {})
    for key in ("active_specialist", "lead_agent_profile_id", "agent_profile_id"):
        candidate = str(metadata.get(key) or "").strip()
        if candidate and candidate != "workflow_controller":
            return candidate
    return DEFAULT_CHAT_AGENT_PROFILE



def _select_follow_up_snapshot(
    *,
    thread_snapshot: Optional[dict],
    case_memory_context: Optional[dict],
) -> tuple[dict, Optional[dict], str]:
    resolved_thread_snapshot = thread_snapshot if isinstance(thread_snapshot, dict) else {}
    resolved_case_memory_context = case_memory_context if isinstance(case_memory_context, dict) else None
    thread_contract = _normalize_memory_contract(snapshot=resolved_thread_snapshot, case_memory_context=None)
    authoritative_snapshot = {}
    if resolved_case_memory_context is not None:
        authoritative_snapshot = (
            resolved_case_memory_context.get("authoritative_snapshot")
            or resolved_case_memory_context.get("memory_snapshot")
            or {}
        )
    authoritative_snapshot = authoritative_snapshot if isinstance(authoritative_snapshot, dict) else {}
    case_contract = _normalize_memory_contract(
        resolved_case_memory_context,
        snapshot=authoritative_snapshot,
    ) if authoritative_snapshot else {}
    if authoritative_snapshot and case_contract.get("memory_is_authoritative") and not thread_contract.get("memory_is_authoritative"):
        return authoritative_snapshot, resolved_case_memory_context, "case_memory"
    if resolved_thread_snapshot:
        return resolved_thread_snapshot, resolved_case_memory_context, "thread_snapshot"
    if authoritative_snapshot:
        return authoritative_snapshot, resolved_case_memory_context, "case_memory"
    return {}, resolved_case_memory_context, "none"


def _finding_snapshot(findings, limit: int = 3) -> str:
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except json.JSONDecodeError:
            findings = []
    if not isinstance(findings, list):
        return ""

    lines = []
    for finding in findings[-limit:]:
        if not isinstance(finding, dict):
            continue
        if finding.get("type") == "tool_result":
            tool = str(finding.get("tool") or "tool_result")
            result = finding.get("result")
            if isinstance(result, dict):
                if result.get("verdict"):
                    detail = f"verdict={result.get('verdict')}"
                elif result.get("severity"):
                    detail = f"severity={result.get('severity')}"
                elif result.get("error"):
                    detail = f"error={str(result.get('error'))[:120]}"
                else:
                    detail = f"keys={', '.join(sorted(result.keys())[:5])}"
            else:
                detail = str(result)[:120]
            lines.append(f"- {tool}: {detail}")
        elif finding.get("type") == "final_answer":
            lines.append(f"- final_answer: {str(finding.get('answer') or '')[:160]}")
    return "\n".join(lines)


def _build_follow_up_goal(session: dict, message: str) -> str:
    return _response_builder.build_legacy_follow_up_goal(
        previous_goal=str(session.get("goal") or ""),
        previous_summary=str(session.get("summary") or "").strip(),
        evidence_snapshot=_finding_snapshot(session.get("findings")),
        message=message,
    )


@router.post('')
async def send_message(request: Request, body: ChatMessage):
    """Send a message to the agent.

    If session_id is provided, this is a follow-up message.
    If playbook_id is provided, execute the playbook directly.
    Otherwise, a new investigation is started (LLM may auto-select a playbook).
    """
    agent_loop = request.app.state.agent_loop
    if agent_loop is None:
        raise HTTPException(503, "Agent loop not initialized. Check LLM configuration.")

    # Direct playbook execution from chat
    if body.playbook_id:
        engine = request.app.state.playbook_engine
        if engine is None:
            raise HTTPException(503, "Playbook engine not initialized")
        try:
            playbook = engine.get_playbook(body.playbook_id) or {}
            input_params = playbook.get("input_params", playbook.get("inputs", playbook.get("input", [])))
            input_data = _coerce_playbook_chat_input(body.message, input_params)

            session_id = await engine.execute(
                body.playbook_id, input_data, case_id=None,
            )
            return {
                "session_id": session_id,
                "status": "processing",
                "playbook_id": body.playbook_id,
                "message": body.message,
            }
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            raise HTTPException(500, f"Playbook execution failed: {str(e)}")

    if body.session_id:
        # Follow-up message to existing session
        store = request.app.state.agent_store
        if store is None:
            raise HTTPException(503, "Agent store not initialized")

        session = store.get_session(body.session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        metadata = _session_metadata(session)
        thread_store = getattr(request.app.state, "thread_store", None)
        case_memory_service = getattr(request.app.state, "case_memory_service", None)
        thread_id = str(metadata.get("thread_id") or "").strip()
        if not thread_id and thread_store is not None and session.get("status") == "active":
            thread_id = thread_store.ensure_thread(
                case_id=session.get("case_id"),
                root_session_id=body.session_id,
                status="active",
            )
            store.update_session_metadata(body.session_id, {"thread_id": thread_id}, merge=True)
        intent_payload = _intent_router.classify(body.message)
        latest_snapshot = thread_store.get_latest_snapshot(thread_id) if thread_store and thread_id else {}
        thread_payload = thread_store.get_thread(thread_id) if thread_store and thread_id else {}
        snapshot = latest_snapshot.get("snapshot", {}) if isinstance(latest_snapshot, dict) else {}
        thread_summary = ""
        if isinstance(thread_payload, dict):
            thread_summary = str(thread_payload.get("thread_summary") or "").strip()

        # If session is still active, return status
        if session.get('status') == 'active':
            command_id = None
            queued_command_payload = {
                "intent": intent_payload["intent"],
                "requires_fresh_evidence": bool(intent_payload["requires_fresh_evidence"]),
                "queued_while_active": True,
            }
            if thread_store and thread_id:
                thread_store.append_message(
                    thread_id=thread_id,
                    role="user",
                    content=body.message,
                    session_id=body.session_id,
                    metadata={"intent": intent_payload["intent"], "queued_while_active": True},
                )
                command_id = thread_store.enqueue_command(
                    thread_id=thread_id,
                    content=body.message,
                    session_id=body.session_id,
                    intent=intent_payload["intent"],
                    payload=queued_command_payload,
                )
            return {
                "session_id": body.session_id,
                "status": "active",
                "response": "The investigation is still running. Your follow-up directive was queued for the active session.",
                "thread_id": thread_id or None,
                "queued_command_id": command_id,
                "queued_intent": intent_payload["intent"],
                "queued_requires_fresh_evidence": queued_command_payload["requires_fresh_evidence"],
                "queued_command_payload": queued_command_payload,
            }

        # If session is completed/failed, start a new investigation with context
        case_memory_context = None
        if case_memory_service is not None and session.get("case_id"):
            case_memory_context = case_memory_service.get_case_memory(session.get("case_id"))
        snapshot, case_memory_context, snapshot_source = _select_follow_up_snapshot(
            thread_snapshot=snapshot,
            case_memory_context=case_memory_context,
        )
        if snapshot_source == "case_memory" and isinstance(case_memory_context, dict):
            thread_summary = thread_summary or str(case_memory_context.get("summary") or "").strip()
            thread_id = thread_id or str(case_memory_context.get("thread_id") or "").strip()

        if snapshot:
            memory_contract = _normalize_memory_contract(case_memory_context, snapshot=snapshot)
            if not memory_contract.get("memory_boundary") and isinstance(case_memory_context, dict):
                inherited_boundary = case_memory_context.get("memory_boundary")
                if isinstance(inherited_boundary, dict):
                    memory_contract = {
                        **memory_contract,
                        "memory_boundary": dict(inherited_boundary),
                    }
            context = _response_builder.build_follow_up_goal(
                previous_goal=str(session.get("goal") or ""),
                thread_summary=thread_summary,
                snapshot=snapshot,
                message=body.message,
                intent=intent_payload["intent"],
                requires_fresh_evidence=bool(intent_payload["requires_fresh_evidence"]),
                memory_scope=memory_contract["memory_scope"],
                memory_boundary=memory_contract["memory_boundary"],
                memory_kind=memory_contract["memory_kind"],
                publication_scope=memory_contract["publication_scope"],
                memory_is_authoritative=memory_contract["memory_is_authoritative"],
            )
        else:
            context = _build_follow_up_goal(session, body.message)
        session_id = await agent_loop.investigate(
            context,
            case_id=session.get('case_id'),
            metadata={
                "agent_profile_id": _preferred_chat_profile(session),
                "chat_mode": True,
                "ui_mode": "chat",
                "response_style": "conversational",
                "chat_user_message": body.message,
                "chat_parent_session_id": body.session_id,
                "thread_id": thread_id or None,
                "chat_intent": intent_payload["intent"],
                "chat_follow_up_requires_fresh_evidence": bool(intent_payload["requires_fresh_evidence"]),
                "memory_scope": memory_contract["memory_scope"] if snapshot else None,
                "memory_kind": memory_contract["memory_kind"] if snapshot else None,
                "memory_is_authoritative": memory_contract["memory_is_authoritative"] if snapshot else None,
                "publication_scope": memory_contract["publication_scope"] if snapshot else None,
                "authoritative_memory_scope": memory_contract["authoritative_memory_scope"] if snapshot else None,
                "memory_boundary": memory_contract["memory_boundary"] if snapshot else {},
                "case_memory_context": case_memory_context if isinstance(case_memory_context, dict) else None,
            },
        )
        return {
            "session_id": session_id,
            "status": "processing",
            "response": "Follow-up investigation started.",
            "thread_id": thread_id or None,
        }
    else:
        # New investigation - LLM will see available playbooks and may auto-select one
        session_id = await agent_loop.investigate(
            body.message,
            metadata={
                "agent_profile_id": DEFAULT_CHAT_AGENT_PROFILE,
                "chat_mode": True,
                "ui_mode": "chat",
                "response_style": "conversational",
                "chat_user_message": body.message,
            },
        )
        return {
            "session_id": session_id,
            "status": "processing",
            "message": body.message,
        }


@router.get('/sessions')
async def list_chat_sessions(request: Request, limit: int = 20):
    """List recent chat sessions."""
    store = request.app.state.agent_store
    if store is None:
        return {"sessions": []}
    sessions = store.list_sessions(limit=limit)
    return {"sessions": sessions}


@router.get('/sessions/{session_id}')
async def get_chat_session(request: Request, session_id: str):
    """Get a chat session with steps."""
    store = request.app.state.agent_store
    if store is None:
        raise HTTPException(503, "Agent store not initialized")
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    steps = store.get_steps(session_id)
    session = _decorate_session_payload(session)
    session['steps'] = steps
    session.update(_chat_history_messages(store, session))
    # Include live state if available
    agent_loop = request.app.state.agent_loop
    if agent_loop:
        live_state = agent_loop.get_state(session_id)
        if live_state:
            session['live_state'] = live_state
    return session
