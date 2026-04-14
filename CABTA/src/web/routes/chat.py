"""
Author: Ugur Ates
Chat API routes - Interactive agent conversation.
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter()


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

        # If session is still active, return status
        if session.get('status') == 'active':
            return {
                "session_id": body.session_id,
                "status": "active",
                "response": "The investigation is still running. Check the progress via WebSocket.",
            }

        # If session is completed/failed, start a new investigation with context
        context = f"(Follow-up to previous investigation: {session.get('goal', '')})\n{body.message}"
        session_id = await agent_loop.investigate(
            context, case_id=session.get('case_id')
        )
        return {
            "session_id": session_id,
            "status": "processing",
            "response": "Follow-up investigation started.",
        }
    else:
        # New investigation - LLM will see available playbooks and may auto-select one
        session_id = await agent_loop.investigate(body.message)
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
    session['steps'] = steps
    # Include live state if available
    agent_loop = request.app.state.agent_loop
    if agent_loop:
        live_state = agent_loop.get_state(session_id)
        if live_state:
            session['live_state'] = live_state
    return session
