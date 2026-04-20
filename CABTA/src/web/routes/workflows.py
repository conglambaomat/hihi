"""Workflow API routes for the CABTA orchestration plane."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import AliasChoices, BaseModel, ConfigDict, Field


router = APIRouter()


class WorkflowRunRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='ignore')

    goal: str = ""
    params: Dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices('params', 'inputs'),
    )
    case_id: Optional[str] = None
    max_steps: Optional[int] = Field(None, ge=1, le=500)


def _require_workflow_registry(request: Request):
    registry = getattr(request.app.state, "workflow_registry", None)
    if registry is None:
        raise HTTPException(503, "Workflow registry not initialized")
    return registry


def _require_workflow_service(request: Request):
    service = getattr(request.app.state, "workflow_service", None)
    if service is None:
        raise HTTPException(503, "Workflow service not initialized")
    return service


@router.get("")
async def list_workflows(request: Request):
    """List orchestration workflows."""
    registry = _require_workflow_registry(request)
    service = _require_workflow_service(request)
    workflows = []
    for item in registry.list_workflows():
        validation = service.validate_dependencies(request.app, item["id"])
        workflows.append({**item, "dependency_status": validation["status"]})
    return {"workflows": workflows}


@router.get("/sessions")
async def list_workflow_runs(
    request: Request,
    limit: int = 50,
    status: Optional[str] = None,
    workflow_id: Optional[str] = None,
):
    service = _require_workflow_service(request)
    return {"items": service.list_runs(limit=limit, status=status, workflow_id=workflow_id)}


@router.get("/sessions/{session_id}")
async def get_workflow_run(request: Request, session_id: str):
    service = _require_workflow_service(request)
    run = service.get_run(session_id)
    if run is None:
        raise HTTPException(404, "Workflow run not found")
    return run


@router.get("/{workflow_id}")
async def get_workflow(request: Request, workflow_id: str):
    """Return workflow metadata and body sections."""
    registry = _require_workflow_registry(request)
    service = _require_workflow_service(request)
    workflow = registry.get_workflow(workflow_id)
    if workflow is None:
        raise HTTPException(404, "Workflow not found")
    workflow["dependencies"] = service.validate_dependencies(request.app, workflow_id)
    return workflow


@router.get("/{workflow_id}/validate")
async def validate_workflow(request: Request, workflow_id: str):
    service = _require_workflow_service(request)
    try:
        return service.validate_dependencies(request.app, workflow_id)
    except ValueError:
        raise HTTPException(404, "Workflow not found")


@router.post("/{workflow_id}/run")
async def run_workflow(request: Request, workflow_id: str, body: WorkflowRunRequest):
    """Execute a workflow via its configured backend."""
    registry = _require_workflow_registry(request)
    service = _require_workflow_service(request)
    workflow = registry.get_workflow(workflow_id)
    if workflow is None:
        raise HTTPException(404, "Workflow not found")

    dependency_state = service.validate_dependencies(request.app, workflow_id)
    if dependency_state["status"] == "blocked":
        raise HTTPException(400, f"Workflow dependencies are not ready: {dependency_state}")

    metadata = {
        "workflow_id": workflow_id,
        "agent_profile_id": workflow.get("default_agent_profile"),
        "lead_agent_profile_id": workflow.get("default_agent_profile"),
        "specialist_team": list(workflow.get("agents") or []),
        "active_specialist": (workflow.get("agents") or [workflow.get("default_agent_profile")])[0] if (workflow.get("agents") or [workflow.get("default_agent_profile")]) else None,
        "specialist_handoffs": [],
        "collaboration_mode": "multi_agent" if len(workflow.get("agents") or []) > 1 else "single_agent",
        "execution_mode": "workflow",
    }

    params = dict(body.params or {})
    if body.goal and "workflow_goal" not in params:
        params["workflow_goal"] = body.goal

    backend = str(workflow.get("execution_backend") or "agent").lower()
    playbook_id = workflow.get("playbook_id")

    if backend == "playbook" and playbook_id:
        engine = getattr(request.app.state, "playbook_engine", None)
        store = getattr(request.app.state, "agent_store", None)
        if engine is None:
            raise HTTPException(503, "Playbook engine not initialized")

        session_id = await engine.execute(
            playbook_id,
            params,
            body.case_id,
        )
        if store is not None:
            store.update_session_metadata(session_id, metadata)
        if body.case_id and getattr(request.app.state, "case_store", None):
            request.app.state.case_store.link_workflow(body.case_id, session_id, workflow_id)
        return {
            "workflow_id": workflow_id,
            "session_id": session_id,
            "status": "running",
            "backend": "playbook",
            "playbook_id": playbook_id,
            "dependency_status": dependency_state["status"],
        }

    agent_loop = getattr(request.app.state, "agent_loop", None)
    if agent_loop is None:
        raise HTTPException(503, "Agent loop not initialized")

    goal = registry.build_goal(workflow_id, goal=body.goal, params=params)
    session_id = await agent_loop.investigate(
        goal=goal,
        case_id=body.case_id,
        playbook_id=playbook_id,
        max_steps=body.max_steps,
        metadata=metadata,
    )
    if body.case_id and getattr(request.app.state, "case_store", None):
        request.app.state.case_store.link_workflow(body.case_id, session_id, workflow_id)
    return {
        "workflow_id": workflow_id,
        "session_id": session_id,
        "status": "running",
        "backend": "agent",
        "playbook_id": playbook_id,
        "dependency_status": dependency_state["status"],
    }
