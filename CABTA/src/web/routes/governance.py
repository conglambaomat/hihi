"""Governance routes for approvals and AI decision logs."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel


router = APIRouter()


class ApprovalReviewRequest(BaseModel):
    approved: bool
    reviewer: str = "analyst"
    comment: str = ""


class DecisionFeedbackRequest(BaseModel):
    feedback: str
    reviewer: str = "analyst"


class StructuredFeedbackRequest(BaseModel):
    session_id: str
    feedback_type: str = "final_answer_quality"
    target_type: str = "answer"
    target_ref: str = "final"
    reviewer: str = "analyst"
    verdict: Optional[str] = None
    useful: Optional[bool] = None
    comment: str = ""
    metadata: Dict[str, Any] = {}
    case_id: Optional[str] = None
    workflow_id: Optional[str] = None
    decision_id: str = ""


def _require_governance_store(request: Request):
    store = getattr(request.app.state, "governance_store", None)
    if store is None:
        raise HTTPException(503, "Governance store not initialized")
    return store


@router.get("/approvals")
async def list_approvals(
    request: Request,
    status: Optional[str] = None,
    case_id: Optional[str] = None,
    session_id: Optional[str] = None,
    limit: int = 100,
):
    store = _require_governance_store(request)
    return {
        "items": store.list_approvals(
            status=status,
            case_id=case_id,
            session_id=session_id,
            limit=limit,
        )
    }


@router.get("/approvals/{approval_id}")
async def get_approval(request: Request, approval_id: str):
    store = _require_governance_store(request)
    approval = store.get_approval(approval_id)
    if approval is None:
        raise HTTPException(404, "Approval not found")
    return approval


@router.post("/approvals/{approval_id}/review")
async def review_approval(request: Request, approval_id: str, payload: ApprovalReviewRequest):
    store = _require_governance_store(request)
    updated = store.review_approval(
        approval_id,
        approved=payload.approved,
        reviewer=payload.reviewer,
        comment=payload.comment,
    )
    if not updated:
        raise HTTPException(404, "Approval not found")
    return {"success": True}


@router.get("/decisions")
async def list_decisions(
    request: Request,
    case_id: Optional[str] = None,
    session_id: Optional[str] = None,
    workflow_id: Optional[str] = None,
    limit: int = 100,
):
    store = _require_governance_store(request)
    return {
        "items": store.list_ai_decisions(
            case_id=case_id,
            session_id=session_id,
            workflow_id=workflow_id,
            limit=limit,
        )
    }


@router.get("/decisions/{decision_id}")
async def get_decision(request: Request, decision_id: str):
    store = _require_governance_store(request)
    decision = store.get_ai_decision(decision_id)
    if decision is None:
        raise HTTPException(404, "AI decision not found")
    return decision


@router.post("/decisions/{decision_id}/feedback")
async def decision_feedback(request: Request, decision_id: str, payload: DecisionFeedbackRequest):
    store = _require_governance_store(request)
    updated = store.add_decision_feedback(
        decision_id,
        feedback=payload.feedback,
        reviewer=payload.reviewer,
    )
    if not updated:
        raise HTTPException(404, "AI decision not found")
    return {"success": True}


@router.get("/events")
async def list_agent_events(
    request: Request,
    session_id: Optional[str] = None,
    case_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 200,
):
    store = _require_governance_store(request)
    return {"items": store.list_agent_events(session_id=session_id, case_id=case_id, event_type=event_type, limit=limit)}


@router.post("/feedback")
async def structured_feedback(request: Request, payload: StructuredFeedbackRequest):
    store = _require_governance_store(request)
    feedback_id = store.record_structured_feedback(
        session_id=payload.session_id,
        case_id=payload.case_id,
        workflow_id=payload.workflow_id,
        decision_id=payload.decision_id,
        feedback_type=payload.feedback_type,
        target_type=payload.target_type,
        target_ref=payload.target_ref,
        reviewer=payload.reviewer,
        verdict=payload.verdict,
        useful=payload.useful,
        comment=payload.comment,
        metadata=payload.metadata,
    )
    try:
        store.record_agent_event(
            event_id=f"feedback-{feedback_id}",
            session_id=payload.session_id,
            case_id=payload.case_id,
            event_type="feedback.recorded",
            timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            payload={"feedback_id": feedback_id, "feedback_type": payload.feedback_type, "target_type": payload.target_type, "target_ref": payload.target_ref},
            refs=[{"target_type": payload.target_type, "target_ref": payload.target_ref}],
        )
    except Exception:
        pass
    return {"success": True, "feedback_id": feedback_id}
