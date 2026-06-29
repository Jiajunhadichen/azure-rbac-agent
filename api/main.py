# api/main.py
import sys
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db import (
    init_db,
    get_access_records,
    get_access_record,
    update_access_record_status,
    get_audit_logs,
    get_dashboard_stats
)
from agents.interpreter_agent import parse_access_request
from agents.recommendation_agent import recommend_access, scan_risks
from agents.approval_agent import create_access_request_plan, create_risk_remediation_plan

app = FastAPI(
    title="AccessSafe Backend API",
    description="Backend API for Azure RBAC lifecycle management agent platform"
)

# Initialize Database on startup
@app.on_event("startup")
def startup_event():
    init_db()

# --- Request Models ---

class NLPRequest(BaseModel):
    request_text: str

class DecisionRequest(BaseModel):
    status: str  # "Approved" or "Rejected"
    operator: str
    reject_reason: Optional[str] = None

class RemediationRequest(BaseModel):
    finding: Dict[str, Any]

# --- Endpoints ---

@app.post("/requests/submit", response_model=Dict[str, Any])
def submit_request(payload: NLPRequest):
    """
    Submits a natural language access request and routes it through:
    Interpreter Agent -> Recommendation Agent -> Approval Coordinator Agent
    """
    try:
        # Step 1: Parse request using NLP / LLM
        interpreter_out = parse_access_request(payload.request_text)
        
        # Step 2: Make RBAC recommendation & check policies
        recommendation_out = recommend_access(interpreter_out)
        
        # Step 3: Write pending plan to access_records and create audit logs
        plan = create_access_request_plan(interpreter_out, recommendation_out)
        return plan
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Request parsing and plan generation failed: {str(e)}")

@app.get("/risk/scan", response_model=List[Dict[str, Any]])
def trigger_risk_scan():
    """
    Scans mock Azure environment assignments to identify policy violations.
    """
    try:
        findings = scan_risks()
        return findings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Risk scanning failed: {str(e)}")

@app.post("/risk/remediate", response_model=Dict[str, Any])
def remediate_risk(payload: RemediationRequest):
    """
    Generates a remediation plan for a risk finding and inserts it to access_records.
    """
    try:
        plan = create_risk_remediation_plan(payload.finding)
        return plan
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation plan generation failed: {str(e)}")

@app.get("/records", response_model=List[Dict[str, Any]])
def list_records(
    status: Optional[str] = Query(None, description="Filter by status (e.g. Pending, Approved, Rejected)"),
    source: Optional[str] = Query(None, description="Filter by source (new_request, risk_scan)")
):
    """
    Lists access records with optional filtering.
    """
    return get_access_records(status=status, source=source)

@app.get("/records/{record_id}", response_model=Dict[str, Any])
def get_record_details(record_id: str):
    """
    Gets details of a specific access record.
    """
    record = get_access_record(record_id)
    if not record:
        raise HTTPException(status_code=44, detail="Access record not found")
    return record

@app.post("/records/{record_id}/decide")
def submit_decision(record_id: str, payload: DecisionRequest):
    """
    Approves or Rejects a pending access request/remediation plan.
    """
    if payload.status not in ["Approved", "Rejected"]:
        raise HTTPException(status_code=400, detail="Decision must be 'Approved' or 'Rejected'")
    
    success = update_access_record_status(
        record_id=record_id,
        status=payload.status,
        operator=payload.operator,
        reject_reason=payload.reject_reason
    )
    if not success:
        raise HTTPException(status_code=404, detail="Record not found or could not be updated")
    
    return {"message": f"Record {record_id} successfully {payload.status.lower()}"}

@app.get("/audit/logs", response_model=List[Dict[str, Any]])
def list_audit_logs(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    search: Optional[str] = Query(None, description="Search term for subject, action, or operator")
):
    """
    Lists audit logs with filtering capability.
    """
    return get_audit_logs(event_type=event_type, risk_level=risk_level, search=search)

@app.get("/dashboard/stats", response_model=Dict[str, int])
def fetch_stats():
    """
    Fetches the stats metrics for the Dashboard cards.
    """
    return get_dashboard_stats()
