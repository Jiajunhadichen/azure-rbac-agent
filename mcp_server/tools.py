# mcp_server/tools.py
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

DATA_DIR = Path(__file__).parent.parent / "data"
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db import write_audit_log as db_write_audit_log

def _load_json(filename: str) -> List[Dict[str, Any]]:
    path = DATA_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# --- Tool 1: get_user_profile ---
def get_user_profile(user_id: str) -> Dict[str, Any]:
    """
    Returns user profile: name, job role, department, join date, status.
    """
    users = _load_json("users.json")
    for u in users:
        if u["id"] == user_id:
            role = u["role"]
            # Derive department based on role
            dept = "Support" if role == "Support Analyst" else "Engineering"
            return {
                "name": u["name"],
                "role": role,
                "department": dept,
                "joined": u["joined"],
                "status": u["status"],
                "left": u.get("left")
            }
    return {"error": f"User {user_id} not found"}

# --- Tool 2: get_role_assignments ---
def get_role_assignments(user_id: str) -> List[Dict[str, Any]]:
    """
    Returns role assignments for a user, indicating role, scope, start date, and expiry.
    """
    assignments = _load_json("role_assignments.json")
    results = []
    for a in assignments:
        if a["user_id"] == user_id:
            results.append({
                "role": a["role"],
                "scope": a["scope"],
                "assigned_date": a["assigned_date"],
                "has_expiry": a.get("expiry_date") is not None,
                "expiry_date": a.get("expiry_date"),
                "last_reviewed": a.get("last_reviewed")
            })
    return results

# --- Tool 3: get_resource_inventory ---
def get_resource_inventory(resource_group: str) -> Dict[str, Any]:
    """
    Returns resources in group and environment classification (dev/test/prod).
    """
    groups = _load_json("resource_groups.json")
    for g in groups:
        if g["name"] == resource_group:
            # Generate mock resources list for demo purposes
            resources = [
                {"name": f"{resource_group}-webapp", "type": "Microsoft.Web/sites", "status": "Running"},
                {"name": f"{resource_group}-db", "type": "Microsoft.Sql/servers/databases", "status": "Online"},
                {"name": f"{resource_group}-monitoring", "type": "Microsoft.OperationalInsights/workspaces", "status": "Active"}
            ]
            return {
                "name": g["name"],
                "environment": g["environment"],
                "sensitivity": g["sensitivity"],
                "resources": resources
            }
    return {"error": f"Resource group {resource_group} not found"}

# --- Tool 4: get_access_policy_templates ---
def get_access_policy_templates(job_role: str) -> Dict[str, Any]:
    """
    Returns policy template recommending role, scope, and duration for a job role.
    """
    templates = _load_json("access_policy_templates.json")
    for t in templates:
        if t["job_role"].lower().replace(" ", "") == job_role.lower().replace(" ", ""):
            return t
    # Fallback template
    return {
        "job_role": job_role,
        "max_role": "Reader",
        "max_scope": "resource_group",
        "max_duration_days": 30,
        "production_access": False
    }

# --- Tool 5: write_audit_log ---
def write_audit_log(event_type: str, subject: str, action: str, result: str, operator: str) -> Dict[str, Any]:
    """
    Writes action or recommendation event to audit logs.
    """
    log_id = db_write_audit_log(event_type, subject, action, result, operator)
    return {
        "status": "success",
        "log_id": log_id,
        "message": "Audit log entry written successfully"
    }

# --- Risk Scanning Helpers (used by agents directly) ---

def get_all_users() -> List[Dict[str, Any]]:
    """Helper to return all users formatted for risk scanning rules."""
    users = _load_json("users.json")
    formatted = []
    for u in users:
        role = u["role"]
        dept = "Support" if role == "Support Analyst" else "Engineering"
        # Map to old agent's expected structure
        formatted.append({
            "user_id": u["id"],
            "display_name": u["name"],
            "job_role": role.lower().replace(" ", "_"),
            "person_type": role.lower(),  # "developer", "intern", "contractor", "support_analyst"
            "department": dept,
            "status": u["status"]
        })
    return formatted

def get_all_role_assignments() -> List[Dict[str, Any]]:
    """Helper to return all role assignments formatted for risk scanning rules."""
    assignments = _load_json("role_assignments.json")
    users = _load_json("users.json")
    user_names = {u["id"]: u["name"] for u in users}
    
    results = []
    for idx, a in enumerate(assignments):
        days_active = None
        if a.get("assigned_date"):
            try:
                assigned = datetime.strptime(a["assigned_date"], "%Y-%m-%d")
                # Use current local time 2026-06-21 as reference or dynamic time
                days_active = (datetime.now() - assigned).days
            except ValueError:
                pass
        
        scope_lvl = "subscription" if a["scope"] == "subscription" else "resource_group"
        
        results.append({
            "assignment_id": f"assign-{idx+1:03d}",
            "user_id": a["user_id"],
            "user_name": user_names.get(a["user_id"], "Unknown"),
            "role": a["role"],
            "scope": a["scope"],
            "scope_level": scope_lvl,
            "assigned_date": a["assigned_date"],
            "expiry_date": a.get("expiry_date"),
            "days_active": days_active,
            "status": "active"
        })
    return results
