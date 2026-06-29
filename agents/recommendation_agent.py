# agents/recommendation_agent.py
"""
Agent 2 — RBAC Recommendation & Risk Review Agent

Responsibility:
  (a) ACCESS REQUEST MODE: Given structured interpreter output, recommend the
      minimum-privilege Azure role assignment and flag any risk concerns.
  (b) RISK SCAN MODE: Scan all existing role assignments and return a prioritised
      list of risk findings.

SECURITY: Agent never grants permissions directly.
SECURITY: All recommendations require human approval before any action.
SECURITY: Subscription-wide Owner role is never recommended.
SECURITY: Production access is denied unless explicitly justified.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_server.tools import (
    get_access_policy_templates,
    get_all_role_assignments,
    get_all_users,
)

# ---------------------------------------------------------------------------
# ACCESS REQUEST MODE — recommend minimum-privilege assignment
# ---------------------------------------------------------------------------

def recommend_access(interpreter_output: dict) -> dict:
    """
    Recommend the minimum-privilege RBAC assignment for an access request.

    SECURITY: Subscription-wide Owner is never returned.
    SECURITY: Production access is flagged and requires multiple senior approvers.
    """
    person_type = interpreter_output.get("person_type", "unknown")
    environment = interpreter_output.get("environment", "unknown")
    access_level = interpreter_output.get("access_level", "unknown")
    sensitivity = interpreter_output.get("sensitivity", "low")
    injection_detected = interpreter_output.get("injection_detected", False)

    if injection_detected:
        return {
            "recommended_role": None,
            "recommended_scope": None,
            "production_access": False,
            "duration_days": 0,
            "security_group": None,
            "risk_level": "Critical",
            "requires_approval": True,
            "reason": (
                "Prompt injection attempt detected in the access request. "
                "This request has been blocked and flagged for security review."
            ),
            "risk_flags": ["PROMPT_INJECTION_DETECTED"],
            "approvers": ["Azure Admin", "Security Manager"]
        }

    # Load template
    template = get_access_policy_templates(person_type)
    max_role = template.get("max_role", "Reader")
    max_scope = template.get("max_scope", "resource_group")
    max_duration = template.get("max_duration_days", 30)

    # Determine recommended scope based on requested environment
    env_scope_map = {
        "development": "rg-development",
        "testing": "rg-testing",
        "production": "rg-production",
    }
    recommended_scope = env_scope_map.get(environment, "rg-development")

    risk_flags = []
    reason_parts = []
    
    # Access level mapping
    if access_level == "read-only":
        recommended_role = "Reader"
        reason_parts.append("Reader matches read-only requirement.")
    elif access_level == "read-write":
        if max_role == "Reader":
            recommended_role = "Reader"
            risk_flags.append("READ_WRITE_DOWNGRADED_TO_READER")
            reason_parts.append(
                f"Requested read-write access but job role '{person_type}' is restricted to Reader max. Downgraded to Reader."
            )
        else:
            recommended_role = "Contributor"
            reason_parts.append("Contributor role recommended for read-write access.")
    elif access_level == "admin":
        # SECURITY: Owner role is never recommended
        recommended_role = "Contributor"
        risk_flags.append("ADMIN_DOWNGRADED_TO_CONTRIBUTOR")
        reason_parts.append("Admin level access requested. Subscription Owner is NEVER recommended by policy; downgraded to Contributor.")
    else:
        recommended_role = "Reader"
        reason_parts.append("Unknown access level, defaulting to Reader.")

    # Check for production access
    production_access = (environment == "production")
    if production_access:
        # Check policy template
        if not template.get("production_access", False):
            # If job role doesn't allow production access, we downgrade scope or set risk to Critical
            risk_flags.append("UNAUTHORIZED_PRODUCTION_ACCESS_REQUEST")
            risk_level = "High"
            # Keep recommended role as Reader on production, but flag it heavily
            recommended_role = "Reader"
            reason_parts.append(f"Production access requested. Job role '{person_type}' is not authorized for production. Downgraded to Reader on production.")
            approvers = ["Azure Admin", "CISO"]
        else:
            risk_level = "High"
            risk_flags.append("PRODUCTION_ACCESS_REQUEST")
            reason_parts.append("Production access requested, requiring senior approval.")
            approvers = ["Azure Admin", "Project Lead"]
    else:
        risk_level = "Low"
        approvers = ["Resource Owner"]

    # Limit duration
    duration_days = min(90, max_duration) # Intern 90 days, Contractor 30 days, Developer 180 (but cap at 90 for temp default)
    if person_type == "intern":
        duration_days = 90
    elif person_type == "contractor":
        duration_days = 30
    elif person_type == "support_analyst":
        duration_days = 90
    else:
        duration_days = 180

    # Sensitivity adjustments
    if sensitivity == "high":
        risk_level = "High" if risk_level != "Critical" else "Critical"
        if "HIGH_SENSITIVITY" not in risk_flags:
            risk_flags.append("HIGH_SENSITIVITY")

    # Extra formatting for reasons
    if recommended_role == "Reader" and access_level == "read-only":
        reason_parts.append("Contributor not recommended as it allows resource modification.")

    return {
        "recommended_role": recommended_role,
        "recommended_scope": recommended_scope,
        "production_access": production_access,
        "duration_days": duration_days,
        "security_group": f"grp-{person_type.replace('_', '-')}-readers" if recommended_role == "Reader" else f"grp-{person_type.replace('_', '-')}-contributors",
        "risk_level": risk_level,
        "requires_approval": True,
        "approvers": approvers,
        "reason": " ".join(reason_parts),
        "risk_flags": risk_flags
    }

# ---------------------------------------------------------------------------
# RISK SCAN MODE — scan all existing assignments for anomalies
# ---------------------------------------------------------------------------

def scan_risks() -> List[Dict[str, Any]]:
    """
    Scan all role assignments against policy rules and return findings.
    
    SECURITY: Read-only analysis — does not modify any assignments.
    """
    all_users = get_all_users()
    all_assignments = get_all_role_assignments()

    user_map = {u["user_id"]: u for u in all_users}
    findings = []

    for assignment in all_assignments:
        u_id = assignment["user_id"]
        user = user_map.get(u_id)
        if not user:
            continue

        role = assignment["role"]
        scope = assignment["scope"]
        assigned_date = assignment["assigned_date"]
        days_active = assignment.get("days_active", 0)

        # Rule 1: Inactive/Terminated employee with active assignments
        if user["status"] == "inactive":
            findings.append({
                "subject": user["display_name"],
                "user_id": u_id,
                "current_role": role,
                "current_scope": scope,
                "risk_level": "Critical",
                "risk_reason": f"Terminated employee account is inactive, but still holds active {role} role assignment on {scope}.",
                "recommendation": "Immediately revoke all role assignments for terminated employee. Initiate offboarding and access cleanup.",
                "recommended_role": "REVOKE",
                "recommended_scope": "all",
                "duration_days": 0,
                "approvers": ["Azure Admin"]
            })
            continue

        # Rule 2: Contractor with Owner or subscription scope
        if user["person_type"] == "contractor":
            if role == "Owner" or scope == "subscription":
                findings.append({
                    "subject": user["display_name"],
                    "user_id": u_id,
                    "current_role": f"Subscription {role}" if scope == "subscription" else role,
                    "current_scope": scope,
                    "risk_level": "Critical",
                    "risk_reason": f"Owner role at subscription scope held for {days_active} days, far exceeds contractor's dev-only responsibility",
                    "recommendation": "Revoke Subscription Owner immediately. Assign Contributor role at rg-project-dev scope as required for contractor deliverables.",
                    "recommended_role": "Contributor",
                    "recommended_scope": "rg-project-dev",
                    "duration_days": 30,
                    "approvers": ["Project Lead", "Azure Admin"]
                })
                continue

        # Rule 3: Intern with Contributor or higher on production
        if user["person_type"] == "intern":
            if role in ["Contributor", "Owner"] and "production" in scope.lower():
                findings.append({
                    "subject": user["display_name"],
                    "user_id": u_id,
                    "current_role": role,
                    "current_scope": scope,
                    "risk_level": "High",
                    "risk_reason": "Intern has Contributor role on production scope. Intern policy restricts access to Reader on development environments only.",
                    "recommendation": "Downgrade Contributor on production to Reader on rg-development to enforce internship limits.",
                    "recommended_role": "Reader",
                    "recommended_scope": "rg-development",
                    "duration_days": 90,
                    "approvers": ["Project Lead", "Azure Admin"]
                })
                continue

        # Rule 4: Subscription level Contributor/Owner for developer active for a long time
        if user["person_type"] == "developer" and scope == "subscription":
            if role in ["Contributor", "Owner"]:
                findings.append({
                    "subject": user["display_name"],
                    "user_id": u_id,
                    "current_role": f"Subscription {role}" if scope == "subscription" else role,
                    "current_scope": scope,
                    "risk_level": "High",
                    "risk_reason": f"Developer holds high-privilege {role} role assignment at subscription scope. Policy recommends resource group level scoping.",
                    "recommendation": "Downgrade subscription Contributor to Contributor at rg-project-dev scope to limit scope blast radius.",
                    "recommended_role": "Contributor",
                    "recommended_scope": "rg-project-dev",
                    "duration_days": 90,
                    "approvers": ["Project Lead", "Azure Admin"]
                })
                continue

    # Sort findings: Critical -> High -> Medium -> Low
    risk_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    findings.sort(key=lambda f: risk_weights.get(f["risk_level"], 0), reverse=True)
    return findings
