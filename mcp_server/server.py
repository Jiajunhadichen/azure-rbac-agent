# mcp_server/server.py
import sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server.fastmcp import FastMCP
from mcp_server.tools import (
    get_user_profile,
    get_role_assignments,
    get_resource_inventory,
    get_access_policy_templates,
    write_audit_log
)

mcp = FastMCP(
    "AccessSafe Mock Azure IAM",
    description="Provides mock Azure IAM data and logs administrative decisions.",
)

@mcp.tool()
def tool_get_user_profile(user_id: str) -> dict:
    """Retrieve profile and job information for a user."""
    return get_user_profile(user_id)

@mcp.tool()
def tool_get_role_assignments(user_id: str) -> list:
    """Retrieve all current Azure role assignments for a user."""
    return get_role_assignments(user_id)

@mcp.tool()
def tool_get_resource_inventory(resource_group: str) -> dict:
    """Retrieve resource inventory for a resource group."""
    return get_resource_inventory(resource_group)

@mcp.tool()
def tool_get_access_policy_templates(job_role: str) -> dict:
    """Retrieve access policy template for a given job role."""
    return get_access_policy_templates(job_role)

@mcp.tool()
def tool_write_audit_log(
    event_type: str, subject: str, action: str, result: str, operator: str
) -> dict:
    """Write administrative decisions and recommendations to audit logs."""
    return write_audit_log(event_type, subject, action, result, operator)

if __name__ == "__main__":
    mcp.run(transport="stdio")
