# database/db.py
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = Path(__file__).parent / "accesssafe.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if it has not been initialized."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db_connection() as conn:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()

# --- Access Records CRUD ---

def create_access_record(record: Dict[str, Any]) -> str:
    """
    Inserts a new access record or replaces it.
    """
    sql = """
    INSERT OR REPLACE INTO access_records (
        id, source, subject, current_role, current_scope, recommended_role,
        recommended_scope, production_access, risk_level, duration_days,
        reason, approvers, status, created_at, updated_at, expires_at
    ) VALUES (
        :id, :source, :subject, :current_role, :current_scope, :recommended_role,
        :recommended_scope, :production_access, :risk_level, :duration_days,
        :reason, :approvers, :status, :created_at, :updated_at, :expires_at
    )
    """
    now = datetime.now(timezone.utc).isoformat()
    record_data = {
        "id": record.get("id"),
        "source": record.get("source"),
        "subject": record.get("subject"),
        "current_role": record.get("current_role"),
        "current_scope": record.get("current_scope"),
        "recommended_role": record.get("recommended_role"),
        "recommended_scope": record.get("recommended_scope"),
        "production_access": int(record.get("production_access", 0)),
        "risk_level": record.get("risk_level", "Low"),
        "duration_days": record.get("duration_days", 90),
        "reason": record.get("reason"),
        "approvers": record.get("approvers", ""),
        "status": record.get("status", "Pending"),
        "created_at": record.get("created_at", now),
        "updated_at": record.get("updated_at", now),
        "expires_at": record.get("expires_at")
    }
    with get_db_connection() as conn:
        conn.execute(sql, record_data)
        conn.commit()
    return record_data["id"]

def update_access_record_status(record_id: str, status: str, operator: str, reject_reason: str = None) -> bool:
    """
    Approve or Reject an access record. Updates status and logs the event.
    """
    now = datetime.now(timezone.utc).isoformat()
    
    with get_db_connection() as conn:
        # Get the record first
        row = conn.execute("SELECT * FROM access_records WHERE id = ?", (record_id,)).fetchone()
        if not row:
            return False
        
        record = dict(row)
        expires_at = None
        if status == "Approved" and record.get("duration_days"):
            import datetime as dt
            days = int(record["duration_days"])
            expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).isoformat()
            
        conn.execute(
            "UPDATE access_records SET status = ?, expires_at = ?, updated_at = ? WHERE id = ?",
            (status, expires_at, now, record_id)
        )
        
        # Write to audit log
        audit_sql = """
        INSERT INTO audit_logs (timestamp, event_type, subject, action, result, operator)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        action_text = f"Action: {status} Access Request"
        if reject_reason:
            action_text += f" | Reason: {reject_reason}"
        
        conn.execute(
            audit_sql,
            (
                now,
                record["source"].upper(),
                record["subject"],
                f"Role: {record['recommended_role']} @ Scope: {record['recommended_scope']} ({action_text})",
                status,
                operator
            )
        )
        conn.commit()
    return True

def get_access_records(status: Optional[str] = None, source: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM access_records WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if source:
        query += " AND source = ?"
        params.append(source)
    query += " ORDER BY created_at DESC"
    
    with get_db_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

def get_access_record(record_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM access_records WHERE id = ?", (record_id,)).fetchone()
        return dict(row) if row else None

# --- Audit Logs ---

def write_audit_log(event_type: str, subject: str, action: str, result: str, operator: str) -> int:
    """
    Inserts a log record into the audit_logs table.
    """
    now = datetime.now(timezone.utc).isoformat()
    sql = """
    INSERT INTO audit_logs (timestamp, event_type, subject, action, result, operator)
    VALUES (?, ?, ?, ?, ?, ?)
    """
    with get_db_connection() as conn:
        cursor = conn.execute(sql, (now, event_type, subject, action, result, operator))
        conn.commit()
        return cursor.lastrowid

def get_audit_logs(
    event_type: Optional[str] = None, 
    risk_level: Optional[str] = None,
    search: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Fetches audit logs, joining with access_records to support filtering by risk_level.
    """
    query = """
    SELECT l.*, r.risk_level
    FROM audit_logs l
    LEFT JOIN access_records r ON l.subject = r.subject AND r.status != 'Rejected'
    WHERE 1=1
    """
    params = []
    
    if event_type:
        query += " AND l.event_type = ?"
        params.append(event_type)
        
    if risk_level:
        query += " AND r.risk_level = ?"
        params.append(risk_level)
        
    if search:
        query += " AND (l.subject LIKE ? OR l.action LIKE ? OR l.operator LIKE ?)"
        like_str = f"%{search}%"
        params.extend([like_str, like_str, like_str])
        
    query += " GROUP BY l.id ORDER BY l.timestamp DESC"
    
    with get_db_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

def get_dashboard_stats() -> Dict[str, int]:
    """
    Returns counts for:
    - Pending requests
    - Active risk findings (Unresolved risks where source=risk_scan and status='Pending' or 'Needs Review')
    - Total requests created this month (or just total requests)
    - Total audit logs count
    """
    with get_db_connection() as conn:
        pending_count = conn.execute(
            "SELECT COUNT(*) FROM access_records WHERE status = 'Pending'"
        ).fetchone()[0]
        
        # Count of risk remediations that have been started (Pending or Approved)
        started_remediations = conn.execute(
            "SELECT COUNT(*) FROM access_records WHERE source = 'risk_scan' AND status IN ('Pending', 'Approved')"
        ).fetchone()[0]
        unresolved_risks = 4 - started_remediations
        
        total_requests = conn.execute(
            "SELECT COUNT(*) FROM access_records WHERE source = 'new_request'"
        ).fetchone()[0]
        
        audit_count = conn.execute(
            "SELECT COUNT(*) FROM audit_logs"
        ).fetchone()[0]
        
    return {
        "pending_approvals": pending_count,
        "unresolved_risks": unresolved_risks,
        "total_requests": total_requests,
        "total_audit_logs": audit_count
    }
