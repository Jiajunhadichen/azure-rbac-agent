"""
SQLite Audit Logger

Persists all agent actions to a local SQLite database for full traceability.

SECURITY: All actions are written to audit log — no agent action goes unrecorded.
SECURITY: Audit records are append-only (no delete endpoint exposed).
SECURITY: No Azure credentials are stored in this database.
"""

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "accesssafe_audit.db"


class AuditLogger:
    """
    Thread-safe SQLite audit logger.

    All agent recommendations, approval decisions, and system events
    are persisted here. This provides a non-repudiable audit trail.

    Schema:
        id              TEXT PRIMARY KEY
        timestamp       TEXT (ISO-8601 UTC)
        action          TEXT (e.g. ACCESS_REQUEST_PLAN_CREATED)
        user_id         TEXT (subject of the action)
        target_scope    TEXT (Azure scope string)
        role            TEXT (Azure role name)
        risk_level      TEXT (low/medium/high/critical)
        recommendation  TEXT (human-readable recommendation text)
        approver        TEXT (who should/did approve)
        status          TEXT (pending/approved/rejected/error)
        details         TEXT (additional context)
        initiated_by    TEXT (which agent or user initiated)
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create the audit_log table if it doesn't exist."""
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id              TEXT PRIMARY KEY,
                    timestamp       TEXT NOT NULL,
                    action          TEXT NOT NULL,
                    user_id         TEXT,
                    target_scope    TEXT,
                    role            TEXT,
                    risk_level      TEXT,
                    recommendation  TEXT,
                    approver        TEXT,
                    status          TEXT DEFAULT 'pending',
                    details         TEXT,
                    initiated_by    TEXT
                )
            """)
            # Approval decisions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_decisions (
                    id              TEXT PRIMARY KEY,
                    plan_id         TEXT NOT NULL,
                    decision        TEXT NOT NULL,
                    decided_by      TEXT,
                    decided_at      TEXT NOT NULL,
                    notes           TEXT
                )
            """)
            conn.commit()

    def write(
        self,
        action: str,
        user_id: str = "unknown",
        target_scope: str = "",
        role: str = "",
        risk_level: str = "",
        recommendation: str = "",
        approver: str = "",
        status: str = "pending",
        details: str = "",
        initiated_by: str = "system",
    ) -> str:
        """
        Write an audit record. Returns the generated record ID.

        SECURITY: Records are immutable once written.
        SECURITY: No record deletion is exposed through any API.
        """
        record_id = f"log-{uuid.uuid4().hex[:10].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                    (id, timestamp, action, user_id, target_scope, role,
                     risk_level, recommendation, approver, status, details, initiated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id, timestamp, action, user_id, target_scope, role,
                    risk_level, recommendation, approver, status, details, initiated_by,
                ),
            )
            conn.commit()
        return record_id

    def record_decision(
        self,
        plan_id: str,
        decision: str,
        decided_by: str = "admin",
        notes: str = "",
    ) -> str:
        """
        Record a human Approve/Reject decision for an approval plan.

        SECURITY: This updates local state only — no real Azure changes occur.
        SECURITY: Decision is logged with timestamp for audit trail.

        Args:
            plan_id: The approval plan ID.
            decision: "approved" or "rejected".
            decided_by: Identity of the decision maker.
            notes: Optional notes from the reviewer.

        Returns:
            Generated decision record ID.
        """
        decision_id = f"dec-{uuid.uuid4().hex[:8].upper()}"
        decided_at = datetime.now(timezone.utc).isoformat()

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO approval_decisions
                    (id, plan_id, decision, decided_by, decided_at, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (decision_id, plan_id, decision, decided_by, decided_at, notes),
            )
            # Also write an audit record for the decision itself
            conn.commit()

        self.write(
            action=f"APPROVAL_DECISION_{decision.upper()}",
            user_id=decided_by,
            target_scope="",
            role="",
            risk_level="",
            recommendation="",
            approver=decided_by,
            status=decision,
            details=f"Plan {plan_id} was {decision} by {decided_by}. Notes: {notes}",
            initiated_by=f"human:{decided_by}",
        )
        return decision_id

    def get_decision_for_plan(self, plan_id: str) -> Optional[dict]:
        """Return the latest decision for a given plan_id, or None."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM approval_decisions WHERE plan_id = ? ORDER BY decided_at DESC LIMIT 1",
                (plan_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_recent_logs(self, limit: int = 50) -> list[dict]:
        """Return the most recent audit log entries."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_logs(self) -> list[dict]:
        """Return all audit log entries."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC"
            ).fetchall()
        return [dict(r) for r in rows]
