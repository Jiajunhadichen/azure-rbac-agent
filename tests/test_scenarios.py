# tests/test_scenarios.py
import sys
import os
import time
import threading
import requests
import uvicorn
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import database.db
database.db.DB_PATH = database.db.DB_PATH.parent / "accesssafe_test.db"

from database.db import DB_PATH, SCHEMA_PATH, init_db
from api.main import app

# Thread helper to run FastAPI
class ServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.srv = None

    def run(self):
        config = uvicorn.Config(app, host="127.0.0.1", port=8082, log_level="warning")
        self.srv = uvicorn.Server(config)
        self.srv.run()

    def shutdown(self):
        if self.srv:
            self.srv.should_exit = True

def run_tests():
    # 1. Clean slate setup
    if DB_PATH.exists():
        try:
            os.remove(DB_PATH)
            print("Removed existing test database.")
        except Exception as e:
            print(f"Could not remove DB file: {e}")

    # Initialize tables
    init_db()
    print("Database tables initialized.")

    # 2. Start API Server
    server_thread = ServerThread()
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to start
    time.sleep(2)
    print("FastAPI server started on http://127.0.0.1:8082")

    base_url = "http://127.0.0.1:8082"

    try:
        # ==========================================================
        # Scenario 1: Submit Carol's Request
        # ==========================================================
        print("\n--- Running Scenario 1: New NLP Access Request ---")
        carol_request = (
            "New Support Analyst Carol needs to view resource status and monitor logs in development. "
            "No resource modifications allowed. No production access."
        )
        
        resp = requests.post(f"{base_url}/requests/submit", json={"request_text": carol_request})
        assert resp.status_code == 200, f"Submit failed: {resp.text}"
        plan = resp.json()
        
        print("Agent 1 & 2 Output:")
        print(f"  Recommended Role : {plan['recommended_role']}")
        print(f"  Recommended Scope: {plan['recommended_scope']}")
        print(f"  Risk Level       : {plan['risk_level']}")
        print(f"  Production Access: {plan['production_access']}")
        print(f"  Reason           : {plan['reason']}")
        
        assert plan["recommended_role"] == "Reader", "Carol should be recommended Reader"
        assert plan["recommended_scope"] == "rg-development", "Carol's scope should be rg-development"
        assert plan["production_access"] == 0, "Carol shouldn't have production access"
        assert plan["risk_level"] == "Low", "Carol's risk level should be Low"
        
        # Verify stats show 1 pending request
        stats_resp = requests.get(f"{base_url}/dashboard/stats")
        stats = stats_resp.json()
        print(f"Dashboard Stats after Scenario 1: {stats}")
        assert stats["pending_approvals"] == 1, "Should have 1 pending approval"
        assert stats["total_requests"] == 1, "Should have 1 total request"

        # ==========================================================
        # Scenario 2: Risk Scan & Remediation
        # ==========================================================
        print("\n--- Running Scenario 2: Risk Scan & Remediation Plan Generation ---")
        scan_resp = requests.get(f"{base_url}/risk/scan")
        assert scan_resp.status_code == 200, f"Scan failed: {scan_resp.text}"
        findings = scan_resp.json()
        
        print(f"Detected {len(findings)} risks:")
        for idx, f in enumerate(findings):
            print(f"  Risk {idx+1}: {f['subject']} ({f['current_role']} on {f['current_scope']}) - Risk Level: {f['risk_level']}")

        # Ensure Contractor-01 with Subscription Owner is detected as Critical
        contractor_finding = next((f for f in findings if f["user_id"] == "contractor-01"), None)
        assert contractor_finding is not None, "Contractor risk not detected"
        assert contractor_finding["risk_level"] == "Critical", "Contractor risk should be Critical"
        
        # Ensure Intern-01 with Production Contributor is detected as High
        intern_finding = next((f for f in findings if f["user_id"] == "intern-01"), None)
        assert intern_finding is not None, "Intern risk not detected"
        assert intern_finding["risk_level"] == "High", "Intern risk should be High"
        
        # Generate remediation plan for Contractor-01
        remed_resp = requests.post(f"{base_url}/risk/remediate", json={"finding": contractor_finding})
        assert remed_resp.status_code == 200, f"Remediation failed: {remed_resp.text}"
        remed_plan = remed_resp.json()
        print("Remediation Plan generated for Contractor-01:")
        print(f"  Downgrade Role : {remed_plan['recommended_role']}")
        print(f"  Downgrade Scope: {remed_plan['recommended_scope']}")
        print(f"  Status         : {remed_plan['status']}")
        
        assert remed_plan["recommended_role"] == "Contributor", "Remediation role should be Contributor"
        assert remed_plan["recommended_scope"] == "rg-project-dev", "Remediation scope should be rg-project-dev"
        assert remed_plan["status"] == "Pending", "Remediation plan status should be Pending"

        # Verify stats update: 2 pending approvals, 3 unresolved risks (since Contractor is in 'Pending' remediation state, 3 others are not started)
        stats_resp = requests.get(f"{base_url}/dashboard/stats")
        stats = stats_resp.json()
        print(f"Dashboard Stats after Scenario 2: {stats}")
        assert stats["pending_approvals"] == 2, "Should have 2 pending approvals"
        assert stats["unresolved_risks"] == 3, "Should have 3 unresolved risks (Bob, Dave, Alice)"

        # ==========================================================
        # Scenario 3: Complete Approval Workflow
        # ==========================================================
        print("\n--- Running Scenario 3: Process Approvals & Audit Log Verification ---")
        
        # Approve Contractor-01's remediation
        remed_id = remed_plan["id"]
        decide_resp = requests.post(
            f"{base_url}/records/{remed_id}/decide",
            json={"status": "Approved", "operator": "Admin"}
        )
        assert decide_resp.status_code == 200, f"Approval decision failed: {decide_resp.text}"
        print(f"Approved Contractor-01 remediation (Record ID: {remed_id})")

        # Verify status changed in database
        rec_resp = requests.get(f"{base_url}/records/{remed_id}")
        rec = rec_resp.json()
        assert rec["status"] == "Approved"
        assert rec["expires_at"] is not None, "Approved record must have an expiration date set"
        print(f"  New Status: {rec['status']}")
        print(f"  Expires At: {rec['expires_at']}")

        # Verify stats after approval: pending approvals down to 1
        stats_resp = requests.get(f"{base_url}/dashboard/stats")
        stats = stats_resp.json()
        print(f"Dashboard Stats after approval: {stats}")
        assert stats["pending_approvals"] == 1, "Should have 1 pending approval left (Carol)"
        assert stats["unresolved_risks"] == 3, "Should still have 3 unresolved risks (Bob, Dave, Alice)"

        # Verify audit logs contain the approval transaction
        audit_resp = requests.get(f"{base_url}/audit/logs")
        logs = audit_resp.json()
        print(f"Fetched {len(logs)} audit log records.")
        assert len(logs) >= 3, "Should have at least 3 audit log records (2 creations + 1 approval)"
        
        # Check approval log entry
        approval_log = next((l for l in logs if l["result"] == "Approved"), None)
        assert approval_log is not None, "No approval event logged in audit trail"
        print(f"Approval Audit Log details: {approval_log}")

        print("\nAll Scenarios Passed Successfully!")

    finally:
        # Graceful shutdown of uvicorn
        print("Shutting down FastAPI server...")
        server_thread.shutdown()
        server_thread.join()

if __name__ == "__main__":
    run_tests()
