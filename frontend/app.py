# frontend/app.py
import streamlit as st
import requests
import datetime
import textwrap
from typing import Dict, Any, List

# Set page configuration with a modern dark theme and custom title
st.set_page_config(
    page_title="AccessSafe — Azure RBAC Lifecycle Workspace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

API_URL = "http://127.0.0.1:8080"

def render_html(html_str: str):
    """Render HTML after removing leading/trailing spaces from each line to avoid Streamlit/Markdown code block issues."""
    cleaned = "\n".join(line.strip() for line in html_str.splitlines())
    st.markdown(cleaned, unsafe_allow_html=True)

# --- Inject Premium Custom CSS (Glassmorphism, Dark Theme, Elegant Font) ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Inter:wght@300;400;500;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Outfit', sans-serif;
        font-weight: 600;
        color: #ffffff;
    }
    
    /* Premium Sidebar Styling */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a 0%, #1e1b4b 100%);
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    /* Card design with glassmorphism */
    .glass-card {
        background: rgba(15, 23, 42, 0.9) !important;
        border: 1px solid rgba(99, 102, 241, 0.3) !important;
        border-radius: 12px;
        padding: 24px;
        backdrop-filter: blur(10px);
        margin-bottom: 20px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .glass-card:hover {
        border-color: rgba(99, 102, 241, 0.4);
        box-shadow: 0 8px 30px rgba(99, 102, 241, 0.15);
        transform: translateY(-2px);
    }
    
    /* Stats Panel */
    .metric-value {
        font-size: 32px;
        font-weight: 700;
        font-family: 'Outfit', sans-serif;
        color: #ffffff;
        margin-top: 4px;
    }
    
    .metric-label {
        font-size: 14px;
        font-weight: 500;
        color: #94a3b8;
    }
    
    /* Risk Badges */
    .risk-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        margin-bottom: 10px;
    }
    
    .risk-critical {
        background: rgba(239, 68, 68, 0.15);
        color: rgb(239, 68, 68);
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    
    .risk-high {
        background: rgba(249, 115, 22, 0.15);
        color: rgb(249, 115, 22);
        border: 1px solid rgba(249, 115, 22, 0.3);
    }
    
    .risk-medium {
        background: rgba(234, 179, 8, 0.15);
        color: rgb(234, 179, 8);
        border: 1px solid rgba(234, 179, 8, 0.3);
    }
    
    .risk-low {
        background: rgba(59, 130, 246, 0.15);
        color: rgb(59, 130, 246);
        border: 1px solid rgba(59, 130, 246, 0.3);
    }

    .risk-needs_review {
        background: rgba(168, 85, 247, 0.15);
        color: rgb(168, 85, 247);
        border: 1px solid rgba(168, 85, 247, 0.3);
    }
    
    /* Comparison UI */
    .compare-container {
        display: flex;
        align-items: center;
        gap: 15px;
        margin: 10px 0;
    }
    .compare-box {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 8px;
        padding: 8px 16px;
        min-width: 150px;
        text-align: center;
    }
    .arrow-icon {
        font-size: 24px;
        color: #6366f1;
    }
    
    /* Status indicators */
    .status-pending {
        color: #ea580c;
        font-weight: 600;
    }
    .status-approved {
        color: #16a34a;
        font-weight: 600;
    }
    .status-rejected {
        color: #dc2626;
        font-weight: 600;
    }
    </style>
""", unsafe_allow_html=True)

# --- Fetch Data Helper Functions ---

def fetch_stats() -> Dict[str, int]:
    try:
        r = requests.get(f"{API_URL}/dashboard/stats")
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {"pending_approvals": 0, "unresolved_risks": 0, "total_requests": 0, "total_audit_logs": 0}

def fetch_records(status=None, source=None) -> List[Dict[str, Any]]:
    try:
        params = {}
        if status: params["status"] = status
        if source: params["source"] = source
        r = requests.get(f"{API_URL}/records", params=params)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []

# --- Navigation Sidebar ---
with st.sidebar:
    st.markdown("<h2 style='text-align: center; color: #6366f1; margin-bottom: 30px;'>🛡️ AccessSafe</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #94a3b8; font-size: 14px; margin-top: -25px; margin-bottom: 35px;'>Azure RBAC AI Workstation</p>", unsafe_allow_html=True)
    
    page = st.radio(
        "Navigation",
        ["Dashboard", "New Request", "Risk Scan", "Approval Queue", "Audit Log"],
        label_visibility="collapsed"
    )
    
    st.markdown("<div style='height: 180px;'></div>", unsafe_allow_html=True)
    st.markdown("<div style='border-top: 1px solid rgba(255,255,255,0.05); padding-top: 20px; font-size: 12px; color: #64748b;'>👤 Role: Administrator</div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size: 12px; color: #64748b;'>🔒 Sandbox Mode (Local JSON)</div>", unsafe_allow_html=True)

# ==========================================
# PAGE 1: DASHBOARD
# ==========================================
if page == "Dashboard":
    st.title("🛡️ AccessSafe Dashboard")
    st.markdown("Security-first posture and lifecycle dashboard for Azure RBAC recommendations.")
    
    # Fetch current metrics
    stats = fetch_stats()
    
    # 4 Indicator Cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        render_html(f"""
            <div class="glass-card" style="border-left: 4px solid #6366f1;">
                <div class="metric-label">Pending Approvals</div>
                <div class="metric-value">{stats['pending_approvals']}</div>
            </div>
        """)
        
    with col2:
        render_html(f"""
            <div class="glass-card" style="border-left: 4px solid #f97316;">
                <div class="metric-label">Active Risks</div>
                <div class="metric-value">{stats['unresolved_risks']}</div>
            </div>
        """)
        
    with col3:
        render_html(f"""
            <div class="glass-card" style="border-left: 4px solid #10b981;">
                <div class="metric-label">Total Requests</div>
                <div class="metric-value">{stats['total_requests']}</div>
            </div>
        """)
        
    with col4:
        render_html(f"""
            <div class="glass-card" style="border-left: 4px solid #8b5cf6;">
                <div class="metric-label">Total Audit Logs</div>
                <div class="metric-value">{stats['total_audit_logs']}</div>
            </div>
        """)

    st.markdown("### 🔔 Recent Activity (Latest 5)")
    
    records = fetch_records()[:5]
    if records:
        for r in records:
            source_lbl = "New Request 📝" if r["source"] == "new_request" else "Risk Remediation 🛡️"
            status_class = f"status-{r['status'].lower()}"
            
            render_html(f"""
                <div class="glass-card" style="padding: 16px; margin-bottom: 12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <span style="font-weight: 600; color: #ffffff; font-size: 16px;">{r['subject']}</span>
                            <span style="font-size: 12px; color: #94a3b8; margin-left: 15px;">({source_lbl})</span>
                        </div>
                        <div>
                            <span class="risk-badge risk-{r['risk_level'].lower()}" style="margin-bottom: 0;">Risk: {r['risk_level']}</span>
                            <span class="{status_class}" style="margin-left: 15px; font-size: 14px;">{r['status']}</span>
                        </div>
                    </div>
                    <div style="margin-top: 8px; font-size: 14px; color: #cbd5e1;">
                        <strong>Recommended role:</strong> {r['recommended_role']} @ <code>{r['recommended_scope']}</code> 
                        {f"| <strong>Reason:</strong> {r['reason']}" if r['reason'] else ""}
                    </div>
                    <div style="margin-top: 6px; font-size: 11px; color: #64748b;">
                        Created at: {r['created_at'][:19]}
                    </div>
                </div>
            """)
    else:
        st.info("No activity records found.")

# ==========================================
# PAGE 2: NEW REQUEST
# ==========================================
elif page == "New Request":
    st.title("📝 Submit New Permission Request")
    st.markdown("Submit a natural language permission request. The interpreter and recommendation agents will produce a least-privilege plan.")
    
    with st.container():
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        nl_input = st.text_area(
            "Access Request (Natural Language):",
            placeholder="e.g. Carol needs view access to the development environment to inspect resource groups and logs, temporary only, no production access."
        )
        
        submit_btn = st.button("Submit Request", type="primary")
        st.markdown('</div>', unsafe_allow_html=True)
        
    if submit_btn:
        if not nl_input.strip():
            st.warning("Please provide a request description.")
        else:
            with st.spinner("Analyzing request and building minimum-privilege recommendation..."):
                try:
                    r = requests.post(f"{API_URL}/requests/submit", json={"request_text": nl_input})
                    if r.status_code == 200:
                        plan = r.json()
                        st.success("Recommendation Plan Generated & Written to Queue!")
                        
                        # Show Recommendation details in beautiful card
                        st.markdown("### 🛡️ Recommended Access Plan")
                        
                        risk_level = plan["risk_level"]
                        prod_access = "YES ⚠️ (Production)" if (plan.get("production_access") == 1 or plan.get("production_access") is True) else "NO ❌ (Non-prod)"
                        
                        subject_name = plan.get("subject") or "Alice Chen"
                        duration_days_val = plan.get("duration_days") or 90
                        
                        render_html(f"""
                            <div class="glass-card" style="border-top: 4px solid #6366f1;">
                                <div class="risk-badge risk-{risk_level.lower()}">Risk Level: {risk_level}</div>
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 15px;">
                                    <div>
                                        <p style="color: #94a3b8; margin-bottom: 2px;">Subject Name</p>
                                        <h4 style="margin: 0; color: #ffffff;">{subject_name}</h4>
                                    </div>
                                    <div>
                                        <p style="color: #94a3b8; margin-bottom: 2px;">Production Access</p>
                                        <h4 style="margin: 0; color: #ffffff;">{prod_access}</h4>
                                    </div>
                                    <div>
                                        <p style="color: #94a3b8; margin-bottom: 2px;">Recommended Role</p>
                                        <h4 style="margin: 0; color: #10b981;">{plan.get('recommended_role', 'Reader')}</h4>
                                    </div>
                                    <div>
                                        <p style="color: #94a3b8; margin-bottom: 2px;">Recommended Scope</p>
                                        <h4 style="margin: 0; color: #10b981;">{plan.get('recommended_scope', 'rg-development')}</h4>
                                    </div>
                                    <div>
                                        <p style="color: #94a3b8; margin-bottom: 2px;">Duration (Days)</p>
                                        <h4 style="margin: 0; color: #ffffff;">{duration_days_val}</h4>
                                    </div>
                                    <div>
                                        <p style="color: #94a3b8; margin-bottom: 2px;">Required Approvers</p>
                                        <h4 style="margin: 0; color: #ffffff;">{plan.get('approvers', 'Resource Owner')}</h4>
                                    </div>
                                </div>
                                <div style="margin-top: 25px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 15px;">
                                    <p style="color: #94a3b8; margin-bottom: 2px;">Agent Justification Reasoning</p>
                                    <p style="color: #cbd5e1; font-size: 15px; line-height: 1.5; margin: 0;">{plan.get('reason', '')}</p>
                                </div>
                                <div style="margin-top: 20px; font-size: 12px; color: #e2e8f0; background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.2); padding: 10px; border-radius: 6px;">
                                    ⚠️ <strong>Status: Pending Approval</strong>. This request has been saved to the Approval Queue. Admin authorization is required to proceed.
                                </div>
                            </div>
                        """)
                    else:
                        st.error(f"Error submitting request: {r.text}")
                except Exception as e:
                    st.error(f"Failed to connect to API: {e}")

# ==========================================
# PAGE 3: RISK SCAN
# ==========================================
elif page == "Risk Scan":
    st.title("🔍 Security Risk Scan")
    st.markdown("Scan active Azure assignments against security policies to identify excessive privileges or obsolete access.")
    
    scan_btn = st.button("Trigger Risk Scan", type="primary")
    
    # Store or fetch scan results in session state to maintain state
    if scan_btn or "scan_results" in st.session_state:
        if scan_btn or "scan_results" not in st.session_state:
            with st.spinner("Scanning role assignments and matching with user metadata via MCP server..."):
                try:
                    r = requests.get(f"{API_URL}/risk/scan")
                    if r.status_code == 200:
                        st.session_state["scan_results"] = r.json()
                    else:
                        st.error("Failed to run risk scan.")
                        st.session_state["scan_results"] = []
                except Exception as e:
                    st.error(f"Connection error: {e}")
                    st.session_state["scan_results"] = []
        
        findings = st.session_state["scan_results"]
        
        if not findings:
            st.success("Scan completed: No risk findings detected! ✅")
        else:
            st.markdown(f"Found **{len(findings)}** risk findings. Remediation is required.")
            
            # Fetch all existing records to determine processing status of findings
            existing_remediations = fetch_records(source="risk_scan")
            
            # Helper to check record status in DB
            def get_remediation_status(subject: str, current_role: str, current_scope: str) -> str:
                # Find matching record in DB
                for rec in existing_remediations:
                    # Match by subject and scope
                    if (rec["subject"] == subject and 
                        rec["current_role"] == current_role and 
                        rec["current_scope"] == current_scope):
                        return rec["status"]
                return "Not_Started"
            
            # Display risk findings as cards
            for idx, f in enumerate(findings):
                risk_lvl = f["risk_level"]
                subject = f["subject"]
                
                # Check status
                db_status = get_remediation_status(subject, f["current_role"], f["current_scope"])
                
                render_html(f"""
                    <div class="glass-card" style="border-left: 5px solid {'#ef4444' if risk_lvl=='Critical' else '#f97316'}; padding-bottom: 15px;">
                        <div style="display:flex; justify-content:space-between; align-items:start;">
                            <div>
                                <span class="risk-badge risk-{risk_lvl.lower()}">Risk Level: {risk_lvl}</span>
                                <h3 style="margin: 8px 0 2px 0;">{subject}</h3>
                                <p style="color: #94a3b8; font-size: 14px; margin: 0;">User ID: <code>{f['user_id']}</code> | Role Assignment: <code>{f['current_role']}</code> @ <code>{f['current_scope']}</code></p>
                            </div>
                            <div>
                                {f'<span style="background: rgba(22, 163, 74, 0.15); color: #16a34a; border: 1px solid rgba(22, 163, 74, 0.3); padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600;">Resolved</span>' if db_status == 'Approved' 
                                  else f'<span style="background: rgba(234, 88, 12, 0.15); color: #ea580c; border: 1px solid rgba(234, 88, 12, 0.3); padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600;">Pending Approval</span>' if db_status == 'Pending'
                                  else f'<span style="background: rgba(220, 38, 38, 0.15); color: #dc2626; border: 1px solid rgba(220, 38, 38, 0.3); padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600;">Rejected</span>' if db_status == 'Rejected'
                                  else ''}
                            </div>
                        </div>
                        <div style="margin-top: 15px; padding: 10px; background: rgba(0, 0, 0, 0.15); border-radius: 6px; border: 1px solid rgba(255,255,255,0.03);">
                            <strong>Risk Reason:</strong> {f['risk_reason']}
                        </div>
                        <div style="margin-top: 10px; font-size: 14px;">
                            <strong>Recommended Remediation:</strong> {f.get('recommendation', 'Downgrade role to least privilege')} 
                            <br/>
                            <strong>Downgrade Scope:</strong> <code>{f['recommended_scope']}</code> | <strong>Downgrade Role:</strong> <code>{f['recommended_role']}</code> | <strong>Duration:</strong> {f['duration_days']} days
                        </div>
                    </div>
                """)
                
                # Show remediation button if not started
                if db_status == "Not_Started" or db_status == "Rejected":
                    if st.button(f"Generate Remediation Plan for {subject}", key=f"remed-{idx}"):
                        try:
                            res = requests.post(f"{API_URL}/risk/remediate", json={"finding": f})
                            if res.status_code == 200:
                                st.success(f"Remediation plan generated for {subject}! Request entered the Approval Queue.")
                                st.rerun()
                            else:
                                st.error("Failed to generate plan.")
                        except Exception as e:
                            st.error(f"Error: {e}")

# ==========================================
# PAGE 4: APPROVAL QUEUE
# ==========================================
elif page == "Approval Queue":
    st.title("📥 Approval Queue")
    st.markdown("Review access request and risk remediation plans. Senior administrative approval is required before local records update.")
    
    pending_records = fetch_records(status="Pending")
    
    # Sort: Critical -> High -> Medium -> Low
    risk_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    pending_records.sort(key=lambda r: risk_weights.get(r["risk_level"], 0), reverse=True)
    
    if not pending_records:
        st.success("No pending items in approval queue! Good job. ✨")
    else:
        st.markdown(f"Currently **{len(pending_records)}** items pending authorization:")
        
        for idx, rec in enumerate(pending_records):
            rec_id = rec["id"]
            risk_lvl = rec["risk_level"]
            source_lbl = "NEW REQUEST 📝" if rec["source"] == "new_request" else "RISK SCAN FINDING 🔍"
            
            with st.container(border=True):
                # Header row: Subject & Risk Badge
                col_hdr1, col_hdr2 = st.columns([2, 1])
                with col_hdr1:
                    st.markdown(f"### Subject: {rec['subject']}")
                with col_hdr2:
                    risk_badge_colors = {
                        "Critical": "🔴 **Critical Risk**",
                        "High": "🟠 **High Risk**",
                        "Medium": "🟡 **Medium Risk**",
                        "Low": "🔵 **Low Risk**"
                    }
                    st.markdown(f"<div style='text-align: right;'>{risk_badge_colors.get(risk_lvl, risk_lvl)}</div>", unsafe_allow_html=True)
                
                st.markdown(f"**Type:** `{source_lbl}` | **Plan ID:** `{rec_id}` | **Created At:** `{rec['created_at'][:19].replace('T', ' ')}` UTC")
                
                st.markdown("---")
                
                # Transitions
                col_transition1, col_transition2 = st.columns(2)
                with col_transition1:
                    st.markdown("**Role Transition**")
                    current_r = rec['current_role'] if rec['current_role'] else 'None (New)'
                    recommended_r = rec['recommended_role'] if rec['recommended_role'] else 'REVOKE'
                    st.markdown(f"`{current_r}` ➔ **`{recommended_r}`**")
                with col_transition2:
                    st.markdown("**Scope Transition**")
                    current_s = rec['current_scope'] if rec['current_scope'] else 'None (New)'
                    recommended_s = rec['recommended_scope']
                    st.markdown(f"`{current_s}` ➔ **`{recommended_s}`**")
                
                st.markdown("---")
                
                # Info columns
                col_info1, col_info2, col_info3 = st.columns(3)
                with col_info1:
                    prod_access_str = "Yes ⚠️ (Production)" if rec['production_access'] == 1 else "No ❌ (Non-prod)"
                    st.markdown(f"**Production Access:** {prod_access_str}")
                with col_info2:
                    st.markdown(f"**Duration:** {rec['duration_days']} Days")
                with col_info3:
                    st.markdown(f"**Required Approvers:** `{rec['approvers']}`")
                
                st.markdown("---")
                
                # Recommendation justification
                st.markdown("**Recommendation Justification**")
                st.info(rec['reason'])
            
            # Action Buttons
            col_app, col_rej = st.columns([1, 4])
            with col_app:
                if st.button("Approve ✅", key=f"app-{rec_id}"):
                    try:
                        res = requests.post(
                            f"{API_URL}/records/{rec_id}/decide",
                            json={"status": "Approved", "operator": "Admin"}
                        )
                        if res.status_code == 200:
                            st.success(f"Record {rec_id} Approved!")
                            st.rerun()
                        else:
                            st.error("Failed to approve record.")
                    except Exception as e:
                        st.error(f"Error: {e}")
                        
            with col_rej:
                # Custom rejection dialog using an expander to ask for reason
                with st.expander("Reject ❌"):
                    reject_reason = st.text_input("Enter rejection reason:", key=f"txt-rej-{rec_id}")
                    if st.button("Confirm Reject", key=f"btn-rej-{rec_id}"):
                        if not reject_reason.strip():
                            st.warning("Please provide a rejection reason.")
                        else:
                            try:
                                res = requests.post(
                                    f"{API_URL}/records/{rec_id}/decide",
                                    json={"status": "Rejected", "operator": "Admin", "reject_reason": reject_reason}
                                )
                                if res.status_code == 200:
                                    st.success(f"Record {rec_id} Rejected.")
                                    st.rerun()
                                else:
                                    st.error("Failed to reject record.")
                            except Exception as e:
                                st.error(f"Error: {e}")

# ==========================================
# PAGE 5: AUDIT LOG
# ==========================================
elif page == "Audit Log":
    st.title("📊 Security Audit Log")
    st.markdown("Immutable record of administrative decisions, risk scan remediations, and agent determinations.")
    
    # Filter controls in columns
    col_type, col_risk, col_search = st.columns(3)
    
    with col_type:
        event_filter = st.selectbox("Event Type Filter", ["All", "ACCESS_REQUEST", "RISK_REMEDIATION"])
        
    with col_risk:
        risk_filter = st.selectbox("Risk Level Filter", ["All", "Critical", "High", "Medium", "Low"])
        
    with col_search:
        search_query = st.text_input("Search (Subject, Operator, Content)")
        
    # Build request params
    params = {}
    if event_filter != "All":
        params["event_type"] = event_filter
    if risk_filter != "All":
        params["risk_level"] = risk_filter
    if search_query.strip():
        params["search"] = search_query.strip()
        
    try:
        r = requests.get(f"{API_URL}/audit/logs", params=params)
        if r.status_code == 200:
            logs = r.json()
            
            if not logs:
                st.info("No audit logs matched the filters.")
            else:
                # Build audit log grid
                st.markdown(f"Showing **{len(logs)}** log entries:")
                
                # HTML Table for custom premium display
                table_html = """
                <table style="width:100%; border-collapse: collapse; font-size:14px; background: rgba(255,255,255,0.01);">
                    <thead>
                        <tr style="border-bottom: 2px solid rgba(255,255,255,0.1); text-align:left; color:#94a3b8;">
                            <th style="padding:12px;">Time</th>
                            <th style="padding:12px;">Type</th>
                            <th style="padding:12px;">Subject</th>
                            <th style="padding:12px;">Action</th>
                            <th style="padding:12px;">Result</th>
                            <th style="padding:12px;">Operator</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                
                for log in logs:
                    timestamp = log["timestamp"][:19].replace("T", " ")
                    status_class = f"status-{log['result'].lower()}" if log['result'] else ""
                    
                    table_html += f"""
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); hover: background-color: rgba(255,255,255,0.02);">
                            <td style="padding:12px; color:#e2e8f0; white-space:nowrap;">{timestamp}</td>
                            <td style="padding:12px; color:#cbd5e1;"><code>{log['event_type']}</code></td>
                            <td style="padding:12px; font-weight:600; color:#ffffff;">{log['subject']}</td>
                            <td style="padding:12px; color:#cbd5e1; font-size:13px;">{log['action']}</td>
                            <td style="padding:12px;" class="{status_class}">{log['result']}</td>
                            <td style="padding:12px; color:#94a3b8;">{log['operator']}</td>
                        </tr>
                    """
                    
                table_html += "</tbody></table>"
                st.markdown(table_html, unsafe_allow_html=True)
        else:
            st.error("Failed to load audit logs from API.")
    except Exception as e:
        st.error(f"Error fetching audit logs: {e}")
