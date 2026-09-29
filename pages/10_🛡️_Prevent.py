"""
Active Threat Prevention & Intrusion Prevention System (IPS)
============================================================
Provides real-time threat mitigation, dynamic IP quarantine,
OS-level firewall rule injection, TCP session termination, and
automated policy enforcement.
"""

import sys, os, time
from datetime import datetime
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

# --- Global Alarm Check ---
try:
    from src.global_alarm import render_global_alarm
    render_global_alarm()
except Exception:
    pass
# --------------------------

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.dashboard_components import THEME, CINEMATIC_CSS
from src.storage import DatabaseManager
from src.ips_engine import IPSEngine

st.set_page_config(
    page_title="Prevent & Mitigate",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.markdown(CINEMATIC_CSS, unsafe_allow_html=True)

bg = THEME['bg']
card = THEME['card']
border = THEME['card_border']
text = THEME['text']
muted = THEME['text_dim']
green = THEME['neon_green']
blue = THEME['neon_blue']
purple = THEME['neon_purple']
red = THEME['neon_red']
amber = THEME['neon_orange']

# Initialize session state for IPS
if "ips" not in st.session_state:
    st.session_state.ips = IPSEngine()
if "db" not in st.session_state:
    st.session_state.db = DatabaseManager()

ips = st.session_state.ips
db = st.session_state.db
stats = ips.get_stats()
blocked_list = ips.get_blocked_list(active_only=True)

# ── Header ──
st.markdown(f"""
<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;">
    <div>
        <div style="font-family:'Orbitron',sans-serif;font-size:24px;font-weight:900;color:{red};letter-spacing:1px;">
            🛡️ ACTIVE INTRUSION PREVENTION (IPS)
        </div>
        <div style="font-family:'Inter',sans-serif;font-size:12px;color:{muted};margin-top:2px;">
            Autonomous Threat Neutralization · Firewall Rule Injection · Active TCP RST Termination
        </div>
    </div>
    <div style="text-align:right;font-family:'JetBrains Mono',monospace;font-size:12px;color:{muted};">
        {datetime.now().strftime('%H:%M:%S')}<br>
        <span style="font-size:10px;color:{green if stats['auto_block_enabled'] else amber};">
            {'● AUTONOMOUS SHIELD: ACTIVE' if stats['auto_block_enabled'] else '○ MANUAL MODE ONLY'}
        </span>
    </div>
</div>
<div style="height:1px;background:{border};margin:12px 0 20px 0;"></div>
""", unsafe_allow_html=True)

# ── Key Metric Cards ──
c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(f"""
    <div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:26px;font-weight:700;color:{red};">{len(blocked_list)}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};letter-spacing:1px;text-transform:uppercase;margin-top:4px;">BLOCKED ATTACKERS</div>
        <div style="font-size:10px;color:{red};margin-top:4px;">Active Quarantined IPs</div>
    </div>""", unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:26px;font-weight:700;color:{green};">{stats['packets_dropped']:,}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};letter-spacing:1px;text-transform:uppercase;margin-top:4px;">PACKETS DROPPED</div>
        <div style="font-size:10px;color:{green};margin-top:4px;">Neutralized at Line-Rate</div>
    </div>""", unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:26px;font-weight:700;color:{blue};">{len(blocked_list)}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};letter-spacing:1px;text-transform:uppercase;margin-top:4px;">FIREWALL RULES</div>
        <div style="font-size:10px;color:{blue};margin-top:4px;">OS Kernel Filter Synced</div>
    </div>""", unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:26px;font-weight:700;color:{purple};">{stats['tcp_rsts_sent']}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};letter-spacing:1px;text-transform:uppercase;margin-top:4px;">TCP RSTS DISPATCHED</div>
        <div style="font-size:10px;color:{purple};margin-top:4px;">Killed Active Sessions</div>
    </div>""", unsafe_allow_html=True)

with c5:
    st.markdown(f"""
    <div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:26px;font-weight:700;color:{amber};">{stats['block_threshold']*100:.0f}%</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};letter-spacing:1px;text-transform:uppercase;margin-top:4px;">AUTO-BLOCK TRIGGER</div>
        <div style="font-size:10px;color:{amber};margin-top:4px;">ML Confidence Threshold</div>
    </div>""", unsafe_allow_html=True)

st.markdown("""
<style>
@keyframes emergency-pulse {
    0% {
        box-shadow: 0 0 15px rgba(255, 51, 85, 0.4), inset 0 0 15px rgba(255, 51, 85, 0.2);
        border-color: #FF3355;
    }
    50% {
        box-shadow: 0 0 35px rgba(255, 51, 85, 0.9), inset 0 0 25px rgba(255, 51, 85, 0.5);
        border-color: #FFFFFF;
    }
    100% {
        box-shadow: 0 0 15px rgba(255, 51, 85, 0.4), inset 0 0 15px rgba(255, 51, 85, 0.2);
        border-color: #FF3355;
    }
}
.urgent-blinking-banner {
    background: rgba(255, 51, 85, 0.15);
    border: 2px solid #FF3355;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 24px;
    animation: emergency-pulse 1.2s infinite ease-in-out;
}
@keyframes target-card-pulse {
    0% { border-color: #FF3355; box-shadow: 0 0 10px rgba(255, 51, 85, 0.4); }
    50% { border-color: #00FF88; box-shadow: 0 0 25px rgba(0, 255, 136, 0.8); }
    100% { border-color: #FF3355; box-shadow: 0 0 10px rgba(255, 51, 85, 0.4); }
}
.highlighted-threat-card {
    animation: target-card-pulse 1.2s infinite ease-in-out !important;
    border: 2px solid #FF3355 !important;
}
</style>
""", unsafe_allow_html=True)

# ── Emergency Immediate Threat Banner (If arriving from Alarm / Prevent Button) ──
highlight_threat = st.session_state.get("highlight_prevent_threat")
highlight_ip = st.session_state.get("highlight_prevent_ip")

if highlight_threat and highlight_ip:
    h_src = highlight_ip
    h_dst = highlight_threat.get("destination_ip") or "10.0.0.1"
    h_type = highlight_threat.get("attack_type") or "Critical Cyber Threat"
    h_sev = str(highlight_threat.get("severity", "HIGH")).upper()
    h_score = float(highlight_threat.get("final_score", 0.85))
    h_port = highlight_threat.get("destination_port") or 80
    h_src_port = highlight_threat.get("source_port") or 1024

    st.markdown(f"""
    <div class="urgent-blinking-banner">
        <div style="display:flex;align-items:center;gap:16px;">
            <div style="font-size:38px;animation:pulse 1s infinite;">🚨</div>
            <div style="flex-grow:1;">
                <div style="font-family:'Orbitron',sans-serif;font-size:18px;font-weight:900;color:{red};letter-spacing:1px;">
                    IMMEDIATE THREAT DETECTED — ACTIVE PREVENTION REQUIRED!
                </div>
                <div style="color:{text};font-size:13px;margin-top:6px;">
                    Attacker IP: <b style="color:#FFFFFF;font-family:'JetBrains Mono',monospace;font-size:15px;background:rgba(255,51,85,0.3);padding:2px 8px;border-radius:4px;">{h_src}</b>
                    &nbsp;→&nbsp; Target Asset: <b style="color:{amber};font-family:'JetBrains Mono',monospace;">{h_dst}:{h_port}</b>
                    &nbsp;|&nbsp; Attack Category: <b style="color:{purple};">{h_type}</b>
                    &nbsp;|&nbsp; Confidence: <b style="color:{green};">{h_score*100:.1f}%</b>
                </div>
                <div style="font-size:11px;color:{muted};margin-top:4px;">
                    Select an immediate mitigation action below to neutralize this threat at the OS/Kernel level and tear down active sessions.
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_em1, col_em2, col_em3 = st.columns([2, 2, 1])
    with col_em1:
        if st.button(f"🚫 1-CLICK INSTANT FIREWALL BLOCK ({h_src})", key="btn_em_block", type="primary", use_container_width=True):
            res = ips.block_ip(
                ip_address=h_src,
                reason=f"Emergency IPS Neutralization: {h_type} (Score: {h_score*100:.1f}%)",
                action="FIREWALL_DROP",
                duration_minutes=120
            )
            st.session_state.highlight_prevent_threat = None
            st.session_state.highlight_prevent_ip = None
            st.success(f"✅ Threat Neutralized: {res['message']}")
            time.sleep(0.6)
            st.rerun()

    with col_em2:
        if st.button(f"⚡ INSTANT TCP RST KILL SESSION", key="btn_em_rst", type="primary", use_container_width=True):
            res = ips.send_tcp_reset(
                src_ip=h_src,
                dst_ip=h_dst,
                src_port=h_src_port,
                dst_port=h_port
            )
            st.success(f"✅ Session Terminated: {res['message']}")
            time.sleep(0.6)
            st.rerun()

    with col_em3:
        if st.button("✕ Dismiss Alert", key="btn_em_dismiss", type="secondary", use_container_width=True):
            st.session_state.highlight_prevent_threat = None
            st.session_state.highlight_prevent_ip = None
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

# ── Navigation Tabs ──
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "⚡ Live Threat Response & Quarantine",
    "✍️ Manual Block & Session Kill",
    "📋 Active Blocklist & Policy Table",
    "⚙️ Autonomous IPS Configuration",
    "📜 Multi-Platform Firewall Rules"
])

# ──────────────────────────────────────────────────────────────
# TAB 1: Live Threat Response & Quick Actions
# ──────────────────────────────────────────────────────────────
with tab1:
    st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-bottom:8px;">Recent High-Risk Detections &amp; Rapid Mitigation</div>', unsafe_allow_html=True)
    st.markdown(f'<div style="font-family:\'Inter\',sans-serif;font-size:11px;color:{muted};margin-bottom:16px;">Execute 1-click countermeasures against active threats detected by the ML &amp; Rule engines.</div>', unsafe_allow_html=True)

    recent_threats = db.get_recent_alerts(limit=10)
    high_threats = [a for a in recent_threats if str(a.get("severity", "")).lower() in ["high", "critical", "medium"]]

    if not high_threats:
        st.info("🟢 No active critical threats detected recently. Network baseline is secure.")
    else:
        for idx, threat in enumerate(high_threats[:6]):
            t_src = threat.get("source_ip") or "Unknown"
            t_dst = threat.get("destination_ip") or "10.0.0.1"
            t_type = threat.get("attack_type") or "Malicious Attack"
            t_sev = str(threat.get("severity", "HIGH")).upper()
            t_score = float(threat.get("final_score", 0.85))
            t_time = str(threat.get("timestamp", ""))[-8:] if threat.get("timestamp") else "--:--"

            is_already_blocked = ips.is_blocked(t_src)

            border_clr = red if t_sev == "HIGH" else amber
            badge_clr = red if t_sev == "HIGH" else amber

            is_highlighted = (t_src == highlight_ip)
            card_class = "glass-card highlighted-threat-card" if is_highlighted else "glass-card"
            badge_extra = f'<span style="background:{red};color:#FFF;padding:2px 8px;border-radius:4px;font-size:10px;margin-left:8px;animation:pulse 1s infinite;">🚨 REQUIRES ACTION</span>' if is_highlighted else ''

            st.markdown(f"""
            <div class="{card_class}" style="padding:14px;margin-bottom:10px;border-left:4px solid {border_clr};">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <span style="font-family:'Orbitron',sans-serif;font-size:13px;font-weight:700;color:{badge_clr};">
                            [{t_sev}] {t_type}
                        </span>
                        {badge_extra}
                        <span style="font-size:11px;color:{muted};margin-left:12px;font-family:'JetBrains Mono',monospace;">{t_time}</span>
                        <div style="font-size:12px;color:{text};margin-top:4px;">
                            Attacker: <b style="color:{blue};">{t_src}</b> &nbsp;→&nbsp; Target Asset: <b style="color:{amber};">{t_dst}</b> &nbsp;|&nbsp; Confidence: <b>{t_score*100:.1f}%</b>
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col_btn1, col_btn2, col_btn3 = st.columns([1.5, 1.5, 3])
            with col_btn1:
                if is_already_blocked:
                    st.button(f"🛡️ {t_src} (BLOCKED)", key=f"btn_blk_stat_{idx}", disabled=True, use_container_width=True)
                else:
                    if st.button(f"🚫 Block IP {t_src}", key=f"btn_blk_{idx}", use_container_width=True):
                        res = ips.block_ip(t_src, reason=f"Mitigated {t_type} threat", action="FIREWALL_DROP")
                        st.success(f"✅ {res['message']}")
                        time.sleep(0.5)
                        st.rerun()

            with col_btn2:
                if st.button(f"⚡ Kill TCP Session", key=f"btn_rst_{idx}", use_container_width=True):
                    res = ips.send_tcp_reset(
                        src_ip=t_src,
                        dst_ip=t_dst,
                        src_port=threat.get("source_port", 0),
                        dst_port=threat.get("destination_port", 80)
                    )
                    st.success(res["message"])
                    time.sleep(0.5)
                    st.rerun()

            with col_btn3:
                if is_already_blocked:
                    if st.button(f"🔓 Unblock {t_src}", key=f"btn_unblk_quick_{idx}", use_container_width=True):
                        ips.unblock_ip(t_src)
                        st.info(f"Released {t_src} from quarantine.")
                        time.sleep(0.5)
                        st.rerun()

# ──────────────────────────────────────────────────────────────
# TAB 2: Manual Enforcement & Session Kill
# ──────────────────────────────────────────────────────────────
with tab2:
    st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-bottom:8px;">Manual Threat Enforcement &amp; Quarantine Dispatch</div>', unsafe_allow_html=True)
    
    col_m1, col_m2 = st.columns(2)
    with col_m1:
        st.markdown(f"""
        <div class="glass-card" style="padding:16px;">
            <div style="font-family:'Orbitron',sans-serif;font-size:14px;color:{red};margin-bottom:12px;">🚫 Enforce IP Block &amp; Quarantine</div>
        """, unsafe_allow_html=True)
        
        manual_ip = st.text_input("Target IP Address to Block:", placeholder="e.g. 198.51.100.77", key="man_ip")
        manual_action = st.selectbox("Mitigation Action:", [
            "FIREWALL_DROP (Complete Inbound Drop)",
            "TCP_RST_ACTIVE (Session Reset Injection)",
            "RATE_LIMIT (Throttle to 50 pps)",
            "QUARANTINE_ISOLATE (Full Asset Isolation)"
        ], key="man_action")
        
        manual_duration = st.selectbox("Quarantine Duration:", [
            ("15 Minutes", 15),
            ("1 Hour", 60),
            ("6 Hours", 360),
            ("24 Hours", 1440),
            ("Permanent", 0)
        ], format_func=lambda x: x[0], key="man_dur")
        
        manual_reason = st.text_input("Reason / Threat Attribution:", value="Manual SOC Operator Quarantine", key="man_reason")
        
        if st.button("🛡️ ENFORCE BLOCK NOW", use_container_width=True, key="btn_enforce_manual"):
            if manual_ip:
                res = ips.block_ip(
                    ip_address=manual_ip,
                    reason=manual_reason,
                    action=manual_action.split(" ")[0],
                    duration_minutes=manual_duration[1]
                )
                if res["success"]:
                    st.success(f"✅ {res['message']} | Rule: `{res.get('rule_name')}`")
                else:
                    st.error(res["message"])
                time.sleep(0.5)
                st.rerun()
            else:
                st.warning("Please enter a valid IP address.")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_m2:
        st.markdown(f"""
        <div class="glass-card" style="padding:16px;">
            <div style="font-family:'Orbitron',sans-serif;font-size:14px;color:{purple};margin-bottom:12px;">⚡ On-Demand TCP Reset (RST) Injection</div>
            <div style="font-size:11px;color:{muted};margin-bottom:12px;">
                Forges raw bidirectional TCP RST packets with matching sequence numbers to instantly collapse active malicious TCP connections.
            </div>
        """, unsafe_allow_html=True)
        
        rst_src = st.text_input("Source IP (Attacker):", placeholder="192.168.1.150", key="rst_src_ip")
        rst_dst = st.text_input("Destination IP (Target):", placeholder="10.0.0.5", key="rst_dst_ip")
        rst_dport = st.number_input("Target Port:", min_value=1, max_value=65535, value=80, key="rst_port")
        
        if st.button("⚡ TRANSMIT TCP RST KILL PACKET", use_container_width=True, key="btn_send_rst"):
            if rst_src and rst_dst:
                res = ips.send_tcp_reset(src_ip=rst_src, dst_ip=rst_dst, dst_port=rst_dport)
                st.success(res["message"])
                time.sleep(0.5)
                st.rerun()
            else:
                st.warning("Please provide both source and destination IPs.")
        st.markdown("</div>", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────
# TAB 3: Active Blocklist & Policy Table
# ──────────────────────────────────────────────────────────────
with tab3:
    st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-bottom:8px;">Active Blocklist &amp; Quarantine Audit Table</div>', unsafe_allow_html=True)
    
    if not blocked_list:
        st.info("No active blocked IPs in the quarantine database.")
    else:
        df_blocked = pd.DataFrame(blocked_list)
        display_cols = ["ip_address", "action", "reason", "blocked_at", "expires_at", "packets_dropped", "rule_name"]
        df_show = df_blocked[[c for c in display_cols if c in df_blocked.columns]]
        df_show.columns = ["IP Address", "Action", "Reason", "Blocked At", "Expires At", "Drops", "Firewall Rule"]
        
        st.dataframe(df_show, use_container_width=True, hide_index=True)
        
        st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:13px;color:{text};margin-top:16px;">Quick Release / Unblock:</div>', unsafe_allow_html=True)
        unblk_cols = st.columns(min(len(blocked_list), 4))
        for i, b in enumerate(blocked_list[:4]):
            with unblk_cols[i % len(unblk_cols)]:
                if st.button(f"🔓 Release {b['ip_address']}", key=f"btn_unblk_tab3_{b['id']}", use_container_width=True):
                    ips.unblock_ip(b['ip_address'])
                    st.success(f"Released {b['ip_address']}")
                    time.sleep(0.5)
                    st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("📜 View Full IPS Audit & Event History", expanded=False):
        audit_logs = ips.get_audit_logs(limit=25)
        if audit_logs:
            df_audit = pd.DataFrame(audit_logs)
            st.dataframe(df_audit, use_container_width=True, hide_index=True)
        else:
            st.caption("No audit events logged yet.")

# ──────────────────────────────────────────────────────────────
# TAB 4: Autonomous IPS Policy Configuration
# ──────────────────────────────────────────────────────────────
with tab4:
    st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-bottom:8px;">Autonomous Prevention Policy &amp; Thresholds</div>', unsafe_allow_html=True)
    st.markdown(f'<div style="font-family:\'Inter\',sans-serif;font-size:11px;color:{muted};margin-bottom:16px;">Configure automated defense reflexes without requiring human SOC analyst intervention.</div>', unsafe_allow_html=True)

    col_p1, col_p2 = st.columns(2)
    with col_p1:
        st.markdown(f"""
        <div class="glass-card">
            <div style="font-family:'Orbitron',sans-serif;font-size:14px;color:{green};margin-bottom:12px;">🛡️ Autonomous Defense Reflexes</div>
        """, unsafe_allow_html=True)
        
        auto_blk = st.checkbox("Enable Autonomous Threat Neutralization", value=ips._auto_block_enabled, key="cfg_autoblk")
        auto_rst = st.checkbox("Auto-Inject TCP RST on High-Risk Sessions", value=ips._auto_rst_enabled, key="cfg_autorst")
        os_sync = st.checkbox("Sync Rules with Host OS Firewall (Netsh / iptables)", value=ips._os_firewall_sync, key="cfg_ossync")
        
        th_slider = st.slider("Auto-Block Trigger Threshold (Score):", 0.50, 1.00, float(ips._block_threshold), 0.05, key="cfg_th_slider")
        st.caption(f"Threats with ML Confidence &gt;= {th_slider*100:.0f}% or High/Critical severity will be immediately blocked.")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_p2:
        st.markdown(f"""
        <div class="glass-card">
            <div style="font-family:'Orbitron',sans-serif;font-size:14px;color:{blue};margin-bottom:12px;">⚡ Rate Limiting &amp; Quarantine Defaults</div>
        """, unsafe_allow_html=True)
        
        def_duration = st.slider("Default Quarantine Duration (Minutes):", 10, 720, 120, 10, key="cfg_def_dur")
        rate_limit = st.slider("DDoS Volumetric Threshold (Packets/Sec):", 50, 2000, 250, 50, key="cfg_rate_limit")
        st.caption("Packets exceeding the volumetric threshold trigger instant rate-limiting drops.")
        st.markdown("</div>", unsafe_allow_html=True)

    if st.button("💾 SAVE IPS POLICIES", use_container_width=True, key="btn_save_ips_pol"):
        ips._auto_block_enabled = auto_blk
        ips._auto_rst_enabled = auto_rst
        ips._os_firewall_sync = os_sync
        ips._block_threshold = th_slider
        st.success("✅ IPS Prevention Policies saved and activated successfully!")

# ──────────────────────────────────────────────────────────────
# TAB 5: Multi-Platform Firewall Rules Generator
# ──────────────────────────────────────────────────────────────
with tab5:
    st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-bottom:8px;">Enterprise Firewall &amp; WAF Rule Deployment</div>', unsafe_allow_html=True)
    st.markdown(f'<div style="font-family:\'Inter\',sans-serif;font-size:11px;color:{muted};margin-bottom:16px;">Export active quarantine rules to your edge infrastructure (Windows Firewall, Linux iptables, Cisco ACL, Nginx WAF).</div>', unsafe_allow_html=True)

    rules = ips.generate_firewall_rules()

    fw_tab1, fw_tab2, fw_tab3, fw_tab4 = st.tabs([
        "🪟 Windows PowerShell",
        "🐧 Linux iptables / UFW",
        "🌐 Cisco IOS ACL",
        "🛡️ Nginx WAF Deny"
    ])

    with fw_tab1:
        st.code(rules["powershell"], language="powershell")
        st.download_button("📥 Download Windows Script (.ps1)", rules["powershell"], "soc_nids_firewall_rules.ps1", "text/plain", use_container_width=True)

    with fw_tab2:
        st.code(rules["iptables"], language="bash")
        st.download_button("📥 Download Linux Script (.sh)", rules["iptables"], "soc_nids_iptables_rules.sh", "text/plain", use_container_width=True)

    with fw_tab3:
        st.code(rules["cisco"], language="text")
        st.download_button("📥 Download Cisco ACL (.txt)", rules["cisco"], "soc_nids_cisco_acl.txt", "text/plain", use_container_width=True)

    with fw_tab4:
        st.code(rules["nginx"], language="nginx")
        st.download_button("📥 Download Nginx Rules (.conf)", rules["nginx"], "soc_nids_nginx_block.conf", "text/plain", use_container_width=True)

st.markdown("---")
st.markdown(f"""
<div style="text-align:center;padding:12px;color:{muted};font-size:11px;font-family:'JetBrains Mono',monospace;">
    SOC-NIDS // ACTIVE INTRUSION PREVENTION (IPS) SUBSYSTEM — REAL-TIME RISK MITIGATION
</div>
""", unsafe_allow_html=True)
