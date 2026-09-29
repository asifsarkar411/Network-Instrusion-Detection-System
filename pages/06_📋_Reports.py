import sys, os
from datetime import datetime
import streamlit as st

# --- Global Alarm Check ---
try:
    from src.global_alarm import render_global_alarm
    render_global_alarm()
except Exception:
    pass
# --------------------------

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.dashboard_components import THEME, CINEMATIC_CSS
from src.storage import DatabaseManager
from src.report_generator import generate_report

st.set_page_config(page_title="Reports", page_icon="📋", layout="wide")
st.markdown(CINEMATIC_CSS, unsafe_allow_html=True)

if "db" not in st.session_state:
    st.session_state.db = DatabaseManager()

bg = THEME['bg']; border = THEME['card_border']; text = THEME['text']
muted = THEME['text_dim']; green = THEME['neon_green']; blue = THEME['neon_blue']
red = THEME['neon_red']; amber = THEME['neon_orange']

st.markdown(f"""
<div style="font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;color:{text};">📋 REPORTS &amp; EXPORT</div>
<div style="font-family:'Inter',sans-serif;font-size:11px;color:{muted};margin-bottom:16px;">Executive summaries · PDF reports · Data exports · Database metrics</div>
<div style="height:1px;background:{border};margin-bottom:16px;"></div>
""", unsafe_allow_html=True)

# Session summary
dc = st.session_state.db.get_alert_count(since_minutes=1440)
total = dc.get("total", 0)
by_sev = dc.get("by_severity", {})
by_type = dc.get("by_type", {})

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""<div class="glass-card" style="text-align:center;">
        <div style="font-family:'Orbitron',sans-serif;font-size:32px;color:{blue};">{total}</div>
        <div style="font-family:'Inter',sans-serif;font-size:10px;color:{muted};">TOTAL ALERTS (24H)</div></div>""", unsafe_allow_html=True)
with c2:
    high = sum(v for k, v in by_sev.items() if str(k).lower() in ["high", "critical"])
    st.markdown(f"""<div class="glass-card" style="text-align:center;">
        <div style="font-family:'Orbitron',sans-serif;font-size:32px;color:{red};">{high}</div>
        <div style="font-family:'Inter',sans-serif;font-size:10px;color:{muted};">CRITICAL/HIGH</div></div>""", unsafe_allow_html=True)
with c3:
    med = sum(v for k, v in by_sev.items() if str(k).lower() == "medium")
    st.markdown(f"""<div class="glass-card" style="text-align:center;">
        <div style="font-family:'Orbitron',sans-serif;font-size:32px;color:{amber};">{med}</div>
        <div style="font-family:'Inter',sans-serif;font-size:10px;color:{muted};">MEDIUM</div></div>""", unsafe_allow_html=True)
with c4:
    low = sum(v for k, v in by_sev.items() if str(k).lower() == "low")
    st.markdown(f"""<div class="glass-card" style="text-align:center;">
        <div style="font-family:'Orbitron',sans-serif;font-size:32px;color:{green};">{low}</div>
        <div style="font-family:'Inter',sans-serif;font-size:10px;color:{muted};">LOW</div></div>""", unsafe_allow_html=True)

# Export & PDF Section
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:24px;margin-bottom:12px;">Generate &amp; Export Reports</div>', unsafe_allow_html=True)

ra = st.session_state.db.get_recent_alerts(limit=500)

exp_col1, exp_col2 = st.columns(2)

with exp_col1:
    st.markdown(f"""
    <div class="glass-card" style="padding:16px;min-height:160px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:14px;color:{blue};margin-bottom:8px;">📄 Executive PDF Report</div>
        <div style="font-family:'Inter',sans-serif;font-size:11px;color:{muted};margin-bottom:16px;">
            Compiles executive metrics, threat breakdowns, and classification summaries into a formatted PDF document.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    gen_btn = st.button("🖨️ Generate Professional PDF Report", use_container_width=True, key="btn_gen_pdf")
    if gen_btn:
        with st.spinner("Generating security report..."):
            try:
                pdf_path = generate_report(ra or [])
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
                st.session_state["cached_pdf"] = {
                    "bytes": pdf_bytes,
                    "filename": os.path.basename(pdf_path),
                    "path": pdf_path,
                }
                st.success(f"✅ Report ready: {os.path.basename(pdf_path)}")
            except Exception as e:
                st.error(f"Failed to generate PDF: {e}")

    if "cached_pdf" in st.session_state and st.session_state["cached_pdf"]:
        st.download_button(
            label=f"📥 Download {st.session_state['cached_pdf']['filename']}",
            data=st.session_state["cached_pdf"]["bytes"],
            file_name=st.session_state["cached_pdf"]["filename"],
            mime="application/pdf",
            use_container_width=True,
            key="dl_pdf_btn",
        )

with exp_col2:
    st.markdown(f"""
    <div class="glass-card" style="padding:16px;min-height:160px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:14px;color:{green};margin-bottom:8px;">💾 Raw Telemetry &amp; Alerts</div>
        <div style="font-family:'Inter',sans-serif;font-size:11px;color:{muted};margin-bottom:16px;">
            Export raw detected alerts data for SIEM integration or further security analysis.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    c_csv, c_json = st.columns(2)
    if ra:
        df = pd.DataFrame(ra)
        with c_csv:
            st.download_button(
                "📥 Download CSV",
                df.to_csv(index=False),
                f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "text/csv",
                use_container_width=True,
            )
        with c_json:
            st.download_button(
                "📥 Download JSON",
                df.to_json(orient="records", indent=2),
                f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json",
                use_container_width=True,
            )
    else:
        with c_csv:
            st.download_button("📥 Download CSV", "timestamp,attack_type,severity,score\n", "empty_alerts.csv", "text/csv", use_container_width=True, disabled=True)
        with c_json:
            st.download_button("📥 Download JSON", "[]", "empty_alerts.json", "application/json", use_container_width=True, disabled=True)
        st.caption("No alerts logged yet. Start monitoring to export raw telemetry.")

# Alert summary table
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:28px;margin-bottom:8px;">Recent Alert Summary</div>', unsafe_allow_html=True)

summary_rows = []
for at, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
    sev_label = "🔴 HIGH" if at in ["DoS", "DDoS"] else "🟡 MEDIUM" if at in ["PortScan", "BruteForce"] else "🟢 LOW"
    summary_rows.append({"Attack Type": at, "Count": count, "Severity Category": sev_label})

if summary_rows:
    st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)
else:
    st.markdown(f'<div style="color:{muted};text-align:center;padding:20px;">No alerts recorded yet. Start monitoring to generate reports.</div>', unsafe_allow_html=True)

# Database info
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:24px;margin-bottom:8px;">System &amp; Storage Telemetry</div>', unsafe_allow_html=True)
size, count = st.session_state.db.get_database_size()
st.markdown(f"""
<div class="glass-card">
    <table style="width:100%;font-family:'JetBrains Mono',monospace;font-size:12px;color:{muted};">
        <tr><td style="color:{text};">Database Size</td><td>{size/1024:.1f} KB</td></tr>
        <tr><td style="color:{text};">Total Alerts Stored</td><td>{count}</td></tr>
        <tr><td style="color:{text};">Last Synced</td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
    </table>
</div>
""", unsafe_allow_html=True)
