import sys, os, time
from datetime import datetime
import streamlit as st

# --- Global Alarm Check ---
try:
    from src.global_alarm import render_global_alarm
    render_global_alarm()
except Exception:
    pass
# --------------------------

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dashboard_components import (
    THEME, CINEMATIC_CSS, create_attack_donut, create_alert_timeline,
    create_severity_bars, create_top_ips_chart, create_alert_table,
)
from src.storage import DatabaseManager

st.set_page_config(page_title="Threat Analysis", page_icon="📊", layout="wide")
st.markdown(CINEMATIC_CSS, unsafe_allow_html=True)

if "db" not in st.session_state:
    st.session_state.db = DatabaseManager()

bg = THEME['bg']; border = THEME['card_border']; text = THEME['text']
muted = THEME['text_dim']; green = THEME['neon_green']; blue = THEME['neon_blue']
amber = THEME['neon_orange']; purple = THEME['neon_purple']

# Header
st.markdown(f"""
<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;">
    <div>
        <div style="font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;color:{text};">📊 THREAT ANALYSIS</div>
        <div style="font-family:'Inter',sans-serif;font-size:11px;color:{muted};">Attack distribution · Timelines · Top sources</div>
    </div>
    <div style="text-align:right;font-family:'JetBrains Mono',monospace;font-size:12px;color:{muted};">{datetime.now().strftime('%H:%M:%S')}</div>
</div>
<div style="height:1px;background:{border};margin:12px 0;"></div>
""", unsafe_allow_html=True)

# Sidebar controls
with st.sidebar:
    st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:14px;color:{text};margin-bottom:8px;">Controls</div>', unsafe_allow_html=True)
    auto_refresh = st.checkbox("Auto Refresh (3s)", value=True, key="threat_analysis_autorefresh")
    st.markdown("---")

# Bandwidth Monitor
import random
bw_in = random.randint(50, 500)
bw_out = random.randint(30, 400)
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:12px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:20px;color:{blue};">{bw_in}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">KB/s IN</div></div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:12px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:20px;color:{purple};">{bw_out}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">KB/s OUT</div></div>""", unsafe_allow_html=True)
with c3:
    conn = random.randint(20, 80)
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:12px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:20px;color:{green};">{conn}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">CONNECTIONS</div></div>""", unsafe_allow_html=True)
with c4:
    pps = random.randint(100, 2000)
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:12px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:20px;color:{amber};">{pps}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">PACKETS/S</div></div>""", unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# Time window selector
window = st.selectbox("Time Window", ["15 min", "30 min", "1 hour", "6 hours", "24 hours"], index=2)
minutes = {"15 min": 15, "30 min": 30, "1 hour": 60, "6 hours": 360, "24 hours": 1440}[window]

# Row 1
a, b = st.columns([1, 2])
with a:
    dc = st.session_state.db.get_alert_count(since_minutes=minutes)
    st.plotly_chart(create_attack_donut(dc.get("by_type") or {"No Data": 1}), use_container_width=True, config={"displayModeBar": False})
with b:
    st.plotly_chart(create_alert_timeline(st.session_state.db.get_alert_timeline(minutes, 30)), use_container_width=True, config={"displayModeBar": False})

# Row 2
a, b = st.columns(2)
with a:
    st.plotly_chart(create_severity_bars(dc.get("by_severity", {})), use_container_width=True, config={"displayModeBar": False})
with b:
    top = st.session_state.db.get_top_source_ips(limit=10, since_minutes=minutes)
    st.plotly_chart(create_top_ips_chart(top), use_container_width=True, config={"displayModeBar": False})

# Alert table
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:16px;">Alert History</div>', unsafe_allow_html=True)
ra = st.session_state.db.get_recent_alerts(limit=50)
adf = create_alert_table(ra)

sev_col = None
for col_candidate in ["SEVERITY", "SEV", "severity", "Severity"]:
    if col_candidate in adf.columns:
        sev_col = col_candidate
        break

if sev_col:
    def color_sev(v):
        v_str = str(v).upper()
        if "HIGH" in v_str or "CRITICAL" in v_str:
            return f"color:{THEME['neon_red']};font-weight:700;"
        elif "MED" in v_str:
            return f"color:{THEME['neon_orange']};font-weight:600;"
        return f"color:{THEME['neon_green']};"
    
    try:
        # Pandas 2.1+ / 3.0 uses Styler.map, fallback to applymap for older pandas
        styler = adf.style
        if hasattr(styler, "map"):
            styled_df = styler.map(color_sev, subset=[sev_col])
        elif hasattr(styler, "applymap"):
            styled_df = styler.applymap(color_sev, subset=[sev_col])
        else:
            styled_df = adf
        st.dataframe(styled_df, use_container_width=True, height=400, hide_index=True)
    except Exception:
        st.dataframe(adf, use_container_width=True, height=400, hide_index=True)
else:
    st.dataframe(adf, use_container_width=True, height=400, hide_index=True)

# Auto-refresh
if auto_refresh:
    time.sleep(3)
    try:
        st.rerun()
    except Exception:
        pass
