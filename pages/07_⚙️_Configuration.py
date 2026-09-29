import sys, os
import streamlit as st

# --- Global Alarm Check ---
try:
    from src.global_alarm import render_global_alarm
    render_global_alarm()
except Exception:
    pass
# --------------------------

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.dashboard_components import THEME, CINEMATIC_CSS

st.set_page_config(page_title="Configuration", page_icon="⚙️", layout="wide")
st.markdown(CINEMATIC_CSS, unsafe_allow_html=True)

bg = THEME['bg']; border = THEME['card_border']; text = THEME['text']
muted = THEME['text_dim']; green = THEME['neon_green']; blue = THEME['neon_blue']
red = THEME['neon_red']; amber = THEME['neon_orange']; purple = THEME['neon_purple']

st.markdown(f"""
<div style="font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;color:{text};">⚙️ CONFIGURATION</div>
<div style="font-family:'Inter',sans-serif;font-size:11px;color:{muted};margin-bottom:16px;">Detection parameters · Interface settings · System controls</div>
<div style="height:1px;background:{border};margin-bottom:16px;"></div>
""", unsafe_allow_html=True)

# Load current config
try:
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
except:
    config = {"capture": {}, "analysis": {}, "flow": {}, "storage": {}}

# Detection Settings
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};">Detection Parameters</div>', unsafe_allow_html=True)

c1, c2 = st.columns(2)
with c1:
    st.markdown(f"""<div class="glass-card">
        <div style="font-family:'Inter',sans-serif;font-size:12px;color:{muted};margin-bottom:12px;">FUSION WEIGHTS</div>""", unsafe_allow_html=True)
    rw = st.slider("Rule Engine Weight", 0.0, 1.0, 0.4, 0.05, key="cfg_rw")
    st.caption(f"ML Model Weight: {1-rw:.2f}")
    th = st.slider("Alert Threshold", 0.0, 1.0, 0.7, 0.05, key="cfg_th")
    st.markdown("</div>", unsafe_allow_html=True)

with c2:
    st.markdown(f"""<div class="glass-card">
        <div style="font-family:'Inter',sans-serif;font-size:12px;color:{muted};margin-bottom:12px;">DETECTION MODES</div>""", unsafe_allow_html=True)
    enable_ml = st.checkbox("Enable ML Detection", value=True)
    enable_rules = st.checkbox("Enable Rule Engine", value=True)
    enable_anomaly = st.checkbox("Enable Anomaly Detection (Isolation Forest)", value=False)
    st.markdown("</div>", unsafe_allow_html=True)

# Capture Settings
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:16px;">Capture Settings</div>', unsafe_allow_html=True)

c1, c2 = st.columns(2)
with c1:
    st.markdown(f"""<div class="glass-card">
        <div style="font-family:'Inter',sans-serif;font-size:12px;color:{muted};margin-bottom:12px;">INTERFACE</div>""", unsafe_allow_html=True)
    interface = st.text_input("Network Interface", value=config.get("capture", {}).get("interface", "eth0"))
    duration = st.slider("Capture Duration (minutes)", 5, 60, 25, 5)
    bpf = st.text_input("BPF Filter", value=config.get("capture", {}).get("bpf_filter", "tcp or (udp and port 53)"))
    st.markdown("</div>", unsafe_allow_html=True)

with c2:
    st.markdown(f"""<div class="glass-card">
        <div style="font-family:'Inter',sans-serif;font-size:12px;color:{muted};margin-bottom:12px;">FLOW SETTINGS</div>""", unsafe_allow_html=True)
    timeout = st.slider("Flow Timeout (seconds)", 10, 300, 60, 10)
    max_flows = st.slider("Max Active Flows", 100, 2000, 500, 100)
    st.markdown("</div>", unsafe_allow_html=True)

# Save button
if st.button("💾 Save Configuration", use_container_width=True):
    new_config = {
        "capture": {
            "interface": interface,
            "duration_minutes": duration,
            "bpf_filter": bpf,
            "ring_buffer_size": 10000,
            "snapshot_length": 65535,
        },
        "flow": {
            "timeout_seconds": timeout,
            "max_active_flows": max_flows,
        },
        "analysis": {
            "rule_weight": rw,
            "ml_weight": 1 - rw,
            "alert_threshold": th,
        },
        "storage": {
            "database_path": "data/nids_alerts.db",
        },
    }
    with open("config.yaml", "w") as f:
        yaml.dump(new_config, f, default_flow_style=False)
    st.success("✅ Configuration saved successfully!")

# Current config display
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:20px;">Current Configuration</div>', unsafe_allow_html=True)
st.code(yaml.dump(config, default_flow_style=False), language="yaml")
