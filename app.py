"""
SOC-NIDS // Threat Command
===========================
Multi-page entry point. Redirects to Live Monitor.
Run: streamlit run app.py
"""

import streamlit as st

st.set_page_config(
    page_title="Threat Command",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:80vh;text-align:center;">
    <div style="font-family:'Orbitron',sans-serif;font-size:56px;font-weight:900;color:#00D4FF;
                text-shadow:0 0 30px rgba(0,212,255,0.5),0 0 80px rgba(0,212,255,0.2);letter-spacing:4px;">
        ◈ THREAT COMMAND
    </div>
    <div style="font-family:'Inter',sans-serif;font-size:16px;color:#8890A4;margin-top:12px;letter-spacing:6px;">
        SOC-NIDS
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#515774;margin-top:32px;">
        Select a page from the sidebar to begin
    </div>
    <div style="font-family:'Inter',sans-serif;font-size:11px;color:#515774;margin-top:8px;">
        📡 Live Monitor &nbsp;|&nbsp; 📊 Threat Analysis &nbsp;|&nbsp; 🔍 Packet Inspector &nbsp;|&nbsp; 🛡️ Prevent &nbsp;|&nbsp; 🏆 Why Our NIDS
    </div>
</div>
""", unsafe_allow_html=True)
