import streamlit as st

def render_global_alarm():
    from src.dashboard_components import THEME
    
    if 'alarm_active' not in st.session_state:
        st.session_state.alarm_active = False
    if 'last_alarm_time' not in st.session_state:
        import datetime
        st.session_state.last_alarm_time = datetime.datetime.now().isoformat()
    if 'current_alarm_data' not in st.session_state:
        st.session_state.current_alarm_data = {}
        
    if 'db' in st.session_state:
        recent = st.session_state.db.get_recent_alerts(limit=1)
        if recent:
            latest = recent[0]
            sev = str(latest.get('severity', '')).lower()
            if latest['timestamp'] > st.session_state.last_alarm_time and sev in ['high', 'medium', 'critical']:
                st.session_state.alarm_active = True
                st.session_state.last_alarm_time = latest['timestamp']
                st.session_state.current_alarm_data = latest
                
    if st.session_state.alarm_active:
        latest = st.session_state.current_alarm_data
        is_high = str(latest.get('severity', '')).lower() in ['high', 'critical']
        alert_color = THEME['neon_red'] if is_high else THEME['neon_orange']
        bg_color = THEME['glow_red'] if is_high else 'rgba(255, 140, 51, 0.1)'
        
        c1, c2, c3 = st.columns([1, 4, 1])
        with c2:
            st.markdown(f'''
            <div style="background: {bg_color}; border: 1px solid {alert_color}; border-left: 4px solid {alert_color}; border-radius: 8px; padding: 16px; margin-bottom: 16px; display: flex; align-items: center; gap: 16px; box-shadow: 0 4px 20px {bg_color};">
                <div style="font-size: 28px; animation: pulse 1.5s infinite;">🚨</div>
                <div style="flex-grow: 1;">
                    <div style="color: {alert_color}; font-family: 'Orbitron', sans-serif; font-weight: bold; font-size: 16px;">{latest.get('severity', 'HIGH').upper()} RISK THREAT DETECTED: {latest.get('attack_type', 'Unknown')}</div>
                    <div style="color: {THEME['text']}; font-size: 13px; margin-top: 4px;">
                        Confidence Score: <span style="color: {alert_color}; font-weight: bold;">{float(latest.get('final_score', 0.0))*100:.1f}%</span>
                    </div>
                </div>
            </div>
            <style>
            @keyframes pulse {{
                0% {{ transform: scale(1); opacity: 1; }}
                50% {{ transform: scale(1.1); opacity: 0.8; }}
                100% {{ transform: scale(1); opacity: 1; }}
            }}
            </style>
            ''', unsafe_allow_html=True)
            
            # Action Buttons Row
            b1, b2 = st.columns(2)
            with b1:
                if st.button("🔕 STOP ALARM", use_container_width=True, type="secondary", key="global_stop_btn"):
                    st.session_state.alarm_active = False
                    st.rerun()
            with b2:
                if st.button("🛡️ PREVENT ATTACK", use_container_width=True, type="primary", key="global_prevent_btn"):
                    st.session_state.alarm_active = False
                    st.session_state.highlight_prevent_threat = latest
                    st.session_state.highlight_prevent_ip = latest.get("source_ip") or latest.get("src_ip")
                    try:
                        st.switch_page("pages/10_🛡️_Prevent.py")
                    except Exception:
                        st.rerun()
                
            import os
            alarm_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "danger_alarm.wav")
            if os.path.exists(alarm_path):
                # Use timestamp as key to force Streamlit to render a brand new audio component every time
                audio_key = "global_alarm_" + str(latest.get('timestamp', '0')).replace(":", "")
                st.audio(alarm_path, format="audio/wav", autoplay=True, loop=True, key=audio_key)
                st.markdown("""
                <style>
                    /* Hide the audio player UI without breaking autoplay */
                    [data-testid="stAudio"] { 
                        opacity: 0; 
                        position: absolute; 
                        width: 1px; 
                        height: 1px; 
                        pointer-events: none;
                        z-index: -100;
                    }
                </style>
                """, unsafe_allow_html=True)
