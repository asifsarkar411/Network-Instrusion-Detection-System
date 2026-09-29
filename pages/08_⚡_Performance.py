"""
Performance Monitoring Page
============================
Real-time system performance metrics:
- CPU, Memory, Throughput
- Inference latency
- System health status
- Historical trends
"""

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
    THEME, CINEMATIC_CSS, create_performance_gauge, create_performance_timeline
)

st.set_page_config(page_title="Performance", page_icon="⚡", layout="wide")
st.markdown(CINEMATIC_CSS, unsafe_allow_html=True)

bg = THEME['bg']; border = THEME['card_border']; text = THEME['text']
muted = THEME['text_dim']; green = THEME['neon_green']; blue = THEME['neon_blue']
red = THEME['neon_red']; amber = THEME['neon_orange']; purple = THEME['neon_purple']

# Init performance monitor if not running
if "perf_monitor" not in st.session_state:
    from src.performance_monitor import PerformanceMonitor
    st.session_state.perf_monitor = PerformanceMonitor()
    st.session_state.perf_monitor.start()

perf = st.session_state.perf_monitor
metrics = perf.get_metrics()
health = perf.get_health_status()

# Header
st.markdown(f"""
<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;">
    <div>
        <div style="font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;color:{text};">⚡ SYSTEM PERFORMANCE</div>
        <div style="font-family:'Inter',sans-serif;font-size:11px;color:{muted};">Real-time resource monitoring · Inference latency · Throughput</div>
    </div>
    <div style="text-align:right;">
        <div style="font-family:'Orbitron',sans-serif;font-size:16px;color:{green if health['healthy'] else red};">{health['status']}</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:{muted};">Uptime: {metrics['uptime_str']}</div>
    </div>
</div>
<div style="height:1px;background:{border};margin:12px 0;"></div>
""", unsafe_allow_html=True)

# Health Issues
if health["issues"]:
    for issue in health["issues"]:
        st.warning(issue)

# Metric Cards Row
c1, c2, c3, c4, c5 = st.columns(5)

with c1:
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:24px;font-weight:700;color:{blue};">{metrics['total_packets']:,}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">PACKETS CAPTURED</div>
    </div>""", unsafe_allow_html=True)

with c2:
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:24px;font-weight:700;color:{purple};">{metrics['total_flows']:,}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">FLOWS PROCESSED</div>
    </div>""", unsafe_allow_html=True)

with c3:
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:24px;font-weight:700;color:{green};">{metrics['total_predictions']:,}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">PREDICTIONS</div>
    </div>""", unsafe_allow_html=True)

with c4:
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:24px;font-weight:700;color:{red if metrics['total_alerts'] > 0 else green};">{metrics['total_alerts']:,}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">ALERTS</div>
    </div>""", unsafe_allow_html=True)

with c5:
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:16px;">
        <div style="font-family:'Orbitron',sans-serif;font-size:24px;font-weight:700;color:{amber};">{metrics['avg_latency_ms']}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">AVG LATENCY (ms)</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Gauges Row
c1, c2, c3, c4 = st.columns(4)

with c1:
    st.plotly_chart(create_performance_gauge(metrics['cpu_percent'], 100, "CPU USAGE", "%", 
                                              red if metrics['cpu_percent'] > 80 else green),
                   use_container_width=True, config={"displayModeBar": False}, key="gauge_cpu")

with c2:
    st.plotly_chart(create_performance_gauge(metrics['memory_mb'], 1024, "MEMORY", " MB",
                                              red if metrics['memory_mb'] > 800 else green),
                   use_container_width=True, config={"displayModeBar": False}, key="gauge_mem")

with c3:
    st.plotly_chart(create_performance_gauge(metrics['packets_per_sec'], 5000, "THROUGHPUT", " p/s",
                                              blue),
                   use_container_width=True, config={"displayModeBar": False}, key="gauge_pps")

with c4:
    st.plotly_chart(create_performance_gauge(metrics['avg_latency_ms'], 100, "LATENCY", " ms",
                                              red if metrics['avg_latency_ms'] > 50 else green),
                   use_container_width=True, config={"displayModeBar": False}, key="gauge_lat")

# Trend Charts
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:16px;">Performance Trends</div>', unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.plotly_chart(create_performance_timeline(metrics['cpu_history'], "CPU History", blue),
                   use_container_width=True, config={"displayModeBar": False}, key="time_cpu")

with c2:
    st.plotly_chart(create_performance_timeline(metrics['memory_history'], "Memory History", purple),
                   use_container_width=True, config={"displayModeBar": False}, key="time_mem")

with c3:
    st.plotly_chart(create_performance_timeline(metrics['pps_history'], "Throughput History", green),
                   use_container_width=True, config={"displayModeBar": False}, key="time_pps")

with c4:
    st.plotly_chart(create_performance_timeline(metrics['latency_history'], "Latency History", amber),
                   use_container_width=True, config={"displayModeBar": False}, key="time_lat")

# System Health Checks
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:16px;">System Health Checks</div>', unsafe_allow_html=True)

checks = health["checks"]
c1, c2, c3, c4 = st.columns(4)

with c1:
    icon = "✅" if checks["cpu"] else "❌"
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:12px;">
        <div style="font-size:28px;">{icon}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">CPU HEALTH</div>
    </div>""", unsafe_allow_html=True)

with c2:
    icon = "✅" if checks["memory"] else "❌"
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:12px;">
        <div style="font-size:28px;">{icon}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">MEMORY HEALTH</div>
    </div>""", unsafe_allow_html=True)

with c3:
    icon = "✅" if checks["latency"] else "❌"
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:12px;">
        <div style="font-size:28px;">{icon}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">LATENCY HEALTH</div>
    </div>""", unsafe_allow_html=True)

with c4:
    icon = "✅" if checks["throughput"] else "❌"
    st.markdown(f"""<div class="glass-card" style="text-align:center;padding:12px;">
        <div style="font-size:28px;">{icon}</div>
        <div style="font-family:'Inter',sans-serif;font-size:9px;color:{muted};">THROUGHPUT HEALTH</div>
    </div>""", unsafe_allow_html=True)

# Alert & Metric Processing (Keep processing active on this page)
if st.session_state.get("monitoring"):
    if st.session_state.get("extractor") and st.session_state.get("detector"):
        perf_mon = st.session_state.perf_monitor
        for flow in st.session_state.extractor.get_completed_flows():
            import time as _time
            t0 = _time.time()
            r = st.session_state.detector.analyze_flow(flow)
            perf_mon.record_prediction(_time.time() - t0)
            perf_mon.record_flow()
            if r["is_alert"]:
                perf_mon.record_alert()
                st.session_state.db.save_alert({
                    "timestamp": datetime.now().isoformat(), "attack_type": r["attack_type"],
                    "severity": r["severity"], "final_score": r["final_score"],
                    "rule_score": r["rule_result"]["score"], "ml_score": r["ml_result"]["score"],
                    "source_ip": flow.get("src_ip") or flow.get("source_ip", "192.168.1.50"),
                    "destination_ip": flow.get("dst_ip") or flow.get("destination_ip", "10.0.0.1"),
                    "source_port": flow.get("src_port") or flow.get("source_port", 0),
                    "destination_port": flow.get("dst_port") or flow.get("destination_port", 0),
                    "protocol": flow.get("protocol") or flow.get("proto", 6),
                    "flow_features": flow, "rule_details": r["rule_result"], "ml_details": r["ml_result"],
                    "packet_summary": f"{r['attack_type']} ({r['severity']})",
                })
        
        cs = st.session_state.capture.get_stats() if st.session_state.get("capture") else {}
        perf_mon.record_packet(cs.get("packets_captured", 0) - perf_mon.packets_total)

# Auto-refresh
time.sleep(1.5)
try:
    st.rerun()
except Exception:
    pass
