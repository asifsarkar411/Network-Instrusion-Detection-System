import sys, os, random
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
import plotly.graph_objects as go

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.dashboard_components import THEME, CINEMATIC_CSS
from src.storage import DatabaseManager

st.set_page_config(page_title="Threat Intelligence", page_icon="🌐", layout="wide")
st.markdown(CINEMATIC_CSS, unsafe_allow_html=True)

if "db" not in st.session_state: st.session_state.db = DatabaseManager()

bg = THEME['bg']; border = THEME['card_border']; text = THEME['text']
muted = THEME['text_dim']; blue = THEME['neon_blue']; red = THEME['neon_red']
amber = THEME['neon_orange']; green = THEME['neon_green']; purple = THEME['neon_purple']

st.markdown(f"""
<div style="font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;color:{text};">🌐 THREAT INTELLIGENCE</div>
<div style="font-family:'Inter',sans-serif;font-size:11px;color:{muted};margin-bottom:16px;">Global attack map · Attacker profiling · Threat patterns</div>
<div style="height:1px;background:{border};margin-bottom:16px;"></div>
""", unsafe_allow_html=True)

# Geo scatter map
top_ips = st.session_state.db.get_top_source_ips(limit=20, since_minutes=1440)

geo_data = []
cities = [
    ("New York", 40.71, -74.00), ("London", 51.51, -0.13), ("Tokyo", 35.68, 139.76),
    ("Moscow", 55.75, 37.62), ("Beijing", 39.90, 116.41), ("Sydney", -33.87, 151.21),
    ("Berlin", 52.52, 13.40), ("Singapore", 1.35, 103.82), ("Mumbai", 19.08, 72.88),
    ("Sao Paulo", -23.55, -46.63), ("Seoul", 37.57, 126.98), ("Paris", 48.86, 2.35),
]

for i, ip in enumerate(top_ips[:12]):
    city = cities[i % len(cities)]
    geo_data.append({
        "ip": ip["source_ip"], "alerts": ip["alert_count"],
        "city": city[0], "lat": city[1] + random.uniform(-2, 2),
        "lon": city[2] + random.uniform(-2, 2),
    })

fig = go.Figure()
fig.add_trace(go.Scattergeo(
    lon=[d["lon"] for d in geo_data], lat=[d["lat"] for d in geo_data],
    mode="markers+text",
    marker=dict(size=[max(d["alerts"]/5, 10) for d in geo_data],
                color=[red if d["alerts"] > 50 else amber if d["alerts"] > 20 else green for d in geo_data],
                opacity=0.8, line=dict(width=1, color="white")),
    text=[f"{d['city']}<br>{d['alerts']} alerts" for d in geo_data],
    textfont=dict(color=text, size=10, family="Inter"),
    hoverinfo="text",
))
fig.update_layout(
    title=dict(text="<b>Global Attack Origins</b>", font=dict(color=text, size=14, family="Orbitron"), x=0.5),
    height=450, margin=dict(t=40, b=10, l=10, r=10),
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    geo=dict(bgcolor="rgba(0,0,0,0)", landcolor=bg, coastlinecolor=border,
             showframe=False, projection_type="natural earth"),
)
st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

# Attacker table
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:16px;">Top Attackers</div>', unsafe_allow_html=True)

df = pd.DataFrame(geo_data, columns=["ip", "city", "alerts"])[["ip", "city", "alerts"]]
df.columns = ["IP Address", "Origin", "Alert Count"]
df["Threat Level"] = df["Alert Count"].apply(lambda x: "🔴 HIGH" if x > 50 else "🟡 MEDIUM" if x > 20 else "🟢 LOW")

st.dataframe(df, use_container_width=True, hide_index=True)

# Attack frequency by type
st.markdown(f'<div style="font-family:\'Orbitron\',sans-serif;font-size:16px;color:{text};margin-top:16px;">Attack Type Distribution (24h)</div>', unsafe_allow_html=True)
dc = st.session_state.db.get_alert_count(since_minutes=1440)
attack_types = dc.get("by_type", {})

if attack_types:
    fig2 = go.Figure(go.Bar(
        x=list(attack_types.values()), y=list(attack_types.keys()),
        orientation="h",
        marker=dict(color=[{"DoS": red, "PortScan": amber, "WebAttack": purple, "DDoS": red,
                            "BruteForce": purple, "Botnet": blue}.get(k, blue) for k in attack_types.keys()],
                    opacity=0.8),
        text=list(attack_types.values()), textposition="outside",
        textfont=dict(color=text, size=12),
    ))
    fig2.update_layout(
        title=dict(text="<b>Attack Frequency</b>", font=dict(color=text, size=14, family="Orbitron"), x=0.5),
        height=300, margin=dict(t=40, b=10, l=10, r=30),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False, visible=False),
        yaxis=dict(tickfont=dict(color=muted, size=11)),
    )
    st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
