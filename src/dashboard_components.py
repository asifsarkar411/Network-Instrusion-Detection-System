
"""
Cinematic Cybersecurity Dashboard Components
============================================
Hollywood-style visualization components with neon aesthetics,
dark backgrounds, and dramatic data presentation.
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from typing import Dict, List, Optional
import random
import warnings
warnings.filterwarnings("ignore")


# ──────────────────────────────────────────────────────────────
# Cinematic Cyber Theme Colors
# ──────────────────────────────────────────────────────────────

THEME = {
    "bg": "#0A0A0F",              # Deep void black
    "card": "#0F1119",            # Dark card surface
    "card_border": "#1A1F2E",     # Subtle border
    "text": "#C8CCD6",            # Cool gray text
    "text_dim": "#6B7280",        # Muted text
    "neon_green": "#00FF88",      # Primary accent - matrix green
    "neon_blue": "#00D4FF",       # Cyber blue
    "neon_purple": "#B44CFF",     # Threat purple
    "neon_red": "#FF3355",        # Alert red
    "neon_orange": "#FF8C33",     # Warning orange
    "neon_yellow": "#FFD633",     # Caution yellow
    "grid": "#141822",            # Grid lines
    "glow_green": "rgba(0,255,136,0.3)",
    "glow_red": "rgba(255,51,85,0.3)",
    "glow_blue": "rgba(0,212,255,0.3)",
}

SEVERITY_COLORS = {
    "high": THEME["neon_red"],
    "medium": THEME["neon_orange"],
    "low": THEME["neon_green"],
}

SEVERITY_GLOW = {
    "high": THEME["glow_red"],
    "medium": "rgba(255,140,51,0.3)",
    "low": THEME["glow_green"],
}

ATTACK_COLORS = {
    "DoS": THEME["neon_red"],
    "PortScan": THEME["neon_orange"],
    "WebAttack": THEME["neon_purple"],
    "Benign": THEME["neon_green"],
}


# ──────────────────────────────────────────────────────────────
# Chart Layout Template
# ──────────────────────────────────────────────────────────────

def cinematic_layout(fig: go.Figure, title: str = "", height: int = 400) -> go.Figure:
    """Apply cinematic theme to any Plotly figure."""
    fig.update_layout(
        title={
            "text": f"<b>{title}</b>" if title else "",
            "font": {"color": THEME["text"], "size": 16, "family": "Courier New"},
            "x": 0.5,
            "xanchor": "center",
        },
        paper_bgcolor=THEME["card"],
        plot_bgcolor=THEME["bg"],
        font={"color": THEME["text_dim"], "family": "Courier New", "size": 11},
        height=height,
        margin=dict(t=50 if title else 30, b=30, l=30, r=30),
        xaxis={
            "gridcolor": THEME["grid"],
            "zerolinecolor": THEME["card_border"],
            "linecolor": THEME["card_border"],
        },
        yaxis={
            "gridcolor": THEME["grid"],
            "zerolinecolor": THEME["card_border"],
            "linecolor": THEME["card_border"],
        },
        legend={
            "font": {"color": THEME["text_dim"]},
            "bgcolor": "rgba(0,0,0,0.5)",
            "bordercolor": THEME["card_border"],
        },
    )
    return fig


# ──────────────────────────────────────────────────────────────
# Gauge Chart — Threat Level
# ──────────────────────────────────────────────────────────────

def create_threat_gauge(value: float, title: str = "THREAT LEVEL", delta_ref: float = 20.0, **kwargs) -> go.Figure:
    """
    Cinematic semi-circular threat gauge with neon glow and live responsive thresholding.
    
    Args:
        value: 0.0 to 1.0 threat score
        title: Gauge title
        delta_ref: Reference percentage baseline for delta comparison
    """
    pct = round(max(0.0, min(1.0, float(value))) * 100, 1)
    
    # Choose color based on threat level
    if pct >= 70:
        bar_color = THEME["neon_red"]
        glow = THEME["glow_red"]
    elif pct >= 35:
        bar_color = THEME["neon_orange"]
        glow = "rgba(255,140,51,0.3)"
    elif pct >= 15:
        bar_color = THEME["neon_yellow"]
        glow = "rgba(255,214,51,0.3)"
    else:
        bar_color = THEME["neon_green"]
        glow = THEME["glow_green"]
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=pct,
        title={
            "text": f"<b>{title}</b>",
            "font": {"color": THEME["text"], "size": 16, "family": "Courier New"},
        },
        number={
            "suffix": "%",
            "font": {"color": bar_color, "size": 44, "family": "Courier New"},
        },
        delta={"reference": delta_ref, "increasing": {"color": THEME["neon_red"]}, "decreasing": {"color": THEME["neon_green"]}},
        gauge={
            "axis": {
                "range": [0, 100],
                "tickcolor": THEME["text_dim"],
                "tickfont": {"size": 10},
            },
            "bar": {"color": bar_color, "thickness": 0.28},
            "bgcolor": THEME["bg"],
            "borderwidth": 0,
            "steps": [
                {"range": [0, 20], "color": "rgba(0,255,136,0.08)"},
                {"range": [20, 50], "color": "rgba(255,214,51,0.08)"},
                {"range": [50, 75], "color": "rgba(255,140,51,0.08)"},
                {"range": [75, 100], "color": "rgba(255,51,85,0.15)"},
            ],
            "threshold": {
                "line": {"color": THEME["neon_red"], "width": 3},
                "thickness": 0.85,
                "value": 75,
            },
        },
    ))
    
    fig.update_layout(
        height=280,
        margin=dict(t=50, b=10, l=20, r=20),
        paper_bgcolor=THEME["card"],
        font={"color": THEME["text_dim"]},
    )
    
    return fig


# ──────────────────────────────────────────────────────────────
# Attack Distribution — Donut Chart
# ──────────────────────────────────────────────────────────────

def create_attack_donut(attack_counts: Dict[str, int]) -> go.Figure:
    """
    Cinematic donut chart showing attack type distribution.
    
    Args:
        attack_counts: Dict of {attack_type: count}
    """
    labels = list(attack_counts.keys())
    values = list(attack_counts.values())
    colors = [ATTACK_COLORS.get(l, THEME["neon_blue"]) for l in labels]
    
    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.65,
        marker={
            "colors": colors,
            "line": {"color": THEME["card"], "width": 2},
        },
        textfont={"color": THEME["text"], "family": "Courier New", "size": 12},
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
        sort=False,
    ))
    
    # Center text
    total = sum(values)
    fig.add_annotation(
        text=f"<b style='font-size:28px; font-family:Courier New; color:{THEME['text']}'>{total}</b><br>"
             f"<span style='font-size:12px; color:{THEME['text_dim']}'>ALERTS</span>",
        x=0.5, y=0.5,
        showarrow=False,
        font={"color": THEME["text"]},
    )
    
    fig.update_layout(
        height=350,
        margin=dict(t=30, b=30, l=30, r=30),
        paper_bgcolor=THEME["card"],
        showlegend=True,
        legend={
            "font": {"color": THEME["text_dim"], "size": 11},
            "orientation": "h",
            "yanchor": "bottom",
            "y": -0.15,
            "xanchor": "center",
            "x": 0.5,
        },
    )
    
    return fig


# ──────────────────────────────────────────────────────────────
# Alert Timeline — Area Chart
# ──────────────────────────────────────────────────────────────

def create_alert_timeline(timeline_data: List[Dict]) -> go.Figure:
    """
    Cinematic timeline chart with glowing area fill.
    
    Args:
        timeline_data: List of {timestamp, count} dicts
    """
    if not timeline_data:
        fig = go.Figure()
        fig.add_annotation(
            text="<b>NO DATA</b><br><span style='font-size:11px'>Awaiting alerts...</span>",
            x=0.5, y=0.5, showarrow=False,
            font={"color": THEME["text_dim"], "size": 18, "family": "Courier New"},
        )
        return cinematic_layout(fig, "ALERT TIMELINE", height=300)
    
    df = pd.DataFrame(timeline_data)
    
    fig = go.Figure()
    
    # Glow area
    fig.add_trace(go.Scatter(
        x=df.iloc[:,0], y=df.iloc[:,1],
        mode="lines",
        line={"width": 0},
        fill="tozeroy",
        fillcolor="rgba(0,255,136,0.08)",
        showlegend=False,
        hoverinfo="skip",
    ))

    # Main line
    fig.add_trace(go.Scatter(
        x=df.iloc[:,0], y=df.iloc[:,1],
        mode="lines+markers",
        line={
            "color": THEME["neon_green"],
            "width": 2,
            "shape": "spline",
        },
        marker={
            "color": THEME["neon_green"],
            "size": 4,
            "symbol": "diamond",
        },
        fill="tozeroy",
        fillcolor="rgba(0,255,136,0.15)",
        name="Alerts",
        hovertemplate="<b>%{x}</b><br>Alerts: %{y}<extra></extra>",
    ))
    
    return cinematic_layout(fig, "ALERT TIMELINE", height=300)


# ──────────────────────────────────────────────────────────────
# Severity Bar Chart
# ──────────────────────────────────────────────────────────────

def create_severity_bars(severity_counts: Dict[str, int]) -> go.Figure:
    """
    Cinematic horizontal bar chart for severity distribution.
    """
    if not severity_counts:
        fig = go.Figure()
        return cinematic_layout(fig, "SEVERITY DISTRIBUTION", height=250)
    
    # Sort: high, medium, low
    order = ["high", "medium", "low"]
    labels = [s.capitalize() for s in order if s in severity_counts]
    values = [severity_counts.get(s, 0) for s in order if s in severity_counts]
    colors = [SEVERITY_COLORS.get(s, THEME["neon_blue"]) for s in order if s in severity_counts]
    
    fig = go.Figure(go.Bar(
        y=labels,
        x=values,
        orientation="h",
        marker={
            "color": colors,
            "line": {"width": 0},
        },
        text=values,
        textposition="outside",
        textfont={"color": THEME["text"], "family": "Courier New", "size": 14},
        hovertemplate="<b>%{y}</b>: %{x} alerts<extra></extra>",
    ))
    
    fig.update_layout(
        xaxis={"showgrid": False, "visible": False},
    )
    
    return cinematic_layout(fig, "SEVERITY DISTRIBUTION", height=250)


# ──────────────────────────────────────────────────────────────
# Top Source IPs — Horizontal Bar
# ──────────────────────────────────────────────────────────────


def create_top_ips_chart(top_ips: List[Dict]) -> go.Figure:
    """
    Cinematic bar chart for top attacking IPs.
    """
    if not top_ips:
        fig = go.Figure()
        fig.add_annotation(
            text="<b>NO ATTACKERS</b>",
            x=0.5, y=0.5, showarrow=False,
            font={"color": THEME["text_dim"], "size": 16, "family": "Courier New"},
        )
        return cinematic_layout(fig, "TOP SOURCE IPs", height=300)
    
    df = pd.DataFrame(top_ips)
    
    # Gradient colors based on rank
    n = len(df)
    gradient_colors = [
        f"rgba({int(255*(1-i/n))}, {int(200*(1-i/n))}, {int(255*(i/n+0.3))}, 0.9)"
        for i in range(n)
    ]
    
    fig = go.Figure(go.Bar(
        y=df["source_ip"],
        x=df["alert_count"],
        orientation="h",
        marker={
            "color": gradient_colors,
            "line": {"width": 0},
        },
        text=df["alert_count"],
        textposition="outside",
        textfont={"color": THEME["text"], "family": "Courier New", "size": 12},
        hovertemplate="<b>%{y}</b><br>Alerts: %{x}<extra></extra>",
    ))
    
    fig.update_layout(
        xaxis={"showgrid": False, "visible": False},
        yaxis={"categoryorder": "total ascending"},
    )
    
    return cinematic_layout(fig, "TOP SOURCE IPs", height=300)


# ──────────────────────────────────────────────────────────────
# Live Alert Feed — Data Table
# ──────────────────────────────────────────────────────────────



def create_alert_table(alerts: List[Dict]) -> pd.DataFrame:
    """
    Format alerts for display in a styled dataframe.
    
    Returns styled dataframe with color-coded severity.
    """
    if not alerts:
        return pd.DataFrame({"Status": ["No alerts detected. System secure."]})
    
    rows = []
    for alert in alerts:
        ts = alert.get("timestamp") or ""
        ts_str = str(ts)
        if "T" in ts_str:
            time_str = ts_str.split("T")[-1][:8]
        elif " " in ts_str:
            time_str = ts_str.split(" ")[-1][:8]
        elif len(ts_str) >= 8:
            time_str = ts_str[-8:]
        else:
            time_str = "--:--:--"

        sev = str(alert.get("severity") or "low").upper()
        score = alert.get("final_score")
        score_val = float(score) if score is not None else 0.0
        src_ip = str(alert.get("source_ip") or "-")
        dst_ip = str(alert.get("destination_ip") or "-")

        rows.append({
            "TIME": time_str,
            "TYPE": alert.get("attack_type") or "Benign",
            "SEVERITY": sev,
            "SCORE": f"{score_val:.2%}",
            "SOURCE": src_ip[:15],
            "DEST": dst_ip[:15],
        })
    
    return pd.DataFrame(rows)


def create_score_breakdown(rule_score: float, ml_score: float, final_score: float) -> go.Figure:
    """
    Cinematic stacked bar showing rule vs ML contribution to final score.
    """
    fig = go.Figure()
    
    # Rule portion
    fig.add_trace(go.Bar(
        name="Rule Engine",
        x=["Detection Score"],
        y=[rule_score],
        marker={"color": THEME["neon_blue"], "line": {"width": 0}},
        text=[f"{rule_score:.2%}"],
        textposition="inside",
        textfont={"color": THEME["bg"], "size": 14, "family": "Courier New"},
        hovertemplate="Rule: %{y:.2%}<extra></extra>",
    ))
    
    # ML portion
    fig.add_trace(go.Bar(
        name="ML Model",
        x=["Detection Score"],
        y=[ml_score],
        marker={"color": THEME["neon_purple"], "line": {"width": 0}},
        text=[f"{ml_score:.2%}"],
        textposition="inside",
        textfont={"color": THEME["text"], "size": 14, "family": "Courier New"},
        hovertemplate="ML: %{y:.2%}<extra></extra>",
    ))
    
    # Add final score line
    fig.add_shape(
        type="line",
        x0=-0.45, x1=0.45,
        y0=final_score, y1=final_score,
        line={"color": THEME["neon_green"], "width": 3, "dash": "dot"},
    )
    
    fig.add_annotation(
        x=0.5, y=final_score,
        text=f"<b>FINAL: {final_score:.2%}</b>",
        showarrow=False,
        font={"color": THEME["neon_green"], "size": 13, "family": "Courier New"},
        yshift=15,
    )
    
    fig.update_layout(
        barmode="stack",
        height=250,
        margin=dict(t=20, b=20, l=20, r=20),
        paper_bgcolor=THEME["card"],
        plot_bgcolor=THEME["bg"],
        font={"color": THEME["text_dim"]},
        yaxis={
            "range": [0, 1.1],
            "tickformat": ".0%",
            "gridcolor": THEME["grid"],
        },
        xaxis={"showgrid": False},
        legend={
            "orientation": "h",
            "yanchor": "top",
            "y": 1.15,
            "xanchor": "center",
            "x": 0.5,
            "font": {"color": THEME["text_dim"]},
        },
    )
    
    return fig


# ──────────────────────────────────────────────────────────────
# System Status Card Data
# ──────────────────────────────────────────────────────────────

def get_system_status(capture_stats: Dict, detector_stats: Dict) -> Dict:
    """
    Generate system status metrics for the dashboard header.
    """
    return {
        "packets_captured": capture_stats.get("packets_captured", 0),
        "flows_analyzed": detector_stats.get("flows_analyzed", 0),
        "alerts_generated": detector_stats.get("alerts_generated", 0),
        "alert_rate": detector_stats.get("alert_rate", 0),
        "active_flows": detector_stats.get("active_flows", 0),
        "uptime_seconds": capture_stats.get("duration_seconds", 0),
    }


# ──────────────────────────────────────────────────────────────
# CSS Injection Helper
# ──────────────────────────────────────────────────────────────

CINEMATIC_CSS = f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    /* Base */
    .stApp, .main, body {{background:{THEME['bg']};font-family:'Inter',sans-serif;}}
    
    /* Headings — Orbitron */
    h1,h2,h3,h4,.neon-text,.page-title,.section-title {{
        font-family:'Orbitron',sans-serif !important;
        color:{THEME['text']} !important;
        font-weight:700 !important;
        letter-spacing:1px !important;
    }}
    h1 {{font-size:28px !important;}}
    h2 {{font-size:20px !important;}}
    h3 {{font-size:16px !important;}}
    
    /* Body/UI — Inter */
    .metric-label,button,.stSelectbox,.stSlider,.stCheckbox,label,.stTextInput {{
        font-family:'Inter',sans-serif !important;
    }}
    p,span,div {{font-family:'Inter',sans-serif;}}
    
    /* Logs/Packets — JetBrains Mono */
    .terminal-container,.packet-row,pre,code,.hex-dump,.dataframe {{
        font-family:'JetBrains Mono',monospace !important;
    }}
    .packet-time,.packet-ip,.packet-port,.packet-proto,.packet-pred,.packet-risk {{
        font-family:'JetBrains Mono',monospace !important;
    }}
    
    /* Sidebar */
    section[data-testid="stSidebar"] {{
        background:{THEME['bg']};
        border-right:1px solid {THEME['card_border']};
    }}
    section[data-testid="stSidebar"] .stMarkdown {{
        font-family:'Inter',sans-serif;
    }}
    section[data-testid="stSidebar"] h1,section[data-testid="stSidebar"] h2 {{
        font-family:'Orbitron',sans-serif !important;
    }}
    
    /* Metric cards */
    .stMetric {{
        background:{THEME['card']};
        border:1px solid {THEME['card_border']};
        border-radius:12px;
        padding:16px 20px;
        box-shadow:0 4px 16px rgba(0,0,0,0.2);
    }}
    .stMetric:hover {{border-color:rgba(0,255,136,0.3);}}
    
    /* Buttons */
    .stButton>button {{
        font-family:'Inter',sans-serif;
        font-weight:600;
        background:{THEME['card']};
        color:{THEME['text']};
        border:1px solid {THEME['card_border']};
        border-radius:8px;
        padding:8px 18px;
        transition:all 0.2s;
    }}
    .stButton>button:hover {{
        border-color:{THEME['neon_green']};
        box-shadow:0 0 16px rgba(0,255,136,0.15);
    }}
    
    /* Sliders */
    .stSlider>div>div>div>div {{background:{THEME['neon_green']};}}
    
    /* Dataframes */
    .stDataFrame {{font-family:'JetBrains Mono',monospace !important;font-size:11px;}}
    
    /* Scrollbar */
    ::-webkit-scrollbar {{width:4px;height:4px;}}
    ::-webkit-scrollbar-track {{background:transparent;}}
    ::-webkit-scrollbar-thumb {{background:{THEME['card_border']};border-radius:2px;}}
    
    /* Animations */
    @keyframes pulse {{0%,100%{{opacity:1}}50%{{opacity:0.4}}}}
    @keyframes fadeIn {{from{{opacity:0;transform:translateY(8px)}}to{{opacity:1;transform:translateY(0)}}}}
    .fade-in {{animation:fadeIn 0.5s ease;}}
    
    /* Glass card */
    .glass-card {{
        background:rgba(15,23,42,0.6);
        backdrop-filter:blur(16px);
        border:1px solid rgba(0,255,136,0.2);
        border-radius:16px;
        padding:20px;
        box-shadow:0 8px 32px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.05);
    }}
    
    /* Live indicator */
    .live-dot {{
        display:inline-block;width:8px;height:8px;border-radius:50%;
        background:{THEME['neon_green']};box-shadow:0 0 12px {THEME['neon_green']};
        animation:pulse 2s infinite;
    }}
    
    /* Status badge */
    .status-online {{color:{THEME['neon_green']};font-family:'Inter',sans-serif;font-weight:600;font-size:11px;}}
    .status-offline {{color:{THEME['neon_red']};font-family:'Inter',sans-serif;font-weight:600;font-size:11px;}}
    
    /* Divider */
    hr {{border-color:{THEME['card_border']};margin:16px 0;}}
</style>
<script>
(function() {{
    function fixAutocomplete() {{
        document.querySelectorAll('input').forEach(function(el) {{
            var ac = el.getAttribute('autocomplete');
            if (ac === '' || ac === null || ac === undefined) {{
                el.setAttribute('autocomplete', 'off');
            }}
        }});
    }}
    fixAutocomplete();
    if (window.MutationObserver) {{
        new MutationObserver(fixAutocomplete).observe(document.documentElement, {{ childList: true, subtree: true }});
    }}
}})();
</script>
"""


# ──────────────────────────────────────────────────────────────
# Particle Network Map (Real-Time Flows & Nodes)
# ──────────────────────────────────────────────────────────────

def create_threat_gauge(value: float, title: str = "THREAT LEVEL", delta_ref: float = 0.0) -> go.Figure:
    """
    Cinematic semi-circular threat gauge with neon glow and dynamic status indicator.
    
    Args:
        value: 0.0 to 1.0 threat score
        title: Gauge title
        delta_ref: Previous reference score
    """
    pct = max(0.0, min(100.0, float(value) * 100))
    
    if pct >= 70:
        bar_color = THEME["neon_red"]
        status_text = "CRITICAL INVASION ALERT"
    elif pct >= 35:
        bar_color = THEME["neon_orange"]
        status_text = "ELEVATED SUSPICIOUS ACTIVITY"
    else:
        bar_color = THEME["neon_green"]
        status_text = "NOMINAL SECURE BASELINE"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=pct,
        title={
            "text": f"<b>{title}</b><br><span style='font-size:10px;font-family:Inter;color:{bar_color};'>{status_text}</span>",
            "font": {"color": THEME["text"], "size": 16, "family": "Orbitron"},
        },
        number={
            "suffix": "%",
            "font": {"color": bar_color, "size": 42, "family": "Orbitron"},
        },
        delta={"reference": delta_ref * 100, "increasing": {"color": THEME["neon_red"]}, "decreasing": {"color": THEME["neon_green"]}},
        gauge={
            "axis": {
                "range": [0, 100],
                "tickcolor": THEME["text_dim"],
                "tickfont": {"size": 9, "color": THEME["text_dim"]},
            },
            "bar": {"color": bar_color, "thickness": 0.28},
            "bgcolor": THEME["bg"],
            "borderwidth": 1,
            "bordercolor": THEME["card_border"],
            "steps": [
                {"range": [0, 35], "color": "rgba(0,255,136,0.12)"},
                {"range": [35, 70], "color": "rgba(255,140,51,0.12)"},
                {"range": [70, 100], "color": "rgba(255,51,85,0.18)"},
            ],
            "threshold": {
                "line": {"color": THEME["neon_red"], "width": 3},
                "thickness": 0.85,
                "value": 75,
            },
        },
    ))
    
    fig.update_layout(
        height=320,
        margin=dict(t=50, b=10, l=20, r=20),
        paper_bgcolor=THEME["card"],
        font={"color": THEME["text_dim"]},
    )
    
    return fig


def create_network_particles(active_nodes: List = None, target_ip: str = "192.168.1.1") -> go.Figure:
    """
    Animated particle network showing live traffic flows and endpoint status.
    """
    import math, time
    now = time.time()
    
    # Normalize input
    parsed_nodes = []
    if active_nodes:
        for item in active_nodes:
            if isinstance(item, str):
                parsed_nodes.append({"ip": item, "type": "Active Host", "threat": False})
            elif isinstance(item, dict):
                parsed_nodes.append(item)
    
    if not parsed_nodes:
        parsed_nodes = [
            {"ip": "192.168.1.105", "type": "Client", "threat": False, "volume": 42},
            {"ip": "10.0.0.15", "type": "Internal", "threat": False, "volume": 68},
            {"ip": "172.16.0.44", "type": "Gateway", "threat": False, "volume": 120},
            {"ip": "192.168.1.201", "type": "Web Client", "threat": False, "volume": 35},
        ]
    
    center_x, center_y = 0.5, 0.5
    n_sources = max(1, min(len(parsed_nodes), 8))
    radius = 0.35
    
    fig = go.Figure()
    
    source_x = []
    source_y = []
    source_colors = []
    source_labels = []
    source_hovers = []
    
    for i, node in enumerate(parsed_nodes[:n_sources]):
        angle = (2 * math.pi * i / n_sources) + (now * 0.08) % (2 * math.pi)
        sx = center_x + radius * math.cos(angle)
        sy = center_y + radius * math.sin(angle)
        source_x.append(sx)
        source_y.append(sy)
        
        is_threat = node.get("threat", False) or str(node.get("type", "")).lower() in ["threat", "dos", "portscan", "botnet", "webattack", "bruteforce", "sqli", "xss"]
        color = THEME["neon_red"] if is_threat else THEME["neon_blue"]
        source_colors.append(color)
        ip_str = str(node.get("ip", f"Node-{i+1}"))
        source_labels.append(ip_str[:13])
        source_hovers.append(f"<b>{ip_str}</b><br>Type: {node.get('type','Host')}<br>Status: {'⚠️ THREAT' if is_threat else '✅ Normal'}")
        
        # Connection line
        line_color = "rgba(255,51,85,0.4)" if is_threat else "rgba(0,212,255,0.25)"
        fig.add_trace(go.Scatter(
            x=[center_x, sx], y=[center_y, sy],
            mode="lines",
            line={"color": line_color, "width": 2 if is_threat else 1, "dash": "dot" if is_threat else "solid"},
            hoverinfo="skip", showlegend=False
        ))
        
        # Animated particle pulses along the edge
        for offset in [0.25, 0.55, 0.85]:
            t_pulse = ((now * 0.7 + offset + i * 0.2) % 1.0)
            px = center_x + (sx - center_x) * t_pulse
            py = center_y + (sy - center_y) * t_pulse
            fig.add_trace(go.Scatter(
                x=[px], y=[py],
                mode="markers",
                marker={
                    "size": 7 if is_threat else 5,
                    "color": THEME["neon_red"] if is_threat else THEME["neon_green"],
                    "symbol": "diamond" if is_threat else "circle",
                    "opacity": 0.85,
                },
                hoverinfo="skip", showlegend=False
            ))
            
    # Source nodes
    fig.add_trace(go.Scatter(
        x=source_x, y=source_y,
        mode="markers+text",
        marker={"size": 15, "color": source_colors, "line": {"width": 2, "color": "#FFFFFF"}, "symbol": "diamond"},
        text=source_labels,
        textposition="top center",
        textfont={"color": THEME["text"], "size": 9, "family": "JetBrains Mono"},
        hoverinfo="text",
        hovertext=source_hovers,
        name="Active Endpoints"
    ))
    
    # Center Defended Gateway
    fig.add_trace(go.Scatter(
        x=[center_x], y=[center_y],
        mode="markers+text",
        marker={"size": 26, "color": THEME["card"], "line": {"width": 3, "color": THEME["neon_green"]}, "symbol": "hexagon"},
        text=["🛡️"],
        textposition="middle center",
        textfont={"size": 14},
        hoverinfo="text",
        hovertext=f"<b>DEFENDED GATEWAY</b><br>Target IP: {target_ip}<br>Status: ACTIVE FIREWALL",
        name="Defended Gateway"
    ))
    
    fig.update_layout(
        title={"text": "<b>NETWORK TRAFFIC MAP</b>", "font": {"color": THEME["text"], "size": 14, "family": "Orbitron"}, "x": 0.5},
        height=320,
        margin=dict(t=40, b=20, l=20, r=20),
        paper_bgcolor=THEME["card"], plot_bgcolor=THEME["bg"],
        xaxis={"visible": False, "range": [0.05, 0.95]},
        yaxis={"visible": False, "range": [0.05, 0.95]},
        showlegend=False,
    )
    return fig


# ──────────────────────────────────────────────────────────────
# Radar Sweep Animation (Real-Time Threat Positioning)
# ──────────────────────────────────────────────────────────────

def create_radar_sweep(threats: List[Dict] = None) -> go.Figure:
    """
    Cinematic rotating radar sweep with threat blips.
    """
    import math, time
    now = time.time()
    
    if not threats:
        threats = [
            {"angle": 45, "distance": 0.65, "severity": "medium", "label": "PROBE"},
            {"angle": 190, "distance": 0.85, "severity": "high", "label": "DOS-SYN"},
            {"angle": 310, "distance": 0.40, "severity": "low", "label": "SCAN"},
        ]
        
    fig = go.Figure()
    
    # Radar concentric circles
    for r in [0.25, 0.5, 0.75, 1.0]:
        theta = [i * 0.02 * math.pi for i in range(101)]
        x = [r * math.cos(t) for t in theta]
        y = [r * math.sin(t) for t in theta]
        fig.add_trace(go.Scatter(
            x=x, y=y, mode="lines",
            line={"color": "rgba(0,255,136,0.15)", "width": 0.8},
            hoverinfo="skip", showlegend=False
        ))
        
    # Cross hairs
    fig.add_trace(go.Scatter(x=[-1, 1], y=[0, 0], mode="lines", line={"color": "rgba(0,255,136,0.25)", "width": 1}, hoverinfo="skip", showlegend=False))
    fig.add_trace(go.Scatter(x=[0, 0], y=[-1, 1], mode="lines", line={"color": "rgba(0,255,136,0.25)", "width": 1}, hoverinfo="skip", showlegend=False))
    
    # Dynamic rotating sweep line based on real-time clock (90 deg / sec)
    sweep_angle = (now * 90) % 360
    sweep_rad = sweep_angle * math.pi / 180
    sweep_x = [0, math.cos(sweep_rad)]
    sweep_y = [0, math.sin(sweep_rad)]
    
    fig.add_trace(go.Scatter(
        x=sweep_x, y=sweep_y,
        mode="lines",
        line={"color": THEME["neon_green"], "width": 2},
        hoverinfo="skip", showlegend=False, name="Sweep"
    ))
    
    # Phosphor trail cone behind sweep line
    trail_angles = [sweep_angle - i * 4 for i in range(10)]
    trail_x = [0] + [math.cos(a * math.pi / 180) for a in trail_angles] + [0]
    trail_y = [0] + [math.sin(a * math.pi / 180) for a in trail_angles] + [0]
    fig.add_trace(go.Scatter(
        x=trail_x, y=trail_y,
        fill="toself",
        fillcolor="rgba(0,255,136,0.08)",
        line={"width": 0},
        hoverinfo="skip", showlegend=False
    ))
    
    # Plot threat blips
    for threat in threats:
        angle_rad = threat["angle"] * math.pi / 180
        tx = threat["distance"] * math.cos(angle_rad)
        ty = threat["distance"] * math.sin(angle_rad)
        sev = str(threat.get("severity", "medium")).lower()
        color = SEVERITY_COLORS.get(sev, THEME["neon_blue"])
        size = 12 if sev == "high" else 9 if sev == "medium" else 6
        
        # Glow ring
        fig.add_trace(go.Scatter(
            x=[tx], y=[ty], mode="markers",
            marker={"size": size * 2.8, "color": color, "opacity": 0.25},
            hoverinfo="skip", showlegend=False
        ))
        
        # Blip marker
        fig.add_trace(go.Scatter(
            x=[tx], y=[ty], mode="markers+text",
            marker={"size": size, "color": color, "symbol": "diamond", "line": {"width": 1.5, "color": "white"}},
            text=[threat.get("label", "TARGET")],
            textposition="top right",
            textfont={"color": color, "size": 9, "family": "JetBrains Mono"},
            hovertext=f"<b>{threat.get('label','THREAT')}</b><br>Severity: {sev.upper()}<br>Range: {threat['distance']:.2f}",
            hoverinfo="text", showlegend=False
        ))
        
    fig.update_layout(
        title={"text": "<b>REAL-TIME THREAT RADAR</b>", "font": {"color": THEME["text"], "size": 14, "family": "Orbitron"}, "x": 0.5},
        height=320,
        margin=dict(t=40, b=20, l=20, r=20),
        paper_bgcolor=THEME["card"], plot_bgcolor=THEME["bg"],
        xaxis={"visible": False, "range": [-1.15, 1.15]},
        yaxis={"visible": False, "range": [-1.15, 1.15], "scaleanchor": "x"},
    )
    return fig


# ──────────────────────────────────────────────────────────────
# Real-Time Throughput Telemetry Chart (PPS / FPS / Alerts)
# ──────────────────────────────────────────────────────────────

def create_live_throughput_chart(history: List[Dict]) -> go.Figure:
    """
    Real-time rolling line chart showing Packets Per Second (PPS) and Flows Per Second (FPS).
    """
    if not history:
        history = [
            {"time": "00:00:00", "pps": 0, "fps": 0, "alerts": 0}
        ]
    df = pd.DataFrame(history)
    fig = go.Figure()
    
    # Packets/sec trace
    fig.add_trace(go.Scatter(
        x=df["time"], y=df["pps"],
        name="Packets/s",
        mode="lines+markers",
        line={"color": THEME["neon_blue"], "width": 2, "shape": "spline"},
        marker={"size": 4, "color": THEME["neon_blue"]},
        fill="tozeroy",
        fillcolor="rgba(0, 212, 255, 0.08)",
        hovertemplate="<b>%{x}</b><br>Throughput: %{y:.1f} pkts/s<extra></extra>"
    ))
    
    # Flows/sec trace
    fig.add_trace(go.Scatter(
        x=df["time"], y=df["fps"],
        name="Flows/s",
        mode="lines",
        line={"color": THEME["neon_purple"], "width": 2, "shape": "spline", "dash": "dash"},
        hovertemplate="<b>%{x}</b><br>Flows: %{y:.1f} flows/s<extra></extra>"
    ))
    
    # Alerts trigger dots
    if "alerts" in df.columns and df["alerts"].sum() > 0:
        alert_df = df[df["alerts"] > 0]
        fig.add_trace(go.Scatter(
            x=alert_df["time"], y=alert_df["pps"],
            name="Alert Spikes",
            mode="markers",
            marker={"size": 10, "color": THEME["neon_red"], "symbol": "cross", "line": {"width": 2, "color": "white"}},
            hovertemplate="<b>ALERT EVENT</b><br>Time: %{x}<br>Alerts in window: %{text}<extra></extra>",
            text=alert_df["alerts"]
        ))
        
    fig.update_layout(
        title={"text": "<b>REAL-TIME TRAFFIC THROUGHPUT & ALERT TELEMETRY</b>", "font": {"color": THEME["text"], "size": 14, "family": "Orbitron"}, "x": 0.5},
        height=280,
        margin=dict(t=40, b=30, l=40, r=20),
        paper_bgcolor=THEME["card"],
        plot_bgcolor=THEME["bg"],
        xaxis={"gridcolor": THEME["grid"], "tickfont": {"color": THEME["text_dim"], "size": 9, "family": "JetBrains Mono"}},
        yaxis={"gridcolor": THEME["grid"], "tickfont": {"color": THEME["text_dim"], "size": 9, "family": "JetBrains Mono"}, "title": "Rate / sec"},
        legend={"font": {"color": THEME["text_dim"], "size": 10}, "orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1},
    )
    return fig


# ──────────────────────────────────────────────────────────────
# Packet Hex Dump Inspector
# ──────────────────────────────────────────────────────────────

def format_hex_dump(packet_data: bytes = None, max_bytes: int = 256) -> str:
    """
    Format raw packet data as a cinematic hex dump.
    
    Returns HTML string with styled hex dump.
    """
    if packet_data is None:
        # Sample data for demonstration
        packet_data = bytes([
            0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
            0x40, 0x06, 0xB1, 0xE6, 0xC0, 0xA8, 0x00, 0xD0,
            0x8E, 0xFA, 0xB3, 0x52, 0xC5, 0x3A, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00, 0x91, 0x7C, 0x00, 0x00,
            0x47, 0x45, 0x54, 0x20, 0x2F, 0x20, 0x48, 0x54,
            0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D, 0x0A,
        ])
    
    data = packet_data[:max_bytes]
    
    hex_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append({
            "offset": f"{i:04X}",
            "hex": hex_part.ljust(47),
            "ascii": ascii_part,
        })
    
    html = """
    <div style="background:#0A0A0F; border:1px solid #1A1F2E; border-radius:4px; padding:15px; font-family:'Courier New',monospace; font-size:11px;">
    <div style="color:#00FF88; margin-bottom:10px; letter-spacing:2px;">╔══════════════════════════════════════════════════════════════╗</div>
    <div style="color:#00FF88; margin-bottom:8px;">║  OFFSET  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII         ║</div>
    <div style="color:#00FF88; margin-bottom:8px;">╠══════════════════════════════════════════════════════════════╣</div>
    """
    
    for line in hex_lines:
        offset_color = "#00D4FF"
        hex_color = "#C8CCD6"
        ascii_color = "#6B7280"
        
        # Highlight HTTP methods
        if "47 45 54" in line["hex"]:  # GET
            hex_color = "#FFD633"
        if "50 4F 53 54" in line["hex"]:  # POST
            hex_color = "#FF8C33"
        
        html += f"""
        <div style="margin:1px 0;">
            <span style="color:{offset_color};">║  {line['offset']}  </span>
            <span style="color:{hex_color};">{line['hex']}</span>
            <span style="color:{ascii_color}; margin-left:8px;">{line['ascii']}</span>
            <span style="color:#00FF88;">║</span>
        </div>"""
    
    html += """
    <div style="color:#00FF88; margin-top:8px;">╚══════════════════════════════════════════════════════════════╝</div>
    </div>
    """
    
    return html


# ──────────────────────────────────────────────────────────────
# Startup Animation Data
# ──────────────────────────────────────────────────────────────

def get_startup_html() -> str:
    """
    Cinematic startup loading sequence HTML.
    Displayed once on app launch.
    """
    return """
    <style>
        #startup-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #0A0A0F;
            z-index: 99999;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: fadeOut 0.5s ease-in-out 3s forwards;
        }
        
        @keyframes fadeOut {
            to { opacity: 0; visibility: hidden; }
        }
        
        .startup-content {
            text-align: center;
        }
        
        .startup-title {
            font-family: 'Courier New', monospace;
            font-size: 42px;
            color: #00FF88;
            text-shadow: 0 0 40px rgba(0,255,136,0.5);
            letter-spacing: 8px;
            animation: glitch 2s infinite;
        }
        
        @keyframes glitch {
            0%, 100% { transform: translate(0); }
            20% { transform: translate(-3px, 2px); }
            40% { transform: translate(3px, -2px); }
            60% { transform: translate(-2px, -1px); }
            80% { transform: translate(2px, 3px); }
        }
        
        .startup-subtitle {
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #6B7280;
            letter-spacing: 4px;
            margin-top: 10px;
        }
        
        .startup-bar {
            width: 300px;
            height: 2px;
            background: #1A1F2E;
            margin: 30px auto;
            position: relative;
            overflow: hidden;
        }
        
        .startup-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, transparent, #00FF88, transparent);
            animation: loadingBar 2.5s ease-in-out;
        }
        
        @keyframes loadingBar {
            from { width: 0; }
            to { width: 100%; }
        }
        
        .startup-status {
            font-family: 'Courier New', monospace;
            font-size: 11px;
            color: #00D4FF;
            letter-spacing: 2px;
            animation: blink 1s infinite;
        }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
    </style>
    
    <div id="startup-overlay">
        <div class="startup-content">
            <div class="startup-title">THREAT<br>COMMAND</div>
            <div class="startup-subtitle">SOC-NIDS // INITIALIZING</div>
            <div class="startup-bar">
                <div class="startup-bar-fill"></div>
            </div>
            <div class="startup-status">▸ LOADING MODULES...</div>
            <div style="font-family:'Courier New',monospace; font-size:9px; color:#6B7280; margin-top:20px;">
                CAPTURE ENGINE: ONLINE<br>
                FLOW EXTRACTOR: ONLINE<br>
                ML MODEL: LOADED<br>
                RULE ENGINE: ARMED<br>
                DASHBOARD: RENDERING...
            </div>
        </div>
    </div>
    """


# ──────────────────────────────────────────────────────────────
# Reusable UI Components for Multi-Page Dashboard
# ──────────────────────────────────────────────────────────────

def glass_card(content: str, padding: str = "20px") -> str:
    """Wrap content in a glassmorphism card."""
    return f"""
    <div style="background:rgba(15,23,42,0.6);backdrop-filter:blur(16px);
                border:1px solid rgba(0,255,136,0.2);border-radius:16px;
                padding:{padding};box-shadow:0 8px 32px rgba(0,0,0,0.4),
                inset 0 1px 0 rgba(255,255,255,0.05);margin-bottom:16px;">
        {content}
    </div>
    """

def neon_header(text: str, size: str = "24px") -> str:
    """Neon glow header."""
    return f"""
    <div style="font-size:{size};font-weight:700;color:{THEME['neon_blue']};
                text-shadow:0 0 10px rgba(0,212,255,0.5),0 0 40px rgba(0,212,255,0.2);
                margin-bottom:4px;">{text}</div>
    """

def metric_card(value, label: str, color: str = None, icon: str = "") -> str:
    """Single metric display card."""
    c = color or THEME['neon_green']
    return f"""
    <div style="background:{THEME['card']};border:1px solid {THEME['card_border']};
                border-radius:12px;padding:16px 20px;text-align:center;
                box-shadow:0 4px 16px rgba(0,0,0,0.2);">
        <div style="font-size:28px;font-weight:700;color:{c};">{icon} {value}</div>
        <div style="font-size:10px;color:{THEME['text_dim']};letter-spacing:1.5px;
                    text-transform:uppercase;margin-top:4px;">{label}</div>
    </div>
    """

def status_badge(status: str = "online") -> str:
    """Live/offline status indicator."""
    color = THEME['neon_green'] if status == "online" else THEME['neon_red']
    label = "LIVE" if status == "online" else "OFFLINE"
    return f"""
    <span style="display:inline-flex;align-items:center;gap:6px;">
        <span style="width:8px;height:8px;border-radius:50%;background:{color};
                     box-shadow:0 0 10px {color};animation:pulse 2s infinite;"></span>
        <span style="color:{color};font-size:11px;font-weight:600;">{label}</span>
    </span>
    """

def section_divider() -> str:
    """Subtle section divider."""
    return f'<div style="height:1px;background:{THEME["card_border"]};margin:16px 0;"></div>'

def page_header(title: str, subtitle: str = "", status_text: str = "") -> str:
    """Consistent page header across all pages."""
    from datetime import datetime
    now = datetime.now().strftime("%H:%M:%S")
    return f"""
    <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;">
        <div>
            <div style="font-size:22px;font-weight:700;color:{THEME['text']};">{title}</div>
            <div style="font-size:11px;color:{THEME['text_dim']};">{subtitle}</div>
        </div>
        <div style="text-align:right;">
            <div style="font-size:14px;color:{THEME['neon_green']};">{now}</div>
            <div style="font-size:10px;color:{THEME['text_dim']};">{status_text}</div>
        </div>
    </div>
    {section_divider()}
    """


# ──────────────────────────────────────────────────────────────
# Performance Monitoring Charts
# ──────────────────────────────────────────────────────────────

def create_performance_gauge(value: float, max_val: float = 100.0, title: str = "", unit: str = "%", 
                             color: str = None, **kwargs) -> go.Figure:
    """Mini gauge for performance metrics."""
    if isinstance(max_val, str):
        # Handle case where caller passed (value, title, unit)
        title, unit, max_val = max_val, title or "%", 100.0
    
    max_val = float(max_val) if max_val else 100.0
    val = float(value) if value is not None else 0.0
    
    if color is None:
        if val > max_val * 0.8:
            color = THEME['neon_red']
        elif val > max_val * 0.5:
            color = THEME['neon_orange']
        else:
            color = THEME['neon_green']
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=val,
        number={"suffix": unit, "font": {"color": color, "size": 24, "family": "Inter"}},
        title={"text": title, "font": {"color": THEME['text_dim'], "size": 10, "family": "Inter"}},
        gauge={
            "axis": {"range": [0, max_val], "tickcolor": THEME['text_dim']},
            "bar": {"color": color, "thickness": 0.15},
            "bgcolor": THEME['bg'],
            "steps": [
                {"range": [0, max_val*0.5], "color": "rgba(16,185,129,0.08)"},
                {"range": [max_val*0.5, max_val*0.8], "color": "rgba(245,158,11,0.08)"},
                {"range": [max_val*0.8, max_val], "color": "rgba(239,68,68,0.12)"},
            ],
        },
    ))
    fig.update_layout(height=200, margin=dict(t=30, b=10, l=10, r=10),
                      paper_bgcolor="rgba(0,0,0,0)")
    return fig


def create_performance_timeline(history: list, title: str = "", color: str = None, **kwargs) -> go.Figure:
    """Sparkline chart for performance history."""
    if not history:
        fig = go.Figure()
        fig.add_annotation(text="No data", x=0.5, y=0.5, showarrow=False,
                          font={"color": THEME['text_dim'], "size": 12})
        fig.update_layout(height=150, margin=dict(t=20, b=10, l=10, r=10),
                         paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                         xaxis={"visible": False}, yaxis={"visible": False})
        return fig
    
    color = color or THEME['neon_green']
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        y=list(history), mode="lines",
        line={"color": color, "width": 1.5, "shape": "spline"},
        fill="tozeroy",
        fillcolor=color.replace(")", ",0.15)").replace("rgb", "rgba") if "rgb" in color else "rgba(0,255,136,0.15)",
        hoverinfo="skip",
        showlegend=False,
    ))
    fig.update_layout(
        title={"text": title, "font": {"color": THEME['text_dim'], "size": 10, "family": "Inter"}, "x": 0.5, "y": 0.9},
        height=150, margin=dict(t=25, b=10, l=10, r=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis={"visible": False, "showgrid": False},
        yaxis={"visible": False, "showgrid": False},
    )
    return fig
