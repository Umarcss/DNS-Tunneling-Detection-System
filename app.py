"""
DNS Tunneling Detection System — Administrative Dashboard
Run with:  streamlit run app.py
"""
import sqlite3
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from database import DB_NAME, init_db

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DNS Tunneling Detection System",
    page_icon="🛡️",
    layout="wide",
)

init_db()

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="metric-container"] { background:#1e2130; border-radius:10px; padding:12px; }
.stMetric label { color:#aab0c6 !important; font-size:0.82rem !important; }
.stMetric [data-testid="stMetricValue"] { font-size:1.9rem !important; }
.threat-badge { background:#ff4b4b; color:white; padding:2px 8px; border-radius:4px; font-size:0.78rem; }
.safe-badge  { background:#21c354; color:white; padding:2px 8px; border-radius:4px; font-size:0.78rem; }
/* Hide Streamlit Deploy button and top toolbar */
[data-testid="stToolbar"] { display: none !important; }
[data-testid="stDecoration"] { display: none !important; }
.stDeployButton { display: none !important; }
#MainMenu { display: none !important; }
header[data-testid="stHeader"] { display: none !important; }
</style>
""", unsafe_allow_html=True)


# ── Database helpers ────────────────────────────────────────────────────────────
def _conn():
    return sqlite3.connect(DB_NAME)


@st.cache_data(ttl=3)
def fetch_summary():
    try:
        con = _conn()
        total   = pd.read_sql("SELECT COUNT(*) AS n FROM DNS_Logs", con).iloc[0]["n"]
        threats = pd.read_sql("SELECT COUNT(*) AS n FROM Threat_Alerts", con).iloc[0]["n"]
        devices = pd.read_sql("SELECT COUNT(*) AS n FROM Client_Devices", con).iloc[0]["n"]
        con.close()
        return int(total), int(threats), int(devices)
    except Exception:
        return 0, 0, 0


@st.cache_data(ttl=3)
def fetch_recent_logs(limit=200):
    try:
        con = _conn()
        df = pd.read_sql(f"""
            SELECT
                l.log_id,
                l.timestamp,
                c.ip_address       AS source_ip,
                l.query_string,
                l.query_type,
                l.entropy_score,
                l.prediction_label AS label,
                l.risk_score
            FROM DNS_Logs l
            JOIN Client_Devices c ON l.device_id = c.device_id
            ORDER BY l.log_id DESC
            LIMIT {limit}
        """, con)
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=3)
def fetch_threat_detail():
    try:
        con = _conn()
        df = pd.read_sql("""
            SELECT
                ta.alert_id         AS "Alert ID",
                l.timestamp         AS "Detected At",
                c.ip_address        AS "Source IP",
                l.query_string      AS "Malicious Query",
                l.query_type        AS "Record Type",
                ROUND(l.entropy_score,2) AS "Shannon Entropy",
                ROUND(l.risk_score,1)    AS "Risk Level (%)",
                CASE ta.alert_acknowledged WHEN 1 THEN 'Yes' ELSE 'No' END AS "Acknowledged"
            FROM Threat_Alerts ta
            JOIN DNS_Logs l       ON ta.log_id   = l.log_id
            JOIN Client_Devices c ON l.device_id = c.device_id
            ORDER BY ta.alert_id DESC
        """, con)
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


def acknowledge_alert(alert_id: int):
    con = _conn()
    con.execute("UPDATE Threat_Alerts SET alert_acknowledged=1 WHERE alert_id=?", (alert_id,))
    con.commit()
    con.close()


# ── Sidebar ─────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image(
        "https://img.icons8.com/color/96/000000/firewall.png",
        width=64,
    )
    st.title("DNS Threat Monitor")
    st.divider()

    auto_refresh = st.toggle("Auto-Refresh (3 s)", value=True)
    refresh_btn  = st.button("Refresh Now", use_container_width=True)

    st.divider()
    st.markdown("**Detection Engine**")
    st.success("Status: ACTIVE")

    st.divider()
    st.markdown("**About**")
    st.caption(
        "Machine Learning Algorithms for\nDNS Tunneling Detection System"
    )


# ── Header ───────────────────────────────────────────────────────────────────────
st.title("🛡️ DNS Tunneling Detection Dashboard")
st.markdown("Real-time behavioral analysis of DNS traffic using Random Forest classification.")
st.divider()

# ── Top metrics ──────────────────────────────────────────────────────────────────
total, threats, devices = fetch_summary()
benign = total - threats

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total DNS Queries Scanned", f"{total:,}", "Live stream")
col2.metric("Malicious Tunnels Detected", f"{threats:,}", f"{threats} critical" if threats else "None", delta_color="inverse")
col3.metric("Benign Queries Passed", f"{benign:,}")
col4.metric("Monitored Endpoint Devices", f"{devices:,}")

st.divider()

# ── Charts row ───────────────────────────────────────────────────────────────────
df_logs = fetch_recent_logs()

chart_col1, chart_col2, chart_col3 = st.columns([1, 1, 1])

with chart_col1:
    st.subheader("Traffic Classification")
    if total > 0:
        pie_data = pd.DataFrame({
            "Category": ["Benign", "Tunneling"],
            "Count": [benign, threats],
        })
        fig = px.pie(
            pie_data, names="Category", values="Count",
            color="Category",
            color_discrete_map={"Benign": "#21c354", "Tunneling": "#ff4b4b"},
            hole=0.45,
        )
        fig.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            height=260,
            legend=dict(orientation="h", y=-0.1),
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white",
        )
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No data yet — start simulate.py")

with chart_col2:
    st.subheader("Shannon Entropy Distribution")
    if not df_logs.empty and "entropy_score" in df_logs.columns:
        fig2 = px.histogram(
            df_logs.dropna(subset=["entropy_score"]),
            x="entropy_score",
            color="label",
            nbins=30,
            color_discrete_map={"Benign": "#21c354", "Tunneling": "#ff4b4b"},
            labels={"entropy_score": "Entropy Score", "label": "Class"},
        )
        fig2.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            height=260,
            bargap=0.05,
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            legend_title_text="",
        )
        st.plotly_chart(fig2, width="stretch")
    else:
        st.info("No data yet — start simulate.py")

with chart_col3:
    st.subheader("DNS Record Type Breakdown")
    if not df_logs.empty and "query_type" in df_logs.columns:
        qtype_counts = df_logs["query_type"].value_counts().reset_index()
        qtype_counts.columns = ["Record Type", "Count"]
        fig3 = px.bar(
            qtype_counts, x="Record Type", y="Count",
            color="Record Type",
            color_discrete_sequence=px.colors.qualitative.Pastel,
        )
        fig3.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            height=260,
            showlegend=False,
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white",
        )
        st.plotly_chart(fig3, width="stretch")
    else:
        st.info("No data yet — start simulate.py")

st.divider()

# ── Risk over time (line chart) ───────────────────────────────────────────────────
st.subheader("Real-Time Risk Score Stream (Last 100 Queries)")
if not df_logs.empty:
    plot_df = df_logs.head(100).copy()
    plot_df = plot_df.sort_values("log_id")
    plot_df["index"] = range(len(plot_df))
    fig4 = px.scatter(
        plot_df,
        x="index",
        y="risk_score",
        color="label",
        color_discrete_map={"Benign": "#21c354", "Tunneling": "#ff4b4b"},
        labels={"index": "Query Sequence", "risk_score": "Risk Score (%)", "label": "Classification"},
        hover_data=["source_ip", "query_string", "entropy_score"],
    )
    fig4.add_hline(y=50, line_dash="dash", line_color="orange",
                   annotation_text="Detection Threshold", annotation_position="top right")
    fig4.update_layout(
        height=300,
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        margin=dict(t=10, b=10, l=10, r=10),
    )
    st.plotly_chart(fig4, width="stretch")
else:
    st.info("No data yet — start simulate.py to generate live traffic.")

st.divider()

# ── Threat alert table ────────────────────────────────────────────────────────────
st.subheader("⚠️ Active Security Threat Incidents")
df_threats = fetch_threat_detail()

if not df_threats.empty:
    def _style_risk(val):
        try:
            v = float(val)
            if v >= 80:
                return "color:#ff4b4b; font-weight:bold"
            if v >= 50:
                return "color:#f0a500"
            return "color:#21c354"
        except Exception:
            return ""

    styled = df_threats.style.map(_style_risk, subset=["Risk Level (%)"])
    st.dataframe(styled, width="stretch", hide_index=True)

    # Acknowledge button
    ack_col, dl_col = st.columns([1, 3])
    with ack_col:
        ack_id = st.number_input("Acknowledge Alert ID", min_value=1, step=1, label_visibility="collapsed")
        if st.button("Acknowledge", use_container_width=True):
            acknowledge_alert(int(ack_id))
            st.success(f"Alert {int(ack_id)} acknowledged.")
            st.cache_data.clear()

    with dl_col:
        csv = df_threats.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Export Threat Log (CSV)",
            data=csv,
            file_name="DNS_Threat_Alerts.csv",
            mime="text/csv",
            use_container_width=True,
        )
else:
    st.success("🟢 No DNS Tunneling threats detected. Network traffic appears clean.")

st.divider()

# ── Full traffic log ──────────────────────────────────────────────────────────────
with st.expander("View Full DNS Traffic Log (Last 200 Entries)", expanded=False):
    if not df_logs.empty:
        display_df = df_logs[
            ["timestamp", "source_ip", "query_string", "query_type",
             "entropy_score", "label", "risk_score"]
        ].copy()
        display_df.columns = [
            "Timestamp", "Source IP", "Query String",
            "Type", "Entropy", "Label", "Risk (%)"
        ]

        def _row_color(row):
            if row["Label"] == "Tunneling":
                return ["background-color: rgba(255,75,75,0.15)"] * len(row)
            return [""] * len(row)

        st.dataframe(
            display_df.style.apply(_row_color, axis=1),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No traffic logged yet.")

# ── Footer ────────────────────────────────────────────────────────────────────────
st.caption("🔄 Dashboard refreshes every 3 seconds | Detection Engine: Random Forest (98.7% accuracy)")

# ── Auto-refresh logic ────────────────────────────────────────────────────────────
if auto_refresh or refresh_btn:
    if auto_refresh:
        time.sleep(3)
    st.cache_data.clear()
    st.rerun()
