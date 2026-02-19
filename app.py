import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest
import plotly.express as px

# ---------------- PAGE CONFIG ---------------- #
st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- CUSTOM CYBER STYLE ---------------- #
st.markdown("""
    <style>
    .main {
        background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
    }
    h1 {
        color: #00ffd5;
        text-align: center;
    }
    .stMetric {
        background-color: rgba(255,255,255,0.05);
        padding: 15px;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

st.markdown("<h1>🛡️ CyberShield AI - Log Threat Detection System</h1>", unsafe_allow_html=True)

st.markdown("AI-powered detection of suspicious login activity.")

# ---------------- SIDEBAR ---------------- #
st.sidebar.header("⚙️ Filter Options")

uploaded_file = st.file_uploader("Upload Log CSV File", type=["csv"])

if uploaded_file:

    df = pd.read_csv(uploaded_file)

    required_columns = {"time", "user", "ip", "status"}

    if not required_columns.issubset(df.columns):
        st.error("CSV must contain: time, user, ip, status")
    else:

        # Sidebar Filters
        selected_status = st.sidebar.multiselect(
            "Filter by Status",
            options=df["status"].unique(),
            default=df["status"].unique()
        )

        df = df[df["status"].isin(selected_status)]

        # ---------------- METRICS ---------------- #
        col1, col2, col3, col4 = st.columns(4)

        total_logs = len(df)
        failed_logs = len(df[df["status"] == "LOGIN_FAIL"])
        unique_ips = df["ip"].nunique()
        unique_users = df["user"].nunique()

        col1.metric("Total Logs", total_logs)
        col2.metric("Failed Logins", failed_logs)
        col3.metric("Unique IPs", unique_ips)
        col4.metric("Unique Users", unique_users)

        # ---------------- FAILED ANALYSIS ---------------- #
        failed = df[df["status"] == "LOGIN_FAIL"]
        fail_counts = failed.groupby("ip").size().reset_index(name="fail_count")

        if len(fail_counts) > 0:

            # Risk scoring
            def calculate_risk(count):
                if count > 3:
                    return "HIGH"
                elif count > 1:
                    return "MEDIUM"
                else:
                    return "LOW"

            fail_counts["risk_level"] = fail_counts["fail_count"].apply(calculate_risk)

            # AI anomaly detection
            if len(fail_counts) > 1:
                model = IsolationForest(contamination=0.2, random_state=42)
                fail_counts["anomaly"] = model.fit_predict(fail_counts[["fail_count"]])
            else:
                fail_counts["anomaly"] = 1

            # ---------------- SUSPICIOUS REPORT ---------------- #
            st.subheader("🚨 Threat Intelligence Report")

            for _, row in fail_counts.iterrows():
                if row["anomaly"] == -1:
                    st.error(f"⚠️ Suspicious IP: {row['ip']} | Failures: {row['fail_count']} | Risk: {row['risk_level']}")
                else:
                    st.success(f"✅ Normal IP: {row['ip']} | Failures: {row['fail_count']} | Risk: {row['risk_level']}")

            # ---------------- BAR CHART ---------------- #
            st.subheader("📊 Failed Login Attempts Per IP")
            st.bar_chart(fail_counts.set_index("ip")["fail_count"])

            # ---------------- PIE CHART ---------------- #
            st.subheader("📈 Risk Distribution")
            pie_fig = px.pie(
                fail_counts,
                names="risk_level",
                title="Risk Level Breakdown"
            )
            st.plotly_chart(pie_fig, use_container_width=True)

            # ---------------- DOWNLOAD REPORT ---------------- #
            st.subheader("📥 Download Threat Report")
            csv_report = fail_counts.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download CSV Report",
                data=csv_report,
                file_name="cybershield_threat_report.csv",
                mime="text/csv"
            )

            # ---------------- DATA TABLE ---------------- #
            st.subheader("📋 Detailed Threat Table")
            st.dataframe(fail_counts, use_container_width=True)

        else:
            st.success("No failed login attempts detected 🎉")

else:
    st.info("Upload a CSV file to begin threat analysis.")
st.markdown("""
<br><br><br>
<hr style="border:1px solid #00ffd5;">
<h2 style='text-align: center; color: #00ffd5;'>
🚀 Created by Laiba
</h2>
""", unsafe_allow_html=True)
