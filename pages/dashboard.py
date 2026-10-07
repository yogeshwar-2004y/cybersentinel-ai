"""SOC overview, CSV intake, triage, and investigation kickoff."""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from utils import read_csv
from ui import header, chart, alerts, COLORS


def render() -> None:
    header(
        "Security operations, in focus.",
        "Detect unusual activity. Retrieve trusted context. Investigate with evidence.",
    )
    config, detector, workflow = st.session_state.config, st.session_state.detector, st.session_state.workflow
    with st.expander("Log intake & reference baseline", expanded=False):
        left, right = st.columns(2)
        with left:
            uploaded = st.file_uploader("Security event CSV", type=["csv"], key="event-upload")
            st.caption("Eight numeric features are required. Metadata is optional. Maximum 20 MiB / 50,000 rows.")
            if st.button("Analyze uploaded CSV", disabled=uploaded is None):
                try:
                    st.session_state.scored = detector.score(read_csv(uploaded.getvalue(), config))
                    st.session_state.dataset_name = uploaded.name
                    st.success("Telemetry scored against the active reference baseline.")
                except (ValueError, RuntimeError) as exc:
                    st.error(str(exc))
            if st.button("Load demonstration dataset"):
                st.session_state.scored = detector.score(pd.read_csv(config.dataset_path))
                st.session_state.dataset_name = "Synthetic demo"
        with right:
            st.caption("Active reference: " + st.session_state.reference_name)
            reference = st.file_uploader("Trusted baseline CSV", type=["csv"], key="baseline-upload")
            st.caption(
                "Use reviewed normal telemetry with the same aggregation window. Minimum 32 rows. Scoring does not refit."
            )
            if st.button("Fit trusted baseline", disabled=reference is None):
                try:
                    from ml.detector import AnomalyDetector

                    baseline = read_csv(reference.getvalue(), config)
                    # A per-session model avoids mutating the shared cached demo estimator.
                    st.session_state.detector = AnomalyDetector(config.contamination).fit(baseline)
                    st.session_state.reference_name = reference.name
                    st.session_state.scored = st.session_state.detector.score(st.session_state.scored)
                    st.rerun()
                except (ValueError, RuntimeError) as exc:
                    st.error(str(exc))
    frame = st.session_state.scored
    found = alerts(frame)
    a, b, c, d = st.columns(4)
    a.metric("Events reviewed", f"{len(frame):,}")
    b.metric("Anomalies flagged", f"{len(found):,}")
    c.metric("High priority", f"{found['severity'].isin(['High', 'Critical']).sum():,}" if not found.empty else "0")
    d.metric("Incident history", len(workflow.history.list()))
    st.caption(
        f"Dataset: {st.session_state.dataset_name} | Model: {detector.reference_id} | Retrieval: {workflow.retriever.mode}"
    )
    left, right = st.columns([1, 1.65])
    with left:
        st.subheader("Severity distribution")
        if not found.empty:
            chart(
                px.pie(found, names="severity", hole=0.7, color="severity", color_discrete_map=COLORS), "severity-pie"
            )
        else:
            st.info("No anomalies detected in this dataset.")
    with right:
        st.subheader("Threat timeline")
        timeline = frame.copy()
        timeline["time"] = pd.to_datetime(timeline.timestamp, utc=True)
        timeline["result"] = timeline.prediction.map({-1: "Anomaly", 1: "Normal"})
        chart(
            px.scatter(
                timeline,
                x="time",
                y="anomaly_score",
                color="result",
                color_discrete_map={"Anomaly": "#fb923c", "Normal": "#23d5c3"},
                hover_data=["event_id", "host"],
            ),
            "timeline",
        )
    left, right = st.columns([1, 1.65])
    with left:
        st.subheader("Risk meter")
        risk = int(found.risk_score.max()) if not found.empty else 0
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=risk,
                number={"suffix": " / 100"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#23d5c3"},
                    "steps": [
                        {"range": [0, 40], "color": "#173749"},
                        {"range": [40, 70], "color": "#5a4727"},
                        {"range": [70, 100], "color": "#613636"},
                    ],
                },
            )
        )
        chart(fig, "risk-meter")
        st.caption("Highest triage estimate. Severity is preliminary until investigation.")
    with right:
        st.subheader("Latest alerts")
        if not found.empty:
            recent = found.sort_values("timestamp", ascending=False).head(20)
            st.dataframe(
                recent[["event_id", "timestamp", "threat_name", "severity", "anomaly_score", "risk_score"]],
                hide_index=True,
                width="stretch",
            )
            st.download_button("Export scored telemetry", frame.to_csv(index=False), "scored_logs.csv", "text/csv")
    st.subheader("Investigate an alert")
    if not found.empty:
        event_id = st.selectbox(
            "Event",
            found.event_id.tolist(),
            format_func=lambda value: value + " / " + found.loc[found.event_id == value, "threat_name"].iloc[0],
        )
        if st.button("Run agent investigation", type="primary"):
            try:
                with st.spinner("Detection → Intelligence → Analysis → Response → Report"):
                    report = workflow.investigate(found.loc[found.event_id == event_id].iloc[0].to_dict())
                st.session_state.active_incident = report["incident_id"]
                st.success("Incident saved: " + report["incident_id"])
            except Exception as exc:
                st.error("Investigation failed: " + type(exc).__name__ + ". Check configuration and application logs.")
    history = workflow.history.list()
    if history:
        latest = workflow.history.get(st.session_state.get("active_incident", history[0]["incident_id"]))
        st.markdown("#### MITRE mapping & response recommendations")
        if latest["mitre_mapping"]:
            st.dataframe(pd.DataFrame(latest["mitre_mapping"]), hide_index=True, width="stretch")
        else:
            st.caption("No supported MITRE technique mapping asserted.")
        for action in latest["recommended_actions"]:
            st.write("• " + action)
        st.caption("Full evidence, playbook, and exports are available in Incident Investigation.")
