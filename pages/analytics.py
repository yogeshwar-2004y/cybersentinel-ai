"""Interactive model, threat, and incident analytics."""

import pandas as pd
import plotly.express as px
import streamlit as st
from ui import header, chart, alerts
from config import FEATURES


def render() -> None:
    header("Threat analytics", "Explore score distributions, telemetry patterns, and investigated activity.")
    frame = st.session_state.scored.copy()
    frame["classification"] = frame.prediction.map({-1: "Anomaly", 1: "Normal"})
    left, right = st.columns(2)
    with left:
        chart(
            px.histogram(
                frame,
                x="anomaly_score",
                color="classification",
                nbins=40,
                barmode="overlay",
                color_discrete_map={"Anomaly": "#fb923c", "Normal": "#23d5c3"},
                title="Anomaly score distribution",
            ),
            "score-hist",
        )
    with right:
        feature = st.selectbox("Feature distribution", FEATURES, index=2)
        chart(
            px.box(
                frame,
                x="classification",
                y=feature,
                color="classification",
                log_y=False,
                color_discrete_map={"Anomaly": "#fb923c", "Normal": "#23d5c3"},
                title=feature,
            ),
            "feature-box",
        )
    found = alerts(frame)
    if not found.empty:
        counts = found.groupby("threat_name").size().reset_index(name="alerts").sort_values("alerts")
        chart(
            px.bar(
                counts,
                x="alerts",
                y="threat_name",
                orientation="h",
                title="Candidate threat categories",
                color_discrete_sequence=["#23d5c3"],
            ),
            "threat-counts",
        )
    st.subheader("Feature relationships")
    chart(
        px.imshow(
            frame[list(FEATURES)].corr(),
            color_continuous_scale="Teal",
            zmin=-1,
            zmax=1,
            title="Numeric telemetry correlation",
        ),
        "feature-correlation",
    )
    if "ground_truth" in frame:
        st.subheader("Synthetic benchmark only")
        st.caption("Demo labels are never model inputs. These results are not evidence of production accuracy.")
        from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

        actual = frame.ground_truth != "normal"
        predicted = frame.prediction == -1
        p, r, f, _ = precision_recall_fscore_support(actual, predicted, average="binary", zero_division=0)
        a, b, c = st.columns(3)
        a.metric("Precision", f"{p:.1%}")
        b.metric("Recall", f"{r:.1%}")
        c.metric("F1", f"{f:.1%}")
        chart(
            px.imshow(
                confusion_matrix(actual, predicted, labels=[False, True]),
                x=["Normal", "Anomaly"],
                y=["Normal", "Anomaly"],
                text_auto=True,
                labels={"x": "Predicted", "y": "Actual"},
                title="Synthetic confusion matrix",
            ),
            "confusion",
        )
    reports = st.session_state.workflow.history.list()
    if reports:
        st.subheader("Investigated incidents")
        summary = pd.DataFrame(
            [
                {k: r[k] for k in ["incident_id", "timestamp", "threat_name", "severity", "status", "risk_score"]}
                for r in reports
            ]
        )
        status = summary.groupby("status").size().reset_index(name="count")
        chart(px.bar(status, x="status", y="count", color_discrete_sequence=["#23d5c3"]), "incident-status")
        st.dataframe(summary, hide_index=True, width="stretch")
