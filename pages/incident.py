"""Investigate flagged events, compare similar threats, and audit incident decisions."""

import pandas as pd
import streamlit as st
from history import STATUSES
from ui import header, alerts, report_view


def render() -> None:
    header("Incident investigation", "Follow the evidence from detection through recovery.")
    workflow = st.session_state.workflow
    found = alerts(st.session_state.scored)
    with st.expander("Start a new investigation", expanded=not bool(workflow.history.list())):
        if found.empty:
            st.info("Upload or load telemetry with anomalies to investigate.")
        else:
            selected = st.selectbox("Flagged event", found.event_id.tolist(), key="investigate-event")
            row = found.loc[found.event_id == selected].iloc[0].to_dict()
            st.json({k: row[k] for k in ["timestamp", "host", "message", "anomaly_score", "confidence"]})
            if st.button("Investigate selected event", type="primary"):
                try:
                    with st.spinner("Running five agents…"):
                        result = workflow.investigate(row)
                    st.session_state.active_incident = result["incident_id"]
                    st.rerun()
                except Exception as exc:
                    st.error("Investigation failed: " + type(exc).__name__)
    history = workflow.history.list()
    if not history:
        return
    ids = [r["incident_id"] for r in history]
    active = st.session_state.get("active_incident", ids[0])
    selected = st.selectbox(
        "Incident history",
        ids,
        index=ids.index(active) if active in ids else 0,
        format_func=lambda value: value + " / " + next(r["threat_name"] for r in history if r["incident_id"] == value),
    )
    report = workflow.history.get(selected)
    report_view(report)
    with st.expander("Update incident status & audit history"):
        with st.form("status-form"):
            status = st.selectbox("Status", STATUSES, index=STATUSES.index(report["status"]))
            note = st.text_area("Audit note", max_chars=2000)
            submit = st.form_submit_button("Save reviewed status")
        if submit:
            try:
                workflow.history.update_status(selected, status, note, report["revision"])
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
        st.dataframe(pd.DataFrame(workflow.history.audit(selected)), hide_index=True, width="stretch")
    st.markdown("#### Similar threat guidance")
    for doc in workflow.retriever.search(report["threat_name"]):
        with st.expander(f"{doc['title']} / similarity {doc['score']:.3f}"):
            st.caption(doc["source_id"])
            st.text(doc["text"])
    st.markdown("#### Related incident history")
    related = [
        {"incident_id": r["incident_id"], "threat": r["threat_name"], "severity": r["severity"], "status": r["status"]}
        for r in history
        if r["incident_id"] != selected and r["threat_name"] == report["threat_name"]
    ]
    if related:
        st.dataframe(pd.DataFrame(related), hide_index=True, width="stretch")
    else:
        st.caption("No matching threat hypothesis in stored incidents.")
