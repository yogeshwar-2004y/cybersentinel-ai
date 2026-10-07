"""Searchable persistent incident register and portable exports."""

import pandas as pd
import streamlit as st
from ui import header, exports


def render() -> None:
    header("Incident reports", "Evidence, rationale, and accountable response in one record.")
    reports = st.session_state.workflow.history.list()
    if not reports:
        st.info("Run an investigation from Dashboard or Incident Investigation to create a report.")
        return
    left, right = st.columns(2)
    severity = left.multiselect(
        "Severity", ["Low", "Medium", "High", "Critical"], default=["Low", "Medium", "High", "Critical"]
    )
    search = right.text_input("Search by threat or incident ID", max_chars=200)
    filtered = [
        r
        for r in reports
        if r["severity"] in severity and search.lower() in (r["threat_name"] + " " + r["incident_id"]).lower()
    ]
    if not filtered:
        st.info("No matching incidents.")
        return
    table = pd.DataFrame(
        [
            {k: r[k] for k in ["incident_id", "timestamp", "threat_name", "severity", "risk_score", "status"]}
            for r in filtered
        ]
    )
    st.dataframe(table, hide_index=True, width="stretch")
    selected = st.selectbox("Export incident", [r["incident_id"] for r in filtered])
    report = st.session_state.workflow.history.get(selected)
    st.write(report["incident_summary"])
    exports(report, "reports-")
    import json

    st.download_button(
        "Export filtered incident bundle (JSON)",
        json.dumps(filtered, indent=2, ensure_ascii=False),
        "incident_bundle.json",
        "application/json",
    )
