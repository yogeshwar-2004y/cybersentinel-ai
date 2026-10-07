"""Shared Streamlit components and Plotly styling."""

import pandas as pd
import streamlit as st
from intelligence import hypothesis
from report.generator import ReportGenerator

COLORS = {"Low": "#38bdf8", "Medium": "#fbbf24", "High": "#fb923c", "Critical": "#f87171"}

CSS = """<style>
.stApp{background:radial-gradient(ellipse at 85% 0%,#102c3a 0%,#09121f 42%);color:#edf5fb}
[data-testid=stSidebar]{background:#0a1523;border-right:1px solid #203346}
[data-testid=stMetric]{background:#0f2032;border:1px solid #244259;border-radius:14px;padding:18px}
[data-testid=stMetricValue]{color:#23d5c3;font-size:2.2rem}
h1,h2,h3{letter-spacing:-.035em} .stButton>button{border-radius:9px}
[data-testid=stHeader]{background:transparent}
.hero{padding:24px 0 18px;border-bottom:1px solid #244259;margin-bottom:25px}
.hero .eyebrow{color:#23d5c3;font-family:monospace;letter-spacing:.16em;font-size:12px}
.hero h1{font-size:42px;margin:8px 0}.hero p{color:#92a9bd;font-size:16px}
</style>"""


def header(title: str, subtitle: str) -> None:
    # Only trusted constants are passed into this component.
    from html import escape

    st.markdown(
        f'<div class="hero"><div class="eyebrow">CYBERSENTINEL / SECURITY OPERATIONS</div>'
        f"<h1>{escape(title)}</h1><p>{escape(subtitle)}</p></div>",
        unsafe_allow_html=True,
    )


def chart(fig, key: str) -> None:
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#b4cadc"},
        margin={"l": 12, "r": 12, "t": 42, "b": 12},
        height=340,
    )
    st.plotly_chart(fig, width="stretch", key=key)


def alerts(frame: pd.DataFrame) -> pd.DataFrame:
    anomalous = frame[frame.prediction == -1].copy()
    if anomalous.empty:
        return anomalous
    candidates = [hypothesis(row) for row in anomalous.to_dict("records")]
    anomalous["threat_name"] = [c["name"] for c in candidates]
    anomalous["severity"] = [c["severity"] for c in candidates]
    anomalous["risk_score"] = [c["risk_score"] for c in candidates]
    return anomalous.sort_values(["risk_score", "anomaly_score"], ascending=False)


def exports(report: dict, prefix: str = "") -> None:
    gen = ReportGenerator()
    cols = st.columns(3)
    identifier = report["incident_id"]
    cols[0].download_button(
        "Download Markdown", gen.markdown(report), identifier + ".md", mime="text/markdown", key=prefix + "md"
    )
    cols[1].download_button(
        "Download JSON", gen.json_bytes(report), identifier + ".json", mime="application/json", key=prefix + "json"
    )
    cols[2].download_button(
        "Download PDF", gen.pdf_bytes(report), identifier + ".pdf", mime="application/pdf", key=prefix + "pdf"
    )


def report_view(report: dict) -> None:
    st.subheader(report["threat_name"])
    st.caption(f"{report['incident_id']} • {report['timestamp']} • {report['status']}")
    a, b, c, d = st.columns(4)
    a.metric("Severity", report["severity"])
    b.metric("Risk estimate", f"{report['risk_score']}/100")
    c.metric("Analysis confidence", f"{report['confidence']:.0%}")
    d.metric("Analysis engine", report["provenance"]["analysis_provider"])
    st.caption("Confidence and risk are uncalibrated heuristics. Candidate techniques require evidence review.")
    if report["provenance"]["fallback_reason"]:
        st.info(report["provenance"]["fallback_reason"])
    tabs = st.tabs(["Analysis", "Evidence & MITRE", "Response", "Sources & Trace"])
    with tabs[0]:
        st.write(report["incident_summary"])
        st.markdown("#### Threat explanation")
        st.write(report["threat_explanation"])
        st.markdown("#### Business impact")
        st.write(report["business_impact"])
        st.markdown("#### Technical explanation")
        st.write(report["technical_explanation"])
        st.markdown("#### Attack chain")
        for item in report["attack_chain"]:
            st.write("• " + item)
        st.markdown("#### Uncertainties")
        for item in report["uncertainties"]:
            st.write("• " + item)
    with tabs[1]:
        if report["mitre_mapping"]:
            st.dataframe(pd.DataFrame(report["mitre_mapping"]), hide_index=True, width="stretch")
        else:
            st.info("No supported technique mapping asserted.")
        st.json(report["evidence"])
    with tabs[2]:
        for action in report["recommended_actions"]:
            st.write("• " + action)
        for step in report["playbook"]:
            with st.expander(step["phase"] + " / " + step["owner"]):
                st.write(step["action"])
                st.caption("Approval required: " + str(step["approval_required"]))
                st.write("Validation: " + step["validation"])
        st.markdown("#### SOC checklist")
        for i, item in enumerate(report["soc_checklist"]):
            st.checkbox(item, key=f"{report['incident_id']}-check-{i}")
        st.caption("Checklist selections are session notes; incident status changes are audited.")
        st.markdown("#### Next investigation steps")
        for item in report["next_investigation_steps"]:
            st.write("• " + item)
        st.markdown("#### Recovery")
        for item in report["recovery"]:
            st.write("• " + item)
    with tabs[3]:
        st.json(report["provenance"])
        st.dataframe(pd.DataFrame(report["agent_trace"]), hide_index=True, width="stretch")
        for doc in report["sources"]:
            with st.expander(f"{doc['title']} / {doc['score']:.3f}"):
                st.caption(doc["source_id"])
                st.text(doc["text"])
    exports(report, "view-")
