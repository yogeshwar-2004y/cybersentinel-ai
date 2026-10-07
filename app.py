"""Streamlit application entry point with explicit navigation and isolated upload state."""

from dataclasses import replace
import pandas as pd
import streamlit as st
from config import Config, ROOT
from ml.detector import AnomalyDetector
from workflow import SOCWorkflow
from utils import setup_logging
from ui import CSS
from pages import dashboard, incident, analytics, reports, knowledge


@st.cache_resource(show_spinner="Preparing local knowledge index…")
def get_workflow(config: Config) -> SOCWorkflow:
    return SOCWorkflow(config)


@st.cache_resource(show_spinner="Training reference anomaly model…")
def demo_detector(contamination: float, baseline_bytes: bytes) -> AnomalyDetector:
    from io import BytesIO

    return AnomalyDetector(contamination).fit(pd.read_csv(BytesIO(baseline_bytes)))


def main() -> None:
    st.set_page_config(page_title="CyberSentinel AI | SOC", page_icon=str(ROOT / "assets/logo.png"), layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    setup_logging()
    base = Config()
    if base.require_auth and not getattr(st.user, "is_logged_in", False):
        st.title("CyberSentinel AI sign-in")
        st.caption("Sign in through the configured organization identity provider.")
        if st.button("Sign in"):
            try:
                st.login()
            except Exception:
                st.error("Configure OIDC in .streamlit/secrets.toml before enabling REQUIRE_AUTH.")
        st.stop()
    with st.sidebar:
        if base.require_auth:
            if st.button("Sign out"):
                st.logout()
        st.image(str(ROOT / "assets/logo.png"), width=60)
        st.title("CyberSentinel AI")
        st.caption("AGENTIC SECURITY OPERATIONS")
        provider = st.selectbox(
            "Analysis provider",
            ["local", "openai", "gemini", "ollama"],
            index=["local", "openai", "gemini", "ollama"].index(base.provider),
        )
        cloud = st.checkbox(
            "Allow redacted logs in cloud requests",
            value=base.allow_cloud_logs,
            help="Enables OpenAI/Gemini transmission. Redaction reduces exposure but cannot guarantee removal of all sensitive content.",
        )
        st.caption("Default: local analysis. API keys are read from .env or environment variables.")
        st.divider()
        st.caption("Response actions are recommendations. Investigations never change external systems.")
    config = replace(base, provider=provider, allow_cloud_logs=cloud)
    try:
        workflow = get_workflow(config)
        if "detector" not in st.session_state:
            st.session_state.detector = demo_detector(
                config.contamination, (ROOT / "data/baseline_logs.csv").read_bytes()
            )
            st.session_state.reference_name = "Independent synthetic normal baseline (800 windows)"
        st.session_state.workflow = workflow
        st.session_state.config = config
        if "scored" not in st.session_state:
            st.session_state.scored = st.session_state.detector.score(pd.read_csv(config.dataset_path))
            st.session_state.dataset_name = "Synthetic demo"
    except Exception as exc:
        st.error("Initialization failed: " + str(exc))
        st.stop()
    page = st.navigation(
        [
            st.Page(
                dashboard.render, title="Dashboard", icon=":material/dashboard:", default=True, url_path="dashboard"
            ),
            st.Page(incident.render, title="Incident Investigation", icon=":material/security:", url_path="incident"),
            st.Page(analytics.render, title="Analytics", icon=":material/analytics:", url_path="analytics"),
            st.Page(reports.render, title="Reports", icon=":material/description:", url_path="reports"),
            st.Page(knowledge.render, title="Knowledge Search", icon=":material/search:", url_path="knowledge"),
        ]
    )
    with st.sidebar:
        st.divider()
        st.caption("Retrieval: " + workflow.retriever.mode)
        if workflow.retriever.embeddings.fallback_reason:
            st.caption(workflow.retriever.embeddings.fallback_reason)
        st.caption("v1.0.0 • Evidence-led investigation")
    page.run()


if __name__ == "__main__":
    main()
