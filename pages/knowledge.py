"""Knowledge and incident similarity search plus grounded SOC chat."""

import pandas as pd
import streamlit as st
from ui import header


def render() -> None:
    header("Knowledge & SOC chat", "Search local guidance and ask questions grounded in retrieved sources.")
    workflow = st.session_state.workflow
    st.caption("Retrieval mode: " + workflow.retriever.mode)
    st.caption("Knowledge guidance is locally authored and versioned. Similarity is not threat likelihood.")
    if st.button("Refresh local knowledge index"):
        with st.spinner("Rebuilding changed knowledge sources…"):
            workflow.retriever.store.build()
        st.success("Knowledge index is current.")
    search_tab, chat_tab = st.tabs(["Knowledge search", "Chat with SOC Agent"])
    with search_tab:
        with st.form("knowledge-form"):
            query = st.text_input(
                "Search threat, technique, or investigation topic", value="brute force mitigation", max_chars=2000
            )
            top_k = st.slider("Top K", 1, 15, 5)
            submit = st.form_submit_button("Search knowledge base")
        if submit:
            st.session_state.search_results = workflow.retriever.search(query, top_k)
        for doc in st.session_state.get("search_results", []):
            with st.expander(f"{doc['title']} / {doc['score']:.3f}", expanded=True):
                st.caption(doc["source_id"])
                st.text(doc["text"])
        with st.expander("Knowledge inventory"):
            sources = {d["path"]: d["title"] for d in workflow.retriever.store.documents}
            st.dataframe(
                pd.DataFrame([{"source": k, "title": v} for k, v in sources.items()]), hide_index=True, width="stretch"
            )
        st.markdown("#### Threat similarity search")
        reports = workflow.history.list()
        if reports:
            query_incident = st.selectbox("Compare incident", [r["incident_id"] for r in reports])
            base = workflow.history.get(query_incident)
            other = [r for r in reports if r["incident_id"] != query_incident]
            if other:
                emb = workflow.retriever.embeddings
                vectors = emb.encode(
                    [base["threat_name"] + " " + base["incident_summary"]]
                    + [r["threat_name"] + " " + r["incident_summary"] for r in other]
                )
                similarity = vectors[1:] @ vectors[0]
                ranked = sorted(zip(other, similarity), key=lambda pair: float(pair[1]), reverse=True)[:5]
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "incident_id": r["incident_id"],
                                "threat": r["threat_name"],
                                "similarity": round(float(score), 4),
                            }
                            for r, score in ranked
                        ]
                    ),
                    hide_index=True,
                    width="stretch",
                )
            else:
                st.caption("Investigate at least two events to compare incident similarity.")
        else:
            st.caption("Create incident reports to enable similarity comparisons.")
    with chat_tab:
        messages = st.session_state.setdefault("chat_messages", [])
        for message in messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        question = st.chat_input("Ask about detection, mitigation, or a technique", max_chars=2000)
        if question:
            try:
                with st.spinner("Retrieving context and preparing response…"):
                    result = workflow.chat(question, messages)
                messages.extend(
                    [{"role": "user", "content": question}, {"role": "assistant", "content": result["answer"]}]
                )
                st.session_state.chat_messages = messages[-40:]
                st.session_state.chat_engine = result["provider"]
                st.session_state.chat_notice = result["fallback_reason"]
                st.rerun()
            except Exception as exc:
                st.error("Chat failed: " + type(exc).__name__)
        st.caption("Engine: " + st.session_state.get("chat_engine", workflow.provider.name))
        if st.session_state.get("chat_notice"):
            st.info(st.session_state.chat_notice)
        if st.button("Clear session chat"):
            st.session_state.chat_messages = []
            st.rerun()
