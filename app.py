"""
CyberShield AI — Streamlit Analyst Interface

Multi-page layout:
  Tab 1 — 💬 Knowledge Chat   (RAG Q&A)
  Tab 2 — 🔍 Incident Analyzer (log upload → detection → RAG enrichment)

Run:  streamlit run app.py
"""

import json
import streamlit as st
import pandas as pd

import config
from rag import CyberShieldRAG
from analyzers.log_parser import LogParser
from analyzers.detection_rules import DetectionEngine
from analyzers.incident_analyzer import IncidentAnalyzer


# ── Page configuration ─────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    .main { background-color: #0e1117; }
    .stChatMessage { border-radius: 12px; }

    .source-card {
        background: linear-gradient(135deg, #1a1f2e 0%, #141824 100%);
        border: 1px solid #2d3548;
        border-radius: 10px;
        padding: 14px 18px;
        margin: 6px 0;
        font-size: 0.88rem;
    }
    .source-card .tag {
        display: inline-block;
        background: #3b82f6;
        color: #fff;
        border-radius: 4px;
        padding: 2px 8px;
        font-weight: 700;
        margin-right: 8px;
        font-size: 0.8rem;
    }
    .source-card .title { font-weight: 600; color: #e2e8f0; }
    .source-card .link  { color: #60a5fa; font-size: 0.8rem; }

    .hero-title {
        font-size: 2rem; font-weight: 800;
        background: linear-gradient(90deg, #3b82f6, #8b5cf6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0;
    }
    .hero-subtitle { color: #94a3b8; font-size: 1rem; margin-top: 4px; }

    .alert-card {
        border-radius: 10px;
        padding: 16px 20px;
        margin: 10px 0;
        border-left: 5px solid;
    }
    .alert-HIGH   { background: #1c1017; border-color: #ef4444; }
    .alert-MEDIUM { background: #1c1a10; border-color: #f59e0b; }
    .alert-LOW    { background: #101c1a; border-color: #22d3ee; }

    .severity-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
        color: #fff;
    }
    .sev-HIGH   { background: #ef4444; }
    .sev-MEDIUM { background: #f59e0b; }
    .sev-LOW    { background: #22d3ee; color: #0e1117; }

    .metric-box {
        background: linear-gradient(135deg, #1a1f2e, #141824);
        border: 1px solid #2d3548;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .metric-box .value {
        font-size: 2rem; font-weight: 800; color: #e2e8f0;
    }
    .metric-box .label {
        font-size: 0.85rem; color: #94a3b8; margin-top: 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ── Sidebar ────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ CyberShield AI")
    st.caption("Cybersecurity Investigation Platform")
    st.divider()

    st.markdown("**LLM Model**")
    st.code(config.LLM_MODEL, language=None)

    st.markdown("**Embedding**")
    st.code(config.EMBEDDING_MODEL, language=None)

    index_exists = config.FAISS_INDEX_PATH.exists()
    if index_exists:
        st.success("FAISS index loaded ✓")
    else:
        st.warning(
            "No FAISS index.  \n"
            "Run `python ingest.py` then `python build_index.py`."
        )

    st.divider()
    st.markdown(
        "**Roadmap**  \n"
        "Week 1 — RAG foundation ✓  \n"
        "Week 2 — Threat intel & investigation ← *here*  \n"
        "Week 3 — Quality & security  \n"
        "Week 4 — Portfolio polish  "
    )


# ── Cached RAG engine ─────────────────────────────────────────────
@st.cache_resource(show_spinner="Loading FAISS index and embedding model …")
def get_rag_engine() -> CyberShieldRAG | None:
    if not config.FAISS_INDEX_PATH.exists():
        return None
    engine = CyberShieldRAG()
    engine.load_index()
    return engine


rag_engine = get_rag_engine()


# ── Helper: render source cards ───────────────────────────────────
def _render_sources(sources: list[dict], hits: list[dict]) -> None:
    with st.expander("📚 View cited sources", expanded=False):
        for src in sources:
            hit_text = ""
            for h in hits:
                if h.get("title") == src.get("title"):
                    hit_text = h.get("text", "")[:300]
                    break
            source_link = src.get("source", "")
            link_html = ""
            if source_link.startswith("http"):
                link_html = (
                    f'<br><a class="link" href="{source_link}" '
                    f'target="_blank">{source_link}</a>'
                )
            st.markdown(
                f'<div class="source-card">'
                f'<span class="tag">[{src["tag"]}]</span>'
                f'<span class="title">{src["title"]}</span>'
                f"{link_html}"
                f"<br><small style='color:#94a3b8'>{hit_text}…</small>"
                f"</div>",
                unsafe_allow_html=True,
            )


# ════════════════════════════════════════════════════════════════════
# TABS
# ════════════════════════════════════════════════════════════════════
st.markdown(
    '<p class="hero-title">🛡️ CyberShield AI</p>'
    '<p class="hero-subtitle">'
    "Cybersecurity investigation platform — "
    "analyze logs, detect threats, and query security knowledge."
    "</p>",
    unsafe_allow_html=True,
)

tab_chat, tab_incident = st.tabs(["💬 Knowledge Chat", "🔍 Incident Analyzer"])


# ────────────────────────────────────────────────────────────────────
# TAB 1 — Knowledge Chat
# ────────────────────────────────────────────────────────────────────
with tab_chat:
    # Chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"], unsafe_allow_html=True)
            if msg["role"] == "assistant" and msg.get("sources"):
                _render_sources(msg["sources"], msg.get("hits", []))

    if user_input := st.chat_input("Ask a cybersecurity question …"):
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        with st.chat_message("assistant"):
            if rag_engine is None:
                answer_text = (
                    "⚠️ **FAISS index not found.**  \n"
                    "Run: `python ingest.py` then `python build_index.py`"
                )
                sources, hits = [], []
                st.markdown(answer_text)
            else:
                with st.spinner("Retrieving evidence and generating answer …"):
                    result = rag_engine.generate(user_input)
                    answer_text = result["answer"]
                    sources = result["sources"]
                    hits = result["hits"]
                st.markdown(answer_text)
                _render_sources(sources, hits)

        st.session_state.messages.append(
            {"role": "assistant", "content": answer_text,
             "sources": sources, "hits": hits}
        )


# ────────────────────────────────────────────────────────────────────
# TAB 2 — Incident Analyzer
# ────────────────────────────────────────────────────────────────────
with tab_incident:
    st.markdown("### Upload Security Logs for Analysis")
    st.caption(
        "Upload a CSV or JSON file with authentication events or SIEM alerts. "
        f"Max file size: {config.MAX_UPLOAD_SIZE_MB} MB."
    )

    col_upload, col_sample = st.columns([3, 1])

    with col_upload:
        uploaded_file = st.file_uploader(
            "Choose a log file",
            type=["csv", "json"],
            help="CSV: auth logs with timestamp, event_id, username, etc.  \n"
                 "JSON: array of alert objects.",
        )

    with col_sample:
        st.markdown("**Or use sample data:**")
        use_sample_csv = st.button("📄 Sample Auth Logs", use_container_width=True)
        use_sample_json = st.button("📋 Sample SIEM Alerts", use_container_width=True)

    # Determine source
    log_source = None
    file_type = None

    if uploaded_file is not None:
        log_source = uploaded_file
        file_type = "csv" if uploaded_file.name.endswith(".csv") else "json"
    elif use_sample_csv:
        log_source = config.SAMPLE_DATA_DIR / "auth_logs.csv"
        file_type = "csv"
    elif use_sample_json:
        log_source = config.SAMPLE_DATA_DIR / "siem_alerts.json"
        file_type = "json"

    if log_source is not None:
        parser = LogParser()

        # Parse
        try:
            if file_type == "csv":
                df = parser.parse_csv(log_source)
                schema = "auth_log"
            else:
                df = parser.parse_json(log_source)
                schema = "siem_alert"
        except Exception as exc:
            st.error(f"Failed to parse file: {exc}")
            st.stop()

        # Validate
        ok, issues = parser.validate_schema(df, schema)
        if not ok:
            for issue in issues:
                st.error(f"Schema issue: {issue}")
            st.info(f"Columns found: {', '.join(df.columns)}")
            st.stop()

        # Normalize
        df = parser.normalize_events(df)

        # Show parsed events
        with st.expander(f"📊 Parsed Events ({len(df)} rows)", expanded=False):
            st.dataframe(df.head(50), use_container_width=True)

        st.divider()

        # Run detection
        analyzer = IncidentAnalyzer(rag_engine=rag_engine)
        with st.spinner("Running detection rules …"):
            report = analyzer.analyze(df, enrich_with_rag=(rag_engine is not None))

        alerts = report["alerts"]
        summary = report["summary"]

        # ── Summary metrics ───────────────────────────────────────
        st.markdown("### 📊 Analysis Summary")
        m1, m2, m3, m4 = st.columns(4)

        with m1:
            st.markdown(
                f'<div class="metric-box">'
                f'<div class="value">{report["total_events"]}</div>'
                f'<div class="label">Total Events</div></div>',
                unsafe_allow_html=True,
            )
        with m2:
            st.markdown(
                f'<div class="metric-box">'
                f'<div class="value" style="color:#ef4444">{summary["HIGH"]}</div>'
                f'<div class="label">High Severity</div></div>',
                unsafe_allow_html=True,
            )
        with m3:
            st.markdown(
                f'<div class="metric-box">'
                f'<div class="value" style="color:#f59e0b">{summary["MEDIUM"]}</div>'
                f'<div class="label">Medium Severity</div></div>',
                unsafe_allow_html=True,
            )
        with m4:
            st.markdown(
                f'<div class="metric-box">'
                f'<div class="value" style="color:#22d3ee">{summary["LOW"]}</div>'
                f'<div class="label">Low Severity</div></div>',
                unsafe_allow_html=True,
            )

        st.divider()

        # ── Alert cards ───────────────────────────────────────────
        if not alerts:
            st.success("✅ No suspicious activity detected in the uploaded logs.")
        else:
            st.markdown(f"### 🚨 Detected Alerts ({len(alerts)})")

            for idx, alert in enumerate(alerts):
                sev = alert["severity"]
                st.markdown(
                    f'<div class="alert-card alert-{sev}">'
                    f'<span class="severity-badge sev-{sev}">{sev}</span> '
                    f'<strong>{alert["rule_name"]}</strong>'
                    f'<br><small style="color:#94a3b8">'
                    f'{alert["timestamp"]} · {alert.get("source_ip", "")}'
                    f"</small>"
                    f'<p style="margin:8px 0 0;color:#e2e8f0">'
                    f'{alert["description"]}</p>'
                    f"</div>",
                    unsafe_allow_html=True,
                )

                # Evidence events
                evidence = alert.get("evidence_events", [])
                if evidence:
                    with st.expander(
                        f"📋 Evidence Events ({len(evidence)} records)",
                        expanded=False,
                    ):
                        ev_df = pd.DataFrame(evidence)
                        display_cols = [
                            c for c in [
                                "timestamp", "username", "source_ip",
                                "action", "status", "workstation",
                            ] if c in ev_df.columns
                        ]
                        if display_cols:
                            st.dataframe(
                                ev_df[display_cols],
                                use_container_width=True,
                            )
                        else:
                            st.json(evidence)

                # RAG context (if available)
                rag_ctx = alert.get("rag_context")
                if rag_ctx and rag_ctx.get("hits"):
                    with st.expander(
                        "🔗 Related MITRE ATT&CK Context",
                        expanded=False,
                    ):
                        for h in rag_ctx["hits"][:3]:
                            st.markdown(
                                f"**{h.get('title', '')}**  \n"
                                f"{h.get('text', '')[:400]}…"
                            )
                            src = h.get("source", "")
                            if src.startswith("http"):
                                st.markdown(f"[Source]({src})")
                            st.divider()

                # Investigate with AI button
                btn_key = f"investigate_{idx}"
                if st.button(
                    "🤖 Investigate with AI",
                    key=btn_key,
                    use_container_width=True,
                ):
                    if rag_engine is None:
                        st.warning(
                            "RAG engine not available. "
                            "Run `python ingest.py` and "
                            "`python build_index.py` first."
                        )
                    else:
                        with st.spinner(
                            "Generating AI investigation report …"
                        ):
                            explanation = analyzer.explain_alert(alert)

                        st.markdown("#### 🤖 AI Investigation Report")
                        st.markdown(explanation["answer"])
                        if explanation.get("sources"):
                            _render_sources(
                                explanation["sources"],
                                explanation.get("hits", []),
                            )

                st.markdown("")  # spacer
