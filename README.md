# 🛡️ CyberShield AI

**A local-first cybersecurity investigation platform powered by Retrieval-Augmented Generation (RAG)**

CyberShield AI ingests trusted threat intelligence (MITRE ATT&CK), analyzes security logs using deterministic detection rules, and explains findings with a locally-hosted LLM — all without sending sensitive data to the cloud.

---

## 📐 Architecture & Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES                                 │
│   MITRE ATT&CK (STIX)  ·  Local PDFs/TXT  ·  CSV/JSON Logs        │
└──────────────┬────────────────────┬─────────────────────────────────┘
               │                    │
               ▼                    │
┌──────────────────────────┐        │
│     INGESTION PIPELINE   │        │
│  ingest.py               │        │
│  • Download ATT&CK STIX  │        │
│  • Parse attack-patterns │        │
│  • Read local docs       │        │
│  • Chunk text (500 char) │        │
└──────────┬───────────────┘        │
           ▼                        │
┌──────────────────────────┐        │
│     VECTOR INDEXING      │        │
│  build_index.py          │        │
│  • Encode with           │        │
│    all-MiniLM-L6-v2      │        │
│  • Build FAISS index     │        │
│  • Save metadata.json    │        │
└──────────┬───────────────┘        │
           │                        │
           ▼                        ▼
┌────────────────────┐   ┌────────────────────────┐
│    RAG ENGINE      │   │   INCIDENT ANALYZER    │
│    rag.py          │   │   analyzers/           │
│                    │   │                        │
│  • Vector search   │   │  • Parse CSV/JSON logs │
│  • Top-K retrieval │   │  • Validate schema     │
│  • Ollama LLM      │   │  • Run 4 detection     │
│  • Cited answers   │   │    rules               │
│    [S1], [S2]...   │   │  • Enrich alerts with  │
│                    │◄──│    RAG context          │
└────────┬───────────┘   └──────────┬─────────────┘
         │                          │
         ▼                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    STREAMLIT UI  (app.py)                            │
│                                                                     │
│   Tab 1: 💬 Knowledge Chat        Tab 2: 🔍 Incident Analyzer      │
│   • Ask security questions        • Upload CSV/JSON logs            │
│   • Get cited RAG answers         • View severity metrics           │
│   • Source cards with links       • Alert cards with evidence       │
│                                   • "Investigate with AI" button    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔍 How It Works — Step by Step

### Knowledge Pipeline (one-time setup)
1. **Ingest** → `python ingest.py` downloads MITRE ATT&CK data and reads local docs
2. **Chunk** → Text is split into 500-character overlapping chunks
3. **Embed** → Each chunk is converted to a vector using Sentence Transformers
4. **Index** → Vectors are stored in a FAISS index for fast similarity search

### Knowledge Chat (Tab 1)
5. **User asks a question** → Question is embedded into a vector
6. **Retrieve** → FAISS finds the 5 closest matching chunks
7. **Generate** → Ollama LLM answers using only the retrieved evidence, citing sources

### Incident Analysis (Tab 2)
8. **Upload logs** → CSV/JSON files are parsed, validated, and normalized
9. **Detect** → 4 deterministic rules scan for suspicious patterns (no AI)
10. **Investigate** → Each alert is enriched with MITRE ATT&CK context from RAG, and the LLM generates a full investigation report

---

## 🚨 Detection Rules

| Rule | What It Detects | Severity | MITRE Technique |
|------|----------------|----------|-----------------|
| Brute Force | ≥5 failed logins from same IP in 5 min | HIGH | T1110 |
| Login After Failures | Success following ≥3 failures | MEDIUM | T1078 |
| Privilege Escalation | Admin privileges after prior failures | HIGH | T1078.002 |
| Off-Hours Login | Login outside 06:00–22:00 UTC | LOW | T1078 |

> **Design decision**: Detection rules are pure Python — no AI. This makes them testable, predictable, and auditable. The AI only explains what the rules already found.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Streamlit |
| Embeddings | Sentence Transformers (`all-MiniLM-L6-v2`) |
| Vector Search | FAISS |
| LLM | Ollama (`llama3.2:3b`, runs locally) |
| Log Analysis | pandas |
| Testing | pytest (31 tests) |

---

## 📁 Project Structure

```
CyberShield-AI/
├── app.py                          # Streamlit UI (2 tabs)
├── config.py                       # Centralized configuration
├── ingest.py                       # Knowledge ingestion pipeline
├── build_index.py                  # FAISS index builder
├── rag.py                          # RAG engine (retrieve + generate)
├── requirements.txt                # Dependencies
├── analyzers/
│   ├── log_parser.py               # CSV/JSON parsing & validation
│   ├── detection_rules.py          # 4 detection rules
│   └── incident_analyzer.py        # Orchestrator (detection + RAG)
├── sample_data/
│   ├── auth_logs.csv               # 50-row sample with attack scenarios
│   └── siem_alerts.json            # 11 sample SIEM alerts
├── tests/
│   ├── test_chunking.py            # 7 tests — text chunking
│   ├── test_log_parser.py          # 11 tests — parsing & validation
│   ├── test_detection.py           # 9 tests — detection rules
│   └── test_incident_analyzer.py   # 4 tests — orchestrator
└── .streamlit/
    └── config.toml                 # Streamlit settings
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com/download) installed and running

### Setup
```bash
# 1. Clone and install
git clone https://github.com/Habeebkhan1312/Cybershield-AI.git
cd Cybershield-AI
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

# 2. Pull the LLM model
ollama pull llama3.2:3b

# 3. Build the knowledge base
python ingest.py
python build_index.py

# 4. Launch the app
streamlit run app.py
```

### Run Tests
```bash
pytest tests/ -v
# 31 passed ✅
```

---

## 🔐 Security & Privacy

- **100% local** — No API keys, no cloud calls, no data leaves your machine
- **Evidence-based** — LLM cites sources; never speculates beyond retrieved evidence
- **Transparent detection** — Rules are deterministic Python, fully auditable
- **Explicit uncertainty** — States when evidence is insufficient rather than guessing
