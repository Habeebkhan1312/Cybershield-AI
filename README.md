# 🛡️ CyberShield AI — Cybersecurity RAG Assistant

A **Retrieval-Augmented Generation** system for cybersecurity analysts. Ingests trusted security knowledge (MITRE ATT&CK + local documents), retrieves relevant evidence via FAISS, and generates cited answers through a local Ollama LLM.

## Features

- **Knowledge Ingestion** — MITRE ATT&CK Enterprise techniques + local PDF/TXT/MD files
- **Vector Search** — Sentence Transformers embeddings in a FAISS index
- **Local LLM** — Ollama-powered answers that stay on your machine
- **Source Citations** — Every claim is traced back to `[S1]`, `[S2]`, etc.
- **Streamlit UI** — Analyst-friendly chat interface with source inspection

## Project Structure

```
cybershield-ai/
├── config.py           # Centralized paths and parameters
├── ingest.py           # Downloads & chunks cybersecurity docs
├── build_index.py      # Embeds chunks → FAISS index
├── rag.py              # Retrieval + Ollama generation engine
├── app.py              # Streamlit analyst interface
├── requirements.txt    # Python dependencies
├── tests/
│   └── test_chunking.py
└── data/
    ├── raw/            # Downloaded source files
    ├── processed/      # Chunked JSONL
    ├── index/          # FAISS index + metadata
    └── local_docs/     # Your own PDF / TXT / MD files
```

## Prerequisites

| Tool | Install |
|------|---------|
| Python 3.11+ | [python.org/downloads](https://www.python.org/downloads/) |
| Ollama | [ollama.com/download](https://ollama.com/download) |

## Quickstart

### 1. Create a virtual environment

```powershell
cd C:\Projects\cybershield-ai

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Pull the local LLM

```bash
ollama pull llama3.2:3b
```

### 3. Ingest & index

```bash
python ingest.py
python build_index.py
```

### 4. (Optional) Add your own documents

Place PDF, TXT, or Markdown files in `data/local_docs/`, then re-run:

```bash
python ingest.py
python build_index.py
```

### 5. Launch the UI

```bash
streamlit run app.py
```

Open **http://localhost:8501** and start asking questions.

## Example Questions

- *What does MITRE ATT&CK say about phishing?*
- *Explain techniques for detecting suspicious PowerShell execution.*
- *What evidence should an analyst collect for repeated failed logins?*

## Run Tests

```bash
python -m pytest tests/ -v
```

## Roadmap

| Week | Focus |
|------|-------|
| **1** | RAG foundation — ingestion, indexing, local inference, citations, Streamlit UI |
| **2** | Threat intel & investigation — CISA docs, hybrid retrieval, ATT&CK mapping |
| **3** | Quality & security — evaluation metrics, prompt-injection resistance |
| **4** | Portfolio polish — FastAPI, Docker, logging, architecture diagrams |

## Disclaimer

This is a **defensive decision-support** project. Test with synthetic or public data. Never treat AI-generated assessments as proof that a system has been compromised.
