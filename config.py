"""
CyberShield AI — Centralized Configuration
All paths, model names, and chunking parameters in one place.
"""

from pathlib import Path

# ── Directory layout ────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
INDEX_DIR = DATA_DIR / "index"
LOCAL_DOCS_DIR = DATA_DIR / "local_docs"
SAMPLE_DATA_DIR = ROOT_DIR / "sample_data"
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "cybershield.db"

# ── Upload limits ──────────────────────────────────────────────────
MAX_UPLOAD_SIZE_MB = 10

# ── Auto-create directories on import ──────────────────────────────
for _d in (RAW_DIR, PROCESSED_DIR, INDEX_DIR, LOCAL_DOCS_DIR, UPLOAD_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ── Chunking ───────────────────────────────────────────────────────
CHUNK_SIZE = 500          # characters per chunk
CHUNK_OVERLAP = 100       # overlap between consecutive chunks

# ── Embedding model (runs locally via sentence-transformers) ───────
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# ── LLM (served by Ollama) ─────────────────────────────────────────
LLM_MODEL = "llama3.2:3b"

# ── MITRE ATT&CK ──────────────────────────────────────────────────
MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)
MITRE_RAW_FILE = RAW_DIR / "enterprise-attack.json"

# ── FAISS index files ──────────────────────────────────────────────
FAISS_INDEX_PATH = INDEX_DIR / "cybershield.faiss"
METADATA_PATH = INDEX_DIR / "metadata.json"

# ── Processed documents ───────────────────────────────────────────
DOCUMENTS_JSONL = PROCESSED_DIR / "documents.jsonl"
