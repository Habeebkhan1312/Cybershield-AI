"""
CyberShield AI — Knowledge Ingestion Pipeline

Downloads MITRE ATT&CK Enterprise data and ingests local documents
(PDF, TXT, Markdown), then chunks everything into overlapping segments
saved as JSONL for downstream embedding and indexing.
"""

import json
import re
import sys
from pathlib import Path
from typing import Generator

import requests

import config


# ────────────────────────────────────────────────────────────────────
# Text chunking
# ────────────────────────────────────────────────────────────────────

def chunk_text(
    text: str,
    title: str = "",
    source: str = "",
    chunk_size: int = config.CHUNK_SIZE,
    chunk_overlap: int = config.CHUNK_OVERLAP,
) -> list[dict]:
    """Split *text* into overlapping chunks and return a list of dicts.

    Each dict has keys: ``text``, ``title``, ``source``, ``chunk_id``.
    """
    if not text or not text.strip():
        return []

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()

    chunks: list[dict] = []
    start = 0
    chunk_id = 0

    while start < len(text):
        end = start + chunk_size
        chunk_str = text[start:end].strip()
        if chunk_str:
            chunks.append(
                {
                    "text": chunk_str,
                    "title": title,
                    "source": source,
                    "chunk_id": f"{source}::chunk_{chunk_id}",
                }
            )
            chunk_id += 1
        start += chunk_size - chunk_overlap

    return chunks


# ────────────────────────────────────────────────────────────────────
# MITRE ATT&CK ingestion
# ────────────────────────────────────────────────────────────────────

def download_mitre_attack() -> Path:
    """Download the MITRE ATT&CK Enterprise STIX bundle if not cached."""
    if config.MITRE_RAW_FILE.exists():
        print(f"[+] MITRE ATT&CK data already cached: {config.MITRE_RAW_FILE}")
        return config.MITRE_RAW_FILE

    print("[*] Downloading MITRE ATT&CK Enterprise dataset …")
    resp = requests.get(config.MITRE_ATTACK_URL, timeout=120)
    resp.raise_for_status()
    config.MITRE_RAW_FILE.write_text(resp.text, encoding="utf-8")
    print(f"[+] Saved to {config.MITRE_RAW_FILE}")
    return config.MITRE_RAW_FILE


def parse_mitre_attack(path: Path) -> Generator[dict, None, None]:
    """Yield technique records from the STIX bundle."""
    data = json.loads(path.read_text(encoding="utf-8"))
    objects = data.get("objects", [])

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        name = obj.get("name", "Unknown Technique")
        description = obj.get("description", "")
        ext_refs = obj.get("external_references", [])
        mitre_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        tactics = []
        for kc in obj.get("kill_chain_phases", []):
            if kc.get("kill_chain_name") == "mitre-attack":
                tactics.append(kc["phase_name"])

        full_text = f"{name} ({mitre_id})\n\n{description}"
        if tactics:
            full_text += f"\n\nTactics: {', '.join(tactics)}"

        yield {
            "text": full_text,
            "title": f"{name} ({mitre_id})",
            "source": url or f"mitre-attack:{mitre_id}",
        }


# ────────────────────────────────────────────────────────────────────
# Local document ingestion
# ────────────────────────────────────────────────────────────────────

def read_pdf(path: Path) -> str:
    """Extract text from a PDF file."""
    from PyPDF2 import PdfReader

    reader = PdfReader(str(path))
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n".join(pages)


def read_text_file(path: Path) -> str:
    """Read a plain-text or Markdown file."""
    return path.read_text(encoding="utf-8", errors="replace")


def ingest_local_docs() -> Generator[dict, None, None]:
    """Yield records from local docs in ``data/local_docs/``."""
    supported = {".pdf", ".txt", ".md"}
    doc_dir = config.LOCAL_DOCS_DIR

    if not doc_dir.exists():
        return

    for fpath in sorted(doc_dir.iterdir()):
        if fpath.suffix.lower() not in supported:
            continue

        print(f"[*] Ingesting local document: {fpath.name}")
        if fpath.suffix.lower() == ".pdf":
            text = read_pdf(fpath)
        else:
            text = read_text_file(fpath)

        yield {
            "text": text,
            "title": fpath.stem,
            "source": f"local:{fpath.name}",
        }


# ────────────────────────────────────────────────────────────────────
# Main ingestion pipeline
# ────────────────────────────────────────────────────────────────────

def run_ingestion() -> Path:
    """Run the full ingestion pipeline and save chunks to JSONL.

    Returns the path to the JSONL file.
    """
    all_chunks: list[dict] = []

    # 1. MITRE ATT&CK
    mitre_path = download_mitre_attack()
    mitre_count = 0
    for record in parse_mitre_attack(mitre_path):
        chunks = chunk_text(
            text=record["text"],
            title=record["title"],
            source=record["source"],
        )
        all_chunks.extend(chunks)
        mitre_count += 1
    print(f"[+] Extracted {mitre_count} MITRE ATT&CK techniques → {len(all_chunks)} chunks")

    # 2. Local documents
    local_start = len(all_chunks)
    for record in ingest_local_docs():
        chunks = chunk_text(
            text=record["text"],
            title=record["title"],
            source=record["source"],
        )
        all_chunks.extend(chunks)
    local_chunks = len(all_chunks) - local_start
    print(f"[+] Ingested local documents → {local_chunks} additional chunks")

    # 3. Save
    print(f"[+] Total chunks: {len(all_chunks)}")
    with open(config.DOCUMENTS_JSONL, "w", encoding="utf-8") as f:
        for chunk in all_chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")
    print(f"[+] Saved to {config.DOCUMENTS_JSONL}")

    return config.DOCUMENTS_JSONL


# ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_ingestion()
    except KeyboardInterrupt:
        sys.exit(1)
