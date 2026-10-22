"""
CyberShield AI — FAISS Index Builder

Reads chunked documents from ``data/processed/documents.jsonl``,
encodes each chunk with a Sentence Transformers model, builds a
FAISS flat-L2 index, and persists the index + metadata to disk.
"""

import json
import sys
from typing import Any

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

import config


def load_chunks(path=config.DOCUMENTS_JSONL) -> list[dict]:
    """Load all chunk records from the JSONL file."""
    chunks: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                chunks.append(json.loads(line))
    print(f"[+] Loaded {len(chunks)} chunks from {path}")
    return chunks


def build_faiss_index(
    chunks: list[dict],
    model_name: str = config.EMBEDDING_MODEL,
) -> tuple[faiss.Index, list[dict[str, Any]]]:
    """Encode chunks and build a FAISS IndexFlatL2.

    Returns (faiss_index, metadata_list) where metadata_list[i]
    corresponds to faiss_index vector i.
    """
    print(f"[*] Loading embedding model: {model_name} …")
    model = SentenceTransformer(model_name)

    texts = [c["text"] for c in chunks]
    print(f"[*] Encoding {len(texts)} chunks …")
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)
    embeddings = np.array(embeddings, dtype="float32")

    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(embeddings)
    print(f"[+] FAISS index built — {index.ntotal} vectors, dim={dim}")

    metadata = [
        {
            "title": c.get("title", ""),
            "source": c.get("source", ""),
            "text": c["text"],
            "chunk_id": c.get("chunk_id", ""),
        }
        for c in chunks
    ]
    return index, metadata


def save_index(
    index: faiss.Index,
    metadata: list[dict],
    index_path=config.FAISS_INDEX_PATH,
    meta_path=config.METADATA_PATH,
) -> None:
    """Persist the FAISS index and metadata JSON to disk."""
    faiss.write_index(index, str(index_path))
    print(f"[+] FAISS index saved → {index_path}")

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    print(f"[+] Metadata saved  → {meta_path}")


def main() -> None:
    """End-to-end: load chunks → embed → build index → save."""
    if not config.DOCUMENTS_JSONL.exists():
        print("[!] documents.jsonl not found. Run ingest.py first.")
        sys.exit(1)

    chunks = load_chunks()
    if not chunks:
        print("[!] No chunks found in documents.jsonl.")
        sys.exit(1)

    index, metadata = build_faiss_index(chunks)
    save_index(index, metadata)
    print("[✓] Index build complete.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
