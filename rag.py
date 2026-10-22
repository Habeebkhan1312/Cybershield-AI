"""
CyberShield AI — RAG Engine

Loads the FAISS index, retrieves relevant evidence for a user query,
and generates answers via a local Ollama LLM with source citations.
"""

import json
from typing import Any

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

import config

try:
    import ollama as _ollama_lib
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class CyberShieldRAG:
    """Retrieve evidence from FAISS and generate cited answers via Ollama."""

    def __init__(
        self,
        index_path: str | None = None,
        metadata_path: str | None = None,
        embedding_model: str = config.EMBEDDING_MODEL,
        llm_model: str = config.LLM_MODEL,
    ):
        self.index_path = str(index_path or config.FAISS_INDEX_PATH)
        self.metadata_path = str(metadata_path or config.METADATA_PATH)
        self.embedding_model_name = embedding_model
        self.llm_model = llm_model

        self._index: faiss.Index | None = None
        self._metadata: list[dict[str, Any]] = []
        self._embedder: SentenceTransformer | None = None

    # ── Loading ────────────────────────────────────────────────────

    def load_index(self) -> None:
        """Load the FAISS index and accompanying metadata from disk."""
        self._index = faiss.read_index(self.index_path)
        with open(self.metadata_path, encoding="utf-8") as f:
            self._metadata = json.load(f)
        print(
            f"[+] Loaded FAISS index ({self._index.ntotal} vectors) "
            f"and {len(self._metadata)} metadata records."
        )

    def _get_embedder(self) -> SentenceTransformer:
        if self._embedder is None:
            self._embedder = SentenceTransformer(self.embedding_model_name)
        return self._embedder

    # ── Retrieval ──────────────────────────────────────────────────

    def retrieve(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Return the *top_k* most relevant chunks for *query*."""
        if self._index is None:
            raise RuntimeError("Index not loaded. Call load_index() first.")

        embedder = self._get_embedder()
        q_vec = embedder.encode([query], convert_to_numpy=True).astype("float32")
        distances, indices = self._index.search(q_vec, top_k)

        hits: list[dict[str, Any]] = []
        for rank, (dist, idx) in enumerate(
            zip(distances[0], indices[0]), start=1
        ):
            if idx < 0 or idx >= len(self._metadata):
                continue
            meta = self._metadata[idx]
            hits.append(
                {
                    "rank": rank,
                    "distance": float(dist),
                    "title": meta.get("title", ""),
                    "text": meta.get("text", ""),
                    "source": meta.get("source", ""),
                    "chunk_id": meta.get("chunk_id", ""),
                }
            )
        return hits

    # ── Generation ─────────────────────────────────────────────────

    def generate(
        self,
        question: str,
        top_k: int = 5,
    ) -> dict[str, Any]:
        """Retrieve evidence and generate a cited answer.

        Returns a dict with keys ``answer``, ``sources``, ``hits``.
        """
        hits = self.retrieve(question, top_k=top_k)

        # Build evidence block
        context_parts: list[str] = []
        for i, hit in enumerate(hits, start=1):
            context_parts.append(
                f"[S{i}] {hit['title']}\n{hit['text']}"
            )
        context = "\n\n".join(context_parts)

        # Build source list for the response
        sources = [
            {"tag": f"S{i}", "title": hit["title"], "source": hit["source"]}
            for i, hit in enumerate(hits, start=1)
        ]

        system_prompt = (
            "You are CyberShield AI, a cybersecurity analyst assistant. "
            "Answer the user's question using ONLY the supplied evidence. "
            "Cite every factual claim as [S1], [S2], etc. corresponding to "
            "the evidence labels. If the evidence is insufficient to answer "
            "the question fully, state that clearly and explain what "
            "additional information would be needed. "
            "Remain factual and analytical — never speculate beyond the evidence."
        )

        user_prompt = (
            f"Question: {question}\n\n"
            f"Evidence:\n{context}"
        )

        if not OLLAMA_AVAILABLE:
            return {
                "answer": (
                    "⚠️ The `ollama` Python package is not installed. "
                    "Install it with `pip install ollama` and ensure the "
                    "Ollama service is running."
                ),
                "sources": sources,
                "hits": hits,
            }

        try:
            response = _ollama_lib.chat(
                model=self.llm_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            answer = response["message"]["content"]
        except Exception as exc:
            answer = (
                f"⚠️ Ollama generation failed: {exc}\n\n"
                "Make sure the Ollama service is running and the model "
                f"`{self.llm_model}` has been pulled:\n"
                f"  ollama pull {self.llm_model}"
            )

        return {
            "answer": answer,
            "sources": sources,
            "hits": hits,
        }
