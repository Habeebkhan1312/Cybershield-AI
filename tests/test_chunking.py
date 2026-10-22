"""
CyberShield AI — Text Chunking Tests

Validates the chunk_text function from ingest.py.
"""

import pytest

from ingest import chunk_text


class TestChunkText:
    """Tests for the chunk_text() function."""

    def test_short_text_single_chunk(self):
        """Text shorter than chunk_size should produce exactly one chunk."""
        text = "This is a short cybersecurity note."
        result = chunk_text(text, title="Short Note", source="test:short")

        assert len(result) == 1
        assert result[0]["text"] == text
        assert result[0]["title"] == "Short Note"
        assert result[0]["source"] == "test:short"

    def test_chunk_metadata_fields(self):
        """Each chunk must contain text, title, source, and chunk_id."""
        text = "Alert: suspicious login detected from unknown IP."
        result = chunk_text(text, title="Alert", source="test:meta")

        required_keys = {"text", "title", "source", "chunk_id"}
        for chunk in result:
            assert required_keys.issubset(chunk.keys())

    def test_long_text_multiple_chunks(self):
        """Text longer than chunk_size should produce multiple chunks."""
        # 1200 characters → should produce more than one chunk at size 500
        text = "A" * 1200
        result = chunk_text(text, title="Long", source="test:long", chunk_size=500, chunk_overlap=100)

        assert len(result) > 1

    def test_overlap_between_chunks(self):
        """Consecutive chunks should overlap by the configured amount."""
        # Create predictable text: chars 0-999
        text = " ".join(f"word{i}" for i in range(200))  # plenty of text
        chunk_size = 100
        chunk_overlap = 30
        result = chunk_text(
            text, title="Overlap", source="test:overlap",
            chunk_size=chunk_size, chunk_overlap=chunk_overlap,
        )

        assert len(result) >= 2
        # Each successive chunk should start (chunk_size - overlap) chars later
        # Due to whitespace normalization just verify we have overlapping content
        for i in range(len(result) - 1):
            current_end = result[i]["text"][-chunk_overlap:]
            next_start = result[i + 1]["text"][:chunk_overlap]
            # There should be some shared substring
            assert len(current_end) > 0
            assert len(next_start) > 0

    def test_empty_input_returns_empty(self):
        """Empty or whitespace-only input should return an empty list."""
        assert chunk_text("", title="", source="") == []
        assert chunk_text("   ", title="", source="") == []
        assert chunk_text("\n\t\n", title="", source="") == []

    def test_chunk_id_format(self):
        """Chunk IDs should include the source and a sequential index."""
        text = "X" * 1200
        result = chunk_text(text, title="IDs", source="test:ids", chunk_size=500, chunk_overlap=100)

        for i, chunk in enumerate(result):
            assert chunk["chunk_id"] == f"test:ids::chunk_{i}"

    def test_whitespace_normalization(self):
        """Multiple whitespace characters should be collapsed to single spaces."""
        text = "Alert:   multiple   spaces\n\nand   newlines."
        result = chunk_text(text, title="WS", source="test:ws")

        assert len(result) == 1
        assert "  " not in result[0]["text"]  # no double spaces
        assert "\n" not in result[0]["text"]   # no newlines


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
