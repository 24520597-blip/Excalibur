"""Lightweight keyword-based knowledge retrieval for Excalibur.

Provides a simple RAG-like interface that loads tool documentation and
markdown knowledge files, then retrieves the most relevant entries for
a given query using TF-IDF-inspired keyword matching.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from excalibur.tools.registry import ToolRegistry


class KnowledgeBase:
    """Keyword-based knowledge retrieval over tool docs and markdown files.

    The knowledge base indexes two types of documents:

    1. **Tool documentation** -- automatically generated from every
       ``TypedSecurityTool`` registered in the provided ``ToolRegistry``.
    2. **Markdown files** -- loaded from an optional ``knowledge_dir``
       directory on disk.

    Retrieval uses a simple TF-IDF-like scoring: each document is
    tokenised into lowercase words, and a query is scored against each
    document by summing the inverse-document-frequency weight of every
    matching term.

    Args:
        registry: The tool registry whose tool docs should be indexed.
            If ``None``, only markdown files are loaded.
        knowledge_dir: Optional path to a directory of ``.md`` files.
    """

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        knowledge_dir: Path | None = None,
    ) -> None:
        self._documents: list[dict[str, Any]] = []
        self._token_index: dict[str, set[int]] = {}
        self._doc_tokens: list[set[str]] = []
        self._total_docs: int = 0

        if registry is not None:
            self._index_registry(registry)
        if knowledge_dir is not None:
            self._load_markdown_files(knowledge_dir)

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def _tokenise(self, text: str) -> set[str]:
        """Split text into a set of lowercase alphanumeric tokens."""
        return set(re.findall(r"[a-z0-9]+", text.lower()))

    def _add_document(
        self,
        title: str,
        content: str,
        source: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a document to the index."""
        doc_id = len(self._documents)
        tokens = self._tokenise(f"{title} {content}")
        self._documents.append(
            {
                "title": title,
                "content": content,
                "source": source,
                "metadata": metadata or {},
            }
        )
        self._doc_tokens.append(tokens)
        for token in tokens:
            if token not in self._token_index:
                self._token_index[token] = set()
            self._token_index[token].add(doc_id)
        self._total_docs += 1

    def _index_registry(self, registry: ToolRegistry) -> None:
        """Index all tools from the registry."""
        for name in registry.list_tools():
            tool = registry.get(name)
            if tool is None:
                continue
            doc = tool.get_documentation()
            self._add_document(
                title=name,
                content=doc,
                source=f"tool:{name}",
                metadata={
                    "category": tool.category.value,
                    "type": "tool",
                },
            )

    def _load_markdown_files(self, knowledge_dir: Path) -> None:
        """Load and index all .md files from a directory."""
        if not knowledge_dir.is_dir():
            return
        for md_file in sorted(knowledge_dir.glob("**/*.md")):
            try:
                content = md_file.read_text(encoding="utf-8")
            except OSError:
                continue
            self._add_document(
                title=md_file.stem,
                content=content,
                source=f"file:{md_file}",
                metadata={"type": "markdown", "path": str(md_file)},
            )

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def _idf(self, token: str) -> float:
        """Inverse document frequency for a token."""
        doc_count = len(self._token_index.get(token, set()))
        if doc_count == 0:
            return 0.0
        return math.log(1.0 + self._total_docs / doc_count)

    def _score_document(self, doc_id: int, query_tokens: set[str]) -> float:
        """Score a document against query tokens using IDF weighting."""
        doc_toks = self._doc_tokens[doc_id]
        score = 0.0
        for qt in query_tokens:
            if qt in doc_toks:
                score += self._idf(qt)
        return score

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Retrieve the most relevant documents for a query.

        Args:
            query: Free-text search query.
            top_k: Maximum number of results to return.

        Returns:
            List of document dicts sorted by relevance (highest first).
            Each dict contains ``title``, ``content``, ``source``,
            ``metadata``, and ``score``.
        """
        if not self._documents:
            return []

        query_tokens = self._tokenise(query)
        if not query_tokens:
            return []

        # Narrow candidate set to documents containing at least one query token
        candidate_ids: set[int] = set()
        for qt in query_tokens:
            candidate_ids.update(self._token_index.get(qt, set()))

        scored: list[tuple[float, int]] = []
        for doc_id in candidate_ids:
            score = self._score_document(doc_id, query_tokens)
            if score > 0:
                scored.append((score, doc_id))

        scored.sort(key=lambda x: x[0], reverse=True)

        results: list[dict[str, Any]] = []
        for score, doc_id in scored[:top_k]:
            doc = self._documents[doc_id].copy()
            doc["score"] = round(score, 4)
            results.append(doc)

        return results

    def retrieve_by_category(
        self,
        category: str,
        top_k: int = 10,
    ) -> list[dict[str, Any]]:
        """Retrieve documents belonging to a specific category.

        Args:
            category: Category value string (e.g., ``"reconnaissance"``).
            top_k: Maximum number of results to return.

        Returns:
            List of matching document dicts.
        """
        results: list[dict[str, Any]] = []
        for doc in self._documents:
            if doc.get("metadata", {}).get("category") == category:
                results.append(doc.copy())
                if len(results) >= top_k:
                    break
        return results

    @property
    def document_count(self) -> int:
        """Return the total number of indexed documents."""
        return self._total_docs
