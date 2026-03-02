from dataclasses import dataclass
from pathlib import Path

import chromadb

from src.rag.embeddings import get_embedding

_STORE_PATH = Path.home() / ".dep_shield" / "chroma"
_collection = None


@dataclass
class SimilarCVE:
    id: str
    description: str
    metadata: str
    distance: float


def _get_collection():
    global _collection
    if _collection is None:
        init_store()
    return _collection


def init_store():
    global _collection
    _STORE_PATH.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(_STORE_PATH))
    _collection = client.get_or_create_collection(
        name="cves",
        metadata={"hnsw:space": "cosine"},
    )


def add_cve(cve_id: str, description: str, metadata: str):
    collection = _get_collection()
    embedding = get_embedding(description)
    collection.upsert(
        ids=[cve_id],
        documents=[description],
        embeddings=[embedding],
        metadatas=[{"data": metadata}],
    )


def search_similar(query: str, k: int = 3) -> list[SimilarCVE]:
    collection = _get_collection()
    count = collection.count()
    if count == 0:
        return []

    embedding = get_embedding(query)
    results = collection.query(
        query_embeddings=[embedding],
        n_results=min(k, count),
    )

    return [
        SimilarCVE(
            id=cve_id,
            description=results["documents"][0][i],
            metadata=results["metadatas"][0][i].get("data", ""),
            distance=results["distances"][0][i],
        )
        for i, cve_id in enumerate(results["ids"][0])
    ]
