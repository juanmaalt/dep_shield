from src.rag.client import openai_client

MODEL = "text-embedding-3-small"


def get_embedding(text: str) -> list[float]:
    response = openai_client.embeddings.create(model=MODEL, input=text)
    return response.data[0].embedding


def get_embeddings_batch(texts: list[str]) -> list[list[float]]:
    response = openai_client.embeddings.create(model=MODEL, input=texts)
    return [item.embedding for item in response.data]
