import os
import chromadb
from chromadb.utils import embedding_functions
from pypdf import PdfReader

# ChromaDB istemcisi
chroma_client = chromadb.PersistentClient(path="/app/chroma_db")

# Sentence-transformers ile embedding fonksiyonu
embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# Koleksiyon oluştur veya mevcut olanı getir
collection = chroma_client.get_or_create_collection(
    name="security_docs",
    embedding_function=embedding_fn
)

def load_text_document(file_path: str, doc_id: str):
    """Bir TXT dosyasını ChromaDB'ye yükle."""
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()
    
    # Metni parçalara böl (her parça max 500 karakter)
    chunks = []
    chunk_size = 500
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i + chunk_size].strip()
        if chunk:
            chunks.append(chunk)
    
    # ChromaDB'ye ekle
    collection.upsert(
        documents=chunks,
        ids=[f"{doc_id}_chunk_{i}" for i in range(len(chunks))],
        metadatas=[{"source": doc_id, "chunk": i} for i in range(len(chunks))]
    )
    print(f"{len(chunks)} parça yüklendi: {doc_id}")
    return len(chunks)

def retrieve(query: str, n_results: int = 3) -> str:
    """Sorguya en yakın doküman parçalarını getir."""
    if collection.count() == 0:
        return ""
    
    results = collection.query(
        query_texts=[query],
        n_results=min(n_results, collection.count())
    )
    
    if not results["documents"] or not results["documents"][0]:
        return ""
    
    # Parçaları birleştir
    context = "\n\n---\n\n".join(results["documents"][0])
    return context

def get_collection_info() -> dict:
    """Koleksiyon hakkında bilgi döndür."""
    return {
        "total_chunks": collection.count(),
        "name": collection.name
    }
