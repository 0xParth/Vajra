"""Curated list of AI/ML packages that are high-value supply chain targets.

These packages are merged with the top-N PyPI packages during batch scans
to ensure comprehensive coverage of the AI ecosystem, regardless of whether
they appear in the top-N by raw download count.

Categories:
  - LLM providers & SDKs
  - LLM orchestration frameworks
  - Agent frameworks
  - ML training & inference
  - Embedding, vector search, RAG
  - Tokenizers & model formats
  - AI infrastructure & serving
  - AI-adjacent data tools
"""

from __future__ import annotations

AI_PACKAGES: list[str] = [
    # ── LLM provider SDKs ──────────────────────────────────────────────
    "openai",
    "anthropic",
    "cohere",
    "mistralai",
    "google-generativeai",
    "google-genai",
    "together",
    "groq",
    "fireworks-ai",
    "replicate",
    "ai21",
    "aleph-alpha-client",
    "voyageai",
    "deepseek-sdk",

    # ── LLM orchestration / routing ────────────────────────────────────
    "litellm",
    "langchain",
    "langchain-core",
    "langchain-community",
    "langchain-openai",
    "langchain-anthropic",
    "langchain-google-genai",
    "langchain-experimental",
    "langsmith",
    "llama-index",
    "llama-index-core",
    "llama-index-llms-openai",
    "llama-index-llms-anthropic",
    "llamaindex-py-client",
    "haystack-ai",
    "dspy",
    "dspy-ai",
    "guidance",
    "instructor",
    "marvin",
    "outlines",
    "semantic-kernel",
    "promptflow",

    # ── Agent frameworks ───────────────────────────────────────────────
    "crewai",
    "crewai-tools",
    "autogen",
    "pyautogen",
    "agency-swarm",
    "phidata",
    "smolagents",
    "pydantic-ai",
    "langgraph",
    "langflow",
    "agno",
    "controlflow",
    "composio-core",
    "browser-use",
    "camel-ai",

    # ── ML core libraries ──────────────────────────────────────────────
    "torch",
    "torchvision",
    "torchaudio",
    "tensorflow",
    "tf-keras",
    "keras",
    "jax",
    "jaxlib",
    "flax",
    "optax",
    "scikit-learn",
    "xgboost",
    "lightgbm",
    "catboost",
    "onnx",
    "onnxruntime",
    "onnxruntime-gpu",

    # ── Hugging Face ecosystem ─────────────────────────────────────────
    "transformers",
    "huggingface-hub",
    "datasets",
    "accelerate",
    "peft",
    "trl",
    "tokenizers",
    "safetensors",
    "diffusers",
    "timm",
    "evaluate",
    "optimum",
    "sentence-transformers",
    "setfit",
    "bitsandbytes",

    # ── Inference engines / serving ────────────────────────────────────
    "vllm",
    "ollama",
    "llama-cpp-python",
    "ctransformers",
    "exllamav2",
    "text-generation-inference",
    "triton",
    "bentoml",
    "modal",
    "runpod",
    "ray",
    "ray[serve]",

    # ── Vector databases & retrieval ───────────────────────────────────
    "chromadb",
    "pinecone-client",
    "pinecone",
    "weaviate-client",
    "qdrant-client",
    "milvus",
    "pymilvus",
    "lancedb",
    "faiss-cpu",
    "faiss-gpu",
    "pgvector",
    "opensearch-py",

    # ── Tokenizers & data formats ──────────────────────────────────────
    "tiktoken",
    "sentencepiece",
    "protobuf",

    # ── RAG & document processing ──────────────────────────────────────
    "unstructured",
    "llama-parse",
    "docling",
    "pypdf",
    "pdfplumber",
    "pymupdf",
    "python-docx",
    "python-pptx",
    "markdownify",

    # ── Guardrails & safety ────────────────────────────────────────────
    "guardrails-ai",
    "nemoguardrails",
    "lakera-guard",
    "rebuff",

    # ── AI infra & experiment tracking ─────────────────────────────────
    "mlflow",
    "wandb",
    "neptune",
    "clearml",
    "comet-ml",
    "tensorboard",
    "optuna",

    # ── AI-powered apps & UI ───────────────────────────────────────────
    "gradio",
    "streamlit",
    "chainlit",
    "panel",
    "nicegui",
    "mesop",

    # ── Widely used AI-adjacent utilities ──────────────────────────────
    "pydantic",
    "pydantic-settings",
    "httpx",
    "aiohttp",
    "fastapi",
    "uvicorn",
    "numpy",
    "pandas",
    "scipy",
    "pillow",
    "opencv-python",
    "matplotlib",
]


def get_ai_packages() -> list[str]:
    """Return the curated AI/ML package list (de-duped, lowercased)."""
    seen: set[str] = set()
    result: list[str] = []
    for pkg in AI_PACKAGES:
        normalized = pkg.lower().split("[")[0]
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result
