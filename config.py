"""Validated application configuration; secrets never enter reports."""

from dataclasses import dataclass, field
from pathlib import Path
import os
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
FEATURES = (
    "failed_attempts",
    "login_frequency",
    "bytes_sent",
    "bytes_received",
    "request_rate",
    "unique_ports",
    "authentication_failures",
    "destination_count",
)
load_dotenv(ROOT / ".env", override=False)


def flag(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"true", "1", "yes"}


@dataclass(frozen=True)
class Config:
    provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "local"))
    openai_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""), repr=False)
    gemini_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""), repr=False)
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    gemini_model: str = field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.2:3b"))
    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"))
    embedding_backend: str = field(default_factory=lambda: os.getenv("EMBEDDING_BACKEND", "auto"))
    embedding_model: str = field(
        default_factory=lambda: os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    )
    allow_model_download: bool = field(default_factory=lambda: flag("ALLOW_MODEL_DOWNLOAD"))
    require_auth: bool = field(default_factory=lambda: flag("REQUIRE_AUTH"))
    allow_cloud_logs: bool = field(default_factory=lambda: flag("ALLOW_CLOUD_LOGS"))
    allow_fallback: bool = field(default_factory=lambda: flag("ALLOW_LOCAL_FALLBACK", True))
    contamination: float = field(default_factory=lambda: float(os.getenv("CONTAMINATION", "0.08")))
    top_k: int = field(default_factory=lambda: int(os.getenv("TOP_K", "5")))
    timeout: int = 45
    max_rows: int = 50000
    max_upload_bytes: int = 20 * 1024 * 1024
    state_dir: Path = field(default_factory=lambda: Path(os.getenv("STATE_DIR", str(ROOT / "state"))).resolve())
    knowledge_dir: Path = ROOT / "knowledge"
    dataset_path: Path = ROOT / "data" / "security_logs.csv"

    def __post_init__(self) -> None:
        if self.provider not in {"local", "openai", "gemini", "ollama"}:
            raise ValueError("Unsupported LLM_PROVIDER")
        if self.embedding_backend not in {"auto", "sentence_transformer", "hashing"}:
            raise ValueError("Unsupported EMBEDDING_BACKEND")
        if not 0 < self.contamination <= 0.5:
            raise ValueError("CONTAMINATION must be in (0, 0.5]")
        if not 1 <= self.top_k <= 15:
            raise ValueError("TOP_K must be between 1 and 15")
        if not self.ollama_url.startswith(("http://", "https://")):
            raise ValueError("OLLAMA_URL must be HTTP(S)")
