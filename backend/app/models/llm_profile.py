import uuid
from datetime import datetime, timezone

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LLMProfile(Base):
    __tablename__ = "llm_profiles"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    base_url: Mapped[str] = mapped_column(Text)
    api_key: Mapped[str | None] = mapped_column(Text)
    model_name: Mapped[str] = mapped_column(String(255))
    cert_path: Mapped[str | None] = mapped_column(Text)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=500)

    # Context window = total tokens the model can handle (input + output combined)
    # Common values: 4096, 8192, 16384, 32768, 65536, 131072, 200000, 400000, 500000-1000000
    context_window: Mapped[int] = mapped_column(Integer, default=131072)

    # Max output tokens = how many tokens the model should generate per response
    # This is sent as max_tokens (or max_completion_tokens for newer APIs)
    max_output_tokens: Mapped[int] = mapped_column(Integer, default=4096)

    # Whether to use max_completion_tokens instead of max_tokens in the API request
    # Some newer OpenAI-compatible endpoints (e.g., vLLM, Ollama) use this field
    use_max_completion_tokens: Mapped[bool] = mapped_column(default=False)

    concurrency: Mapped[int] = mapped_column(Integer, default=2)
    is_default: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
