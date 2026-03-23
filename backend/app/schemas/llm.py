import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# Preset context window sizes for the UI dropdown
CONTEXT_WINDOW_PRESETS = {
    "4k": 4096,
    "8k": 8192,
    "16k": 16384,
    "32k": 32768,
    "64k": 65536,
    "128k": 131072,
    "200k": 200000,
    "400k": 400000,
}


class LLMProfileCreate(BaseModel):
    name: str
    base_url: str
    api_key: str | None = None
    model_name: str
    cert_path: str | None = None
    timeout_seconds: int = 120
    context_window: int = Field(default=131072, description="Total context window size in tokens (input + output). E.g. 131072 for 128k.")
    max_output_tokens: int = Field(default=4096, description="Max tokens per response (output only).")
    use_max_completion_tokens: bool = Field(default=False, description="Use max_completion_tokens field instead of max_tokens in API requests.")
    concurrency: int = 2
    is_default: bool = False


class LLMProfileUpdate(BaseModel):
    name: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    model_name: str | None = None
    cert_path: str | None = None
    timeout_seconds: int | None = None
    context_window: int | None = None
    max_output_tokens: int | None = None
    use_max_completion_tokens: bool | None = None
    concurrency: int | None = None
    is_default: bool | None = None


class LLMProfileOut(BaseModel):
    id: uuid.UUID
    name: str
    base_url: str
    api_key_set: bool = False
    model_name: str
    cert_path: str | None
    timeout_seconds: int
    context_window: int
    max_output_tokens: int
    use_max_completion_tokens: bool
    concurrency: int
    is_default: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LLMTestResult(BaseModel):
    success: bool
    model_name: str | None = None
    response_time_ms: int | None = None
    error: str | None = None
