import time
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.llm_profile import LLMProfile
from app.orchestrator.llm_client import LLMClient
from app.schemas.llm import LLMProfileCreate, LLMProfileOut, LLMProfileUpdate, LLMTestResult

router = APIRouter(prefix="/llm-profiles", tags=["llm"])


def _to_out(p: LLMProfile) -> LLMProfileOut:
    return LLMProfileOut(
        id=p.id,
        name=p.name,
        base_url=p.base_url,
        api_key_set=bool(p.api_key),
        model_name=p.model_name,
        cert_path=p.cert_path,
        timeout_seconds=p.timeout_seconds,
        context_window=p.context_window,
        max_output_tokens=p.max_output_tokens,
        use_max_completion_tokens=p.use_max_completion_tokens,
        concurrency=p.concurrency,
        is_default=p.is_default,
        created_at=p.created_at,
    )


@router.get("", response_model=list[LLMProfileOut])
async def list_profiles(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LLMProfile).order_by(LLMProfile.created_at))
    return [_to_out(p) for p in result.scalars().all()]


@router.post("", response_model=LLMProfileOut, status_code=201)
async def create_profile(body: LLMProfileCreate, db: AsyncSession = Depends(get_db)):
    # If setting as default, clear other defaults
    if body.is_default:
        result = await db.execute(select(LLMProfile).where(LLMProfile.is_default == True))
        for p in result.scalars().all():
            p.is_default = False

    profile = LLMProfile(**body.model_dump())
    db.add(profile)
    await db.flush()
    return _to_out(profile)


@router.patch("/{profile_id}", response_model=LLMProfileOut)
async def update_profile(
    profile_id: uuid.UUID, body: LLMProfileUpdate, db: AsyncSession = Depends(get_db)
):
    profile = await db.get(LLMProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")

    updates = body.model_dump(exclude_unset=True)
    if updates.get("is_default"):
        result = await db.execute(select(LLMProfile).where(LLMProfile.is_default == True))
        for p in result.scalars().all():
            p.is_default = False

    for field, value in updates.items():
        setattr(profile, field, value)
    await db.flush()
    return _to_out(profile)


@router.delete("/{profile_id}", status_code=204)
async def delete_profile(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    profile = await db.get(LLMProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")

    # Check if any scans reference this profile
    from app.models.scan import Scan
    scan_ref = await db.execute(
        select(Scan).where(Scan.llm_profile_id == profile_id).limit(1)
    )
    if scan_ref.scalar_one_or_none():
        # Unlink scans from this profile instead of blocking delete
        from sqlalchemy import update
        await db.execute(
            update(Scan).where(Scan.llm_profile_id == profile_id).values(llm_profile_id=None)
        )

    await db.delete(profile)


@router.post("/{profile_id}/test", response_model=LLMTestResult)
async def test_connection(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    profile = await db.get(LLMProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")

    start = time.monotonic()
    client = LLMClient(
        base_url=profile.base_url,
        model_name=profile.model_name,
        api_key=profile.api_key,
        cert_path=profile.cert_path,
        timeout=profile.timeout_seconds,
        context_window=profile.context_window,
        max_output_tokens=min(max(profile.max_output_tokens, 64), 256),
        use_max_completion_tokens=profile.use_max_completion_tokens,
        concurrency=1,
    )
    try:
        result = await client.chat_json(
            "You are testing structured output compatibility.",
            'Return exactly this JSON object and nothing else: {"ok": true}',
            temperature=0,
            max_tokens=64,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        if result.get("ok") is True:
            return LLMTestResult(
                success=True,
                model_name=profile.model_name,
                response_time_ms=elapsed_ms,
            )
        return LLMTestResult(
            success=False,
            model_name=profile.model_name,
            response_time_ms=elapsed_ms,
            error=(
                "Endpoint responded, but it did not return parseable structured JSON. "
                f"Parsed response: {result!r}"
            ),
        )
    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return LLMTestResult(
            success=False,
            response_time_ms=elapsed_ms,
            error=str(e),
        )
    finally:
        try:
            await client.close()
        except Exception:
            pass


# ── Model discovery helper ─────────────────────────────────────

# OpenAI-compatible endpoints vary: some serve at /v1/models, some at /models,
# some at /api/v1/models. We try all common paths in order.
_MODEL_PATHS = LLMClient.model_path_candidates() + [
    "/",              # Some endpoints serve model list at root
]


async def _discover_models_from_endpoint(
    base_url: str,
    api_key: str = "",
    cert_path: str = "",
) -> dict:
    """Try multiple model-listing paths against an OpenAI-compatible endpoint."""
    import ssl as _ssl

    ssl_context = None
    if cert_path:
        ssl_context = _ssl.create_default_context(cafile=cert_path)

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    errors = []

    normalized_base_url = LLMClient._normalise_base_url(base_url)

    async with httpx.AsyncClient(
        base_url=normalized_base_url,
        timeout=15,
        verify=ssl_context or True,
    ) as client:
        for path in _MODEL_PATHS:
            try:
                resp = await client.get(path, headers=headers)
                if resp.status_code in {404, 405}:
                    continue  # This path doesn't exist, try next
                resp.raise_for_status()
                data = resp.json()

                # Handle standard OpenAI format: {"data": [{"id": "..."}]}
                model_list = data.get("data", [])

                # Some endpoints return a plain list or {"models": [...]}
                if not model_list and isinstance(data, list):
                    model_list = data
                elif not model_list and "models" in data:
                    model_list = data["models"]

                models = []
                for m in model_list:
                    if isinstance(m, str):
                        models.append({"id": m, "owned_by": ""})
                    elif isinstance(m, dict):
                        model_id = m.get("id") or m.get("name") or m.get("model") or ""
                        if model_id:
                            models.append({
                                "id": model_id,
                                "owned_by": m.get("owned_by", ""),
                            })

                if models:
                    return {
                        "models": sorted(models, key=lambda x: x["id"]),
                        "endpoint_used": path,
                    }
            except Exception as e:
                errors.append(f"{path}: {e}")
                continue

    error_msg = "No models found at any endpoint. Tried: " + ", ".join(
        p for p in _MODEL_PATHS
    )
    if errors:
        error_msg += f". Errors: {'; '.join(errors[:3])}"
    return {"models": [], "error": error_msg}


@router.post("/{profile_id}/models")
async def list_models(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Fetch available models from a saved profile's LLM endpoint."""
    profile = await db.get(LLMProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")

    return await _discover_models_from_endpoint(
        base_url=profile.base_url,
        api_key=profile.api_key or "",
        cert_path=profile.cert_path or "",
    )


class DiscoverModelsRequest(BaseModel):
    base_url: str
    api_key: str = ""
    cert_path: str = ""


@router.post("/discover-models")
async def discover_models_direct(body: DiscoverModelsRequest):
    """Fetch models without needing a saved profile. Used during profile creation."""
    # Validate base_url is an HTTP(S) URL to prevent SSRF with file:// or internal schemes
    if not body.base_url.startswith(("http://", "https://")):
        from fastapi import HTTPException
        raise HTTPException(400, "base_url must start with http:// or https://")
    return await _discover_models_from_endpoint(
        base_url=body.base_url,
        api_key=body.api_key,
        cert_path=body.cert_path,
    )
