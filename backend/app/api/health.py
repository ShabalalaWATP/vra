import shutil

from fastapi import APIRouter

from app.config import settings
from app.scanners.eslint import ESLintAdapter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    return {"status": "ok", "version": "0.1.0"}


@router.get("/health/tools")
async def tool_availability():
    """Check which scanners are available on this system."""
    tools = {}

    for name, binary in [
        ("semgrep", settings.semgrep_binary),
        ("bandit", settings.bandit_binary),
    ]:
        path = shutil.which(binary)
        tools[name] = {
            "available": path is not None,
            "path": path,
        }

    eslint_adapter = ESLintAdapter()
    eslint_available = await eslint_adapter.is_available()
    eslint_path = eslint_adapter._resolve_binary_path()
    tools["eslint"] = {
        "available": eslint_available,
        "path": str(eslint_path) if eslint_path else None,
    }

    tools["advisory_db"] = {
        "available": settings.advisory_db_path.exists(),
        "path": str(settings.advisory_db_path),
    }

    # Count Semgrep rules
    rules_path = settings.semgrep_rules_path
    rule_count = 0
    rule_languages = []
    if rules_path.exists():
        for lang_dir in rules_path.iterdir():
            if lang_dir.is_dir() and lang_dir.name != "__pycache__":
                rule_languages.append(lang_dir.name)
                for rf in lang_dir.rglob("*.yaml"):
                    try:
                        content = rf.read_text()
                        rule_count += content.count("- id:")
                    except Exception:
                        pass
                for rf in lang_dir.rglob("*.yml"):
                    try:
                        content = rf.read_text()
                        rule_count += content.count("- id:")
                    except Exception:
                        pass

    tools["semgrep_rules"] = {
        "available": rules_path.exists() and rule_count > 0,
        "path": str(rules_path),
        "rule_count": rule_count,
        "languages": sorted(rule_languages),
        "warning": None if rule_count >= 100 else (
            f"Only {rule_count} bundled rules. Run 'python -m scripts.download_semgrep_rules' "
            "on an internet-connected machine and copy data/semgrep-rules/ to this deployment "
            "for full coverage (3000+ rules)."
        ),
    }

    # CodeQL
    codeql_path = shutil.which(settings.codeql_binary)
    if not codeql_path:
        # Check project tools directory
        from pathlib import Path as _Path
        project_codeql = _Path(__file__).parent.parent.parent / "tools" / "codeql"
        if (project_codeql / "codeql.exe").exists():
            codeql_path = str(project_codeql / "codeql.exe")
        elif (project_codeql / "codeql").exists():
            codeql_path = str(project_codeql / "codeql")
    tools["codeql"] = {
        "available": codeql_path is not None,
        "path": codeql_path,
    }

    # jadx (APK decompiler)
    from app.analysis.apk_decompiler import is_jadx_available, get_jadx_version
    jadx_available = await is_jadx_available()
    tools["jadx"] = {
        "available": jadx_available,
        "version": await get_jadx_version() if jadx_available else None,
        "supports": [".apk", ".aab", ".dex", ".jar"],
    }

    return {"tools": tools}


@router.get("/health/icons")
async def icon_availability():
    """List available offline technology icons."""
    from app.analysis.icons import get_available_icons

    icons = get_available_icons()
    return {
        "count": len(icons),
        "icons": icons,
    }


@router.get("/icons/{icon_name}.svg")
async def get_icon(icon_name: str):
    """Serve a single technology icon as SVG."""
    from fastapi.responses import Response

    from app.analysis.icons import get_icon_svg

    svg = get_icon_svg(icon_name)
    if not svg:
        from fastapi import HTTPException
        raise HTTPException(404, f"Icon not found: {icon_name}")
    return Response(content=svg, media_type="image/svg+xml")
