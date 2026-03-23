from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import chat, files, findings, health, llm_profiles, projects, reports, scans, websocket
from app.config import settings


async def _auto_migrate():
    """Run alembic migrations on startup so the DB is always up to date."""
    import asyncio
    from pathlib import Path

    alembic_dir = Path(__file__).parent.parent / "alembic"
    if not alembic_dir.exists():
        return

    try:
        proc = await asyncio.create_subprocess_exec(
            "alembic", "upgrade", "head",
            cwd=str(Path(__file__).parent.parent),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode == 0:
            import logging
            logging.getLogger(__name__).info("Database migrations applied successfully")
        else:
            import logging
            logging.getLogger(__name__).warning(
                "Migration warning (code %d): %s", proc.returncode, stderr.decode()[:500]
            )
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Auto-migration skipped: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.export_dir.mkdir(parents=True, exist_ok=True)

    # Auto-run database migrations
    await _auto_migrate()

    # Register the orchestrator scan runner
    from app.orchestrator.engine import run_scan

    scans.set_scan_runner(run_scan)

    yield
    # Shutdown (cleanup if needed)


def create_app() -> FastAPI:
    app = FastAPI(
        title="VRAgent API",
        description="Offline AI-assisted static vulnerability research platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS: default allows localhost dev servers; override via VRAGENT_CORS_ORIGINS
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # REST routers
    app.include_router(health.router, prefix="/api")
    app.include_router(projects.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(findings.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    app.include_router(llm_profiles.router, prefix="/api")
    app.include_router(files.router, prefix="/api")
    app.include_router(chat.router, prefix="/api")

    # WebSocket
    app.include_router(websocket.router)

    # Serve pre-built frontend from dist/ if it exists (production / air-gapped)
    from pathlib import Path
    dist_dir = Path(__file__).parent.parent.parent / "frontend" / "dist"
    if dist_dir.exists():
        from fastapi.staticfiles import StaticFiles
        from fastapi.responses import FileResponse

        # Serve static assets (JS, CSS, fonts, images)
        assets_dir = dist_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="static-assets")

        # Serve other static files (fonts, icons, logo)
        for static_subdir in ["fonts", "icons"]:
            static_path = dist_dir / static_subdir
            if static_path.exists():
                app.mount(f"/{static_subdir}", StaticFiles(directory=str(static_path)), name=f"static-{static_subdir}")

        # SPA fallback: serve index.html for all non-API routes
        @app.get("/{path:path}")
        async def spa_fallback(path: str):
            # Don't intercept API, WebSocket, or actual static file requests
            if path.startswith(("api/", "ws/")):
                from fastapi import HTTPException
                raise HTTPException(404)
            # Try to serve the exact file first (e.g., logo.jpg, favicon)
            file_path = dist_dir / path
            if file_path.is_file() and ".." not in path:
                return FileResponse(str(file_path))
            # Otherwise serve index.html for client-side routing
            return FileResponse(str(dist_dir / "index.html"))

    return app


app = create_app()
