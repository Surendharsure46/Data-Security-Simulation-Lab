"""Threatready API application."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import db as dbmod
from .config import get_settings
from .routers import admin, auth, curriculum, environment, investigations, labs, policies, sessions
from .services.common import DomainError

log = logging.getLogger("threatready")

API_CSP = "default-src 'none'; frame-ancestors 'none'"
UI_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
          "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


def create_app() -> FastAPI:
    settings = get_settings()
    if dbmod.SessionLocal is None:
        dbmod.configure()
    app = FastAPI(title="Threatready API", version="0.1.0",
                  description="Data Security Operations & Simulation Lab. All scenario data is synthetic.",
                  docs_url="/api/docs" if settings.env != "production" else None, redoc_url=None,
                  openapi_url="/api/openapi.json" if settings.env != "production" else None)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.url.path.startswith("/api/docs"):
            pass  # Swagger UI needs its own assets (development only)
        elif request.url.path.startswith("/api/"):
            response.headers.setdefault("Content-Security-Policy", API_CSP)
            response.headers.setdefault("Cache-Control", "no-store")
        else:
            response.headers.setdefault("Content-Security-Policy", UI_CSP)
        return response

    @app.exception_handler(DomainError)
    async def domain_error(_request: Request, exc: DomainError):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        errors = [{"field": ".".join(str(p) for p in e["loc"] if p != "body"), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": "Invalid input", "errors": errors})

    @app.exception_handler(Exception)
    async def unhandled(_request: Request, exc: Exception):  # pragma: no cover - safety net
        log.exception("Unhandled error", exc_info=exc)
        return JSONResponse(status_code=500, content={"detail": "Internal error. The incident was logged; no details are exposed."})

    for r in (auth.router, sessions.router, environment.router, policies.router, policies.eng, investigations.router,
              curriculum.router, labs.router, admin.router):
        app.include_router(r)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "product": "Threatready", "data": "synthetic"}

    dist = settings.frontend_dist
    if dist.is_dir() and (dist / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path.startswith("api/"):
                raise StarletteHTTPException(status_code=404)
            candidate = (dist / full_path).resolve()
            if full_path and candidate.is_file() and dist.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")

    return app


app = create_app()
