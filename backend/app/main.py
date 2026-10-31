from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api import health
from app.api import v1 as api_v1
from app.config import Settings, get_settings
from app.errors import register_error_handlers
from app.logging_config import configure_logging
from app.middleware import REQUEST_ID_HEADER, request_context


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(title="Veritor API", version="0.1.0")
    register_error_handlers(app)

    # The middleware added last runs first, so CORS also covers errors from request_context.
    app.add_middleware(BaseHTTPMiddleware, dispatch=request_context)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        expose_headers=[REQUEST_ID_HEADER],
    )

    app.include_router(health.router)
    app.include_router(api_v1.router)
    return app


app = create_app()
