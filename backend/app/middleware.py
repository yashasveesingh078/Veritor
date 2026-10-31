import logging
import time
from uuid import uuid4

from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.errors import error_response

logger = logging.getLogger("app.request")

REQUEST_ID_HEADER = "X-Request-ID"


async def request_context(request: Request, call_next: RequestResponseEndpoint) -> Response:
    """Log each request, tag its response, and turn unhandled errors into a JSON 500.

    Errors are caught here rather than by a FastAPI ``Exception`` handler because that
    handler runs outside CORSMiddleware, which would hide the 500 from browser clients.
    """
    # The ID is always generated, so a client cannot write arbitrary values into the logs.
    request_id = uuid4().hex
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "unhandled error request_id=%s method=%s path=%r",
            request_id,
            request.method,
            request.url.path,
        )
        response = error_response(500, "internal_server_error", "Internal server error")

    response.headers[REQUEST_ID_HEADER] = request_id
    # The path is client-controlled and URL-decoded, so %r keeps newlines out of the log.
    logger.info(
        "request_id=%s method=%s path=%r status=%d duration_ms=%.1f",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        (time.perf_counter() - started) * 1000,
    )
    return response
