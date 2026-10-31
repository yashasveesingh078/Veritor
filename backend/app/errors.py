from collections.abc import Mapping
from http import HTTPStatus

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.requests import Request

from app.schemas.common import ErrorBody, ErrorDetail, ErrorResponse

VALUE_ERROR_PREFIX = "Value error, "


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=details or []))
    return JSONResponse(status_code=status_code, content=body.model_dump(), headers=headers)


async def handle_http_exception(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, HTTPException)  # noqa: S101
    code = HTTPStatus(exc.status_code).phrase.lower().replace(" ", "_").replace("-", "_")
    return error_response(exc.status_code, code, str(exc.detail), headers=exc.headers)


async def handle_validation_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    # Only location and message are returned: the rejected input is never echoed back.
    details = [
        ErrorDetail(
            field=".".join(str(part) for part in error["loc"]),
            message=str(error["msg"]).removeprefix(VALUE_ERROR_PREFIX),
        )
        for error in exc.errors()
    ]
    return error_response(422, "validation_error", "Request validation failed", details)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(HTTPException, handle_http_exception)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
