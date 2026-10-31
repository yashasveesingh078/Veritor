import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from tests.conftest import TEST_ORIGIN

INTERNAL_MESSAGE = "sensitive internal detail"


@pytest.fixture
def failing_client(app: FastAPI) -> TestClient:
    def boom() -> None:
        raise RuntimeError(INTERNAL_MESSAGE)

    app.add_api_route("/boom", boom)
    return TestClient(app)


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_response_has_generated_request_id(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "client-value"})

    assert len(response.headers["X-Request-ID"]) == 32
    assert response.headers["X-Request-ID"] != "client-value"


def test_unknown_route_returns_error_envelope(client: TestClient) -> None:
    response = client.get("/missing")

    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "not_found", "message": "Not Found", "details": []}
    }


def test_wrong_method_keeps_allow_header(client: TestClient) -> None:
    response = client.get("/api/v1/scans")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"
    assert response.headers["Allow"] == "POST"


def test_unhandled_error_is_generic_and_logged(
    failing_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="app.request"):
        response = failing_client.get("/boom")

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_server_error",
            "message": "Internal server error",
            "details": [],
        }
    }
    assert INTERNAL_MESSAGE not in response.text
    assert response.headers["X-Request-ID"] in caplog.text
    assert INTERNAL_MESSAGE in caplog.text


def test_unhandled_error_keeps_cors_headers(failing_client: TestClient) -> None:
    response = failing_client.get("/boom", headers={"Origin": TEST_ORIGIN})

    assert response.status_code == 500
    assert response.headers["Access-Control-Allow-Origin"] == TEST_ORIGIN


def test_cors_allows_configured_origin(client: TestClient) -> None:
    response = client.options(
        "/api/v1/scans",
        headers={
            "Origin": TEST_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == TEST_ORIGIN


def test_cors_exposes_request_id(client: TestClient) -> None:
    response = client.get("/health", headers={"Origin": TEST_ORIGIN})

    assert response.headers["Access-Control-Expose-Headers"] == "X-Request-ID"


def test_cors_ignores_other_origins(client: TestClient) -> None:
    response = client.get("/health", headers={"Origin": "http://evil.test"})

    assert "Access-Control-Allow-Origin" not in response.headers


def test_request_log_cannot_be_split_by_path(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.request"):
        client.get("/x%0aFORGED")

    assert "\nFORGED" not in caplog.text
    assert "status=404" in caplog.text


def test_settings_read_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERITOR_TRIAGE_MODEL", "example-model")
    monkeypatch.setenv("VERITOR_CORS_ORIGINS", '["http://one.test"]')

    settings = Settings()

    assert settings.triage_model == "example-model"
    assert settings.cors_origins == ["http://one.test"]
