import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

TEST_ORIGIN = "http://frontend.test"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def app() -> FastAPI:
    return create_app(Settings(log_level="INFO", cors_origins=[TEST_ORIGIN]))


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)
