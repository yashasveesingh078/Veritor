from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

URL = "/api/v1/scans"


def payload(**overrides: Any) -> dict[str, Any]:
    return {"ecosystem": "npm", "package_name": "left-pad", "version": "1.3.0", **overrides}


def error_fields(body: dict[str, Any]) -> list[str]:
    return [detail["field"] for detail in body["error"]["details"]]


@pytest.mark.parametrize(
    ("ecosystem", "package_name", "version"),
    [
        ("npm", "left-pad", "1.3.0"),
        ("npm", "@babel/core", "7.26.0"),
        ("npm", "JSONStream", "1.3.5"),
        ("npm", "pkg", "1.0.0-rc.1+build.5"),
        ("pypi", "requests", "2.32.3"),
        ("pypi", "zope.interface", "7.2"),
        ("pypi", "Flask_Cors", "1.0rc1"),
        ("pypi", "pkg", "2024.1.post1"),
    ],
)
def test_valid_scan_is_accepted(
    client: TestClient, ecosystem: str, package_name: str, version: str
) -> None:
    response = client.post(
        URL, json={"ecosystem": ecosystem, "package_name": package_name, "version": version}
    )

    assert response.status_code == 202
    body = response.json()
    assert UUID(body.pop("scan_id")).version == 4
    assert body == {
        "status": "accepted",
        "ecosystem": ecosystem,
        "package_name": package_name,
        "version": version,
    }


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"ecosystem": "rubygems"}, "ecosystem"),
        ({"ecosystem": "NPM"}, "ecosystem"),
        ({"package_name": ""}, "package_name"),
        ({"package_name": "a" * 215}, "package_name"),
        ({"package_name": "../etc/passwd"}, "package_name"),
        ({"package_name": ".hidden"}, "package_name"),
        ({"package_name": "a/b"}, "package_name"),
        ({"package_name": "@Scope/pkg"}, "package_name"),
        ({"package_name": "left-pad\n"}, "package_name"),
        ({"package_name": "name with space"}, "package_name"),
        ({"version": ""}, "version"),
        ({"version": "latest"}, "version"),
        ({"version": "^1.0.0"}, "version"),
        ({"version": "1.0"}, "version"),
        ({"version": "01.0.0"}, "version"),
        ({"version": "1.0.0\n"}, "version"),
        ({"version": "1." + "1" * 256}, "version"),
        ({"ecosystem": "pypi", "package_name": "@scope/pkg"}, "package_name"),
        ({"ecosystem": "pypi", "package_name": "trailing-"}, "package_name"),
        ({"ecosystem": "pypi", "version": "not-a-version"}, "version"),
        ({"ecosystem": "pypi", "version": " 1.0 "}, "version"),
        ({"ecosystem": "pypi", "version": "1.0\n"}, "version"),
        ({"package_name": 123}, "package_name"),
    ],
)
def test_invalid_field_is_rejected(
    client: TestClient, overrides: dict[str, Any], field: str
) -> None:
    response = client.post(URL, json=payload(**overrides))

    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error"
    assert error_fields(body) == [f"body.{field}"]


@pytest.mark.parametrize("field", ["ecosystem", "package_name", "version"])
def test_missing_field_is_rejected(client: TestClient, field: str) -> None:
    data = payload()
    del data[field]

    response = client.post(URL, json=data)

    assert response.status_code == 422
    assert error_fields(response.json()) == [f"body.{field}"]


def test_unknown_field_is_rejected(client: TestClient) -> None:
    response = client.post(URL, json=payload(callback_url="http://example.test"))

    assert response.status_code == 422
    assert error_fields(response.json()) == ["body.callback_url"]


def test_every_invalid_field_is_reported(client: TestClient) -> None:
    response = client.post(URL, json=payload(package_name="../x", version="latest"))

    assert sorted(error_fields(response.json())) == ["body.package_name", "body.version"]


def test_validation_error_message_has_no_internal_prefix(client: TestClient) -> None:
    response = client.post(URL, json=payload(version="latest"))

    assert response.json()["error"]["details"][0]["message"] == "Not an exact semantic version"


def test_rejected_input_is_not_echoed(client: TestClient) -> None:
    response = client.post(URL, json=payload(package_name="<script>alert(1)</script>"))

    assert response.status_code == 422
    assert "<script>" not in response.text


def test_malformed_json_returns_error_envelope(client: TestClient) -> None:
    response = client.post(URL, content=b"{not json", headers={"Content-Type": "application/json"})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
