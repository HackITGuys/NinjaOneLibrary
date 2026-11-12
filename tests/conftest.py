"""Shared fixtures: a client against a mocked NinjaOne API (no network)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
import responses
from responses import matchers

from NinjaOne import NinjaOneClient, NinjaOneSettings

BASE = "https://ninja.test"
API = BASE + "/v2"
TOKEN_URL = BASE + "/ws/oauth/token"


@pytest.fixture
def settings() -> NinjaOneSettings:
    # _env_file=None: never pick up a developer's real .env during tests.
    return NinjaOneSettings(
        _env_file=None,
        base_url=BASE,
        client_id="test-id",
        client_secret="test-secret",
        page_size=2,
        max_attempts=3,
    )


@pytest.fixture
def api() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        mock.post(TOKEN_URL, json={"access_token": "tok", "expires_in": 3600, "scope": "monitoring"})
        yield mock


@pytest.fixture
def client(settings: NinjaOneSettings, api: responses.RequestsMock) -> NinjaOneClient:
    return NinjaOneClient(settings)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("NinjaOne.client.time.sleep", lambda _seconds: None)


def get(mock: responses.RequestsMock, path: str, body: Any, params: dict[str, Any] | None = None) -> None:
    """Register GET /v2{path}; with params, only a request with exactly these query params matches."""
    match = [matchers.query_param_matcher(params)] if params is not None else []
    mock.get(API + path, json=body, match=match)


def raw_device(
    device_id: int,
    *,
    name: str = "",
    org: tuple[int, str] | None = (1, "Contoso"),
    role: tuple[int, str] | None = (10, "Windows Server"),
    location: tuple[int, str] | None = (100, "Oslo"),
    node_class: str = "WINDOWS_SERVER",
    tags: list[str] | None = None,
    os_name: str | None = "Windows Server 2022 Standard",
    offline: bool = False,
) -> dict[str, Any]:
    """A /v2/devices-detailed record, camelCase as the API sends it."""
    references: dict[str, Any] = {}
    if org and org[1]:
        references["organization"] = {"id": org[0], "name": org[1]}
    if role and role[1]:
        references["role"] = {"id": role[0], "name": role[1]}
    if location and location[1]:
        references["location"] = {"id": location[0], "name": location[1]}
    return {
        "id": device_id,
        "systemName": name or f"HOST{device_id}",
        "dnsName": f"host{device_id}.example.test",
        "nodeClass": node_class,
        "organizationId": org[0] if org else None,
        "nodeRoleId": role[0] if role else None,
        "locationId": location[0] if location else None,
        "approvalStatus": "APPROVED",
        "offline": offline,
        "lastContact": 1767225600.0,  # 2026-01-01T00:00:00Z
        "publicIP": "203.0.113.7",
        "tags": tags or [],
        "os": {"name": os_name, "buildNumber": "20348"} if os_name else None,
        "references": references,
    }


PAGE_SIZE = 2
"""Matches the settings fixture."""


def get_query(
    mock: responses.RequestsMock, path: str, rows: list[dict[str, Any]], params: dict[str, Any] | None = None
) -> None:
    """Register a /v2/queries/* endpoint serving `rows` as properly chained cursor pages."""
    pages = [rows[i : i + PAGE_SIZE] for i in range(0, len(rows), PAGE_SIZE)]
    if not pages or len(pages[-1]) == PAGE_SIZE:
        pages.append([])  # a final short (here empty) page with no cursor ends the query
    for number, page in enumerate(pages):
        last = number == len(pages) - 1
        cursor = {
            "name": None if last else f"c{number + 1}",
            "offset": number * PAGE_SIZE,
            "count": len(rows),
        }
        page_params = {**(params or {}), "pageSize": str(PAGE_SIZE)}
        if number:
            page_params["cursor"] = f"c{number}"
        get(mock, path, {"cursor": cursor, "results": page}, page_params)
