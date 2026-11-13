from __future__ import annotations

from pathlib import Path

import pytest
import responses

from NinjaOne import NinjaOneAuthError, NinjaOneClient, NinjaOneError, NinjaOneSettings
from tests.conftest import API, TOKEN_URL, get


def token_calls(api: responses.RequestsMock) -> int:
    return sum(1 for call in api.calls if call.request.url == TOKEN_URL)


def test_token_is_cached_across_requests(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get(api, "/roles", [])
    client.get("/roles")
    client.get("/roles")
    assert token_calls(api) == 1
    assert api.calls[1].request.headers["Authorization"] == "Bearer tok"


def test_401_reauthenticates_once(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    api.get(API + "/roles", status=401)
    api.get(API + "/roles", json=[{"id": 1}])
    assert client.get("/roles") == [{"id": 1}]
    assert token_calls(api) == 2


def test_403_is_a_scope_error(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    api.get(API + "/roles", status=403)
    with pytest.raises(NinjaOneAuthError, match="scope"):
        client.get("/roles")


def test_429_is_retried(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    api.get(API + "/roles", status=429, headers={"Retry-After": "1"})
    api.get(API + "/roles", json=[])
    assert client.get("/roles") == []


def test_missing_credentials() -> None:
    client = NinjaOneClient(NinjaOneSettings(_env_file=None, client_id="", client_secret=""))
    with pytest.raises(NinjaOneAuthError, match="NINJA_CLIENT_ID"):
        client.token()


def test_get_list_rejects_an_envelope(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get(api, "/roles", {"results": []})
    with pytest.raises(NinjaOneError, match="expected a JSON array"):
        client.get_list("/roles")


def test_paginate_after_continues_past_a_short_page(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    # page_size is 2. A short page is NOT the end (the server may cap pageSize); an empty one is.
    get(api, "/organizations", [{"id": 1}, {"id": 2}], {"pageSize": "2"})
    get(api, "/organizations", [{"id": 3}], {"pageSize": "2", "after": "2"})
    get(api, "/organizations", [], {"pageSize": "2", "after": "3"})
    assert [r["id"] for r in client.paginate_after("/organizations")] == [1, 2, 3]


def test_paginate_after_refuses_a_stuck_cursor(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get(api, "/organizations", [{"id": 1}, {"id": 2}])  # same page whatever `after` says
    with pytest.raises(NinjaOneError, match="did not advance"):
        list(client.paginate_after("/organizations"))


def envelope(results: list[dict[str, int]], name: str | None, offset: int, count: int) -> dict[str, object]:
    return {"cursor": {"name": name, "offset": offset, "count": count}, "results": results}


def test_paginate_cursor_follows_the_cursor(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get(api, "/queries/software", envelope([{"d": 1}, {"d": 2}], "c1", 0, 3), {"pageSize": "2"})
    get(api, "/queries/software", envelope([{"d": 3}], None, 2, 3), {"pageSize": "2", "cursor": "c1"})
    assert [r["d"] for r in client.paginate_cursor("/queries/software")] == [1, 2, 3]


def test_paginate_cursor_skips_a_repeated_page(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    page_one = envelope([{"d": 1}, {"d": 2}], "c1", 0, 3)
    get(api, "/queries/software", page_one, {"pageSize": "2"})
    api.get(API + "/queries/software", json=page_one)  # served again for cursor=c1 ...
    api.get(API + "/queries/software", json=envelope([{"d": 3}], None, 2, 3))  # ... then moves on
    assert [r["d"] for r in client.paginate_cursor("/queries/software")] == [1, 2, 3]


def test_paginate_cursor_restarts_a_query_that_ends_early(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    # First pass: an empty page that still carries a cursor, with 1 of 3 records. Second pass: complete.
    api.get(API + "/queries/os-patches", json=envelope([{"d": 1}, {"d": 2}], "c1", 0, 3))
    api.get(API + "/queries/os-patches", json=envelope([], "c1", 2, 3))
    api.get(API + "/queries/os-patches", json=envelope([{"d": 1}, {"d": 2}], "c2", 0, 3))
    api.get(API + "/queries/os-patches", json=envelope([{"d": 3}], None, 2, 3))
    assert [r["d"] for r in client.paginate_cursor("/queries/os-patches")] == [1, 2, 3]


def test_paginate_cursor_transforms_records_as_they_arrive(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    get(api, "/queries/software", envelope([{"d": 1, "x": 9}, {"d": 2}], "c1", 0, 3), {"pageSize": "2"})
    get(api, "/queries/software", envelope([{"d": 3}], None, 2, 3), {"pageSize": "2", "cursor": "c1"})
    assert list(client.paginate_cursor("/queries/software", transform=lambda r: r["d"])) == [1, 2, 3]


def test_cache_dir_expands_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NINJA_CACHE_DIR", "~/ninja-cache")
    assert NinjaOneSettings(_env_file=None).cache_dir == Path.home() / "ninja-cache"
