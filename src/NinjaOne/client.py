"""HTTP client for the NinjaOne Public API v2.

Reference: {base_url}/apidocs/NinjaRMM-API-v2.json (the apidocs-beta pages are a JS app
over that spec).

PAGINATION IS THE TRAP HERE. The API uses two different paging rules, and getting
either wrong silently reports a fraction of the fleet as the whole fleet:

    /v2/devices, /v2/devices-detailed, /v2/organizations, /v2/locations
        Bare JSON array. `pageSize` + `after`, where `after` is the id of the LAST
        RECORD ON THE PREVIOUS PAGE. There is no `next` field. Paging stops at the
        first empty page: a short page is NOT treated as the end, because a server that
        caps pageSize below what was asked for would otherwise end the listing early.

    /v2/queries/*
        Envelope {cursor: {name, offset, count, expires}, results: [...]}. Pass
        `cursor=<cursor.name>` to continue; a short or empty page is the last one.

Every call is a GET except the OAuth token POST, which is a POST by protocol.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from types import TracebackType
from typing import Any, Self

import requests

from NinjaOne.config import NinjaOneSettings

log = logging.getLogger("NinjaOne")

RETRY_STATUSES = (429, 502, 503, 504)
MAX_PAGES = 100_000
"""Backstop against a paging loop the cursor guards don't catch."""
MAX_REPEATED_PAGES = 3
"""/v2/queries/* occasionally serves the same page twice (seen live on os-patch-installs).
Asking again moves on; only a page that keeps repeating is treated as a stuck cursor."""
PROGRESS_EVERY = 50
MAX_RESTARTS = 3
"""/v2/queries/* occasionally ends a cursor early (an empty page mid-way, seen live on
os-patches). The query is restarted this many times before giving up."""


class NinjaOneError(RuntimeError):
    pass


class NinjaOneAuthError(NinjaOneError):
    pass


class NinjaOneClient:
    """Authenticated, read-only access to one NinjaOne instance.

    One token per client, cached until shortly before `expires_in` and re-acquired
    once on a 401, so a long sweep doesn't die halfway when the token lapses.

        with NinjaOneClient() as client:          # NINJA_* from env / .env
            devices = list_devices(client, os="Windows 11")
    """

    def __init__(
        self,
        settings: NinjaOneSettings | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.settings = settings or NinjaOneSettings()
        self.session = session or requests.Session()
        self._token: str | None = None
        self._token_expires_at = 0.0

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self.session.close()

    # -- auth -------------------------------------------------------------------

    def _acquire_token(self) -> str:
        """Client-credentials token. The one write verb in this library."""
        settings = self.settings
        secret = settings.client_secret.get_secret_value()
        if not settings.client_id or not secret:
            raise NinjaOneAuthError("NINJA_CLIENT_ID / NINJA_CLIENT_SECRET are not set (environment or .env)")

        response = self.session.post(
            settings.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.client_id,
                "client_secret": secret,
                "scope": settings.scope,
            },
            timeout=settings.timeout,
        )
        if response.status_code != 200:
            # Deliberately not logging the body: it can echo the client_id back.
            raise NinjaOneAuthError(
                f"Token request failed with HTTP {response.status_code}. Check "
                f"NINJA_CLIENT_ID/SECRET, NINJA_BASE_URL, and that the client app grants the "
                f"'{settings.scope}' scope with grant type client_credentials."
            )

        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise NinjaOneAuthError(f"No access_token in token response: {payload.get('error')}")

        granted = payload.get("scope")
        if granted and settings.scope not in granted:
            # A token without monitoring 403s on every read, which reads like a broken
            # endpoint rather than a misconfigured client app.
            log.warning("token granted scope %r, expected to include %r", granted, settings.scope)

        expires_in = float(payload.get("expires_in") or 3600)
        self._token = str(token)
        self._token_expires_at = time.monotonic() + max(expires_in - 60, 0)
        return self._token

    def token(self) -> str:
        if self._token is None or time.monotonic() >= self._token_expires_at:
            return self._acquire_token()
        return self._token

    # -- requests ---------------------------------------------------------------

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET one /v2 path. Honours Retry-After; re-authenticates once on 401."""
        url = self.settings.api_root + path
        reauthenticated = False
        response: requests.Response | None = None

        for attempt in range(1, self.settings.max_attempts + 1):
            headers = {"Authorization": f"Bearer {self.token()}", "Accept": "application/json"}
            response = self.session.get(url, headers=headers, params=params, timeout=self.settings.timeout)

            if response.status_code == 401 and not reauthenticated:
                reauthenticated = True
                self._token = None
                continue
            if response.status_code in RETRY_STATUSES and attempt < self.settings.max_attempts:
                retry_after = response.headers.get("Retry-After", "")
                delay = float(retry_after) if retry_after.isdigit() else min(2**attempt, 60)
                log.debug("HTTP %s on %s, retrying in %.0fs", response.status_code, path, delay)
                time.sleep(delay)
                continue
            break

        assert response is not None  # max_attempts >= 1, so the loop always assigns
        if response.status_code == 403:
            raise NinjaOneAuthError(
                f"GET /v2{path} returned 403. The token's granted scope probably lacks "
                f"'{self.settings.scope}' - check the client app, not the endpoint."
            )
        response.raise_for_status()
        if not response.content:
            return None
        return response.json()

    def get_list(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """GET a path that returns a bare array. Fails loudly if it doesn't.

        Silently coercing an unexpected envelope turns a shape change into an empty
        fleet, which reads as "nothing is affected" - the most misleading outcome.
        """
        payload = self.get(path, params)
        if payload is None:
            return []
        if not isinstance(payload, list):
            raise NinjaOneError(
                f"GET /v2{path} returned {type(payload).__name__}, expected a JSON array. "
                f"The endpoint's shape may have changed - check the API reference."
            )
        return payload

    def get_object(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET a path that returns a JSON object. Fails loudly if it doesn't."""
        payload = self.get(path, params)
        if not isinstance(payload, dict):
            raise NinjaOneError(
                f"GET /v2{path} returned {type(payload).__name__}, expected a JSON object. "
                f"The endpoint's shape may have changed - check the API reference."
            )
        return payload

    def paginate_after(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        page_size: int | None = None,
        id_field: str = "id",
    ) -> Iterator[dict[str, Any]]:
        """Every record from a bare-array endpoint paged with `after`.

        `after` carries the previous page's last id; the first empty page ends the listing.
        """
        size = page_size or self.settings.page_size
        after: Any = None
        seen: set[Any] = set()

        for _ in range(MAX_PAGES):
            page_params: dict[str, Any] = {**(params or {}), "pageSize": size}
            if after is not None:
                page_params["after"] = after

            page = self.get_list(path, page_params)
            if not page:
                return
            yield from page

            next_after = page[-1].get(id_field)
            if next_after is None:
                raise NinjaOneError(
                    f"A page from /v2{path} has no {id_field!r} on its last record, so "
                    f"there is no cursor to continue from. Paging cannot proceed safely."
                )
            if next_after in seen:
                raise NinjaOneError(f"Paging cursor for /v2{path} did not advance past {next_after!r}.")
            seen.add(next_after)
            after = next_after

        raise NinjaOneError(f"/v2{path} exceeded {MAX_PAGES} pages; refusing to continue.")

    def paginate_cursor(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        page_size: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Every record from a /v2/queries/* endpoint ({cursor, results} envelope).

        Two server faults are handled, both seen live:

        - **A page served twice** (same offset, same records): asked for again, never
          yielded twice. Only MAX_REPEATED_PAGES repeats in a row count as a stuck cursor.
        - **A page that ends the query early**: an empty or short page that still carries
          a cursor, with the server's own `cursor.count` not yet reached. The whole query
          is restarted with a fresh cursor instead (MAX_RESTARTS times), and an error is
          raised rather than partial data returned.

        Records are collected per attempt and only yielded once an attempt is complete,
        so a restart never yields duplicates.
        """
        size = page_size or self.settings.page_size
        detail = ""
        for attempt in range(1, MAX_RESTARTS + 1):
            records, detail = self._cursor_pass(path, params, size)
            if not detail:
                yield from records
                return
            log.warning(
                "/v2%s %s; restarting the query (attempt %d of %d)", path, detail, attempt, MAX_RESTARTS
            )
        raise NinjaOneError(
            f"/v2{path} {detail}, on all {MAX_RESTARTS} attempts. "
            f"Refusing to return partial data - try again in a minute."
        )

    def _cursor_pass(
        self, path: str, params: dict[str, Any] | None, size: int
    ) -> tuple[list[dict[str, Any]], str]:
        """One pass over a cursor. Returns (records, "") if complete, else (partial, what went wrong)."""
        cursor_name: str | None = None
        seen: set[str] = set()
        records: list[dict[str, Any]] = []
        expected: int | None = None
        repeats = pages = 0

        for _ in range(MAX_PAGES):
            page_params: dict[str, Any] = {**(params or {}), "pageSize": size}
            if cursor_name:
                page_params["cursor"] = cursor_name

            payload = self.get(path, page_params)
            if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                raise NinjaOneError(
                    f"GET /v2{path} did not return a {{cursor, results}} envelope. "
                    f"The endpoint's shape may have changed - check the API reference."
                )
            results: list[dict[str, Any]] = payload["results"]
            cursor = payload.get("cursor") or {}
            if expected is None and isinstance(cursor.get("count"), int):
                expected = cursor["count"]

            if results:
                marker = json.dumps(
                    [cursor.get("offset"), results[0], results[-1]], sort_keys=True, default=str
                )
                if marker in seen:
                    repeats += 1
                    if repeats > MAX_REPEATED_PAGES:
                        raise NinjaOneError(
                            f"Paging cursor for /v2{path} did not advance: the page at offset "
                            f"{cursor.get('offset')} came back {repeats} times in a row; refusing to loop."
                        )
                    log.info("/v2%s repeated the page at offset %s; asking again", path, cursor.get("offset"))
                    continue
                seen.add(marker)
            repeats = 0

            records.extend(results)
            pages += 1
            if pages % PROGRESS_EVERY == 0:
                log.info(
                    "/v2%s: %s of %s records", path, len(records), expected if expected is not None else "?"
                )
            if len(results) < size:
                # The true last page carries no cursor. A short page that still has one,
                # before the server's own count is reached, is the early-end fault.
                if cursor.get("name") and expected is not None and len(records) < expected:
                    offset = cursor.get("offset")
                    return (
                        records,
                        f"ended early at offset {offset} with {len(records)} of {expected} records",
                    )
                return records, ""

            cursor_name = cursor.get("name")
            if not cursor_name:
                raise NinjaOneError(
                    f"A full page from /v2{path} came back without a cursor name, so "
                    f"there is no way to continue. Paging cannot proceed safely."
                )

        raise NinjaOneError(f"/v2{path} exceeded {MAX_PAGES} pages; refusing to continue.")

    def fetch_spec(self) -> dict[str, Any]:
        """The instance's OpenAPI document. Public; no token needed."""
        response = self.session.get(self.settings.spec_url, timeout=self.settings.timeout)
        response.raise_for_status()
        spec: dict[str, Any] = response.json()
        return spec
