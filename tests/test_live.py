"""Read-only calls against a real NinjaOne instance. Skipped by default.

uv run pytest -m live          # needs NINJA_CLIENT_ID / NINJA_CLIENT_SECRET (env or .env)
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from NinjaOne import (
    NinjaOneClient,
    NinjaOneSettings,
    list_devices,
    list_kbs,
    list_organizations,
    list_roles,
    list_software,
    list_tags,
    vulnerability_counts,
)

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def live_client() -> Iterator[NinjaOneClient]:
    settings = NinjaOneSettings()
    if not settings.client_id or not settings.client_secret.get_secret_value():
        pytest.skip("NINJA_CLIENT_ID / NINJA_CLIENT_SECRET not set")
    with NinjaOneClient(settings) as client:
        yield client


def test_base_data(live_client: NinjaOneClient) -> None:
    organizations = list_organizations(live_client)
    assert organizations, "an instance has at least one organisation"
    list_roles(live_client)
    list_tags(live_client)
    devices = list_devices(live_client, organization_id=organizations[0].id)
    assert all(device.organization_id == organizations[0].id for device in devices)


def test_software_and_security(live_client: NinjaOneClient) -> None:
    org_df = f"org = {list_organizations(live_client)[0].id}"
    list_software(live_client, df=org_df, vendor="Microsoft")
    list_kbs(live_client, df=org_df)
    vulnerability_counts(live_client, df=org_df)
