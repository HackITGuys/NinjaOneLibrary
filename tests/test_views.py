from __future__ import annotations

from datetime import UTC, datetime

import pytest
import responses

from NinjaOne import (
    Device,
    DeviceVulnerabilityCounts,
    KbSummary,
    Location,
    NinjaOneClient,
    OsPatch,
    SoftwareInstall,
    SoftwarePatch,
    brief,
    render_table,
    summarise_software,
)
from NinjaOne.models import ApiModel
from tests.conftest import get, raw_device


def install(
    device_id: int, name: str, version: str | None, publisher: str = "Igor Pavlov"
) -> SoftwareInstall:
    return SoftwareInstall(device_id=device_id, name=name, publisher=publisher, version=version)


def test_render_table_aligns_columns() -> None:
    rows = [
        {"name": "SRV-SQL01", "devices": 12, "active": True, "tags": ["Production", "DMZ"], "note": None},
        {"name": "WS-1", "devices": 3, "active": False, "tags": [], "note": "a  b\nc"},
    ]
    assert render_table(rows).splitlines() == [
        "NAME       DEVICES  ACTIVE  TAGS             NOTE",
        "SRV-SQL01       12  yes     Production, DMZ",
        "WS-1             3  no                       a b c",
    ]
    assert render_table([]) == ""


def test_brief_of_nothing_and_of_an_unknown_type(client: NinjaOneClient) -> None:
    assert brief(client, []) == []

    class Unknown(ApiModel):
        id: int

    with pytest.raises(TypeError, match="No brief view for Unknown"):
        brief(client, [Unknown(id=1)])


def test_devices(client: NinjaOneClient) -> None:
    device = Device.model_validate(raw_device(5, name="SRV-SQL01", tags=["Production"]))
    assert brief(client, [device]) == [
        {
            "id": 5,
            "name": "SRV-SQL01",
            "organization": "Contoso",
            "location": "Oslo",
            "role": "Windows Server",
            "os": "Windows Server 2022 Standard",
            "state": "online",
            "tags": ["Production"],
            "last_contact": "2026-01-01 00:00",
        }
    ]


def test_software_is_one_row_per_product_and_version(client: NinjaOneClient) -> None:
    installs = [
        install(1, "7-Zip", "23.01"),
        install(2, "7-Zip", "24.09"),
        install(3, "7-Zip", "24.09"),
        install(3, "7-Zip", "24.09"),  # the same device twice still counts once
        install(4, "7-Zip", None),
        install(1, "Notepad++", "8.6", publisher="Notepad++ Team"),
    ]
    assert brief(client, installs) == [
        {"publisher": "Igor Pavlov", "name": "7-Zip", "version": "24.09", "devices": 2},
        {"publisher": "Igor Pavlov", "name": "7-Zip", "version": "23.01", "devices": 1},
        {"publisher": "Igor Pavlov", "name": "7-Zip", "version": None, "devices": 1},
        {"publisher": "Notepad++ Team", "name": "Notepad++", "version": "8.6", "devices": 1},
    ]


def test_software_summaries(client: NinjaOneClient) -> None:
    installs = [install(1, "7-Zip", "9.20"), install(2, "7-Zip", "24.09"), install(2, "7-Zip", "")]
    assert brief(client, summarise_software(installs)) == [
        {
            "publisher": "Igor Pavlov",
            "name": "7-Zip",
            "devices": 2,
            "installs": 3,
            "versions": 3,
            "newest": "24.09",  # by version, not by text
        }
    ]


def test_kbs_show_counts_not_device_ids(client: NinjaOneClient) -> None:
    kbs = [
        KbSummary(
            kb="KB5031356",
            name="2026-01 Cumulative Update",
            severity="CRITICAL",
            release_date=datetime(2026, 1, 13, 18, 0, tzinfo=UTC),
            device_count=3,
            counts={"installed": 2, "pending": 1},
            devices={"installed": [1, 3], "pending": [2]},
        ),
        KbSummary(kb="KB5000000", device_count=1, counts={"failed": 1}, devices={"failed": [4]}),
    ]
    rows = brief(client, kbs)
    assert rows[0] == {
        "kb": "KB5031356",
        "name": "2026-01 Cumulative Update",
        "severity": "CRITICAL",
        "released": "2026-01-13",
        "devices": 3,
        "pending": 1,
        "failed": 0,
        "installed": 2,
    }
    assert list(rows[1]) == list(rows[0])  # every row has every status column, in status order
    assert not any(isinstance(value, list | dict) for row in rows for value in row.values())  # no ids


def test_patches_are_grouped_per_patch_and_status(client: NinjaOneClient) -> None:
    def patch(device_id: int, kb: str, status: str) -> OsPatch:
        return OsPatch(
            device_id=device_id, kb_number=kb, name=f"Update {kb}", severity="CRITICAL", status=status
        )

    records = [
        patch(1, "KB1", "MANUAL"),
        patch(2, "KB1", "MANUAL"),
        patch(2, "KB1", "MANUAL"),  # the same device twice still counts once
        patch(3, "KB1", "FAILED"),
        patch(1, "KB2", "APPROVED"),
    ]
    assert brief(client, records) == [
        {"kb": "KB1", "name": "Update KB1", "severity": "CRITICAL", "status": "pending", "devices": 2},
        {"kb": "KB1", "name": "Update KB1", "severity": "CRITICAL", "status": "failed", "devices": 1},
        {"kb": "KB2", "name": "Update KB2", "severity": "CRITICAL", "status": "approved", "devices": 1},
    ]


def test_software_patches(client: NinjaOneClient) -> None:
    records = [
        SoftwarePatch(device_id=d, vendor="Google", title="Chrome", version="131.0", status="MANUAL")
        for d in (1, 2)
    ]
    assert brief(client, records) == [
        {
            "vendor": "Google",
            "title": "Chrome",
            "version": "131.0",
            "impact": None,
            "status": "pending",
            "devices": 2,
        }
    ]


def test_locations_get_organisation_names(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get(api, "/organizations", [{"id": 1, "name": "Contoso"}], {"pageSize": "2"})
    get(api, "/organizations", [], {"pageSize": "2", "after": "1"})
    locations = [
        Location(id=100, name="Oslo", organization_id=1, address="Storgata 1"),
        Location(id=101, name="Lab", organization_id=7),  # unknown organisation: its id
    ]
    assert brief(client, locations) == [
        {"id": 100, "name": "Oslo", "organization": "Contoso", "address": "Storgata 1"},
        {"id": 101, "name": "Lab", "organization": 7, "address": None},
    ]
    assert sum("/organizations" in (call.request.url or "") for call in api.calls) == 2  # fetched once


def test_vulnerabilities_with_and_without_names(client: NinjaOneClient) -> None:
    named = DeviceVulnerabilityCounts(
        device_id=1,
        critical_vulnerability_count=2,
        high_vulnerability_count=1,
        health_status="UNHEALTHY",
        device_name="SRV-SQL01",
        organization_name="Contoso",
    )
    unnamed = DeviceVulnerabilityCounts(device_id=9, low_vulnerability_count=1)
    assert brief(client, [named, unnamed]) == [
        {
            "device": "SRV-SQL01",
            "organization": "Contoso",
            "critical": 2,
            "high": 1,
            "medium": 0,
            "low": 0,
            "total": 3,
            "health": "unhealthy",
        },
        {
            "device": 9,
            "organization": None,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 1,
            "total": 1,
            "health": None,
        },
    ]
