from __future__ import annotations

from datetime import date

import responses

from NinjaOne import (
    NinjaOneClient,
    OsPatch,
    find_endpoints,
    list_kbs,
    list_scan_groups,
    normalise_kb,
    normalise_status,
    os_patches,
    summarise_kbs,
    vulnerability_counts,
)
from tests.conftest import BASE, get, get_query


def patch(device_id: int, kb: str | None, status: str, at: float = 1767225600.0) -> OsPatch:
    return OsPatch.model_validate(
        {
            "deviceId": device_id,
            "kbNumber": kb,
            "status": status,
            "timestamp": at,
            "name": "2026-01 Cumulative Update",
        }
    )


def test_normalisation() -> None:
    assert normalise_kb("5031356") == normalise_kb("kb 5031356") == "KB5031356"
    assert normalise_status("MANUAL") == "pending"
    assert normalise_status("Installed") == "installed"
    assert normalise_status("SOMETHING_NEW") == "something_new"
    assert normalise_status(None) == "unknown"
    assert patch(1, "5031356", "MANUAL").kb == "KB5031356"
    assert patch(1, None, "MANUAL").kb is None


def test_summarise_kbs_latest_record_wins() -> None:
    records = [
        patch(1, "KB1111111", "FAILED", at=100),
        patch(1, "1111111", "INSTALLED", at=200),  # later: device 1 is installed
        patch(2, "KB1111111", "MANUAL", at=100),
        patch(3, "KB1111111", "FAILED", at=100),
        patch(3, "KB1111111", "INSTALLED", at=100),  # same time: the more final status wins
        patch(4, None, "MANUAL"),  # no KB (e.g. a Linux package): skipped
    ]
    [summary] = summarise_kbs(records, kbs=["KB2222222"])[:1]
    assert summary.kb == "KB1111111"
    assert summary.device_count == 3
    assert summary.counts == {"pending": 1, "installed": 2}  # in status order
    assert summary.devices == {"pending": [2], "installed": [1, 3]}
    assert summary.name == "2026-01 Cumulative Update"

    requested = summarise_kbs(records, kbs=["2222222"])[1]
    assert (requested.kb, requested.device_count, requested.counts) == ("KB2222222", 0, {})


def test_os_patches_filters_kbs_client_side(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    rows = [{"deviceId": 1, "kbNumber": "KB1", "status": "MANUAL"}, {"deviceId": 1, "kbNumber": "KB5031356"}]
    get_query(api, "/queries/os-patches", rows, {"status": "MANUAL", "df": "org in (1)"})
    found = os_patches(client, df="org in (1)", status="MANUAL", kbs=["5031356"])
    assert [p.kb for p in found] == ["KB5031356"]


def test_list_kbs_merges_outstanding_and_installs(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    get_query(
        api,
        "/queries/os-patches",
        [{"deviceId": 1, "kbNumber": "KB5031356", "status": "MANUAL", "timestamp": 100}],
    )
    get_query(
        api,
        "/queries/os-patch-installs",
        [{"deviceId": 2, "kbNumber": "KB5031356", "status": "INSTALLED", "installedAt": 200}],
        {"installedAfter": "2026-01-01"},
    )
    [summary] = list_kbs(client, include_installed=True, installed_after=date(2026, 1, 1))
    assert summary.counts == {"pending": 1, "installed": 1}


def test_vulnerability_counts(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    rows = [
        {"deviceId": 1, "criticalVulnerabilityCount": 0, "highVulnerabilityCount": 3},
        {"deviceId": 2, "criticalVulnerabilityCount": 1, "pendingOSPatchesCount": 4},
        {"deviceId": 3},
    ]
    get_query(api, "/queries/device-health", rows)
    worst_first = vulnerability_counts(client)
    assert [(c.device_id, c.total) for c in worst_first] == [(2, 1), (1, 3)]
    assert worst_first[0].pending_os_patches_count == 4


def test_scan_groups(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get(api, "/vulnerability/scan-groups", [{"id": 1, "groupName": "Qualys", "cveIdHeader": "CVE"}])
    [group] = list_scan_groups(client)
    assert (group.group_name, group.cve_id_header) == ("Qualys", "CVE")


def test_find_endpoints(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    spec = {
        "paths": {
            "/v2/vulnerability/scan-groups": {
                "get": {"tags": ["Vulnerability Management"], "summary": "Fetch all Scan Groups"},
                "post": {"tags": ["Vulnerability Management"], "summary": "Create"},
            },
            "/v2/devices": {"get": {"tags": ["system"], "summary": "List devices"}},
        }
    }
    api.get(BASE + "/apidocs/NinjaRMM-API-v2.json", json=spec)
    assert find_endpoints(client) == {"/v2/vulnerability/scan-groups": ["GET Fetch all Scan Groups"]}
