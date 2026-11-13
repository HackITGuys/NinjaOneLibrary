from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import responses

from NinjaOne import (
    NinjaOneClient,
    NinjaOneSettings,
    SnapshotDevice,
    SnapshotSoftware,
    SoftwareSnapshot,
    load_software_snapshot,
    save_software_snapshot,
    snapshot_path,
    software_catalog,
    software_devices,
    software_snapshot,
    take_software_snapshot,
)
from NinjaOne.snapshot import SNAPSHOT_FORMAT
from tests.conftest import BASE, get, get_query, raw_device


def make_snapshot(**overrides: Any) -> SoftwareSnapshot:
    fields: dict[str, Any] = {
        "format": SNAPSHOT_FORMAT,
        "instance": BASE,
        "taken_at": datetime.now(UTC),
        "install_count": 5,
        "devices": {
            1: SnapshotDevice(id=1, name="SRV-SQL01", organization_id=1, organization_name="Contoso"),
            2: SnapshotDevice(id=2, name="WS-0042", organization_id=2, organization_name="Fabrikam"),
        },
        "software": [
            SnapshotSoftware(
                publisher="Igor Pavlov", name="7-Zip 23.01 (x64)", version="23.01", device_ids=[1, 2, 9]
            ),
            SnapshotSoftware(
                publisher="Igor Pavlov", name="7-Zip 24.09 (x64)", version="24.09", device_ids=[2]
            ),
            SnapshotSoftware(
                publisher="Microsoft Corporation",
                name="Microsoft Visual C++ 2015",
                version="14.0",
                system_component=True,
                device_ids=[1],
            ),
        ],
    }
    return SoftwareSnapshot(**{**fields, **overrides})


def register_inventory(api: responses.RequestsMock) -> None:
    rows = [
        {"deviceId": 1, "name": "7-Zip 23.01 (x64)", "publisher": "Igor Pavlov", "version": "23.01"},
        {"deviceId": 2, "name": "7-Zip 23.01 (x64)", "publisher": "Igor Pavlov", "version": "23.01"},
        {"deviceId": 2, "name": "7-Zip 24.09 (x64)", "publisher": "Igor Pavlov", "version": "24.09"},
        {"deviceId": 2, "name": "7-Zip 24.09 (x64)", "publisher": "Igor Pavlov", "version": "24.09"},
        {
            "deviceId": 3,
            "name": "Microsoft Visual C++ 2015",
            "publisher": "Microsoft Corporation",
            "version": "14.0",
            "isSystemComponent": True,
        },
        {"deviceId": 3, "name": "In-house tool", "publisher": "", "version": ""},
    ]
    get_query(api, "/queries/software", rows)
    get(api, "/devices-detailed", [raw_device(1, name="SRV-SQL01"), raw_device(2)], {"pageSize": "2"})
    get(api, "/devices-detailed", [raw_device(3)], {"pageSize": "2", "after": "2"})
    get(api, "/devices-detailed", [], {"pageSize": "2", "after": "3"})


def software_reads(api: responses.RequestsMock) -> int:
    return sum("/queries/software" in (call.request.url or "") for call in api.calls)


def test_take_keeps_one_entry_per_software_with_its_devices(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    register_inventory(api)
    snapshot = take_software_snapshot(client)
    assert snapshot.install_count == 6
    assert [
        (s.publisher, s.name, s.version, s.system_component, s.device_ids) for s in snapshot.software
    ] == [
        (None, "In-house tool", None, False, [3]),  # "" is "not reported"
        ("Igor Pavlov", "7-Zip 23.01 (x64)", "23.01", False, [1, 2]),
        ("Igor Pavlov", "7-Zip 24.09 (x64)", "24.09", False, [2]),  # the duplicate counts once
        ("Microsoft Corporation", "Microsoft Visual C++ 2015", "14.0", True, [3]),
    ]
    assert snapshot.devices[1] == SnapshotDevice(
        id=1, name="SRV-SQL01", organization_id=1, organization_name="Contoso"
    )
    assert snapshot.instance == BASE


def test_save_and_load(settings: NinjaOneSettings) -> None:
    path = snapshot_path(settings)
    assert path.parent == settings.cache_dir
    assert path.name.startswith("software-ninja.test-") and path.suffix == ".json"
    assert load_software_snapshot(path) is None  # nothing saved yet

    snapshot = make_snapshot()
    save_software_snapshot(snapshot, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600  # it names the tenant's devices
    assert load_software_snapshot(path) == snapshot

    path.write_text("{not json")
    assert load_software_snapshot(path) is None
    path.write_text(json.dumps({**json.loads(make_snapshot().model_dump_json()), "format": 0}))
    assert load_software_snapshot(path) is None  # an older format is read again, not misread


def test_a_fresh_snapshot_is_reused_and_a_stale_one_read_again(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    path = snapshot_path(client.settings)
    save_software_snapshot(make_snapshot(install_count=99), path)
    assert software_snapshot(client).install_count == 99
    assert software_reads(api) == 0  # no API call at all

    register_inventory(api)
    assert software_snapshot(client, refresh=True).install_count == 6
    assert load_software_snapshot(path).install_count == 6  # type: ignore[union-attr]  # saved

    save_software_snapshot(make_snapshot(taken_at=datetime.now(UTC) - timedelta(hours=25)), path)
    assert software_snapshot(client).install_count == 6  # older than 24 h: read again
    save_software_snapshot(make_snapshot(instance="https://other.test"), path)
    assert software_snapshot(client).install_count == 6  # another instance's: read again
    assert software_reads(api) == 3 * 4  # three reads of a 4-page query


def test_catalog_matches_exactly() -> None:
    snapshot = make_snapshot()

    def found(**filters: Any) -> list[tuple[str, int]]:
        return [(entry.name, entry.device_count) for entry in software_catalog(snapshot, **filters)]

    assert found(publisher="igor pavlov") == [("7-Zip 23.01 (x64)", 3), ("7-Zip 24.09 (x64)", 1)]
    assert found(publisher="pavlov") == []  # not a substring search
    assert found(publisher="Igor Pavlov", name="7-zip*", version="<24.09") == [("7-Zip 23.01 (x64)", 3)]
    assert found(name="7-Zip 24.09 (x64)", version="24.09") == [("7-Zip 24.09 (x64)", 1)]
    assert found(organization_ids=[1]) == [("7-Zip 23.01 (x64)", 1), ("Microsoft Visual C++ 2015", 1)]
    assert len(found(include_system_components=False)) == 2
    with pytest.raises(ValueError, match="not a version specifier"):
        found(version="<<1")


def test_devices_a_software_appears_on() -> None:
    snapshot = make_snapshot()
    rows = software_devices(snapshot, publisher="Igor Pavlov", name="7-Zip 23.01 (x64)", version="23.01")
    assert [(r.device_id, r.device_name, r.organization_name) for r in rows] == [
        (9, None, None),  # in the inventory, no longer among the devices: kept, unnamed
        (1, "SRV-SQL01", "Contoso"),
        (2, "WS-0042", "Fabrikam"),
    ]
    scoped = software_devices(snapshot, name="7-Zip*", organization_ids=[2])
    assert [(r.device_id, r.version) for r in scoped] == [(2, "23.01"), (2, "24.09")]
