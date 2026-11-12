from __future__ import annotations

from datetime import UTC, datetime

import responses

from NinjaOne import (
    Device,
    NinjaOneClient,
    build_df,
    filter_devices,
    find_organizations,
    list_devices,
    list_locations,
    list_organizations,
    list_tags,
)
from tests.conftest import get, raw_device


def test_build_df() -> None:
    assert build_df() is None
    assert build_df(organization_ids=3) == "org in (3)"
    assert (
        build_df(
            organization_ids=[1, 2], location_ids=[7], node_classes=["windows_server", "MAC"], df="online"
        )
        == "org in (1, 2) AND loc in (7) AND class in (WINDOWS_SERVER, MAC) AND online"
    )


def test_device_parses_references_timestamps_and_aliases() -> None:
    device = Device.model_validate(raw_device(5, tags=["Production"]))
    assert (device.organization_name, device.role_name, device.location_name) == (
        "Contoso",
        "Windows Server",
        "Oslo",
    )
    assert device.last_contact == datetime(2026, 1, 1, tzinfo=UTC)
    assert device.public_ip == "203.0.113.7"
    assert device.os is not None and device.os.build_number == "20348"

    dumped = device.model_dump(mode="json")
    assert dumped["name"] == "HOST5"
    assert dumped["state"] == "online"
    assert dumped["last_contact"] == "2026-01-01T00:00:00Z"
    assert "references" not in dumped


def test_device_state() -> None:
    assert Device.model_validate(raw_device(1, offline=True)).state == "offline"
    assert (
        Device.model_validate({**raw_device(1), "approvalStatus": "DECOMMISSIONED"}).state == "decommissioned"
    )
    assert Device.model_validate({**raw_device(1), "maintenance": {"status": "IN_MAINTENANCE"}}).state == (
        "maintenance"
    )


FLEET = [
    Device.model_validate(raw_device(1, tags=["Production", "DMZ"], os_name="Windows Server 2022 Standard")),
    Device.model_validate(raw_device(2, tags=["production"], os_name="Windows Server 2019 Datacenter")),
    Device.model_validate(
        raw_device(
            3,
            role=(11, "Windows Desktop"),
            node_class="WINDOWS_WORKSTATION",
            tags=["DMZ"],
            os_name="Windows 11 Enterprise",
        )
    ),
    Device.model_validate(
        raw_device(4, role=(12, "Linux Server"), node_class="LINUX_SERVER", os_name="Ubuntu")
    ),
]


def ids(devices: list[Device]) -> list[int]:
    return [device.id for device in devices]


def test_filter_by_tags_all_and_any() -> None:
    assert ids(filter_devices(FLEET, tags=["production"])) == [1, 2]  # case-insensitive
    assert ids(filter_devices(FLEET, tags=["Production", "DMZ"])) == [1]
    assert ids(filter_devices(FLEET, tags=["Production", "DMZ"], all_tags=False)) == [1, 2, 3]


def test_filter_by_os_role_class_and_state() -> None:
    assert ids(filter_devices(FLEET, os="server 2022")) == [1]
    assert ids(filter_devices(FLEET, os="windows")) == [1, 2, 3]
    assert ids(filter_devices(FLEET, role="desktop")) == [3]
    assert ids(filter_devices(FLEET, node_class="linux")) == [4]
    assert ids(filter_devices(FLEET, state="online")) == [1, 2, 3, 4]
    assert ids(filter_devices(FLEET, os="Windows", tags=["DMZ"])) == [1, 3]


def test_list_devices_sends_df_and_fills_gaps_from_lookups(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    df = "org in (1) AND class in (WINDOWS_SERVER)"
    no_role_name = raw_device(2, role=(10, ""), tags=["Production"])
    get(api, "/devices-detailed", [raw_device(1), no_role_name], {"df": df, "pageSize": "2"})
    get(api, "/devices-detailed", [], {"df": df, "pageSize": "2", "after": "2"})
    get(api, "/roles", [{"id": 10, "name": "Windows Server", "nodeClass": "WINDOWS_SERVER"}])

    devices = list_devices(client, organization_id=1, node_class="WINDOWS_SERVER")
    assert ids(devices) == [1, 2]
    assert devices[1].role_name == "Windows Server"

    get(api, "/devices-detailed", [raw_device(1), no_role_name], {"df": df, "pageSize": "2"})
    assert ids(list_devices(client, organization_id=1, node_class="WINDOWS_SERVER", tags=["production"])) == [
        2
    ]


def test_list_tags_unwraps_the_envelope(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get(
        api, "/tag", {"tags": [{"id": 1, "name": "Production", "targetsCount": 12, "createTime": 1767225600}]}
    )
    [tag] = list_tags(client)
    assert (tag.name, tag.targets_count, tag.create_time) == (
        "Production",
        12,
        datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_organizations_and_locations(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    orgs = [{"id": 1, "name": "Contoso"}, {"id": 2, "name": "Contoso Labs"}, {"id": 3, "name": "Fabrikam"}]
    get(api, "/organizations", orgs[:2], {"pageSize": "2"})
    get(api, "/organizations", orgs[2:], {"pageSize": "2", "after": "2"})
    get(api, "/organizations", [], {"pageSize": "2", "after": "3"})
    fetched = list_organizations(client)
    assert [org.name for org in fetched] == ["Contoso", "Contoso Labs", "Fabrikam"]

    assert [o.id for o in find_organizations(client, "contoso", fetched)] == [1]  # exact name wins
    assert [o.id for o in find_organizations(client, "conto", fetched)] == [1, 2]
    assert [o.id for o in find_organizations(client, "3", fetched)] == [3]
    assert find_organizations(client, "nope", fetched) == []

    get(api, "/organization/1/locations", [{"id": 100, "name": "Oslo", "address": "Street 1"}])
    [location] = list_locations(client, 1)
    assert (location.name, location.organization_id) == ("Oslo", 1)
