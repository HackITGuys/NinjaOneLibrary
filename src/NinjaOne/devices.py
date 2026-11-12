"""Devices, device roles and asset tags.

Filtering happens in two places, because the API's device filter (`df`) only knows some
dimensions:

    server-side (df)   organisation, location, node class - plus any raw `df` you pass
    client-side        role name, tags, OS name, state

`df` syntax: "org = 12", "org in (12, 15)", "loc in (3)", "class in (WINDOWS_SERVER)",
"role in (5)", "status = APPROVED", "online", "offline", conditions joined with AND. See
https://resources.ninjarmm.com/API/Ninja+RMM+Public+API+v2.0.5+Device+Filter+Syntax.pdf
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from NinjaOne.client import NinjaOneClient
from NinjaOne.models import Device, Role, Tag
from NinjaOne.organizations import list_locations, list_organizations


def list_roles(client: NinjaOneClient) -> list[Role]:
    """Every device role."""
    return [Role.model_validate(raw) for raw in client.get_list("/roles")]


def list_tags(client: NinjaOneClient) -> list[Tag]:
    """Every asset tag, with how many assets carry it."""
    payload = client.get_object("/tag")
    return [Tag.model_validate(raw) for raw in payload.get("tags") or []]


def _ids(value: int | Sequence[int] | None) -> list[int]:
    if value is None:
        return []
    return [value] if isinstance(value, int) else list(value)


def _names(value: str | Sequence[str] | None) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def build_df(
    organization_ids: int | Sequence[int] | None = None,
    location_ids: int | Sequence[int] | None = None,
    node_classes: str | Sequence[str] | None = None,
    df: str | None = None,
) -> str | None:
    """A NinjaOne device filter from ids and node classes, AND-ed with an optional raw `df`."""
    parts: list[str] = []
    orgs = _ids(organization_ids)
    locations = _ids(location_ids)
    classes = _names(node_classes)
    if orgs:
        parts.append(f"org in ({', '.join(str(int(org)) for org in orgs)})")
    if locations:
        parts.append(f"loc in ({', '.join(str(int(loc)) for loc in locations)})")
    if classes:
        parts.append(f"class in ({', '.join(c.strip().upper() for c in classes)})")
    if df and df.strip():
        parts.append(df.strip())
    return " AND ".join(parts) or None


def _contains(value: str | None, wanted: str | None) -> bool:
    return wanted is None or wanted.lower() in (value or "").lower()


def _has_tags(device: Device, tags: Sequence[str], all_tags: bool) -> bool:
    have = {tag.lower() for tag in device.tags}
    wanted = [tag.lower() for tag in tags]
    return all(tag in have for tag in wanted) if all_tags else any(tag in have for tag in wanted)


def filter_devices(
    devices: Iterable[Device],
    *,
    role: str | None = None,
    tags: Sequence[str] | None = None,
    all_tags: bool = True,
    os: str | None = None,
    node_class: str | None = None,
    state: str | None = None,
) -> list[Device]:
    """Devices matching every given filter.

    role        case-insensitive substring of the role name ("server", "Windows Desktop")
    tags        case-insensitive tag names; the device needs all of them, or any with all_tags=False
    os          case-insensitive substring of the OS name ("Windows 11", "Server 2022", "Ubuntu")
    node_class  case-insensitive substring of the node class ("WINDOWS_SERVER", "LINUX")
    state       exact Device.state ("online", "offline", "maintenance", ...)
    """
    tag_list = list(tags or [])
    return [
        device
        for device in devices
        if _contains(device.role_name, role)
        and (not tag_list or _has_tags(device, tag_list, all_tags))
        and _contains(device.os.name if device.os else None, os)
        and _contains(device.node_class, node_class)
        and (state is None or device.state == state.lower())
    ]


class _Lookups:
    """Organisation/role/location names, fetched only if `references` left gaps."""

    def __init__(self, client: NinjaOneClient) -> None:
        self.client = client
        self._organizations: dict[int, str] | None = None
        self._roles: dict[int, str] | None = None
        self._locations: dict[int, str] | None = None

    def organization(self, organization_id: int) -> str:
        if self._organizations is None:
            self._organizations = {org.id: org.name for org in list_organizations(self.client)}
        return self._organizations.get(organization_id, "")

    def role(self, role_id: int) -> str:
        if self._roles is None:
            self._roles = {role.id: role.name for role in list_roles(self.client)}
        return self._roles.get(role_id, "")

    def location(self, location_id: int) -> str:
        if self._locations is None:
            self._locations = {loc.id: loc.name for loc in list_locations(self.client)}
        return self._locations.get(location_id, "")

    def fill(self, device: Device) -> Device:
        if not device.organization_name and device.organization_id is not None:
            device.organization_name = self.organization(device.organization_id)
        if not device.role_name and device.node_role_id is not None:
            device.role_name = self.role(device.node_role_id)
        if not device.location_name and device.location_id is not None:
            device.location_name = self.location(device.location_id)
        return device


def list_devices(
    client: NinjaOneClient,
    *,
    organization_id: int | Sequence[int] | None = None,
    location_id: int | Sequence[int] | None = None,
    node_class: str | Sequence[str] | None = None,
    role: str | None = None,
    tags: Sequence[str] | None = None,
    all_tags: bool = True,
    os: str | None = None,
    state: str | None = None,
    df: str | None = None,
) -> list[Device]:
    """Devices, with organisation, location and role names resolved.

    organization_id, location_id and node_class (exact NinjaOne node classes such as
    WINDOWS_SERVER) are sent to the API as a device filter, together with any raw `df`.
    role, tags, os and state are then applied client-side - see filter_devices.
    """
    params = {"df": query} if (query := build_df(organization_id, location_id, node_class, df)) else None
    lookups = _Lookups(client)
    devices = [
        lookups.fill(Device.model_validate(raw)) for raw in client.paginate_after("/devices-detailed", params)
    ]
    return filter_devices(devices, role=role, tags=tags, all_tags=all_tags, os=os, state=state)


def get_device(client: NinjaOneClient, device_id: int) -> Device:
    """One device, with organisation, location and role names resolved."""
    return _Lookups(client).fill(Device.model_validate(client.get_object(f"/device/{device_id}")))


def devices_by_id(devices: Iterable[Device]) -> dict[int, Device]:
    return {device.id: device for device in devices}
