"""A local snapshot of the software inventory, for fast "does it exist" and "where" lookups.

NinjaOne's /v2/queries/software returns one record per install and can't be filtered by
publisher, name or version, so "which software exists" means reading every install
(200k+ on a large fleet). A snapshot reads them once, keeps one entry per distinct
(publisher, name, version) with the ids of the devices that have it, and saves that to
settings.cache_dir. Lookups then run against the snapshot, without API calls:

    with NinjaOneClient() as client:
        snapshot = software_snapshot(client)     # saved one if under 24 h old, else read again
        software_catalog(snapshot, publisher="Igor Pavlov")          # what exists, with device counts
        software_devices(snapshot, publisher="Igor Pavlov", name="7-Zip 23.01 (x64)", version="23.01")

Publisher and name must equal the whole value, case-insensitively, unless the pattern
has glob characters ("7-Zip*"). The version is exact, a glob ("24.*") or a range
("<24.09"), as in NinjaOne.software.

The file holds the tenant's device and software names, so it is written readable by its
owner only, and outside any repository by default (~/.cache/ninjaone).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from NinjaOne.client import NinjaOneClient
from NinjaOne.config import NinjaOneSettings
from NinjaOne.devices import list_devices
from NinjaOne.models import (
    SnapshotDevice,
    SnapshotSoftware,
    SoftwareCatalogEntry,
    SoftwareDevice,
    SoftwareSnapshot,
)
from NinjaOne.software import text_equals, version_key, version_matches, version_specifier

log = logging.getLogger("NinjaOne")

SNAPSHOT_FORMAT = 1
"""Bump when SoftwareSnapshot changes shape: older files are then read again, not misread."""

SoftwareKey = tuple[str | None, str, str | None]
"""(publisher, name, version)."""


# -- reading the inventory ------------------------------------------------------------------


def _text(value: Any) -> str | None:
    """Interned: 200k installs share a few thousand distinct publishers, names and versions."""
    return sys.intern(str(value)) if value not in (None, "") else None


def _compact(raw: dict[str, Any]) -> tuple[str | None, str, str | None, Any, bool]:
    """What a snapshot needs of one install record, held while the query is read."""
    return (
        _text(raw.get("publisher")),
        _text(raw.get("name")) or "",
        _text(raw.get("version")),
        raw.get("deviceId"),
        bool(raw.get("isSystemComponent")),
    )


def _ordered(keys: Iterable[SoftwareKey]) -> list[SoftwareKey]:
    """By publisher and name, newest version first."""
    ordered = sorted(keys, key=lambda key: version_key(key[2]), reverse=True)
    ordered.sort(key=lambda key: ((key[0] or "").casefold(), key[1].casefold()))
    return ordered


def take_software_snapshot(client: NinjaOneClient) -> SoftwareSnapshot:
    """Read the whole software inventory, and every device for names, into a snapshot.

    This is the expensive call (one /v2/queries/software read of every install); it
    doesn't save anything. software_snapshot() reuses a saved one while it is fresh.
    """
    devices: dict[SoftwareKey, set[int]] = defaultdict(set)
    system: set[SoftwareKey] = set()
    count = 0
    records = client.paginate_cursor("/queries/software", transform=_compact)
    for publisher, name, version, device_id, is_system_component in records:
        count += 1
        key = (publisher, name, version)
        ids = devices[key]
        if device_id is not None:
            ids.add(int(device_id))
        if is_system_component:
            system.add(key)
    fleet = {
        device.id: SnapshotDevice(
            id=device.id,
            name=device.name,
            organization_id=device.organization_id,
            organization_name=device.organization_name or None,
        )
        for device in list_devices(client)
    }
    software = [
        SnapshotSoftware(
            publisher=key[0],
            name=key[1],
            version=key[2],
            system_component=key in system,
            device_ids=sorted(devices[key]),
        )
        for key in _ordered(devices)
    ]
    log.info("Software snapshot: %s installs of %s distinct software", count, len(software))
    return SoftwareSnapshot(
        format=SNAPSHOT_FORMAT,
        instance=client.settings.base_url,
        taken_at=datetime.now(UTC),
        install_count=count,
        devices=fleet,
        software=software,
    )


# -- saving and loading ---------------------------------------------------------------------


def snapshot_path(settings: NinjaOneSettings) -> Path:
    """One file per instance and client app: software-<host>-<hash of the client id>.json."""
    host = urlsplit(settings.base_url).hostname or "ninjaone"
    tenant = hashlib.sha256(settings.client_id.encode()).hexdigest()[:10]
    return settings.cache_dir / f"software-{host}-{tenant}.json"


def save_software_snapshot(snapshot: SoftwareSnapshot, path: Path) -> None:
    """Write atomically, readable by the owner only."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    partial = path.with_name(path.name + ".partial")
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(snapshot.model_dump_json())
    os.chmod(partial, 0o600)  # in case an older partial file had wider permissions
    os.replace(partial, path)


def load_software_snapshot(path: Path) -> SoftwareSnapshot | None:
    """The snapshot saved at `path`, or None if there is none, it is unreadable, or it is
    in an older format."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log.warning("Ignoring the unreadable software snapshot %s: %s", path, exc)
        return None
    if not isinstance(data, dict) or data.get("format") != SNAPSHOT_FORMAT:
        log.info("The software snapshot %s is in another format; it will be read again", path)
        return None
    try:
        return SoftwareSnapshot.model_validate(data)
    except ValidationError as exc:
        log.warning("Ignoring the unreadable software snapshot %s: %s", path, exc)
        return None


def snapshot_age(snapshot: SoftwareSnapshot) -> timedelta:
    return datetime.now(UTC) - snapshot.taken_at


def load_fresh_software_snapshot(
    settings: NinjaOneSettings, max_age: timedelta | None = None
) -> SoftwareSnapshot | None:
    """The saved snapshot if it is from this instance and younger than `max_age`
    (default: settings.snapshot_max_age_hours), else None."""
    snapshot = load_software_snapshot(snapshot_path(settings))
    if snapshot is None or snapshot.instance != settings.base_url:
        return None
    limit = max_age if max_age is not None else timedelta(hours=settings.snapshot_max_age_hours)
    return snapshot if snapshot_age(snapshot) <= limit else None


def refresh_software_snapshot(client: NinjaOneClient) -> SoftwareSnapshot:
    """Read the inventory again and save the snapshot."""
    snapshot = take_software_snapshot(client)
    save_software_snapshot(snapshot, snapshot_path(client.settings))
    return snapshot


def software_snapshot(
    client: NinjaOneClient, *, refresh: bool = False, max_age: timedelta | None = None
) -> SoftwareSnapshot:
    """The saved snapshot while it is fresh; otherwise (or with refresh=True) a new one."""
    if not refresh:
        cached = load_fresh_software_snapshot(client.settings, max_age)
        if cached is not None:
            return cached
    return refresh_software_snapshot(client)


# -- lookups --------------------------------------------------------------------------------


def _selected(
    snapshot: SoftwareSnapshot,
    publisher: str | None,
    name: str | None,
    version: str | None,
    include_system_components: bool,
) -> Iterator[SnapshotSoftware]:
    if version:
        version_specifier(version)  # fail on a bad specifier before looking at anything
    for entry in snapshot.software:
        if (
            text_equals(entry.publisher, publisher)
            and text_equals(entry.name, name)
            and version_matches(entry.version, version)
            and (include_system_components or not entry.system_component)
        ):
            yield entry


def _in_scope(
    snapshot: SoftwareSnapshot, device_ids: list[int], organization_ids: set[int] | None
) -> list[int]:
    if organization_ids is None:
        return device_ids
    return [
        device_id
        for device_id in device_ids
        if (device := snapshot.devices.get(device_id)) is not None
        and device.organization_id in organization_ids
    ]


def software_catalog(
    snapshot: SoftwareSnapshot,
    *,
    publisher: str | None = None,
    name: str | None = None,
    version: str | None = None,
    include_system_components: bool = True,
    organization_ids: Iterable[int] | None = None,
) -> list[SoftwareCatalogEntry]:
    """What software exists: one entry per (publisher, name, version) with its device
    count, by publisher and name, newest version first. Only devices of
    `organization_ids` count, if given."""
    scope = set(organization_ids) if organization_ids is not None else None
    entries = []
    for entry in _selected(snapshot, publisher, name, version, include_system_components):
        ids = _in_scope(snapshot, entry.device_ids, scope)
        if ids:
            entries.append(
                SoftwareCatalogEntry(
                    publisher=entry.publisher, name=entry.name, version=entry.version, device_count=len(ids)
                )
            )
    return entries


def software_devices(
    snapshot: SoftwareSnapshot,
    *,
    publisher: str | None = None,
    name: str | None = None,
    version: str | None = None,
    include_system_components: bool = True,
    organization_ids: Iterable[int] | None = None,
) -> list[SoftwareDevice]:
    """Every device the matching software appears on: one row per device and version, by
    organisation and device name."""
    scope = set(organization_ids) if organization_ids is not None else None
    rows = []
    for entry in _selected(snapshot, publisher, name, version, include_system_components):
        for device_id in _in_scope(snapshot, entry.device_ids, scope):
            device = snapshot.devices.get(device_id)
            rows.append(
                SoftwareDevice(
                    device_id=device_id,
                    device_name=device.name if device else None,
                    organization_id=device.organization_id if device else None,
                    organization_name=device.organization_name if device else None,
                    publisher=entry.publisher,
                    name=entry.name,
                    version=entry.version,
                )
            )
    return sorted(
        rows,
        key=lambda row: (
            (row.organization_name or "").casefold(),
            (row.device_name or "").casefold(),
            row.device_id,
        ),
    )
