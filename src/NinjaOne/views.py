"""Brief views: short, aggregated rows for reading on screen.

    rows = brief(client, list_kbs(client))   # [{"kb", "name", ..., "devices", "pending", ...}, ...]
    print(render_table(rows))

brief() picks the projection by record type. Device-id lists become counts, and
per-device records are grouped: software installs into one row per product and version,
patch records into one row per patch and status, each with its number of distinct
devices. The rows are plain dicts, so integrations can use them too; the full models
stay what the library's functions return.

The only API call a projection makes is one /organizations listing, for the
organisation names of locations.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from NinjaOne.client import NinjaOneClient
from NinjaOne.devices import NameLookups
from NinjaOne.models import (
    Device,
    DeviceVulnerabilityCounts,
    KbSummary,
    Location,
    Organization,
    OsPatch,
    Role,
    ScanGroup,
    SoftwareCatalogEntry,
    SoftwareDevice,
    SoftwareInstall,
    SoftwarePatch,
    SoftwareProduct,
    SoftwareSummary,
    Tag,
)
from NinjaOne.security import normalise_status, status_sort_key
from NinjaOne.software import version_key

Row = dict[str, Any]


def _lower(value: str | None) -> str | None:
    return value.lower() if value else None


def _when(value: datetime | None) -> str | None:
    """2026-01-01 13:45 (UTC)."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%d %H:%M")


def _day(value: datetime | None) -> str | None:
    return value.date().isoformat() if value else None


# -- base data ---------------------------------------------------------------------------


def brief_organizations(client: NinjaOneClient, organizations: Sequence[Organization]) -> list[Row]:
    return [
        {"id": o.id, "name": o.name, "approval_mode": _lower(o.node_approval_mode)} for o in organizations
    ]


def brief_locations(client: NinjaOneClient, locations: Sequence[Location]) -> list[Row]:
    """Locations with their organisation's name (one /organizations listing), else its id."""
    names = NameLookups(client)
    return [
        {
            "id": loc.id,
            "name": loc.name,
            "organization": (
                (names.organization(loc.organization_id) or loc.organization_id)
                if loc.organization_id is not None
                else None
            ),
            "address": loc.address,
        }
        for loc in locations
    ]


def brief_roles(client: NinjaOneClient, roles: Sequence[Role]) -> list[Row]:
    return [{"id": r.id, "name": r.name, "class": r.node_class, "custom": r.custom} for r in roles]


def brief_tags(client: NinjaOneClient, tags: Sequence[Tag]) -> list[Row]:
    return [
        {"id": t.id, "name": t.name, "devices": t.targets_count, "description": t.description} for t in tags
    ]


def brief_devices(client: NinjaOneClient, devices: Sequence[Device]) -> list[Row]:
    return [
        {
            "id": d.id,
            "name": d.name,
            "organization": d.organization_name or d.organization_id,
            "location": d.location_name or d.location_id,
            "role": d.role_name or None,
            "os": d.os.name if d.os else None,
            "state": d.state,
            "tags": d.tags,
            "last_contact": _when(d.last_contact),
        }
        for d in devices
    ]


# -- software ----------------------------------------------------------------------------


def brief_software(client: NinjaOneClient, installs: Sequence[SoftwareInstall]) -> list[Row]:
    """One row per product and version with its number of distinct devices. Most widespread
    product first, newest version first."""
    devices: dict[tuple[str | None, str, str], set[int]] = defaultdict(set)
    spread: dict[tuple[str | None, str], set[int]] = defaultdict(set)
    for install in installs:
        devices[(install.publisher, install.name, install.version or "")].add(install.device_id)
        spread[(install.publisher, install.name)].add(install.device_id)
    # Two stable sorts: newest version first, then products by spread and name.
    ordered = sorted(devices, key=lambda key: version_key(key[2]), reverse=True)
    ordered.sort(
        key=lambda key: (-len(spread[(key[0], key[1])]), key[1].casefold(), (key[0] or "").casefold())
    )
    return [
        {"publisher": key[0], "name": key[1], "version": key[2] or None, "devices": len(devices[key])}
        for key in ordered
    ]


def brief_software_summaries(client: NinjaOneClient, summaries: Sequence[SoftwareSummary]) -> list[Row]:
    rows = []
    for summary in summaries:
        known = [version for version in summary.versions if version]
        rows.append(
            {
                "publisher": summary.publisher,
                "name": summary.name,
                "devices": summary.device_count,
                "installs": summary.install_count,
                "versions": len(summary.versions),
                "newest": max(known, key=version_key) if known else None,
            }
        )
    return rows


def brief_software_catalog(client: NinjaOneClient, entries: Sequence[SoftwareCatalogEntry]) -> list[Row]:
    return [
        {"publisher": e.publisher, "name": e.name, "version": e.version, "devices": e.device_count}
        for e in entries
    ]


def brief_software_devices(client: NinjaOneClient, rows: Sequence[SoftwareDevice]) -> list[Row]:
    return [
        {
            "id": r.device_id,
            "device": r.device_name,
            "organization": r.organization_name or r.organization_id,
            "publisher": r.publisher,
            "name": r.name,
            "version": r.version,
        }
        for r in rows
    ]


def brief_software_products(client: NinjaOneClient, products: Sequence[SoftwareProduct]) -> list[Row]:
    return [
        {
            "id": p.id,
            "vendor": p.vendor_name,
            "product": p.product_name,
            "installable": p.installable,
            "active": p.active,
        }
        for p in products
    ]


# -- patches and security ------------------------------------------------------------------


def _patch_rows(groups: Mapping[tuple[Any, ...], set[int]], columns: Sequence[str]) -> list[Row]:
    """Grouped patch records as rows. `columns` name the key fields; the last one is the
    status. Most widespread patch first, its statuses in STATUS_ORDER."""
    spread: dict[tuple[Any, ...], set[int]] = defaultdict(set)
    for key, ids in groups.items():
        spread[key[:-1]] |= ids
    ordered = sorted(
        groups,
        key=lambda key: (
            -len(spread[key[:-1]]),
            tuple(str(part or "").casefold() for part in key[:-1]),
            status_sort_key(key[-1]),
        ),
    )
    return [{**dict(zip(columns, key, strict=True)), "devices": len(groups[key])} for key in ordered]


def brief_os_patches(client: NinjaOneClient, records: Sequence[OsPatch]) -> list[Row]:
    """One row per patch and status with its number of distinct devices."""
    groups: dict[tuple[Any, ...], set[int]] = defaultdict(set)
    for r in records:
        groups[(r.kb, r.name, r.severity, normalise_status(r.status))].add(r.device_id)
    return _patch_rows(groups, ("kb", "name", "severity", "status"))


def brief_software_patches(client: NinjaOneClient, records: Sequence[SoftwarePatch]) -> list[Row]:
    """One row per patch and status with its number of distinct devices."""
    groups: dict[tuple[Any, ...], set[int]] = defaultdict(set)
    for r in records:
        groups[(r.vendor, r.title, r.version, r.impact, normalise_status(r.status))].add(r.device_id)
    return _patch_rows(groups, ("vendor", "title", "version", "impact", "status"))


def brief_kbs(client: NinjaOneClient, kbs: Sequence[KbSummary]) -> list[Row]:
    """One row per KB: a device count per status (columns for the statuses present), no ids."""
    statuses = sorted({status for kb in kbs for status in kb.counts}, key=status_sort_key)
    return [
        {
            "kb": kb.kb,
            "name": kb.name,
            "severity": kb.severity,
            "released": _day(kb.release_date),
            "devices": kb.device_count,
            **{status: kb.counts.get(status, 0) for status in statuses},
        }
        for kb in kbs
    ]


def brief_vulnerabilities(client: NinjaOneClient, counts: Sequence[DeviceVulnerabilityCounts]) -> list[Row]:
    """One row per device, in the order given (vulnerability_counts sorts worst first). The
    device id stands in for its name unless devices were passed to vulnerability_counts."""
    return [
        {
            "device": c.device_name or c.device_id,
            "organization": c.organization_name,
            "critical": c.critical_vulnerability_count,
            "high": c.high_vulnerability_count,
            "medium": c.medium_vulnerability_count,
            "low": c.low_vulnerability_count,
            "total": c.total,
            "health": _lower(c.health_status),
        }
        for c in counts
    ]


def brief_scan_groups(client: NinjaOneClient, groups: Sequence[ScanGroup]) -> list[Row]:
    return [
        {
            "id": g.id,
            "name": g.group_name,
            "vendor": g.vendor,
            "status": _lower(g.status),
            "records": g.records_processed,
            "uploaded": g.last_file_upload_date,
        }
        for g in groups
    ]


BRIEF: dict[type[BaseModel], Callable[[NinjaOneClient, Sequence[Any]], list[Row]]] = {
    Organization: brief_organizations,
    Location: brief_locations,
    Role: brief_roles,
    Tag: brief_tags,
    Device: brief_devices,
    SoftwareInstall: brief_software,
    SoftwareSummary: brief_software_summaries,
    SoftwareCatalogEntry: brief_software_catalog,
    SoftwareDevice: brief_software_devices,
    SoftwareProduct: brief_software_products,
    OsPatch: brief_os_patches,
    SoftwarePatch: brief_software_patches,
    KbSummary: brief_kbs,
    DeviceVulnerabilityCounts: brief_vulnerabilities,
    ScanGroup: brief_scan_groups,
}


def brief(client: NinjaOneClient, records: Iterable[BaseModel]) -> list[Row]:
    """The brief rows for a list of records of one type (see the module docstring)."""
    items = list(records)
    if not items:
        return []
    for cls in type(items[0]).__mro__:
        projection = BRIEF.get(cls)
        if projection is not None:
            return projection(client, items)
    raise TypeError(f"No brief view for {type(items[0]).__name__}")


# -- tables ----------------------------------------------------------------------------------


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list | tuple):
        return ", ".join(_cell(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    return " ".join(str(value).split())


def _numeric(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def render_table(rows: Sequence[Mapping[str, Any]]) -> str:
    """Rows as aligned text columns with upper-case headers. Numbers are right-aligned; None is
    an empty cell. Nothing is truncated, so the output greps cleanly."""
    if not rows:
        return ""
    columns: list[str] = []
    for row in rows:
        columns.extend(key for key in row if key not in columns)
    cells = [[_cell(row.get(column)) for column in columns] for row in rows]
    headers = [column.upper() for column in columns]
    widths = [max(len(header), *(len(line[i]) for line in cells)) for i, header in enumerate(headers)]
    right = [
        all(_numeric(row.get(column)) or row.get(column) is None for row in rows)
        and any(_numeric(row.get(column)) for row in rows)
        for column in columns
    ]

    def line(values: Sequence[str]) -> str:
        padded = [
            value.rjust(width) if align else value.ljust(width)
            for value, width, align in zip(values, widths, right, strict=True)
        ]
        return "  ".join(padded).rstrip()

    return "\n".join([line(headers), *(line(values) for values in cells)])
