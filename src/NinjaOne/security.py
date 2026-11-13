"""Patches, KBs and the vulnerability data the public API exposes.

What NinjaOne's public API (v2.0.9-draft) offers here:

    /v2/queries/os-patches              OS patches not installed: MANUAL (pending), APPROVED, FAILED, REJECTED
    /v2/queries/os-patch-installs       OS patch install attempts: INSTALLED, FAILED
    /v2/queries/software-patches        same split, for 3rd-party software
    /v2/queries/software-patch-installs
    /v2/queries/device-health           per-device critical/high/medium/low vulnerability COUNTS
    /v2/vulnerability/scan-groups       scanner CSV imports - metadata only

There is NO endpoint that returns CVE records. OS patch records carry a KB number, so
list_kbs() gives every KB with its per-status device counts - map those KBs to CVEs with
whichever source you trust (e.g. Microsoft's MSRC CVRF API). find_endpoints() scans the
live OpenAPI spec, so the day a CVE endpoint appears it shows up there.

None of the patch queries can be filtered by KB or title server-side; those filters run
here. Install-history dates must be YYYY-MM-DD (the API rejects full timestamps).
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import date, datetime
from typing import Any

from NinjaOne.client import NinjaOneClient
from NinjaOne.devices import devices_by_id
from NinjaOne.models import (
    Device,
    DeviceVulnerabilityCounts,
    KbSummary,
    OsPatch,
    ScanGroup,
    SoftwarePatch,
    normalise_kb,
)

STATUS_ALIASES = {
    "MANUAL": "pending",
    "PENDING": "pending",
    "APPROVED": "approved",
    "FAILED": "failed",
    "REJECTED": "rejected",
    "INSTALLED": "installed",
}
STATUS_ORDER = ("pending", "approved", "failed", "rejected", "installed")
"""Display order. Unknown statuses sort after these."""
_TIE_BREAK = {"installed": 5, "failed": 4, "approved": 3, "pending": 2, "rejected": 1}
"""When two records for one (device, KB) share a timestamp, the more final one wins."""


def normalise_status(raw: str | None) -> str:
    """API status -> pending/approved/failed/rejected/installed.

    An unrecognised value is kept (lower-cased) rather than dropped or forced into a
    known bucket: a new status should show up in the counts, not vanish from them.
    """
    if not raw:
        return "unknown"
    return STATUS_ALIASES.get(raw.strip().upper(), raw.strip().lower())


def _params(df: str | None, **extra: Any) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for key, value in extra.items():
        if value is None:
            continue
        params[key] = value.isoformat() if isinstance(value, date) else value
    if df:
        params["df"] = df
    return params


def _keep_kbs(records: list[OsPatch], kbs: Iterable[str] | None) -> list[OsPatch]:
    if kbs is None:
        return records
    wanted = {normalise_kb(kb) for kb in kbs}
    return [record for record in records if record.kb in wanted]


def _keep_software(
    records: list[SoftwarePatch], vendor: str | None, title: str | None
) -> list[SoftwarePatch]:
    def matches(value: str | None, needle: str | None) -> bool:
        return needle is None or needle.lower() in (value or "").lower()

    return [record for record in records if matches(record.vendor, vendor) and matches(record.title, title)]


# -- OS patches -----------------------------------------------------------------


def os_patches(
    client: NinjaOneClient,
    *,
    df: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    type: str | None = None,
    kbs: Iterable[str] | None = None,
) -> list[OsPatch]:
    """OS patches with no successful install: pending (MANUAL), approved, failed, rejected.

    status, severity and type are passed to the API as-is; kbs is filtered here.
    """
    params = _params(df, status=status, severity=severity, type=type)
    records = [OsPatch.model_validate(raw) for raw in client.paginate_cursor("/queries/os-patches", params)]
    return _keep_kbs(records, kbs)


def os_patch_installs(
    client: NinjaOneClient,
    *,
    df: str | None = None,
    status: str | None = None,
    installed_after: date | None = None,
    installed_before: date | None = None,
    kbs: Iterable[str] | None = None,
) -> list[OsPatch]:
    """OS patch install attempts (INSTALLED or FAILED).

    Without installed_after this is the whole fleet's install history, which can be over
    a million records on a large instance. Give a window when you can.
    """
    params = _params(df, status=status, installedAfter=installed_after, installedBefore=installed_before)
    records = [
        OsPatch.model_validate(raw) for raw in client.paginate_cursor("/queries/os-patch-installs", params)
    ]
    return _keep_kbs(records, kbs)


def device_os_patches(client: NinjaOneClient, device_id: int, *, installed: bool = False) -> list[OsPatch]:
    """One device's OS patches: outstanding (default) or its install history."""
    path = f"/device/{device_id}/os-patch-installs" if installed else f"/device/{device_id}/os-patches"
    return [OsPatch.model_validate({"deviceId": device_id, **raw}) for raw in client.get_list(path)]


# -- software patches -------------------------------------------------------------


def software_patches(
    client: NinjaOneClient,
    *,
    df: str | None = None,
    status: str | None = None,
    product_identifier: str | None = None,
    vendor: str | None = None,
    title: str | None = None,
) -> list[SoftwarePatch]:
    """3rd-party software patches with no successful install.

    vendor and title are case-insensitive substrings, filtered here.
    """
    params = _params(df, status=status, productIdentifier=product_identifier)
    records = [
        SoftwarePatch.model_validate(raw)
        for raw in client.paginate_cursor("/queries/software-patches", params)
    ]
    return _keep_software(records, vendor, title)


def software_patch_installs(
    client: NinjaOneClient,
    *,
    df: str | None = None,
    status: str | None = None,
    product_identifier: str | None = None,
    installed_after: date | None = None,
    installed_before: date | None = None,
    vendor: str | None = None,
    title: str | None = None,
) -> list[SoftwarePatch]:
    """3rd-party software patch install attempts. Same history caveat as os_patch_installs."""
    params = _params(
        df,
        status=status,
        productIdentifier=product_identifier,
        installedAfter=installed_after,
        installedBefore=installed_before,
    )
    records = [
        SoftwarePatch.model_validate(raw)
        for raw in client.paginate_cursor("/queries/software-patch-installs", params)
    ]
    return _keep_software(records, vendor, title)


def device_software_patches(
    client: NinjaOneClient, device_id: int, *, installed: bool = False
) -> list[SoftwarePatch]:
    """One device's software patches: outstanding (default) or its install history."""
    path = (
        f"/device/{device_id}/software-patch-installs"
        if installed
        else f"/device/{device_id}/software-patches"
    )
    return [SoftwarePatch.model_validate({"deviceId": device_id, **raw}) for raw in client.get_list(path)]


# -- KBs --------------------------------------------------------------------------


def status_sort_key(status: str) -> tuple[int, str]:
    """Sort key: the STATUS_ORDER statuses in that order, then any others alphabetically."""
    return (STATUS_ORDER.index(status) if status in STATUS_ORDER else len(STATUS_ORDER), status)


def _sort_time(record: OsPatch) -> float:
    moment = record.installed_at or record.timestamp
    return moment.timestamp() if moment else 0.0


def summarise_kbs(records: Iterable[OsPatch], kbs: Iterable[str] | None = None) -> list[KbSummary]:
    """Per KB: how many devices are in each status, and which.

    The latest record for a (device, KB) pair is its current status - a device that
    failed and then installed counts as installed. Records without a KB number (most
    non-Windows patches) are skipped. KBs listed in `kbs` that have no records are still
    returned, with no devices, so "nothing found" is visible rather than silent.
    """
    latest: dict[tuple[int, str], tuple[OsPatch, str]] = {}
    for record in records:
        if not record.kb:
            continue
        status = normalise_status(record.status)
        pair = (record.device_id, record.kb)
        current = latest.get(pair)
        if current is None:
            latest[pair] = (record, status)
            continue
        current_record, current_status = current
        newer = _sort_time(record) > _sort_time(current_record)
        tie_wins = _sort_time(record) == _sort_time(current_record) and _TIE_BREAK.get(
            status, 0
        ) > _TIE_BREAK.get(current_status, 0)
        if newer or tie_wins:
            latest[pair] = (record, status)

    devices: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    details: dict[str, dict[str, Any]] = defaultdict(dict)
    for (device_id, kb), (record, status) in latest.items():
        devices[kb][status].append(device_id)
        info = details[kb]
        for field in ("name", "severity", "type", "os", "release_date"):
            if info.get(field) is None and getattr(record, field) is not None:
                info[field] = getattr(record, field)

    for kb in kbs or []:
        devices.setdefault(normalise_kb(kb), defaultdict(list))

    summaries = []
    for kb in sorted(devices):
        by_status = {
            status: sorted(ids)
            for status, ids in sorted(devices[kb].items(), key=lambda i: status_sort_key(i[0]))
        }
        info = details.get(kb, {})
        release_date: datetime | None = info.get("release_date")
        summaries.append(
            KbSummary(
                kb=kb,
                name=info.get("name"),
                severity=info.get("severity"),
                type=info.get("type"),
                os=info.get("os"),
                release_date=release_date,
                device_count=sum(len(ids) for ids in by_status.values()),
                counts={status: len(ids) for status, ids in by_status.items()},
                devices=by_status,
            )
        )
    return summaries


def list_kbs(
    client: NinjaOneClient,
    *,
    df: str | None = None,
    kbs: Sequence[str] | None = None,
    include_installed: bool = False,
    installed_after: date | None = None,
) -> list[KbSummary]:
    """Every KB NinjaOne has a patch record for (or just `kbs`), with device counts per status.

    By default only outstanding patches are read (pending/approved/failed/rejected): the
    devices still needing action, and fast. include_installed also reads the install
    history - from installed_after, or ALL of it when that is None (can be very large).

    A device on a later cumulative update that supersedes a KB has no record for it, and
    is not counted under that KB.
    """
    records = os_patches(client, df=df, kbs=kbs)
    if include_installed:
        records += os_patch_installs(client, df=df, installed_after=installed_after, kbs=kbs)
    return summarise_kbs(records, kbs)


# -- vulnerabilities --------------------------------------------------------------


def vulnerability_counts(
    client: NinjaOneClient,
    *,
    df: str | None = None,
    only_vulnerable: bool = True,
    devices: dict[int, Device] | Iterable[Device] | None = None,
) -> list[DeviceVulnerabilityCounts]:
    """Per-device critical/high/medium/low vulnerability counts (from device-health).

    Sorted worst first. only_vulnerable drops devices with no vulnerabilities. device-health
    only carries device ids: pass already-fetched `devices` to fill in device_name and
    organization_name.
    """
    params = {"df": df} if df else None
    counts = [
        DeviceVulnerabilityCounts.model_validate(raw)
        for raw in client.paginate_cursor("/queries/device-health", params)
    ]
    if only_vulnerable:
        counts = [entry for entry in counts if entry.total > 0]
    if devices is not None:
        device_map = devices if isinstance(devices, dict) else devices_by_id(devices)
        for entry in counts:
            device = device_map.get(entry.device_id)
            if device is not None:
                entry.device_name = device.name
                entry.organization_name = device.organization_name or None
    return sorted(
        counts,
        key=lambda entry: (
            -entry.critical_vulnerability_count,
            -entry.high_vulnerability_count,
            -entry.total,
            entry.device_id,
        ),
    )


def list_scan_groups(client: NinjaOneClient) -> list[ScanGroup]:
    """Vulnerability scan groups (third-party scanner CSV imports)."""
    return [ScanGroup.model_validate(raw) for raw in client.get_list("/vulnerability/scan-groups")]


def get_scan_group(client: NinjaOneClient, scan_group_id: int) -> ScanGroup:
    return ScanGroup.model_validate(client.get_object(f"/vulnerability/scan-groups/{scan_group_id}"))


def find_endpoints(
    client: NinjaOneClient, pattern: str = r"vulnerab|cve", methods: Iterable[str] = ("get",)
) -> dict[str, list[str]]:
    """Paths in the live OpenAPI spec whose path, tags or summary match `pattern`.

    Returns {path: ["GET summary", ...]}, read-only methods by default. Run it now and
    then: the day a CVE read endpoint appears, this is where it shows up.
    """
    regex = re.compile(pattern, re.IGNORECASE)
    wanted = {method.lower() for method in methods}
    matches: dict[str, list[str]] = {}
    for path, operations in (client.fetch_spec().get("paths") or {}).items():
        for method, operation in (operations or {}).items():
            if method.lower() not in wanted or not isinstance(operation, dict):
                continue
            haystack = " ".join([path, *operation.get("tags", []), operation.get("summary", "")])
            if regex.search(haystack):
                matches.setdefault(path, []).append(
                    f"{method.upper()} {operation.get('summary', '')}".strip()
                )
    return dict(sorted(matches.items()))
