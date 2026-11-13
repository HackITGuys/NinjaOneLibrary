"""Software inventory: who has what, from which vendor, at which version.

Text filters (vendor, name) are case-insensitive substrings, or globs if the pattern has
`*`, `?` or `[`. With exact=True they must equal the whole value instead (still
case-insensitive; a pattern with glob characters is still a glob). The version filter is
one of:

    "<24.09", ">=2.4,<2.4.62", "!=1.0"    PEP 440 specifier set (starts with < > = ! ~)
    "24.*", "1.2.?"                       glob on the raw version string
    "24.09"                               exact match on the raw version string

Versions NinjaOne reports are not always PEP 440 ("2.4.58 (x64)", "1.2.3-beta"). For
specifiers the leading dotted number is used; a version with no such number never
matches a specifier. A Debian or RPM epoch ("1:9.6p1-3ubuntu13") is skipped.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import date

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from NinjaOne.client import NinjaOneClient
from NinjaOne.devices import devices_by_id
from NinjaOne.models import Device, SoftwareInstall, SoftwareProduct, SoftwareSummary

_LEADING_VERSION = re.compile(r"\d+(?:\.\d+)*")
_EPOCH = re.compile(r"^\s*\d+:")
_SPECIFIER_START = ("<", ">", "=", "!", "~")


def text_matches(value: str | None, pattern: str | None) -> bool:
    """Case-insensitive: a glob if the pattern has glob characters, else a substring."""
    if not pattern:
        return True
    if value is None:
        return False
    value, pattern = value.lower(), pattern.lower()
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatchcase(value, pattern)
    return pattern in value


def text_equals(value: str | None, pattern: str | None) -> bool:
    """Case-insensitive: a glob if the pattern has glob characters, else the whole value.
    Surrounding whitespace is ignored."""
    if not pattern:
        return True
    if value is None:
        return False
    value, pattern = value.strip().lower(), pattern.strip().lower()
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatchcase(value, pattern)
    return value == pattern


def parse_version(raw: str | None) -> Version | None:
    """The leading dotted number of a version string, as a comparable Version."""
    if not raw:
        return None
    match = _LEADING_VERSION.search(_EPOCH.sub("", raw))
    if not match:
        return None
    try:
        return Version(match.group(0))
    except InvalidVersion:
        return None


def version_specifier(wanted: str) -> SpecifierSet | None:
    """The SpecifierSet for a version filter that is one, else None (glob/exact)."""
    text = wanted.strip()
    if not text.startswith(_SPECIFIER_START):
        return None
    try:
        return SpecifierSet(text)
    except InvalidSpecifier as exc:
        raise ValueError(f"{wanted!r} is not a version specifier (try '<24.09' or '>=2.4,<2.4.62')") from exc


def version_matches(raw: str | None, wanted: str | None) -> bool:
    """Whether a reported version satisfies a version filter (see the module docstring)."""
    if not wanted or not wanted.strip():
        return True
    specifier = version_specifier(wanted)
    if specifier is not None:
        version = parse_version(raw)
        return version is not None and specifier.contains(version, prereleases=True)
    if raw is None:
        return False
    pattern = wanted.strip().lower()
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatchcase(raw.strip().lower(), pattern)
    return raw.strip().lower() == pattern


def filter_software(
    installs: Iterable[SoftwareInstall],
    *,
    vendor: str | None = None,
    name: str | None = None,
    version: str | None = None,
    include_system_components: bool = True,
    exact: bool = False,
) -> list[SoftwareInstall]:
    """Installs whose publisher matches `vendor`, name matches `name` and version matches
    `version`. exact=True: publisher and name must be the whole value, not a substring."""
    if version:
        version_specifier(version)  # fail on a bad specifier before looking at any install
    matches = text_equals if exact else text_matches
    return [
        install
        for install in installs
        if matches(install.publisher, vendor)
        and matches(install.name, name)
        and version_matches(install.version, version)
        and (include_system_components or not install.is_system_component)
    ]


def attach_devices(
    installs: Iterable[SoftwareInstall], devices: dict[int, Device] | Iterable[Device]
) -> list[SoftwareInstall]:
    """Fill in device_name and organization_name from already-fetched devices."""
    device_map = devices if isinstance(devices, dict) else devices_by_id(devices)
    result = []
    for install in installs:
        device = device_map.get(install.device_id)
        if device is not None:
            install.device_name = device.name
            install.organization_name = device.organization_name or None
        result.append(install)
    return result


def list_software(
    client: NinjaOneClient,
    *,
    vendor: str | None = None,
    name: str | None = None,
    version: str | None = None,
    include_system_components: bool = True,
    installed_after: date | None = None,
    installed_before: date | None = None,
    df: str | None = None,
    devices: dict[int, Device] | Iterable[Device] | None = None,
    exact: bool = False,
) -> list[SoftwareInstall]:
    """Software installs across the fleet (or the devices `df` selects), filtered.

    The API can't filter by publisher, name or version: those filters run here, so this
    always reads every install in scope (200k+ on a large fleet). For repeated lookups use
    a snapshot (NinjaOne.snapshot) instead. installed_after / installed_before are
    applied by the API, on the install date. Pass `devices` (e.g. from list_devices) to
    get device and organisation names on each install; nothing extra is fetched otherwise.
    """
    params: dict[str, str] = {}
    if df:
        params["df"] = df
    if installed_after:
        params["installedAfter"] = installed_after.isoformat()
    if installed_before:
        params["installedBefore"] = installed_before.isoformat()
    inventory = (
        SoftwareInstall.model_validate(raw) for raw in client.paginate_cursor("/queries/software", params)
    )
    selected = filter_software(
        inventory,
        vendor=vendor,
        name=name,
        version=version,
        include_system_components=include_system_components,
        exact=exact,
    )
    return attach_devices(selected, devices) if devices is not None else selected


def device_software(client: NinjaOneClient, device_id: int) -> list[SoftwareInstall]:
    """Everything installed on one device."""
    return [
        SoftwareInstall.model_validate({**raw, "deviceId": device_id})
        for raw in client.get_list(f"/device/{device_id}/software")
    ]


def version_key(raw: str | None) -> tuple[bool, Version | str, str]:
    """Sort key for raw version strings. With reverse=True: parseable versions first,
    newest first; the rest after them, by text."""
    parsed = parse_version(raw)
    return (parsed is not None, parsed or "", raw or "")


def summarise_software(installs: Iterable[SoftwareInstall]) -> list[SoftwareSummary]:
    """One entry per (publisher, name): device and install counts, and devices per version.

    Sorted by device count, most widespread first.
    """
    devices: dict[tuple[str | None, str], set[int]] = defaultdict(set)
    installs_per: Counter[tuple[str | None, str]] = Counter()
    versions: dict[tuple[str | None, str], dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    for install in installs:
        key = (install.publisher, install.name)
        devices[key].add(install.device_id)
        installs_per[key] += 1
        versions[key][install.version or ""].add(install.device_id)

    summaries = [
        SoftwareSummary(
            publisher=publisher,
            name=name,
            device_count=len(devices[(publisher, name)]),
            install_count=installs_per[(publisher, name)],
            versions={
                version: len(ids)
                for version, ids in sorted(
                    versions[(publisher, name)].items(), key=lambda item: version_key(item[0]), reverse=True
                )
            },
        )
        for publisher, name in devices
    ]
    return sorted(summaries, key=lambda s: (-s.device_count, s.name.lower(), (s.publisher or "").lower()))


def list_software_products(client: NinjaOneClient) -> list[SoftwareProduct]:
    """NinjaOne's 3rd-party patching catalogue: products it can patch, by vendor."""
    return [SoftwareProduct.model_validate(raw) for raw in client.get_list("/software-products")]
