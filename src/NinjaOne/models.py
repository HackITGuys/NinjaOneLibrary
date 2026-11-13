"""Records returned by the library.

Field names follow the API (organization, not organisation) so a record can be traced
back to the JSON it came from. API models validate straight from the camelCase payload
and dump as snake_case: `model.model_dump(mode="json")` is ready for json.dumps, with
epoch timestamps turned into ISO-8601 datetimes.

Unknown API fields are ignored. For anything not modelled here, use client.get().
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, computed_field, model_validator
from pydantic.alias_generators import to_camel


def as_datetime(value: Any) -> datetime | None:
    """NinjaOne timestamps are epoch seconds (float) on most endpoints, ISO on some.

    0 and "" mean "not set". A value too large for seconds is read as milliseconds.
    """
    if value is None or value == "" or value == 0:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, int | float):
        seconds = float(value) / 1000 if float(value) > 1e11 else float(value)
        return datetime.fromtimestamp(seconds, tz=UTC)
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


EpochDatetime = Annotated[datetime | None, BeforeValidator(as_datetime)]

_KB_RE = re.compile(r"^(?:KB)?\s*(\d{6,8})$", re.IGNORECASE)


def normalise_kb(kb: str) -> str:
    """'5031356', 'kb5031356', 'KB 5031356' -> 'KB5031356'. Anything else, upper-cased."""
    match = _KB_RE.match(kb.strip())
    return f"KB{match.group(1)}" if match else kb.strip().upper()


class ApiModel(BaseModel):
    """camelCase in, snake_case attributes, unknown fields ignored."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


# -- organisation structure -----------------------------------------------------


class Location(ApiModel):
    id: int
    name: str = ""
    address: str | None = None
    description: str | None = None
    organization_id: int | None = None


class Organization(ApiModel):
    id: int
    name: str = ""
    description: str | None = None
    node_approval_mode: str | None = None
    """AUTOMATIC, MANUAL or REJECT."""
    locations: list[Location] | None = None
    """Only from get_organization (the detailed record)."""


class Role(ApiModel):
    """A device role (what /v2/roles calls a role; nodeRoleId on a device)."""

    id: int
    name: str = ""
    description: str | None = None
    node_class: str | None = None
    custom: bool | None = None
    chassis_type: str | None = None


class Tag(ApiModel):
    """An asset tag. Devices carry tags by name (Device.tags)."""

    id: int
    name: str = ""
    description: str | None = None
    targets_count: int | None = None
    """How many assets carry the tag."""
    create_time: EpochDatetime = None
    update_time: EpochDatetime = None


# -- devices ---------------------------------------------------------------------


class OperatingSystem(ApiModel):
    name: str | None = None
    """e.g. "Windows 11 Enterprise Edition", "Windows Server 2022 Standard", "Ubuntu 24.04 LTS"."""
    manufacturer: str | None = None
    architecture: str | None = None
    build_number: str | None = None
    release_id: str | None = None
    service_pack_major_version: int | None = None
    service_pack_minor_version: int | None = None
    locale: str | None = None
    language: str | None = None
    last_boot_time: EpochDatetime = None
    needs_reboot: bool | None = None


class DeviceSystem(ApiModel):
    """Hardware details (agent and MDM devices)."""

    manufacturer: str | None = None
    model: str | None = None
    serial_number: str | None = None
    bios_serial_number: str | None = None
    domain: str | None = None
    virtual_machine: bool | None = None
    chassis_type: str | None = None


class Maintenance(ApiModel):
    status: str | None = None
    """PENDING, IN_MAINTENANCE or FAILED."""
    start: EpochDatetime = None
    end: EpochDatetime = None


def _reference_name(references: dict[str, Any], key: str) -> str:
    reference = references.get(key) or {}
    return str(reference.get("name") or "") if isinstance(reference, dict) else ""


class Device(ApiModel):
    """One device from /v2/devices-detailed (or /v2/device/{id}).

    organization_name, location_name and role_name come from the record's `references`,
    and are filled in from lookups by list_devices when references leave a gap.
    """

    id: int
    uid: str | None = None
    system_name: str = ""
    display_name: str = ""
    dns_name: str = ""
    netbios_name: str | None = None
    node_class: str | None = None
    """WINDOWS_SERVER, WINDOWS_WORKSTATION, LINUX_SERVER, MAC, ..."""
    node_role_id: int | None = None
    organization_id: int | None = None
    location_id: int | None = None
    policy_id: int | None = None
    approval_status: str | None = None
    """PENDING, STAGED, APPROVED or DECOMMISSIONED."""
    offline: bool | None = None
    created: EpochDatetime = None
    last_contact: EpochDatetime = None
    last_update: EpochDatetime = None
    last_logged_in_user: str | None = None
    public_ip: str | None = Field(default=None, alias="publicIP")
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    os: OperatingSystem | None = None
    system: DeviceSystem | None = None
    maintenance: Maintenance | None = None

    organization_name: str = ""
    location_name: str = ""
    role_name: str = ""

    @model_validator(mode="before")
    @classmethod
    def _lift_references(cls, data: Any) -> Any:
        if not isinstance(data, dict) or not isinstance(data.get("references"), dict):
            return data
        references = data["references"]
        data = dict(data)
        for field, key in (
            ("organizationName", "organization"),
            ("locationName", "location"),
            ("roleName", "role"),
        ):
            if not data.get(field):
                data[field] = _reference_name(references, key)
        return data

    @computed_field  # type: ignore[prop-decorator]
    @property
    def name(self) -> str:
        """The best human-facing name: displayName, then systemName, then the DNS label."""
        return self.display_name or self.system_name or self.dns_name.split(".")[0] or f"device-{self.id}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def state(self) -> str:
        """One word for the device's operational state, most significant first:
        decommissioned, approval-pending, approval-staged, maintenance, offline, online, unknown."""
        approval = (self.approval_status or "").upper()
        if approval == "DECOMMISSIONED":
            return "decommissioned"
        if approval in ("PENDING", "STAGED"):
            return f"approval-{approval.lower()}"
        if self.maintenance and self.maintenance.status == "IN_MAINTENANCE":
            return "maintenance"
        if self.offline is True:
            return "offline"
        if self.offline is False:
            return "online"
        return "unknown"

    @property
    def hostname(self) -> str:
        """systemName, falling back to the first DNS label, upper-cased."""
        return (self.system_name or self.dns_name.split(".")[0]).strip().upper()


DEVICE_STATES = (
    "online",
    "offline",
    "maintenance",
    "approval-pending",
    "approval-staged",
    "decommissioned",
    "unknown",
)
"""Every value Device.state can take."""


# -- software --------------------------------------------------------------------


class SoftwareInstall(ApiModel):
    """One installed product on one device (/v2/queries/software or /v2/device/{id}/software)."""

    device_id: int
    name: str = ""
    publisher: str | None = None
    version: str | None = None
    install_date: str | None = None
    location: str | None = None
    product_code: str | None = None
    is_system_component: bool | None = None
    size: int | None = None
    timestamp: EpochDatetime = None
    """When NinjaOne last collected this record."""

    device_name: str | None = None
    organization_name: str | None = None
    """Filled in only when the caller passes devices to list_software."""


class SoftwareSummary(BaseModel):
    """One product (publisher + name) across the selected installs."""

    publisher: str | None
    name: str
    device_count: int
    install_count: int
    """Can exceed device_count: a device can have several versions installed."""
    versions: dict[str, int] = Field(default_factory=dict)
    """version -> number of devices with it. "" is a version NinjaOne didn't report."""


class SoftwareProduct(ApiModel):
    """A product in NinjaOne's 3rd-party patching catalogue (/v2/software-products)."""

    id: str
    vendor_name: str | None = None
    product_name: str | None = None
    installable: bool | None = None
    active: bool | None = None


# -- patches and security ---------------------------------------------------------


class OsPatch(ApiModel):
    """One OS patch on one device: /v2/queries/os-patches (not installed: MANUAL,
    APPROVED, FAILED, REJECTED) or /v2/queries/os-patch-installs (INSTALLED, FAILED)."""

    id: str | None = None
    device_id: int
    name: str | None = None
    kb_number: str | None = None
    severity: str | None = None
    status: str | None = None
    type: str | None = None
    os: str | None = None
    version: str | None = None
    reboot_required: str | None = None
    release_date: EpochDatetime = None
    installed_at: EpochDatetime = None
    timestamp: EpochDatetime = None
    install_errors: list[Any] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def kb(self) -> str | None:
        """kb_number normalised to "KB1234567", or None for patches without one."""
        return normalise_kb(self.kb_number) if self.kb_number else None


class SoftwarePatch(ApiModel):
    """One 3rd-party software patch on one device: /v2/queries/software-patches or
    /v2/queries/software-patch-installs."""

    id: str | None = None
    device_id: int
    product_identifier: str | None = None
    title: str | None = None
    vendor: str | None = None
    version: str | None = None
    impact: str | None = None
    status: str | None = None
    type: str | None = None
    architecture: str | None = None
    os: str | None = None
    reboot_required: str | None = None
    release_date: EpochDatetime = None
    installed_at: EpochDatetime = None
    timestamp: EpochDatetime = None


class KbSummary(BaseModel):
    """One KB across the fleet: how many devices are in each patch status.

    A device counts once per KB, under its latest status. Statuses are normalised:
    pending (API: MANUAL), approved, failed, rejected, installed; anything else is kept
    lower-cased.
    """

    kb: str
    name: str | None = None
    severity: str | None = None
    type: str | None = None
    os: str | None = None
    release_date: datetime | None = None
    device_count: int = 0
    counts: dict[str, int] = Field(default_factory=dict)
    """status -> number of devices."""
    devices: dict[str, list[int]] = Field(default_factory=dict)
    """status -> device ids."""


class DeviceVulnerabilityCounts(ApiModel):
    """Per-device counts from /v2/queries/device-health - the only per-device
    vulnerability data the public API exposes."""

    device_id: int
    critical_vulnerability_count: int = 0
    high_vulnerability_count: int = 0
    medium_vulnerability_count: int = 0
    low_vulnerability_count: int = 0
    health_status: str | None = None
    """UNKNOWN, HEALTHY, NEEDS_ATTENTION or UNHEALTHY."""
    pending_os_patches_count: int | None = Field(default=None, alias="pendingOSPatchesCount")
    failed_os_patches_count: int | None = Field(default=None, alias="failedOSPatchesCount")
    offline: bool | None = None

    device_name: str | None = None
    organization_name: str | None = None
    """Filled in only when the caller passes devices to vulnerability_counts."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total(self) -> int:
        return (
            self.critical_vulnerability_count
            + self.high_vulnerability_count
            + self.medium_vulnerability_count
            + self.low_vulnerability_count
        )


class ScanGroup(ApiModel):
    """A vulnerability scan group: a third-party scanner's CSV import into NinjaOne.

    Metadata only - the public API has no endpoint that returns the imported CVE rows.
    """

    id: int
    group_name: str | None = None
    file_name: str | None = None
    status: str | None = None
    """COMPLETE, IN_PROGRESS or FAILED."""
    vendor: str | None = None
    third_party_api_tile: str | None = None
    device_id_header: str | None = None
    device_internal_mapping: str | None = None
    cve_id_header: str | None = None
    last_file_upload_date: str | None = None
    records_processed: int | None = None
