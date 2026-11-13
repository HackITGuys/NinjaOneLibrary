"""Read-only Python bindings for the NinjaOne Public API v2.

    from NinjaOne import NinjaOneClient, list_devices, list_software, list_kbs

    with NinjaOneClient() as client:                    # NINJA_* from env / .env
        servers = list_devices(client, node_class="WINDOWS_SERVER", tags=["Production"])
        old_7zip = list_software(client, vendor="Igor Pavlov", version="<24.09", devices=servers)
        kbs = list_kbs(client, df="class in (WINDOWS_SERVER)")

Every function returns pydantic models; `model.model_dump(mode="json")` gives a plain,
JSON-ready dict. `brief(client, records)` turns a listing into short, aggregated rows
(counts instead of device ids) and `render_table(rows)` prints them as aligned columns.

The API can't filter software by name, so `software_snapshot(client)` reads the inventory
once and saves it; `software_catalog` and `software_devices` then answer from it.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from NinjaOne.client import NinjaOneAuthError, NinjaOneClient, NinjaOneError, ProgressHook
from NinjaOne.config import NinjaOneSettings
from NinjaOne.devices import (
    build_df,
    devices_by_id,
    filter_devices,
    get_device,
    list_devices,
    list_roles,
    list_tags,
)
from NinjaOne.models import (
    DEVICE_STATES,
    Device,
    DeviceSystem,
    DeviceVulnerabilityCounts,
    KbSummary,
    Location,
    Maintenance,
    OperatingSystem,
    Organization,
    OsPatch,
    Role,
    ScanGroup,
    SnapshotDevice,
    SnapshotSoftware,
    SoftwareCatalogEntry,
    SoftwareDevice,
    SoftwareInstall,
    SoftwarePatch,
    SoftwareProduct,
    SoftwareSnapshot,
    SoftwareSummary,
    Tag,
    normalise_kb,
)
from NinjaOne.organizations import find_organizations, get_organization, list_locations, list_organizations
from NinjaOne.security import (
    device_os_patches,
    device_software_patches,
    find_endpoints,
    get_scan_group,
    list_kbs,
    list_scan_groups,
    normalise_status,
    os_patch_installs,
    os_patches,
    software_patch_installs,
    software_patches,
    summarise_kbs,
    vulnerability_counts,
)
from NinjaOne.snapshot import (
    load_fresh_software_snapshot,
    load_software_snapshot,
    refresh_software_snapshot,
    save_software_snapshot,
    snapshot_path,
    software_catalog,
    software_devices,
    software_snapshot,
    take_software_snapshot,
)
from NinjaOne.software import (
    attach_devices,
    device_software,
    filter_software,
    list_software,
    list_software_products,
    parse_version,
    summarise_software,
    text_equals,
    text_matches,
    version_matches,
)
from NinjaOne.views import brief, render_table

try:
    __version__ = _version("ninjaone-library")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"

__all__ = [
    "DEVICE_STATES",
    "Device",
    "DeviceSystem",
    "DeviceVulnerabilityCounts",
    "KbSummary",
    "Location",
    "Maintenance",
    "NinjaOneAuthError",
    "NinjaOneClient",
    "NinjaOneError",
    "NinjaOneSettings",
    "OperatingSystem",
    "Organization",
    "OsPatch",
    "ProgressHook",
    "Role",
    "ScanGroup",
    "SnapshotDevice",
    "SnapshotSoftware",
    "SoftwareCatalogEntry",
    "SoftwareDevice",
    "SoftwareInstall",
    "SoftwarePatch",
    "SoftwareProduct",
    "SoftwareSnapshot",
    "SoftwareSummary",
    "Tag",
    "__version__",
    "attach_devices",
    "brief",
    "build_df",
    "device_os_patches",
    "device_software",
    "device_software_patches",
    "devices_by_id",
    "filter_devices",
    "filter_software",
    "find_endpoints",
    "find_organizations",
    "get_device",
    "get_organization",
    "get_scan_group",
    "list_devices",
    "list_kbs",
    "list_locations",
    "list_organizations",
    "list_roles",
    "list_scan_groups",
    "list_software",
    "list_software_products",
    "list_tags",
    "load_fresh_software_snapshot",
    "load_software_snapshot",
    "normalise_kb",
    "normalise_status",
    "os_patch_installs",
    "os_patches",
    "parse_version",
    "refresh_software_snapshot",
    "render_table",
    "save_software_snapshot",
    "snapshot_path",
    "software_catalog",
    "software_devices",
    "software_patch_installs",
    "software_patches",
    "software_snapshot",
    "summarise_kbs",
    "summarise_software",
    "take_software_snapshot",
    "text_equals",
    "text_matches",
    "version_matches",
    "vulnerability_counts",
]
