"""Read-only Python bindings for the NinjaOne Public API v2.

    from NinjaOne import NinjaOneClient, list_devices, list_software, list_kbs

    with NinjaOneClient() as client:                    # NINJA_* from env / .env
        servers = list_devices(client, node_class="WINDOWS_SERVER", tags=["Production"])
        old_7zip = list_software(client, vendor="Igor Pavlov", version="<24.09", devices=servers)
        kbs = list_kbs(client, df="class in (WINDOWS_SERVER)")

Every function returns pydantic models; `model.model_dump(mode="json")` gives a plain,
JSON-ready dict.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from NinjaOne.client import NinjaOneAuthError, NinjaOneClient, NinjaOneError
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
    SoftwareInstall,
    SoftwarePatch,
    SoftwareProduct,
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
from NinjaOne.software import (
    attach_devices,
    device_software,
    filter_software,
    list_software,
    list_software_products,
    parse_version,
    summarise_software,
    text_matches,
    version_matches,
)

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
    "Role",
    "ScanGroup",
    "SoftwareInstall",
    "SoftwarePatch",
    "SoftwareProduct",
    "SoftwareSummary",
    "Tag",
    "__version__",
    "attach_devices",
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
    "normalise_kb",
    "normalise_status",
    "os_patch_installs",
    "os_patches",
    "parse_version",
    "software_patch_installs",
    "software_patches",
    "summarise_kbs",
    "summarise_software",
    "text_matches",
    "version_matches",
    "vulnerability_counts",
]
