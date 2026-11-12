# NinjaOneLibrary

Read-only Python bindings for the [NinjaOne](https://www.ninjaone.com/) Public API v2. You call a function and get pydantic models back; `model_dump(mode="json")` turns any of them into a plain dict that is ready for JSON.

- **Base data:** organisations, locations, device roles, asset tags and devices. Devices can be filtered by organisation, location, node class, role, tag, OS and state.
- **Software:** a fleet-wide inventory you can search by vendor, product name and version (exact, glob or PEP 440 range), a per-device inventory, a per-product summary, and the 3rd-party patching catalogue.
- **Security:** OS and software patch records, KBs with device counts per patch status (the input for KB→CVE mapping), per-device vulnerability counts and vulnerability scan groups.

Every call is a `GET` made with NinjaOne's read-only `monitoring` scope, so the library cannot change a tenant.

## Install

```sh
uv add "ninjaone-library @ git+https://github.com/HackITGuys/NinjaOneLibrary"
# or pin a tag/commit:  ...NinjaOneLibrary@v0.1.0
```

It installs as `ninjaone-library`, imports as `NinjaOne`, and needs Python 3.12 or newer.

## Credentials

1. In NinjaOne, go to **Administration → Apps → API → Client App IDs → Add**.
2. Set **Application platform** to *API Services (machine-to-machine)*, **Scopes** to *Monitoring* only, and **Allowed grant types** to *Client Credentials*.
3. Copy the client ID and secret into a `.env` file (see [.env.example](.env.example)):

```dotenv
NINJA_BASE_URL=https://eu.ninjarmm.com     # app. (US), us2., ca., eu. or oc.ninjarmm.com
NINJA_CLIENT_ID=...
NINJA_CLIENT_SECRET=...
NINJA_SCOPE=monitoring
```

Settings come from environment variables first and then from `.env` in the current directory. `NinjaOneSettings(_env_file="other.env")` or `NinjaOneSettings(client_id=..., client_secret=...)` overrides both.

## Library

```python
from datetime import date

from NinjaOne import (
    NinjaOneClient,
    list_organizations,
    list_locations,
    list_devices,
    list_tags,
    list_software,
    summarise_software,
    list_kbs,
    vulnerability_counts,
)

with NinjaOneClient() as client:
    orgs = list_organizations(client)
    oslo = list_locations(client, organization_id=orgs[0].id)

    # org / location / node class are filtered by the API; role, tags, OS and state locally.
    servers = list_devices(
        client,
        organization_id=orgs[0].id,
        node_class="WINDOWS_SERVER",
        tags=["Production"],  # all of them; all_tags=False for any
        os="Server 2019",  # substring of the OS name
        role="SQL",  # substring of the role name
    )

    # Software: vendor/name are substrings (or globs), version is exact, a glob or a range.
    old_7zip = list_software(client, vendor="Igor Pavlov", version="<24.09", devices=servers)
    per_product = summarise_software(list_software(client, vendor="Adobe"))

    # KBs with device counts per status: map these to CVEs with the source you trust.
    kbs = list_kbs(client, df=f"org = {orgs[0].id}", include_installed=True, installed_after=date(2026, 1, 1))

    worst = vulnerability_counts(client)  # critical/high/medium/low per device, worst first

print([device.model_dump(mode="json") for device in servers])
```

| Area | Functions |
|---|---|
| Organisations | `list_organizations`, `get_organization`, `find_organizations`, `list_locations` |
| Devices | `list_devices`, `get_device`, `filter_devices`, `build_df`, `list_roles`, `list_tags` |
| Software | `list_software`, `device_software`, `filter_software`, `summarise_software`, `attach_devices`, `list_software_products`, `version_matches` |
| Patches & KBs | `os_patches`, `os_patch_installs`, `device_os_patches`, `software_patches`, `software_patch_installs`, `device_software_patches`, `list_kbs`, `summarise_kbs` |
| Vulnerabilities | `vulnerability_counts`, `list_scan_groups`, `get_scan_group`, `find_endpoints` |

For anything not wrapped yet, `client.get("/path")`, `client.paginate_after(...)` and `client.paginate_cursor(...)` give you the raw JSON with authentication, retries and paging handled.

### What the API does and doesn't offer

- **There is no CVE endpoint.** NinjaOne exposes KB numbers on OS patch records, vulnerability *counts* per device, and scan-group *metadata*, but not CVE rows. `list_kbs` is the bridge: map its KBs to CVEs elsewhere, for example with Microsoft's MSRC CVRF API. `find_endpoints()` searches the live OpenAPI spec, so a future CVE endpoint will show up there.
- **Tags and OS can't be filtered server-side.** The device filter (`df`) covers organisation, location, role id, node class, approval status, online/offline, creation date and group. Tag and OS filters run on the fetched devices.
- **Install history is large.** `os_patch_installs` / `list_kbs(include_installed=True)` with no `installed_after` read the whole history, which can be over a million rows. The CLI defaults to the last 90 days.

## CLI

Every command prints JSON on stdout; logs and errors go to stderr.

```sh
ninjaone organizations
ninjaone locations --org Contoso
ninjaone roles
ninjaone tags
ninjaone devices --org Contoso --class WINDOWS_SERVER --tag Production --os "Server 2022"
ninjaone device 1234
ninjaone software --vendor "Igor Pavlov" --version "<24.09"
ninjaone software --org Contoso --vendor Adobe --summary
ninjaone software-products --vendor Mozilla
ninjaone patches --org Contoso --kb KB5031356 --installed --since 2026-01-01
ninjaone software-patches --vendor Google
ninjaone kbs --org Contoso --include-installed
ninjaone vulnerabilities --org Contoso
ninjaone scan-groups
ninjaone endpoints --match "vulnerab|cve"
```

`--org` takes an id or a name. An exact name wins; otherwise every organisation whose name contains the text is included. The global options are `--env-file`, `-o/--output FILE`, `--compact` and `-v`.

## Development

[devenv](https://devenv.sh) provides Python and [uv](https://docs.astral.sh/uv/), and runs `uv sync` when you enter the shell (direnv does this automatically via `.envrc`):

```sh
devenv shell
uv run pytest                    # unit tests, no network
uv run pytest -m live            # read-only calls to the instance in your .env
uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
devenv test                      # all of the above except live
uv build                         # wheel + sdist in dist/
```

Dependencies are managed with `uv add` / `uv remove`. Commit `uv.lock`.

### Releases

Packages are built only from tags. Bump the version, commit, and push a matching `v` tag:

```sh
uv version --bump minor          # or patch / major; updates pyproject.toml and uv.lock
git commit -am "Release $(uv version --short)"
git tag "v$(uv version --short)" && git push origin main --tags
```

The [release workflow](.github/workflows/release.yml) runs the CI checks, fails if the tag doesn't match the version in `pyproject.toml`, builds the wheel and sdist, and attaches them to a GitHub release with generated notes. Other projects can then pin the tag (`...NinjaOneLibrary@v0.2.0`).

### Dependency updates

[Dependabot](.github/dependabot.yml) checks the uv dependencies and GitHub Actions every Monday at 23:00 (Europe/Oslo). It opens one grouped PR for minor and patch updates and one for major updates. [CI](.github/workflows/ci.yml) runs lint, type checks and tests on Python 3.12 and 3.14 for every PR. Merging stays manual.

- Security-alert PRs are switched on in the repository settings (Code security → Dependabot security updates), not in the config file.
- Dependabot can't update `devenv.lock` (Nix). Run `devenv update` for that.
