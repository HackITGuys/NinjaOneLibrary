"""`ninjaone` - the library's functions as JSON on stdout.

    ninjaone organizations
    ninjaone devices --org "Contoso" --os "Windows 11" --tag Production
    ninjaone software --vendor "Igor Pavlov" --version "<24.09"
    ninjaone kbs --org Contoso --include-installed --since 2026-01-01

Logs and errors go to stderr, so stdout is always valid JSON (or nothing, on error).
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any, TypeVar

import click
import requests
from pydantic_core import to_jsonable_python

from NinjaOne.client import NinjaOneClient, NinjaOneError
from NinjaOne.config import NinjaOneSettings
from NinjaOne.devices import build_df, get_device, list_devices, list_roles, list_tags
from NinjaOne.models import DEVICE_STATES
from NinjaOne.organizations import find_organizations, list_locations, list_organizations
from NinjaOne.security import (
    find_endpoints,
    get_scan_group,
    list_kbs,
    list_scan_groups,
    os_patch_installs,
    os_patches,
    software_patch_installs,
    software_patches,
    vulnerability_counts,
)
from NinjaOne.software import (
    device_software,
    filter_software,
    list_software,
    list_software_products,
    summarise_software,
)

log = logging.getLogger("NinjaOne")

F = TypeVar("F", bound=Callable[..., Any])

DEFAULT_SINCE_DAYS = 90
"""How far back install history is read unless --since says otherwise. The full history
can be over a million records."""


@dataclass
class State:
    env_file: Path | None = None
    output: Path | None = None
    compact: bool = False
    _client: NinjaOneClient | None = field(default=None, repr=False)

    @property
    def client(self) -> NinjaOneClient:
        if self._client is None:
            settings = NinjaOneSettings(_env_file=self.env_file) if self.env_file else NinjaOneSettings()
            self._client = NinjaOneClient(settings)
        return self._client


pass_state = click.make_pass_decorator(State)


def emit(state: State, data: Any) -> None:
    """Models, lists of models and dicts of them -> JSON on stdout (or --output)."""
    text = json.dumps(
        to_jsonable_python(data, by_alias=False),
        indent=None if state.compact else 2,
        ensure_ascii=False,
        sort_keys=False,
    )
    if state.output:
        state.output.parent.mkdir(parents=True, exist_ok=True)
        state.output.write_text(text + "\n", encoding="utf-8")
        count = f"{len(data)} records" if isinstance(data, list | dict) else "1 record"
        click.echo(f"Wrote {count} to {state.output}", err=True)
    else:
        click.echo(text)


def _parse_since(ctx: click.Context, param: click.Parameter, value: str | None) -> date | None:
    """--since: YYYY-MM-DD, or "all" (None: the whole history)."""
    text = (value or "").strip().lower()
    if not text or text == "all":
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise click.BadParameter(f"{value!r} is not a date (YYYY-MM-DD) or 'all'") from None


def since_option(help_text: str) -> Callable[[F], F]:
    return click.option(
        "--since",
        metavar="YYYY-MM-DD|all",
        default=lambda: (date.today() - timedelta(days=DEFAULT_SINCE_DAYS)).isoformat(),
        show_default=f"{DEFAULT_SINCE_DAYS} days ago",
        callback=_parse_since,
        help=help_text,
    )


org_option = click.option(
    "--org", help="Organisation id or name (exact name, else every name containing it)."
)
df_option = click.option(
    "--df", help='Raw NinjaOne device filter, AND-ed on, e.g. "class in (WINDOWS_SERVER)".'
)

_ID_SEPARATORS = re.compile(r"[\s,;]+")


def split_ids(values: Sequence[str]) -> list[str]:
    """Repeated options and comma/space/semicolon-separated lists, flattened and de-duplicated."""
    ids: dict[str, None] = {}
    for value in values:
        for part in _ID_SEPARATORS.split(value):
            if part:
                ids.setdefault(part, None)
    return list(ids)


def org_ids(state: State, org: str | None) -> list[int] | None:
    """--org -> organisation ids, or None when not given. No match is an error, not 'everything'."""
    if not org:
        return None
    matches = find_organizations(state.client, org)
    if not matches:
        raise click.ClickException(f"No NinjaOne organisation matches {org!r}")
    log.info("--org %r matches: %s", org, ", ".join(f"{o.name} ({o.id})" for o in matches))
    return [o.id for o in matches]


def scope(state: State, org: str | None, df: str | None = None) -> str | None:
    return build_df(organization_ids=org_ids(state, org), df=df)


class Group(click.Group):
    """Turns API and input errors into a one-line message and exit code 1."""

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except (NinjaOneError, ValueError, requests.RequestException) as exc:
            raise click.ClickException(str(exc)) from exc


@click.group(cls=Group)
@click.option(
    "--env-file",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Read NINJA_* settings from this file instead of ./.env.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write JSON here instead of stdout.",
)
@click.option("--compact", is_flag=True, help="One-line JSON.")
@click.option("-v", "--verbose", count=True, help="-v for progress, -vv for HTTP retries.")
@click.version_option(package_name="ninjaone-library")
@click.pass_context
def main(ctx: click.Context, env_file: Path | None, output: Path | None, compact: bool, verbose: int) -> None:
    """Read-only NinjaOne API queries, printed as JSON."""
    logging.basicConfig(
        stream=sys.stderr,
        level=max(logging.DEBUG, logging.WARNING - 10 * verbose),
        format="%(levelname)s %(message)s",
    )
    if not isinstance(ctx.obj, State):
        ctx.obj = State()
    ctx.obj.env_file, ctx.obj.output, ctx.obj.compact = env_file, output, compact


# -- base data ------------------------------------------------------------------


@main.command()
@click.option("--name", help="Only organisations whose name contains this.")
@pass_state
def organizations(state: State, name: str | None) -> None:
    """List organisations."""
    orgs = list_organizations(state.client)
    if name:
        orgs = [org for org in orgs if name.lower() in org.name.lower()]
    emit(state, orgs)


@main.command()
@org_option
@pass_state
def locations(state: State, org: str | None) -> None:
    """List locations: all, or those of the organisations --org matches."""
    ids = org_ids(state, org)
    if ids is None:
        emit(state, list_locations(state.client))
    else:
        emit(state, [loc for org_id in ids for loc in list_locations(state.client, org_id)])


@main.command()
@pass_state
def roles(state: State) -> None:
    """List device roles."""
    emit(state, list_roles(state.client))


@main.command()
@pass_state
def tags(state: State) -> None:
    """List asset tags."""
    emit(state, list_tags(state.client))


@main.command()
@org_option
@click.option("--location", "location_ids", type=int, multiple=True, help="Location id. Repeatable.")
@click.option(
    "--class", "node_classes", multiple=True, help="Node class, e.g. WINDOWS_SERVER, MAC. Repeatable."
)
@click.option("--role", help="Role name contains this (case-insensitive).")
@click.option("--tag", "tag_names", multiple=True, help="Has this tag. Repeatable: must have all of them.")
@click.option("--any-tag", is_flag=True, help="With several --tag: having any one of them is enough.")
@click.option("--os", "os_name", help='OS name contains this, e.g. "Windows 11", "Server 2022", "Ubuntu".')
@click.option("--state", "device_state", type=click.Choice(DEVICE_STATES), help="Operational state.")
@df_option
@pass_state
def devices(
    state: State,
    org: str | None,
    location_ids: tuple[int, ...],
    node_classes: tuple[str, ...],
    role: str | None,
    tag_names: tuple[str, ...],
    any_tag: bool,
    os_name: str | None,
    device_state: str | None,
    df: str | None,
) -> None:
    """List devices, filtered by organisation, location, class, role, tags, OS and state."""
    emit(
        state,
        list_devices(
            state.client,
            organization_id=org_ids(state, org),
            location_id=list(location_ids) or None,
            node_class=list(node_classes) or None,
            role=role,
            tags=list(tag_names) or None,
            all_tags=not any_tag,
            os=os_name,
            state=device_state,
            df=df,
        ),
    )


@main.command()
@click.argument("device_id", type=int)
@pass_state
def device(state: State, device_id: int) -> None:
    """Show one device."""
    emit(state, get_device(state.client, device_id))


# -- software -------------------------------------------------------------------


@main.command()
@org_option
@click.option("--device", "device_id", type=int, help="Only this device (by id).")
@click.option("--vendor", help="Publisher contains this (or matches it, as a glob).")
@click.option("--name", help="Product name contains this (or matches it, as a glob).")
@click.option("--version", help='Version: "<24.09", ">=2.4,<2.4.62", a glob like "24.*", or exact.')
@click.option("--no-system", is_flag=True, help="Leave out system components.")
@click.option("--summary", is_flag=True, help="One entry per product with device counts per version.")
@df_option
@pass_state
def software(
    state: State,
    org: str | None,
    device_id: int | None,
    vendor: str | None,
    name: str | None,
    version: str | None,
    no_system: bool,
    summary: bool,
    df: str | None,
) -> None:
    """Search installed software by vendor, name and version."""
    if device_id is not None:
        installs = filter_software(
            device_software(state.client, device_id),
            vendor=vendor,
            name=name,
            version=version,
            include_system_components=not no_system,
        )
    else:
        ids = org_ids(state, org)
        installs = list_software(
            state.client,
            vendor=vendor,
            name=name,
            version=version,
            include_system_components=not no_system,
            df=build_df(organization_ids=ids, df=df),
            # Device names make the listing readable; a summary doesn't need them.
            devices=None if summary else list_devices(state.client, organization_id=ids, df=df),
        )
    emit(state, summarise_software(installs) if summary else installs)


@main.command("software-products")
@click.option("--vendor", help="Vendor name contains this.")
@pass_state
def software_products(state: State, vendor: str | None) -> None:
    """List the 3rd-party products NinjaOne can patch."""
    products = list_software_products(state.client)
    if vendor:
        products = [p for p in products if vendor.lower() in (p.vendor_name or "").lower()]
    emit(state, products)


# -- security -------------------------------------------------------------------


@main.command()
@org_option
@click.option("--kb", "kb_values", multiple=True, help="KB number(s); repeatable or comma-separated.")
@click.option(
    "--status",
    help="API status filter, e.g. MANUAL, APPROVED, FAILED, REJECTED (INSTALLED with --installed).",
)
@click.option("--installed", is_flag=True, help="Read the install history instead of outstanding patches.")
@since_option("With --installed: installs on or after this date, or 'all'.")
@df_option
@pass_state
def patches(
    state: State,
    org: str | None,
    kb_values: tuple[str, ...],
    status: str | None,
    installed: bool,
    since: date | None,
    df: str | None,
) -> None:
    """List OS patch records (outstanding, or install history with --installed)."""
    query = scope(state, org, df)
    kbs = split_ids(kb_values) or None
    if installed:
        emit(state, os_patch_installs(state.client, df=query, status=status, installed_after=since, kbs=kbs))
    else:
        emit(state, os_patches(state.client, df=query, status=status, kbs=kbs))


@main.command("software-patches")
@org_option
@click.option("--vendor", help="Vendor contains this.")
@click.option("--title", help="Patch title contains this.")
@click.option("--status", help="API status filter.")
@click.option("--installed", is_flag=True, help="Read the install history instead of outstanding patches.")
@since_option("With --installed: installs on or after this date, or 'all'.")
@df_option
@pass_state
def software_patches_command(
    state: State,
    org: str | None,
    vendor: str | None,
    title: str | None,
    status: str | None,
    installed: bool,
    since: date | None,
    df: str | None,
) -> None:
    """List 3rd-party software patch records."""
    query = scope(state, org, df)
    if installed:
        records = software_patch_installs(
            state.client, df=query, status=status, installed_after=since, vendor=vendor, title=title
        )
    else:
        records = software_patches(state.client, df=query, status=status, vendor=vendor, title=title)
    emit(state, records)


@main.command()
@org_option
@click.option("--kb", "kb_values", multiple=True, help="Only these KB(s); repeatable or comma-separated.")
@click.option("--include-installed", is_flag=True, help="Also read install history and count installs.")
@since_option("With --include-installed: installs on or after this date, or 'all'.")
@df_option
@pass_state
def kbs(
    state: State,
    org: str | None,
    kb_values: tuple[str, ...],
    include_installed: bool,
    since: date | None,
    df: str | None,
) -> None:
    """List KBs with device counts per patch status - the input for KB -> CVE mapping."""
    emit(
        state,
        list_kbs(
            state.client,
            df=scope(state, org, df),
            kbs=split_ids(kb_values) or None,
            include_installed=include_installed,
            installed_after=since,
        ),
    )


@main.command()
@org_option
@click.option("--all", "show_all", is_flag=True, help="Include devices with no vulnerabilities.")
@df_option
@pass_state
def vulnerabilities(state: State, org: str | None, show_all: bool, df: str | None) -> None:
    """Per-device vulnerability counts (critical/high/medium/low), worst first."""
    emit(state, vulnerability_counts(state.client, df=scope(state, org, df), only_vulnerable=not show_all))


@main.command("scan-groups")
@click.argument("scan_group_id", type=int, required=False)
@pass_state
def scan_groups(state: State, scan_group_id: int | None) -> None:
    """List vulnerability scan groups, or show one."""
    if scan_group_id is None:
        emit(state, list_scan_groups(state.client))
    else:
        emit(state, get_scan_group(state.client, scan_group_id))


@main.command()
@click.option(
    "--match", "pattern", default=r"vulnerab|cve", show_default=True, help="Regex on path/tag/summary."
)
@pass_state
def endpoints(state: State, pattern: str) -> None:
    """Search the live OpenAPI spec for GET endpoints (e.g. a future CVE endpoint)."""
    emit(state, find_endpoints(state.client, pattern))


if __name__ == "__main__":
    main()
