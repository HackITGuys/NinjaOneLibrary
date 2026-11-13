"""`ninjaone` - the library's functions as JSON on stdout, or as tables with --brief.

    ninjaone organizations
    ninjaone devices --org "Contoso" --os "Windows 11" --tag Production --brief
    ninjaone software --vendor "Igor Pavlov" --version "<24.09" --brief
    ninjaone kbs --org Contoso --include-installed --since 2026-01-01

stdout is JSON unless a listing is given --brief, which prints aggregated rows as a
table (--json prints those rows as JSON instead; -o always writes JSON). Logs, errors
and the live progress line go to stderr.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, timedelta
from pathlib import Path
from typing import Any, TextIO, TypeVar

import click
import requests
from pydantic_core import to_jsonable_python

from NinjaOne import views
from NinjaOne.client import NinjaOneClient, NinjaOneError
from NinjaOne.config import NinjaOneSettings
from NinjaOne.devices import build_df, get_device, list_devices, list_roles, list_tags
from NinjaOne.models import DEVICE_STATES, SoftwareSnapshot
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
from NinjaOne.snapshot import (
    load_fresh_software_snapshot,
    load_software_snapshot,
    refresh_software_snapshot,
    snapshot_age,
    snapshot_path,
    software_catalog,
    software_devices,
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


def _records(count: int) -> str:
    return f"{count:,} record" + ("" if count == 1 else "s")


class StderrProgress:
    """One live status line on stderr: "devices-detailed: 1,500 records", "software: 500/2,000".

    Updates are throttled; the line is cleared before anything else is printed.
    """

    INTERVAL = 0.1

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self._shown = False
        self._last = 0.0
        self._label = ""
        self._lock = threading.Lock()

    def __call__(self, label: str, done: int, total: int | None) -> None:
        now = time.monotonic()
        with self._lock:
            final = total is not None and done >= total
            if not final and label == self._label and now - self._last < self.INTERVAL:
                return
            self._last, self._label = now, label
            text = f"{label}: {done:,}/{total:,}" if total is not None else f"{label}: {_records(done)}"
            self.stream.write("\r\033[K" + text + "...")
            self.stream.flush()
            self._shown = True

    def clear(self) -> None:
        with self._lock:
            if self._shown:
                self.stream.write("\r\033[K")
                self.stream.flush()
                self._shown = False


class _ProgressAwareHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Log lines clear the progress line first, so they don't print over it."""

    def __init__(self, progress: StderrProgress | None) -> None:
        super().__init__(sys.stderr)
        self.progress = progress

    def emit(self, record: logging.LogRecord) -> None:
        if self.progress is not None:
            self.progress.clear()
        super().emit(record)


@dataclass
class State:
    env_file: Path | None = None
    output: Path | None = None
    compact: bool = False
    json_output: bool = False
    progress: StderrProgress | None = None
    _client: NinjaOneClient | None = field(default=None, repr=False)

    @property
    def client(self) -> NinjaOneClient:
        if self._client is None:
            settings = NinjaOneSettings(_env_file=self.env_file) if self.env_file else NinjaOneSettings()
            self._client = NinjaOneClient(settings, progress=self.progress)
        return self._client


pass_state = click.make_pass_decorator(State)


def emit(state: State, data: Any, *, table: bool = False, source: int | None = None) -> None:
    """Models, lists of models and dicts of them -> JSON on stdout (or --output, always JSON).

    table=True prints a list of rows as aligned columns instead, unless --json is given,
    with a count on stderr; `source` is how many records the rows were made from.
    """
    payload = to_jsonable_python(data, by_alias=False)
    if state.progress is not None:
        state.progress.clear()
    if state.output:
        text = json.dumps(payload, indent=None if state.compact else 2, ensure_ascii=False)
        state.output.parent.mkdir(parents=True, exist_ok=True)
        state.output.write_text(text + "\n", encoding="utf-8")
        count = _records(len(data)) if isinstance(data, list | dict) else "1 record"
        click.echo(f"Wrote {count} to {state.output}", err=True)
    elif table and not state.json_output and isinstance(payload, list):
        if payload:
            click.echo(views.render_table(payload))
        rows = len(payload)
        if source is None or source == rows:
            click.echo(_records(rows), err=True)
        else:
            click.echo(f"{rows:,} row{'' if rows == 1 else 's'} from {_records(source)}", err=True)
    else:
        click.echo(json.dumps(payload, indent=None if state.compact else 2, ensure_ascii=False))


def show(state: State, brief: bool, records: Sequence[Any]) -> None:
    """Full records as JSON, or with --brief the aggregated rows, as a table."""
    if brief:
        emit(state, views.brief(state.client, records), table=True, source=len(records))
    else:
        emit(state, records)


brief_option = click.option(
    "--brief",
    is_flag=True,
    help="Short, aggregated rows (counts instead of device ids) as a table. --json prints them as JSON.",
)


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
@click.option("--json", "json_output", is_flag=True, help="Print JSON on stdout, never tables.")
@click.option(
    "--progress/--no-progress",
    default=None,
    help="A live status line on stderr while fetching (default: on when stderr is a terminal).",
)
@click.option("-v", "--verbose", count=True, help="-v for more detail, -vv for HTTP retries.")
@click.version_option(package_name="ninjaone-library")
@click.pass_context
def main(
    ctx: click.Context,
    env_file: Path | None,
    output: Path | None,
    compact: bool,
    json_output: bool,
    progress: bool | None,
    verbose: int,
) -> None:
    """Read-only NinjaOne API queries, printed as JSON (or tables with --brief)."""
    show_progress = sys.stderr.isatty() if progress is None else progress
    reporter = StderrProgress() if show_progress else None
    handler = _ProgressAwareHandler(reporter)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logging.basicConfig(
        level=max(logging.DEBUG, logging.WARNING - 10 * verbose), handlers=[handler], force=True
    )
    if not isinstance(ctx.obj, State):
        ctx.obj = State()
    state = ctx.obj
    state.env_file, state.output, state.compact = env_file, output, compact
    state.json_output, state.progress = json_output, reporter
    if reporter is not None:
        if state._client is not None:  # a client handed in (tests): report through it too
            state._client.progress = reporter
        ctx.call_on_close(reporter.clear)


# -- base data ------------------------------------------------------------------


@main.command()
@click.option("--name", help="Only organisations whose name contains this.")
@brief_option
@pass_state
def organizations(state: State, name: str | None, brief: bool) -> None:
    """List organisations (--brief: id, name, approval mode)."""
    orgs = list_organizations(state.client)
    if name:
        orgs = [org for org in orgs if name.lower() in org.name.lower()]
    show(state, brief, orgs)


@main.command()
@org_option
@brief_option
@pass_state
def locations(state: State, org: str | None, brief: bool) -> None:
    """List locations: all, or those of the organisations --org matches."""
    ids = org_ids(state, org)
    if ids is None:
        show(state, brief, list_locations(state.client))
    else:
        show(state, brief, [loc for org_id in ids for loc in list_locations(state.client, org_id)])


@main.command()
@brief_option
@pass_state
def roles(state: State, brief: bool) -> None:
    """List device roles."""
    show(state, brief, list_roles(state.client))


@main.command()
@brief_option
@pass_state
def tags(state: State, brief: bool) -> None:
    """List asset tags (--brief: with how many devices carry each)."""
    show(state, brief, list_tags(state.client))


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
@brief_option
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
    brief: bool,
) -> None:
    """List devices, filtered by organisation, location, class, role, tags, OS and state."""
    show(
        state,
        brief,
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
@click.option("--exact", is_flag=True, help="--vendor and --name must equal the whole value, not a part.")
@df_option
@brief_option
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
    exact: bool,
    df: str | None,
    brief: bool,
) -> None:
    """Search installed software by vendor, name and version, live.

    The API can't filter software by name, so this reads every install in scope each
    time. For repeated lookups, software-catalog and software-devices answer from a saved
    snapshot instead.

    --brief: one row per product and version with its device count (with --summary: one
    row per product).
    """
    if device_id is not None:
        installs = filter_software(
            device_software(state.client, device_id),
            vendor=vendor,
            name=name,
            version=version,
            include_system_components=not no_system,
            exact=exact,
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
            # Device names make the full listing readable; summaries and brief rows don't show them.
            devices=None if summary or brief else list_devices(state.client, organization_id=ids, df=df),
            exact=exact,
        )
    show(state, brief, summarise_software(installs) if summary else installs)


# -- software snapshot ---------------------------------------------------------


def _age(snapshot: SoftwareSnapshot) -> str:
    minutes = int(snapshot_age(snapshot).total_seconds() // 60)
    if minutes < 1:
        return "just now"
    if minutes < 120:
        return f"{minutes} min ago"
    hours = minutes // 60
    return f"{hours} h ago" if hours < 48 else f"{hours // 24} days ago"


def _taken(snapshot: SoftwareSnapshot) -> str:
    return f"{snapshot.taken_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC, {_age(snapshot)}"


def load_snapshot(state: State, refresh: bool) -> SoftwareSnapshot:
    """The saved snapshot while it is fresh, else a new one; says which on stderr."""
    settings = state.client.settings
    if not refresh:
        cached = load_fresh_software_snapshot(settings)
        if cached is not None:
            click.echo(
                f"Software snapshot from {_taken(cached)} ({cached.install_count:,} installs); "
                "--refresh reads the inventory again.",
                err=True,
            )
            return cached
    click.echo(
        "Reading the whole software inventory into a local snapshot; lookups reuse it for "
        f"{settings.snapshot_max_age_hours:g} h...",
        err=True,
    )
    snapshot = refresh_software_snapshot(state.client)
    if state.progress is not None:
        state.progress.clear()
    click.echo(
        f"Saved the snapshot: {snapshot.install_count:,} installs of {len(snapshot.software):,} "
        f"distinct software on {len(snapshot.devices):,} devices.",
        err=True,
    )
    return snapshot


def match_options[G: Callable[..., Any]](f: G) -> G:
    """--publisher/--name/--version for snapshot lookups: exact unless the value is a glob."""
    f = click.option("--no-system", is_flag=True, help="Leave out system components.")(f)
    f = click.option(
        "--refresh", is_flag=True, help="Read the inventory again instead of using the saved snapshot."
    )(f)
    f = click.option("--version", help='Version: exact, a glob like "24.*", or a range like "<24.09".')(f)
    f = click.option("--name", help='Software name, exactly (case-insensitive); a glob like "7-Zip*" too.')(f)
    f = click.option(
        "--publisher", "--vendor", "publisher", help="Publisher, exactly (case-insensitive); a glob too."
    )(f)
    return f


@main.command("software-catalog")
@org_option
@match_options
@brief_option
@pass_state
def software_catalog_command(
    state: State,
    org: str | None,
    publisher: str | None,
    name: str | None,
    version: str | None,
    refresh: bool,
    no_system: bool,
    brief: bool,
) -> None:
    """What software exists: each publisher, name and version, with its device count.

    Answered from a local snapshot of the inventory, read once and reused until it is
    NINJA_SNAPSHOT_MAX_AGE_HOURS old (default 24). Matching is exact, not by substring.
    """
    ids = org_ids(state, org)  # an unknown --org fails before the inventory is read
    snapshot = load_snapshot(state, refresh)
    entries = software_catalog(
        snapshot,
        publisher=publisher,
        name=name,
        version=version,
        include_system_components=not no_system,
        organization_ids=ids,
    )
    show(state, brief, entries)


@main.command("software-devices")
@org_option
@match_options
@brief_option
@pass_state
def software_devices_command(
    state: State,
    org: str | None,
    publisher: str | None,
    name: str | None,
    version: str | None,
    refresh: bool,
    no_system: bool,
    brief: bool,
) -> None:
    """Every device a software appears on, from the same snapshot as software-catalog."""
    if not (publisher or name):
        raise click.UsageError("Give --publisher and/or --name")
    ids = org_ids(state, org)
    snapshot = load_snapshot(state, refresh)
    rows = software_devices(
        snapshot,
        publisher=publisher,
        name=name,
        version=version,
        include_system_components=not no_system,
        organization_ids=ids,
    )
    show(state, brief, rows)


@main.command("software-snapshot")
@click.option("--refresh", is_flag=True, help="Read the inventory again now (e.g. from a nightly job).")
@pass_state
def software_snapshot_command(state: State, refresh: bool) -> None:
    """Where the software snapshot is, how old and how big it is."""
    settings = state.client.settings
    path = snapshot_path(settings)
    snapshot = load_snapshot(state, refresh=True) if refresh else load_software_snapshot(path)
    if snapshot is None:
        raise click.ClickException(f"No software snapshot at {path} yet; --refresh reads one.")
    age = snapshot_age(snapshot)
    emit(
        state,
        {
            "path": str(path),
            "instance": snapshot.instance,
            "taken_at": snapshot.taken_at,
            "age_hours": round(age.total_seconds() / 3600, 1),
            "fresh": age <= timedelta(hours=settings.snapshot_max_age_hours),
            "installs": snapshot.install_count,
            "software": len(snapshot.software),
            "devices": len(snapshot.devices),
        },
    )


@main.command("software-products")
@click.option("--vendor", help="Vendor name contains this.")
@brief_option
@pass_state
def software_products(state: State, vendor: str | None, brief: bool) -> None:
    """List the 3rd-party products NinjaOne can patch."""
    products = list_software_products(state.client)
    if vendor:
        products = [p for p in products if vendor.lower() in (p.vendor_name or "").lower()]
    show(state, brief, products)


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
@brief_option
@pass_state
def patches(
    state: State,
    org: str | None,
    kb_values: tuple[str, ...],
    status: str | None,
    installed: bool,
    since: date | None,
    df: str | None,
    brief: bool,
) -> None:
    """List OS patch records (outstanding, or install history with --installed).

    --brief: one row per patch and status with its device count.
    """
    query = scope(state, org, df)
    kbs = split_ids(kb_values) or None
    if installed:
        records = os_patch_installs(state.client, df=query, status=status, installed_after=since, kbs=kbs)
    else:
        records = os_patches(state.client, df=query, status=status, kbs=kbs)
    show(state, brief, records)


@main.command("software-patches")
@org_option
@click.option("--vendor", help="Vendor contains this.")
@click.option("--title", help="Patch title contains this.")
@click.option("--status", help="API status filter.")
@click.option("--installed", is_flag=True, help="Read the install history instead of outstanding patches.")
@since_option("With --installed: installs on or after this date, or 'all'.")
@df_option
@brief_option
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
    brief: bool,
) -> None:
    """List 3rd-party software patch records (--brief: device counts per patch and status)."""
    query = scope(state, org, df)
    if installed:
        records = software_patch_installs(
            state.client, df=query, status=status, installed_after=since, vendor=vendor, title=title
        )
    else:
        records = software_patches(state.client, df=query, status=status, vendor=vendor, title=title)
    show(state, brief, records)


@main.command()
@org_option
@click.option("--kb", "kb_values", multiple=True, help="Only these KB(s); repeatable or comma-separated.")
@click.option("--include-installed", is_flag=True, help="Also read install history and count installs.")
@since_option("With --include-installed: installs on or after this date, or 'all'.")
@df_option
@brief_option
@pass_state
def kbs(
    state: State,
    org: str | None,
    kb_values: tuple[str, ...],
    include_installed: bool,
    since: date | None,
    df: str | None,
    brief: bool,
) -> None:
    """List KBs with device counts per patch status - the input for KB -> CVE mapping.

    --brief: one row per KB with a count column per status, no device ids.
    """
    show(
        state,
        brief,
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
@brief_option
@pass_state
def vulnerabilities(state: State, org: str | None, show_all: bool, df: str | None, brief: bool) -> None:
    """Per-device vulnerability counts (critical/high/medium/low), worst first, with device names."""
    query = scope(state, org, df)
    counts = vulnerability_counts(
        state.client,
        df=query,
        only_vulnerable=not show_all,
        # device-health only has device ids; one device listing of the same scope names them.
        devices=list_devices(state.client, df=query),
    )
    show(state, brief, counts)


@main.command("scan-groups")
@click.argument("scan_group_id", type=int, required=False)
@brief_option
@pass_state
def scan_groups(state: State, scan_group_id: int | None, brief: bool) -> None:
    """List vulnerability scan groups, or show one."""
    if scan_group_id is None:
        show(state, brief, list_scan_groups(state.client))
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
