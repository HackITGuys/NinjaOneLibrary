from __future__ import annotations

import io

import responses
from click.testing import CliRunner

from NinjaOne import NinjaOneClient, list_organizations, list_software
from NinjaOne.cli import State, StderrProgress, main
from tests.conftest import get, get_query

ORGS = [{"id": 1, "name": "Contoso"}, {"id": 2, "name": "Fabrikam"}, {"id": 3, "name": "Northwind"}]


def register_orgs(api: responses.RequestsMock) -> None:
    get(api, "/organizations", ORGS[:2], {"pageSize": "2"})
    get(api, "/organizations", ORGS[2:], {"pageSize": "2", "after": "2"})
    get(api, "/organizations", [], {"pageSize": "2", "after": "3"})


def test_paging_reports_progress_only_when_asked(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    register_orgs(api)
    get_query(api, "/queries/software", [{"deviceId": i, "name": "7-Zip"} for i in range(1, 4)])
    list_organizations(client)  # no hook: nothing to report to

    seen: list[tuple[str, int, int | None]] = []
    client.progress = lambda label, done, total: seen.append((label, done, total))
    list_organizations(client)
    list_software(client)
    assert seen == [
        ("organizations", 2, None),  # `after` listings don't say how many there are
        ("organizations", 3, None),
        ("software", 2, 3),  # /queries/* do: cursor.count
        ("software", 3, 3),
    ]


def test_stderr_progress_line() -> None:
    stream = io.StringIO()
    progress = StderrProgress(stream)
    progress("devices-detailed", 1500, None)
    progress("devices-detailed", 2000, None)  # same label within 0.1s: skipped
    progress("software", 1, 120)  # a new label always shows
    progress("software", 120, 120)  # so does a final count
    assert stream.getvalue() == (
        "\r\x1b[Kdevices-detailed: 1,500 records...\r\x1b[Ksoftware: 1/120...\r\x1b[Ksoftware: 120/120..."
    )
    progress.clear()
    assert stream.getvalue().endswith("\r\x1b[K")
    progress.clear()  # nothing shown: nothing written
    assert stream.getvalue().count("\r\x1b[K") == 4


def test_cli_progress_on_request_only(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    register_orgs(api)
    quiet = CliRunner().invoke(main, ["organizations", "--brief"], obj=State(_client=client))
    assert quiet.exit_code == 0, quiet.output
    assert "records..." not in quiet.stderr  # not a terminal: off by default

    loud = CliRunner().invoke(main, ["--progress", "organizations", "--brief"], obj=State(_client=client))
    assert loud.exit_code == 0, loud.output
    assert "organizations: 2 records..." in loud.stderr  # the next update is within 0.1s: throttled
    assert loud.stderr.endswith("3 records\n")  # the line is cleared before the count
    assert loud.stdout.splitlines()[1].split() == ["1", "Contoso"]  # the table is unaffected
