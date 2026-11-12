from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import responses
from click.testing import CliRunner

from NinjaOne import NinjaOneClient
from NinjaOne.cli import State, main, split_ids
from tests.conftest import get, get_query, raw_device

ORGS = [{"id": 1, "name": "Contoso"}, {"id": 2, "name": "Fabrikam"}]


def run(client: NinjaOneClient, *args: str) -> Any:
    result = CliRunner().invoke(main, list(args), obj=State(_client=client))
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def register_orgs(api: responses.RequestsMock) -> None:
    get(api, "/organizations", ORGS, {"pageSize": "2"})
    get(api, "/organizations", [], {"pageSize": "2", "after": "2"})


def test_split_ids() -> None:
    assert split_ids(["KB1, KB2", "KB3 KB1"]) == ["KB1", "KB2", "KB3"]


def test_organizations(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    register_orgs(api)
    assert run(client, "organizations", "--name", "fab") == [
        {"id": 2, "name": "Fabrikam", "description": None, "node_approval_mode": None, "locations": None}
    ]


def test_devices_resolves_org_name_to_df(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    register_orgs(api)
    win11 = raw_device(2, os_name="Windows 11 Pro", tags=["Production"])
    get(api, "/devices-detailed", [raw_device(1), win11], {"df": "org in (1)", "pageSize": "2"})
    get(api, "/devices-detailed", [], {"df": "org in (1)", "pageSize": "2", "after": "2"})

    output = run(
        client, "--compact", "devices", "--org", "contoso", "--os", "windows 11", "--tag", "production"
    )
    assert [d["id"] for d in output] == [2]
    assert output[0]["organization_name"] == "Contoso"
    assert output[0]["os"]["name"] == "Windows 11 Pro"


def test_software_summary(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    rows = [
        {"deviceId": 1, "name": "7-Zip 23.01 (x64)", "publisher": "Igor Pavlov", "version": "23.01"},
        {"deviceId": 2, "name": "7-Zip 24.09 (x64)", "publisher": "Igor Pavlov", "version": "24.09"},
        {"deviceId": 3, "name": "Notepad++", "publisher": "Notepad++ Team", "version": "8.6"},
    ]
    get_query(api, "/queries/software", rows)
    output = run(client, "software", "--vendor", "igor", "--version", "<24.09", "--summary")
    assert output == [
        {
            "publisher": "Igor Pavlov",
            "name": "7-Zip 23.01 (x64)",
            "device_count": 1,
            "install_count": 1,
            "versions": {"23.01": 1},
        }
    ]


def test_kbs_and_output_file(client: NinjaOneClient, api: responses.RequestsMock, tmp_path: Path) -> None:
    get_query(
        api,
        "/queries/os-patches",
        [
            {"deviceId": 1, "kbNumber": "KB5031356", "status": "MANUAL"},
            {"deviceId": 2, "kbNumber": "KB1234567", "status": "FAILED"},
        ],
    )
    target = tmp_path / "out" / "kbs.json"
    result = CliRunner().invoke(
        main, ["-o", str(target), "kbs", "--kb", "5031356,KB5000000"], obj=State(_client=client)
    )
    assert result.exit_code == 0, result.output
    assert "Wrote 2 records" in result.stderr
    kbs = json.loads(target.read_text())
    assert [(k["kb"], k["counts"]) for k in kbs] == [("KB5000000", {}), ("KB5031356", {"pending": 1})]


def test_unknown_org_is_an_error(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    register_orgs(api)
    result = CliRunner().invoke(main, ["devices", "--org", "nope"], obj=State(_client=client))
    assert result.exit_code == 1
    assert "No NinjaOne organisation matches 'nope'" in result.stderr
    assert result.stdout == ""


def test_bad_since_is_a_usage_error(client: NinjaOneClient) -> None:
    result = CliRunner().invoke(main, ["kbs", "--since", "last week"], obj=State(_client=client))
    assert result.exit_code == 2
    assert "is not a date" in result.stderr
