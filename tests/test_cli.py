from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import responses
from click.testing import CliRunner

from NinjaOne import NinjaOneClient, load_software_snapshot, save_software_snapshot, snapshot_path
from NinjaOne.cli import State, main, split_ids
from tests.conftest import get, get_query, raw_device
from tests.test_snapshot import make_snapshot, register_inventory

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


def brief_run(client: NinjaOneClient, *args: str) -> tuple[list[str], str]:
    """stdout lines (the table) and stderr of a successful run."""
    result = CliRunner().invoke(main, list(args), obj=State(_client=client))
    assert result.exit_code == 0, result.output
    return result.stdout.splitlines(), result.stderr


def test_devices_brief_is_a_table(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    devices = [raw_device(1, name="SRV-SQL01", tags=["Production", "DMZ"]), raw_device(2, name="WS-0042")]
    get(api, "/devices-detailed", devices, {"pageSize": "2"})
    get(api, "/devices-detailed", [], {"pageSize": "2", "after": "2"})
    lines, stderr = brief_run(client, "devices", "--brief")
    assert lines[0].split() == [
        "ID", "NAME", "ORGANIZATION", "LOCATION", "ROLE", "OS", "STATE", "TAGS", "LAST_CONTACT"
    ]  # fmt: skip
    assert lines[1].startswith(" 1  SRV-SQL01  Contoso")
    assert "Production, DMZ" in lines[1]
    assert len(lines) == 3
    assert stderr == "2 records\n"


def test_software_brief_counts_devices_per_version(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    rows = [
        {"deviceId": 1, "name": "7-Zip", "publisher": "Igor Pavlov", "version": "23.01"},
        {"deviceId": 2, "name": "7-Zip", "publisher": "Igor Pavlov", "version": "23.01"},
        {"deviceId": 3, "name": "7-Zip", "publisher": "Igor Pavlov", "version": "24.09"},
    ]
    get_query(api, "/queries/software", rows)
    # No /devices-detailed is registered: --brief must not fetch device names.
    lines, stderr = brief_run(client, "software", "--vendor", "igor", "--brief")
    assert [line.split() for line in lines] == [
        ["PUBLISHER", "NAME", "VERSION", "DEVICES"],
        ["Igor", "Pavlov", "7-Zip", "24.09", "1"],
        ["Igor", "Pavlov", "7-Zip", "23.01", "2"],
    ]
    assert stderr == "2 rows from 3 records\n"


def test_kbs_brief_has_counts_and_json_and_file_output(
    client: NinjaOneClient, api: responses.RequestsMock, tmp_path: Path
) -> None:
    get_query(
        api,
        "/queries/os-patches",
        [
            {"deviceId": 1, "kbNumber": "KB5031356", "status": "MANUAL"},
            {"deviceId": 2, "kbNumber": "KB5031356", "status": "MANUAL"},
            {"deviceId": 3, "kbNumber": "KB5031356", "status": "FAILED"},
        ],
    )
    expected = {
        "kb": "KB5031356",
        "name": None,
        "severity": None,
        "released": None,
        "devices": 3,
        "pending": 2,
        "failed": 1,
    }
    lines, _ = brief_run(client, "kbs", "--brief")
    assert [line.split() for line in lines] == [
        ["KB", "NAME", "SEVERITY", "RELEASED", "DEVICES", "PENDING", "FAILED"],
        ["KB5031356", "3", "2", "1"],
    ]
    assert run(client, "--json", "kbs", "--brief") == [expected]

    target = tmp_path / "kbs.json"
    _, stderr = brief_run(client, "-o", str(target), "kbs", "--brief")
    assert json.loads(target.read_text()) == [expected]
    assert stderr == f"Wrote 1 record to {target}\n"


def test_vulnerabilities_carry_device_names(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get_query(api, "/queries/device-health", [{"deviceId": 1, "criticalVulnerabilityCount": 2}])
    get(api, "/devices-detailed", [raw_device(1, name="SRV-SQL01")], {"pageSize": "2"})
    get(api, "/devices-detailed", [], {"pageSize": "2", "after": "1"})
    [entry] = run(client, "vulnerabilities")
    assert (entry["device_name"], entry["organization_name"]) == ("SRV-SQL01", "Contoso")
    lines, _ = brief_run(client, "vulnerabilities", "--brief")
    assert lines[1].split() == ["SRV-SQL01", "Contoso", "2", "0", "0", "0", "2"]


def test_software_catalog_from_the_saved_snapshot(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    save_software_snapshot(make_snapshot(), snapshot_path(client.settings))
    lines, stderr = brief_run(client, "software-catalog", "--publisher", "igor pavlov", "--brief")
    assert [line.split() for line in lines] == [
        ["PUBLISHER", "NAME", "VERSION", "DEVICES"],
        ["Igor", "Pavlov", "7-Zip", "23.01", "(x64)", "23.01", "3"],
        ["Igor", "Pavlov", "7-Zip", "24.09", "(x64)", "24.09", "1"],
    ]
    assert "Software snapshot from" in stderr and "--refresh reads the inventory again" in stderr
    assert not [call for call in api.calls if call.request.method == "GET"]  # answered offline


def test_software_catalog_reads_the_inventory_once(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    register_inventory(api)
    result = CliRunner().invoke(
        main, ["software-catalog", "--name", "7-Zip 24.09 (x64)"], obj=State(_client=client)
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == [
        {"publisher": "Igor Pavlov", "name": "7-Zip 24.09 (x64)", "version": "24.09", "device_count": 1}
    ]
    assert "Reading the whole software inventory" in result.stderr
    assert "Saved the snapshot: 6 installs of 4 distinct software on 3 devices." in result.stderr
    assert load_software_snapshot(snapshot_path(client.settings)) is not None


def test_software_devices(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    register_orgs(api)
    save_software_snapshot(make_snapshot(), snapshot_path(client.settings))
    args = [
        "software-devices",
        "--publisher",
        "Igor Pavlov",
        "--name",
        "7-Zip 23.01 (x64)",
        "--version",
        "23.01",
    ]
    rows = run(client, *args, "--org", "Fabrikam")
    assert [(r["device_id"], r["device_name"], r["organization_name"]) for r in rows] == [
        (2, "WS-0042", "Fabrikam")
    ]
    lines, _ = brief_run(client, *args, "--brief")
    assert lines[0].split() == ["ID", "DEVICE", "ORGANIZATION", "PUBLISHER", "NAME", "VERSION"]
    assert len(lines) == 4

    missing = CliRunner().invoke(main, ["software-devices", "--version", "1.0"], obj=State(_client=client))
    assert missing.exit_code == 2 and "Give --publisher and/or --name" in missing.stderr


def test_software_snapshot_status(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    none_yet = CliRunner().invoke(main, ["software-snapshot"], obj=State(_client=client))
    assert none_yet.exit_code == 1 and "--refresh reads one" in none_yet.stderr

    register_inventory(api)
    status = run(client, "software-snapshot", "--refresh")
    assert (status["installs"], status["software"], status["devices"], status["fresh"]) == (6, 4, 3, True)
    assert status["path"] == str(snapshot_path(client.settings))
