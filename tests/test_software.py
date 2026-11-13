from __future__ import annotations

from datetime import date

import pytest
import responses

from NinjaOne import (
    Device,
    NinjaOneClient,
    SoftwareInstall,
    device_software,
    filter_software,
    list_software,
    summarise_software,
    text_equals,
    text_matches,
    version_matches,
)
from tests.conftest import get, get_query, raw_device


def install(
    device_id: int, name: str, version: str | None, publisher: str | None = "Igor Pavlov"
) -> SoftwareInstall:
    return SoftwareInstall(device_id=device_id, name=name, version=version, publisher=publisher)


def test_text_matches_substring_and_glob() -> None:
    assert text_matches("7-Zip 23.01 (x64)", "7-zip")
    assert text_matches("7-Zip 23.01 (x64)", "7-zip*x64)")
    assert not text_matches("7-Zip 23.01 (x64)", "zip*x86*")
    assert not text_matches(None, "zip")
    assert text_matches(None, None)


def test_text_equals_is_whole_value_or_glob() -> None:
    assert text_equals("7-Zip 23.01 (x64)", " 7-zip 23.01 (X64) ")
    assert not text_equals("7-Zip 23.01 (x64)", "7-zip")  # a part is not enough
    assert text_equals("7-Zip 23.01 (x64)", "7-zip*")
    assert not text_equals(None, "7-zip")
    assert text_equals(None, None)


@pytest.mark.parametrize(
    ("raw", "wanted", "expected"),
    [
        ("23.01", "<24.09", True),
        ("24.09", "<24.09", False),
        ("24.09 (x64)", ">=24.09", True),
        ("2.4.58", ">=2.4,<2.4.62", True),
        ("2.4.62", ">=2.4,<2.4.62", False),
        ("1:9.6p1-3ubuntu13", "<9.7", True),  # epoch skipped
        ("unknown", "<99", False),  # unparseable never matches a specifier
        (None, "<99", False),
        ("24.09", "24.*", True),
        ("23.01", "24.*", False),
        ("24.09", "24.09", True),
        ("24.09.1", "24.09", False),  # exact means exact
        ("anything", None, True),
    ],
)
def test_version_matches(raw: str | None, wanted: str | None, expected: bool) -> None:
    assert version_matches(raw, wanted) is expected


def test_bad_specifier_fails_up_front() -> None:
    with pytest.raises(ValueError, match="not a version specifier"):
        filter_software([], version="<<1")


def test_filter_software() -> None:
    installs = [
        install(1, "7-Zip 23.01 (x64)", "23.01"),
        install(2, "7-Zip 24.09 (x64)", "24.09"),
        install(3, "Notepad++", "8.6", publisher="Notepad++ Team"),
        SoftwareInstall(device_id=4, name="Microsoft Visual C++ 2015", is_system_component=True),
    ]
    assert [i.device_id for i in filter_software(installs, vendor="pavlov", version="<24.09")] == [1]
    assert [i.device_id for i in filter_software(installs, name="7-zip")] == [1, 2]
    assert len(filter_software(installs, include_system_components=False)) == 3
    assert filter_software(installs, vendor="pavlov", exact=True) == []
    exact = filter_software(installs, vendor="igor pavlov", name="7-Zip 24.09 (x64)", exact=True)
    assert [i.device_id for i in exact] == [2]


def test_list_software_sends_dates_and_attaches_devices(
    client: NinjaOneClient, api: responses.RequestsMock
) -> None:
    rows = [
        {"deviceId": 1, "name": "7-Zip 23.01 (x64)", "publisher": "Igor Pavlov", "version": "23.01"},
        {"deviceId": 2, "name": "Notepad++", "publisher": "Notepad++ Team", "version": "8.6"},
    ]
    get_query(api, "/queries/software", rows, {"df": "org in (1)", "installedAfter": "2026-01-01"})
    found = list_software(
        client,
        vendor="Igor",
        df="org in (1)",
        installed_after=date(2026, 1, 1),
        devices=[Device.model_validate(raw_device(1))],
    )
    assert len(found) == 1
    assert (found[0].device_name, found[0].organization_name) == ("HOST1", "Contoso")


def test_device_software_sets_the_device_id(client: NinjaOneClient, api: responses.RequestsMock) -> None:
    get(api, "/device/9/software", [{"name": "Firefox", "version": "140.0"}])
    [found] = device_software(client, 9)
    assert (found.device_id, found.name) == (9, "Firefox")


def test_summarise_software() -> None:
    installs = [
        install(1, "7-Zip", "23.01"),
        install(2, "7-Zip", "24.09"),
        install(3, "7-Zip", "24.09"),
        install(3, "7-Zip", "9.20"),  # two versions on one device
        install(4, "Notepad++", None, publisher="Notepad++ Team"),
    ]
    first, second = summarise_software(installs)
    assert (first.name, first.device_count, first.install_count) == ("7-Zip", 3, 4)
    assert list(first.versions.items()) == [("24.09", 2), ("23.01", 1), ("9.20", 1)]  # newest first
    assert (second.name, second.versions) == ("Notepad++", {"": 1})
