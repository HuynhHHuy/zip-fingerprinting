"""Contracts for the pre-registered SW2 screening; generated ZIPs here are not evidence."""

import json
import os
from pathlib import Path
import shutil
import sys
import zipfile

import pytest

from experiments import sw2_screening as screening

ROOT = Path(__file__).resolve().parents[2]
ADDED = b"added payload\n"


def test_cells_match_preregistration():
    # docs/research/sw2-screening-preregistration.md, commit 8c4975d
    assert screening.CELLS == {
        "S1": ("bandizip", "7zip", "delete"),
        "S2": ("bandizip", "winrar", "delete"),
        "S3": ("bandizip", "powershell5", "add"),
        "S4": ("bandizip", "pwsh7", "add"),
        "S5": ("bandizip", "shell", "add"),
        "S6": ("7zip", "bandizip", "delete"),
    }


def test_sw2_commands_match_preregistration(tmp_path):
    archive, added = tmp_path / "after.zip", tmp_path / "add" / "added.txt"
    exe = Path("C:/tools/x.exe")
    assert screening.sw2_command("7zip", exe, archive, added)[0] == [
        str(exe),
        "d",
        "-tzip",
        str(archive),
        "target.txt",
    ]
    assert screening.sw2_command("winrar", exe, archive, added)[0] == [
        str(exe),
        "d",
        "-ibck",
        "-inul",
        "-y",
        str(archive),
        "target.txt",
    ]
    assert screening.sw2_command("bandizip", exe, archive, added)[0] == [
        str(exe),
        "d",
        "-y",
        str(archive),
        "target.txt",
    ]
    for tool in ("powershell5", "pwsh7"):
        argv, env = screening.sw2_command(tool, exe, archive, added)
        assert argv[0] == str(exe)
        assert "Compress-Archive -LiteralPath $env:ZIP_PROV_ADD" in argv[-1]
        assert "-DestinationPath $env:ZIP_PROV_ARCHIVE -Update" in argv[-1]
        assert env == {"ZIP_PROV_ADD": str(added), "ZIP_PROV_ARCHIVE": str(archive)}
    argv, env = screening.sw2_command("shell", exe, archive, added)
    assert str(ROOT / "scripts" / "add_zip_entry_shell.ps1") in argv
    assert argv[argv.index("-Archive") + 1] == str(archive)
    assert argv[argv.index("-File") + 1].endswith("add_zip_entry_shell.ps1")
    assert argv[argv.index("-Source") + 1] == str(added)
    assert env == {}


def test_missing_tools_are_skipped_and_runs_do_not_overwrite(tmp_path):
    first = screening.screen(tmp_path, {}, list(screening.CELLS))
    second = screening.screen(tmp_path, {}, ["S1"])
    assert first["run_directory"] != second["run_directory"]
    assert [cell["status"] for cell in first["cells"]] == ["skipped"] * 6
    assert "bandizip" in first["cells"][0]["reason"]
    saved = json.loads((Path(first["run_directory"]) / "metadata.json").read_text("utf-8"))
    assert saved == first
    assert (Path(first["run_directory"]) / "report.md").is_file()
    assert screening.exit_code(first, require_case2=False) == 2


def test_unknown_cells_are_refused(tmp_path):
    with pytest.raises(ValueError, match="Unknown cells"):
        screening.screen(tmp_path, {}, ["S7"])


def test_failed_native_command_is_retained(tmp_path):
    # A real process that cannot act as an archiver, without mocking subprocess.
    tools = {"bandizip": Path(sys.executable), "7zip": Path(sys.executable)}
    report = screening.screen(tmp_path, tools, ["S1"])
    cell = report["cells"][0]
    assert cell["status"] == "failed"
    assert cell["commands"][0]["returncode"] != 0
    assert "comparison" not in cell
    saved = json.loads((Path(report["run_directory"]) / "metadata.json").read_text("utf-8"))
    assert saved["cells"][0]["status"] == "failed"
    assert screening.exit_code(report, require_case2=False) == 1


def test_confirmation_runs_exactly_one_cell(tmp_path):
    report = screening.screen(tmp_path, {}, ["S3"], confirmation_of="S3")
    assert report["confirmation_of"] == "S3"
    with pytest.raises(ValueError, match="one cell"):
        screening.screen(tmp_path, {}, ["S3", "S4"], confirmation_of="S3")


@pytest.mark.parametrize(
    ("scopes", "require", "code"),
    [
        (["none", "partial"], False, 0),
        (["none", "partial"], True, 2),
        (["none", "all"], True, 0),
    ],
)
def test_exit_code_follows_scopes(scopes, require, code):
    report = {
        "cells": [
            {"status": "generated", "comparison": {"rewrite_scope": scope}} for scope in scopes
        ]
    }
    assert screening.exit_code(report, require_case2=require) == code


def test_cli_without_bandizip_skips_bandizip_cells(tmp_path):
    code = screening.main(["run", "--output", str(tmp_path), "--cell", "S1"])
    assert code == 2
    (run,) = tmp_path.iterdir()
    saved = json.loads((run / "metadata.json").read_text("utf-8"))
    assert saved["cells"][0]["status"] == "skipped"


def _native_tools():
    tools = screening.discover_tools(None)
    if "7zip" not in tools:
        pytest.skip("Requires installed Windows 7-Zip")
    return tools


@pytest.mark.parametrize("sw2", ["7zip", "powershell5", "shell"])
def test_native_pair_preserves_payloads(tmp_path, sw2):
    tools = _native_tools()
    if sw2 not in tools:
        pytest.skip(f"Requires {sw2}")
    operation = "delete" if sw2 == "7zip" else "add"
    work = tmp_path / "pair"
    cell = screening.run_cell(work, "7zip", sw2, operation, tools)
    assert cell["status"] == "generated", cell.get("reason")
    assert cell["comparison"]["payload_validation"] is True
    with zipfile.ZipFile(work / "after.zip") as archive:
        names = set(archive.namelist())
        assert ("target.txt" in names) is (operation == "add")
        if operation == "add":
            assert archive.read("added.txt") == ADDED
    assert screening.sha256(work / "before.zip") == cell["before"]["sha256"]
    assert {"tracker_before", "tracker_after"} <= cell.keys()


def test_tool_inventory_records_hash_and_signature(tmp_path):
    exe = tmp_path / "tool.exe"
    shutil.copyfile(sys.executable, exe)
    row = screening.describe_tool(exe)
    assert row["sha256"] == screening.sha256(exe)
    assert row["path"] == str(exe)
    if os.name == "nt":
        assert row["signature"]
