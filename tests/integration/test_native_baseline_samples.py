"""Baseline comparison and observed profiles on this project's native samples (#35).

The samples are gitignored run outputs (data/modified_samples) and are absent in CI, so every
test skips without them. Point ZIP_PROV_NATIVE_SAMPLES at a directory holding the runs, e.g. the
extracted evidence bundles of PH4-PROV-002, to run them.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from zip_fingerprint.baseline import compare_archives
from zip_fingerprint.models import ZipArchiveRecord
from zip_fingerprint.observed_rules import get_observed_rules
from zip_fingerprint.parser import ZipBinaryParser
from zip_fingerprint.provenance import ProvenanceTracker
from zip_fingerprint.rules import get_all_rules

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = Path(os.environ.get("ZIP_PROV_NATIVE_SAMPLES", ROOT / "data" / "modified_samples"))
SW2_RUNS = ["run-sw2-_kiollnq", "run-sw2-gtjtd6ue"]
SIMULATOR_RUNS = ["run-0fjyoqhr", "run-qeaq7kx8"]
EXPLORER_RUN = "run-case2-dlq9ulnc"


def _metadata(run: str) -> Dict[str, Any]:
    path = SAMPLES / run / "metadata.json"
    if not path.is_file():
        pytest.skip(f"Native sample run not available: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _parse(path: Path) -> ZipArchiveRecord:
    with ZipBinaryParser(path) as parser:
        return parser.parse()


def _sw2_cells() -> List[Dict[str, Any]]:
    cells = []
    for run in SW2_RUNS:
        for cell in _metadata(run)["cells"]:
            if cell["status"] == "generated":
                cell = dict(cell, run=run, directory=SAMPLES / run / cell["id"])
                cells.append(cell)
    return cells


def _case1(path: Path, observed: bool) -> bool:
    rules = get_all_rules() + get_observed_rules() if observed else None
    return ProvenanceTracker(_parse(path), rules=rules).analyze().case1_detected


def _compare(directory: Path):
    return compare_archives(_parse(directory / "before.zip"), _parse(directory / "after.zip"))


def test_s6_runs_are_baseline_all():
    s6 = [cell for cell in _sw2_cells() if cell["id"] == "S6"]
    assert len(s6) == 2
    for cell in s6:
        result = _compare(cell["directory"])
        assert result.rewrite_scope == "all", cell["run"]
        assert result.case2_detected is True


def test_bandizip_sw1_cells_are_baseline_none():
    cells = [cell for cell in _sw2_cells() if cell["id"] in {"S1", "S2", "S3", "S4", "S5"}]
    assert len(cells) == 5
    for cell in cells:
        assert _compare(cell["directory"]).rewrite_scope == "none", cell["id"]


def test_baseline_scope_matches_preregistered_comparator():
    for cell in _sw2_cells():
        expected = cell["comparison"]["rewrite_scope"]
        assert _compare(cell["directory"]).rewrite_scope == expected, (cell["run"], cell["id"])


def test_explorer_delete_run_is_baseline_none():
    metadata = _metadata(EXPLORER_RUN)
    assert metadata["comparison"]["rewrite_scope"] == "none"
    assert _compare(SAMPLES / EXPLORER_RUN).rewrite_scope == "none"


def test_observed_profiles_fix_s6_without_new_misses():
    for cell in _sw2_cells():
        after = cell["directory"] / "after.zip"
        before = cell["directory"] / "before.zip"
        if cell["id"] == "S6":
            assert _case1(after, observed=False) is True
            assert _case1(after, observed=True) is False
        if cell["id"] in {"S3", "S4", "S5"}:
            assert _case1(after, observed=True) is True, cell["id"]
        assert _case1(before, observed=False) is False, cell["id"]
        assert _case1(before, observed=True) is False, cell["id"]


def test_recorded_native_case1_stays_detected_with_observed_profiles():
    checked = 0
    for run in SIMULATOR_RUNS:
        for scenario in _metadata(run)["scenarios"]:
            if scenario.get("status") != "generated":
                continue
            recorded = scenario["after"]["analysis"]["cases"]["case1_mixed_fingerprints"]
            after = SAMPLES / run / scenario["after"]["path"]
            assert _case1(after, observed=False) is recorded, (run, scenario["id"])
            if recorded:
                checked += 1
                assert _case1(after, observed=True) is True, (run, scenario["id"])
    assert checked > 0
