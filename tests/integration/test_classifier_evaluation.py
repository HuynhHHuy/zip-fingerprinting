"""PH7-EVAL-002: evaluator contracts with independently hand-computed expectations.

The predictor is stubbed so that metric arithmetic, denominators and exclusion
rules are verified independently of the heuristic rule catalogue. These are
synthetic tests of the evaluator, NOT a scientific acceptance result.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "experiments/evaluate_classifier.py"
spec = importlib.util.spec_from_file_location("evaluate_classifier", SCRIPT)
ev = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ev  # dataclasses resolve string annotations via sys.modules
spec.loader.exec_module(ev)


def cand(os_name, app, confidence=1.0, tier="HIGH"):
    return {
        "target_os": os_name,
        "application": app,
        "confidence": confidence,
        "weight_tier": tier,
        "matched_rules": [],
        "notes": [],
    }


def sample(data_dir, run_id, name, tool_id, payload=None, status="generated", sha=None, path=None):
    record = {"sample_id": f"{run_id}_{name}", "tool_id": tool_id, "variant": "root"}
    record["status"] = status
    record["tool"] = {"application": tool_id, "version": "1.0"}
    if status != "generated":
        return record
    rel = path or f"ground_truth/{run_id}/{name}/sample.zip"
    if payload is not None:
        target = data_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        record["size_bytes"] = len(payload)
    record["path"] = rel
    record["sha256"] = sha or hashlib.sha256(payload or b"absent").hexdigest()
    return record


def write_catalogue(data_dir, runs):
    path = data_dir / "metadata.json"
    path.write_text(json.dumps({"schema_version": 1, "runs": runs}), encoding="utf-8")
    return path


def run(run_id, samples, host="Windows"):
    return {"run_id": run_id, "environment": {"os": host}, "samples": samples}


def stub(mapping):
    def predictor(data):
        value = mapping[data]
        if isinstance(value, Exception):
            raise value
        return value

    return predictor


@pytest.fixture
def scenario(tmp_path):
    """Ten catalogue samples covering every outcome; expectations computed by hand."""
    d = tmp_path
    run_a = [
        sample(d, "run-a", "correct", "7zip", b"A"),
        sample(d, "run-a", "wrong", "winrar", b"B"),
        sample(d, "run-a", "unknown", "bandizip", b"C"),
        sample(d, "run-a", "tie", "winrar", b"D"),
        sample(d, "run-a", "badsum", "7zip", b"E", sha="0" * 64),
        sample(d, "run-a", "missing", "7zip", None, sha="1" * 64),
        sample(d, "run-a", "skipped", "bandizip", status="skipped"),
        sample(d, "run-a", "powershell", "powershell", b"F"),
        sample(d, "run-a", "error", "7zip", b"G"),
    ]
    run_b = [sample(d, "run-b", "dup", "7zip", b"A")]
    catalogue_path = write_catalogue(d, [run("run-a", run_a), run("run-b", run_b)])
    predictor = stub(
        {
            b"A": [cand("Windows", "7-Zip")],
            b"B": [cand("Windows", "7-Zip")],
            b"C": [],
            # WinRAR listed first on purpose: a tie must never pick the first element.
            b"D": [
                cand("Windows", "WinRAR", 0.7, "SUBSIDIARY"),
                cand("Windows", "7-Zip", 0.7, "SUBSIDIARY"),
                cand("Windows", "WinZip", 0.3, "SUBSIDIARY"),
            ],
            b"F": [cand("Windows", "Compressed folder")],
            b"G": RuntimeError("parser exploded"),
        }
    )
    catalogue = ev.load_catalogue(catalogue_path)
    results = ev.evaluate_samples(catalogue, d, predictor)
    return {r.sample_id.split("_", 1)[1]: r for r in results}, results, catalogue_path, d


def test_per_sample_outcomes(scenario):
    rows, _, _, _ = scenario
    assert rows["correct"].outcome == "correct"
    assert rows["wrong"].outcome == "wrong" and rows["wrong"].predicted == "Windows/7-Zip"
    assert rows["unknown"].outcome == ev.UNKNOWN and rows["unknown"].predicted is None
    assert rows["error"].outcome == ev.ERROR and "parser exploded" in rows["error"].error
    assert rows["dup"].outcome == "correct"


def test_tie_is_ambiguous_not_first_candidate(scenario):
    tie = scenario[0]["tie"]
    assert tie.outcome == ev.AMBIGUOUS
    assert tie.predicted is None
    assert sorted(tie.top_candidates) == ["Windows/7-Zip", "Windows/WinRAR"]
    assert tie.truth_in_candidates is True
    assert tie.os_outcome == "correct"  # both tied candidates share Windows
    assert len(tie.candidates) == 3  # every candidate and score is kept


@pytest.mark.parametrize(
    "name, reason",
    [
        ("badsum", "checksum_mismatch"),
        ("missing", "missing_artifact"),
        ("skipped", "status_skipped"),
    ],
)
def test_exclusions_are_recorded(scenario, name, reason):
    row = scenario[0][name]
    assert row.included is False
    assert row.exclusion_reason == reason
    assert row.outcome is None and row.denominators == []


def test_powershell_is_out_of_catalog_not_compressed_folder(scenario):
    row = scenario[0]["powershell"]
    assert row.truth.in_catalog is False
    assert row.truth.application == "powershell"  # fixture records the adapter id verbatim
    assert row.truth.label is None
    assert row.outcome == "false_attribution"
    assert "out_of_catalog" in row.denominators and "tool_accuracy" not in row.denominators


def test_truth_never_comes_from_prediction(scenario):
    for row in scenario[1]:
        if row.included and row.truth.in_catalog:
            assert row.truth.source == "invocation_provenance"
            assert row.truth.label == f"Windows/{ev.TOOL_LABELS[row.tool_id]}"


def test_raw_metrics_match_hand_computed(scenario):
    _, results, _, _ = scenario
    labels = ev.catalog_labels()
    m = ev.classification_metrics(results, labels)
    # In-catalog included: correct, wrong, unknown, tie, error, dup = 6; correct = 2.
    assert m["tool_accuracy"] == {"numerator": 2, "denominator": 6, "value": round(2 / 6, 6)}
    assert m["windows_tool_accuracy"]["numerator"] == 2
    assert m["windows_tool_accuracy"]["denominator"] == 6
    assert m["outcomes"] == {"correct": 2, "wrong": 1, "UNKNOWN": 1, "AMBIGUOUS": 1, "ERROR": 1}
    seven = m["per_class"]["Windows/7-Zip"]
    assert (seven["precision"]["numerator"], seven["precision"]["denominator"]) == (2, 3)
    assert (seven["recall"]["numerator"], seven["recall"]["denominator"]) == (2, 3)
    winrar = m["per_class"]["Windows/WinRAR"]
    assert (winrar["recall"]["numerator"], winrar["recall"]["denominator"]) == (0, 2)
    folder = m["per_class"]["Windows/Compressed folder"]
    assert folder["precision"]["value"] is None
    assert folder["precision_with_out_of_catalog"] == {
        "numerator": 0,
        "denominator": 1,
        "value": 0.0,
    }
    matrix = m["confusion_matrix"]["matrix"]
    assert matrix["Windows/7-Zip"]["Windows/7-Zip"] == 2
    assert matrix["Windows/7-Zip"]["ERROR"] == 1
    assert matrix["Windows/WinRAR"]["Windows/7-Zip"] == 1
    assert matrix["Windows/WinRAR"]["AMBIGUOUS"] == 1
    assert matrix["Windows/Bandizip"]["UNKNOWN"] == 1
    assert sum(sum(row.values()) for row in matrix.values()) == 6

    os_m = ev.os_metrics(results)
    # OS scope: 6 in-catalog + PowerShell = 7; correct: correct, wrong, tie, powershell, dup.
    assert (os_m["os_accuracy"]["numerator"], os_m["os_accuracy"]["denominator"]) == (5, 7)
    cov = ev.candidate_coverage(results)
    assert (cov["numerator"], cov["denominator"]) == (3, 6)


def test_unique_sha_set_counts_duplicates_once(scenario):
    _, results, _, _ = scenario
    unique, conflicts = ev.dedupe_by_sha(results)
    assert conflicts == []
    assert len(unique) == 6
    m = ev.classification_metrics(unique, ev.catalog_labels())
    assert (m["tool_accuracy"]["numerator"], m["tool_accuracy"]["denominator"]) == (1, 5)
    counts = ev.counts_report(results, unique)
    assert counts["catalogue_samples"] == 10
    assert counts["included"] == 7 and counts["excluded"] == 3
    assert counts["unique_sha256"] == 6
    assert counts["sha256_seen_in_multiple_runs"] == 1
    assert counts["exclusion_reasons"] == {
        "checksum_mismatch": 1,
        "missing_artifact": 1,
        "status_skipped": 1,
    }


def test_conflicting_truth_for_same_sha_is_excluded_from_unique(tmp_path):
    runs = [
        run("run-a", [sample(tmp_path, "run-a", "x", "7zip", b"Z")]),
        run("run-b", [sample(tmp_path, "run-b", "y", "winrar", b"Z")]),
    ]
    catalogue = ev.load_catalogue(write_catalogue(tmp_path, runs))
    results = ev.evaluate_samples(catalogue, tmp_path, stub({b"Z": []}))
    unique, conflicts = ev.dedupe_by_sha(results)
    assert unique == []
    assert len(conflicts) == 1 and len(conflicts[0]["sample_ids"]) == 2


def test_thresholds_not_met_are_reported(scenario):
    _, results, catalogue_path, data_dir = scenario
    report = ev.build_report(results, catalogue_path, data_dir, ["test"])
    thresholds = report["thresholds"]
    # Unique set: OS 4/6 (dup removed), Windows tool 1/5.
    assert thresholds["os_accuracy"]["observed"]["numerator"] == 4
    assert thresholds["os_accuracy"]["observed"]["denominator"] == 6
    assert thresholds["os_accuracy"]["status"] == "not_met"
    assert thresholds["windows_tool_accuracy"]["status"] == "not_met"
    assert report["metrics"]["raw"]["out_of_catalog"]["samples"] == 1
    assert len(report["samples"]) == 10
    json.dumps(report)  # serialisable


def test_perfect_but_incomplete_coverage_is_not_met(tmp_path):
    runs = [run("run-a", [sample(tmp_path, "run-a", "x", "7zip", b"A")])]
    catalogue_path = write_catalogue(tmp_path, runs)
    results = ev.evaluate_samples(
        ev.load_catalogue(catalogue_path), tmp_path, stub({b"A": [cand("Windows", "7-Zip")]})
    )
    report = ev.build_report(results, catalogue_path, tmp_path, ["test"])
    for key in ("os_accuracy", "windows_tool_accuracy"):
        assert report["thresholds"][key]["observed"]["value"] == 1.0
        assert report["thresholds"][key]["status"] == "insufficient_coverage"
    assert "macOS" in report["thresholds"]["os_accuracy"]["missing"]
    assert "Windows/WinZip" in report["thresholds"]["windows_tool_accuracy"]["missing"]


def test_no_data_threshold(tmp_path):
    report = ev.build_report([], tmp_path / "metadata.json", tmp_path, ["test"])
    assert report["thresholds"]["os_accuracy"]["status"] == "no_data"


@pytest.mark.parametrize("bad", ["../outside.zip", "/abs/sample.zip", "C:/x/sample.zip", ""])
def test_unsafe_catalogue_paths_are_refused(tmp_path, bad):
    (tmp_path.parent / "outside.zip").write_bytes(b"A")
    record = {
        "sample_id": "s",
        "tool_id": "7zip",
        "status": "generated",
        "path": bad,
        "sha256": hashlib.sha256(b"A").hexdigest(),
    }
    data, reason = ev.verify_artifact(tmp_path, record)
    assert data is None and reason in {"unsafe_path", "missing_path"}


def test_size_mismatch_is_excluded(tmp_path):
    record = sample(tmp_path, "run-a", "x", "7zip", b"A")
    record["size_bytes"] = 99
    assert ev.verify_artifact(tmp_path, record) == (None, "size_mismatch")


def test_linux_host_is_not_relabelled_ubuntu(tmp_path):
    runs = [run("run-a", [sample(tmp_path, "run-a", "x", "7zip", b"A")], host="Linux")]
    results = ev.evaluate_samples(
        ev.load_catalogue(write_catalogue(tmp_path, runs)),
        tmp_path,
        stub({b"A": [cand("Ubuntu", "7-Zip")]}),
    )
    row = results[0]
    assert row.truth.os is None and row.truth.in_catalog is False
    assert row.os_outcome == "truth_os_unmapped"


def test_catalogue_schema_validation(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_text("{}", encoding="utf-8")
    assert ev.load_catalogue(path) == {"schema_version": 1, "runs": []}
    path.write_text('{"schema_version": 2, "runs": []}', encoding="utf-8")
    with pytest.raises(ev.CatalogueError):
        ev.load_catalogue(path)
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ev.CatalogueError):
        ev.load_catalogue(path)


def test_run_filter(scenario):
    _, _, catalogue_path, data_dir = scenario
    catalogue = ev.load_catalogue(catalogue_path)
    results = ev.evaluate_samples(
        catalogue, data_dir, stub({b"A": [cand("Windows", "7-Zip")]}), run_ids=["run-b"]
    )
    assert [r.run_id for r in results] == ["run-b"]


def test_default_predictor_and_main_end_to_end(tmp_path):
    """Real parser/extractor/classifier on a zipfile-built archive (synthetic, not native)."""
    archive = tmp_path / "ground_truth/run-x/7zip-root/sample.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("set1/a.txt", b"payload")
    payload = archive.read_bytes()
    candidates = ev.default_predictor(payload)
    assert isinstance(candidates, list)
    assert all({"target_os", "application", "confidence"} <= set(c) for c in candidates)

    record = {
        "sample_id": "run-x_7zip_root",
        "tool_id": "7zip",
        "variant": "root",
        "status": "generated",
        "path": "ground_truth/run-x/7zip-root/sample.zip",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
        "tool": {"application": "7-Zip", "version": "test"},
    }
    write_catalogue(tmp_path, [run("run-x", [record])])
    output = tmp_path / "out/report.json"
    code = ev.main(["--data-dir", str(tmp_path), "--output", str(output)])
    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["counts"]["included"] == 1
    assert report["samples"][0]["outcome"] in {"correct", "wrong", "UNKNOWN", "AMBIGUOUS", "ERROR"}
    assert report["reproduction"]["catalogue_sha256"]


def test_main_exit_codes(tmp_path):
    (tmp_path / "metadata.json").write_text("broken", encoding="utf-8")
    assert ev.main(["--data-dir", str(tmp_path), "--output", str(tmp_path / "r.json")]) == 1
    write_catalogue(tmp_path, [])
    assert ev.main(["--data-dir", str(tmp_path), "--output", str(tmp_path / "r.json")]) == 2
