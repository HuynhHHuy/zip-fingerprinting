"""PH7-EVAL-002: evaluate the classifier against provenance-labelled native ZIP samples.

Ground truth is taken only from the schema-v1 catalogue written by
``scripts/generate_ground_truth.py`` (invocation provenance: host OS + archiver
adapter). Predictions never feed back into labels. Heuristic SUBSIDIARY scores
are not calibrated probabilities, and a small self-generated corpus is neither
blind nor statistically representative.

The author reference samples (PH0-REF-002, ``data/reference/author_pkzip``) are
evaluated as a separate set under ``reference_sets.author_pkzip``. Their labels
are declared by the paper's authors through file names, not invocation
provenance, so the two sets are never pooled.

Usage::

    python experiments/evaluate_classifier.py
    python experiments/evaluate_classifier.py --predictor cli
    python experiments/evaluate_classifier.py --data-dir C:/Temp/zip-data --run run-abc
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from zip_fingerprint.classifier import AutomatedClassifier  # noqa: E402
from zip_fingerprint.extractor import StructuralFeatureExtractor  # noqa: E402
from zip_fingerprint.parser import ZipBinaryParser  # noqa: E402
from zip_fingerprint.rules import get_all_rules  # noqa: E402

REPORT_SCHEMA_VERSION = 1
DEFAULT_OUTPUT = ROOT / "results/benchmarks/reproduction_evaluation.json"

# Host OS as recorded by platform.system() -> catalogue OS label. "Linux" is
# deliberately absent: the catalogue rules are for Ubuntu and the evaluator
# must not infer a distribution that the provenance did not record.
OS_LABELS = {"Windows": "Windows", "Darwin": "macOS"}

# Generator adapter id -> catalogue application label. ``powershell`` is
# deliberately absent: PowerShell Compress-Archive is NOT Explorer/"Compressed
# folder" and stays out-of-catalog.
TOOL_LABELS = {"7zip": "7-Zip", "winrar": "WinRAR", "bandizip": "Bandizip"}

THRESHOLDS = {"os_accuracy": 1.0, "windows_tool_accuracy": 0.90}

UNKNOWN, AMBIGUOUS, ERROR = "UNKNOWN", "AMBIGUOUS", "ERROR"

INVOCATION_PROVENANCE = "invocation_provenance"
AUTHOR_LABEL_BASIS = "author_declared_filename"
AUTHOR_MANIFEST_SCHEMA = "author-reference-manifest/v1"
AUTHOR_RUN_ID = "author-pkzip"
AUTHOR_VERIFIED_STATUS = "verified_label"
AUTHOR_SET = "author_pkzip"
CLI_TIMEOUT_SECONDS = 120

AUTHOR_DEFINITIONS = {
    "ground_truth": (
        "Label = (os, application) declared by the paper's authors through the sample file "
        "name, accepted in PH0-REF-002 because it is consistent with the paper's structural "
        "claims. Not invocation provenance; never derived from classifier output."
    ),
    "included": (
        "Manifest sample with label_verified=true, a safe relative path inside the samples "
        "directory, an existing artifact whose size and SHA-256 match the manifest."
    ),
}

AUTHOR_LIMITATIONS = [
    "Labels are author-declared file names, not independent provenance of the tool invocation.",
    "Tool versions, OS versions, Windows language and workstation (PC1-PC3) are unknown.",
    "The samples were published by the authors; they are not a blind test set.",
    "macOS samples were fetched from an archive; NFD file-name normalisation is not verifiable.",
]

DEFINITIONS = {
    "ground_truth": (
        "Label = (OS from run.environment.os, application from sample.tool_id) as recorded "
        "by the generator invocation. Never derived from classifier output."
    ),
    "included": (
        "Catalogue sample with status 'generated', a safe relative path inside data_dir, an "
        "existing artifact whose size and SHA-256 match the catalogue. Bytes are read once and "
        "the same bytes are hashed and classified."
    ),
    "in_catalog": "Truth (OS, application) exists in zip_fingerprint.rules.get_all_rules().",
    "top1": (
        "Prediction exists only when exactly one candidate holds the maximum score. Ties at the "
        "maximum are AMBIGUOUS; empty candidate lists are UNKNOWN; exceptions are ERROR. The "
        "first list element is never chosen to break a tie."
    ),
    "os_prediction": (
        "OS predicted when every maximum-score candidate shares one OS (a tool tie within one "
        "OS still yields an OS prediction); otherwise AMBIGUOUS/UNKNOWN/ERROR."
    ),
    "accuracy": (
        "correct / denominator, where the denominator counts every in-scope included sample "
        "including UNKNOWN, AMBIGUOUS and ERROR outcomes (all counted as not correct)."
    ),
    "tool_accuracy_scope": "Included, in-catalog samples (overall) / with truth OS Windows.",
    "os_accuracy_scope": (
        "Included samples whose truth OS maps to a catalogue OS, in-catalog and out-of-catalog "
        "applications alike."
    ),
    "precision": (
        "TP(X) / unique top-1 predictions of X among in-catalog samples. "
        "precision_with_out_of_catalog also counts out-of-catalog false attributions to X."
    ),
    "recall": "TP(X) / in-catalog samples whose truth is X.",
    "candidate_coverage": "In-catalog samples whose truth label appears anywhere in candidates.",
    "unique_sha256": (
        "One representative per SHA-256 among included samples. Groups whose members disagree on "
        "truth are excluded from unique metrics and reported as conflicts."
    ),
    "threshold_status": (
        "met | not_met | insufficient_coverage | no_data; computed on the unique-SHA-256 set. "
        "'met' additionally requires every catalogue label in scope to have at least one sample."
    ),
}

LIMITATIONS = [
    "Heuristic SUBSIDIARY scores are not calibrated probabilities.",
    "Self-generated CLI corpus is small, not blind and not statistically representative.",
    "Repeated runs on one machine with the same tool versions are not independent evidence.",
    "CLI invocation is not GUI/Explorer equivalence; PowerShell is not 'Compressed folder'.",
    "Results do not establish reproduction of the paper, BMAC or Case 2.",
]

Predictor = Callable[[bytes], List[Dict[str, Any]]]


@dataclass
class Truth:
    os: Optional[str]
    application: Optional[str]
    in_catalog: bool
    host_os_recorded: Optional[str]
    tool_id: Optional[str]
    source: str = INVOCATION_PROVENANCE

    @property
    def label(self) -> Optional[str]:
        return label_of(self.os, self.application) if self.in_catalog else None


@dataclass
class SampleResult:
    run_id: str
    sample_id: str
    tool_id: Optional[str]
    recorded_application: Optional[str]
    tool_version: Optional[str]
    variant: Optional[str]
    status: Optional[str]
    path: Optional[str]
    sha256: Optional[str]
    included: bool = False
    exclusion_reason: Optional[str] = None
    truth: Optional[Truth] = None
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    top_score: Optional[float] = None
    top_candidates: List[str] = field(default_factory=list)
    predicted: Optional[str] = None
    outcome: Optional[str] = None
    os_predicted: Optional[str] = None
    os_outcome: Optional[str] = None
    truth_in_candidates: Optional[bool] = None
    error: Optional[str] = None
    denominators: List[str] = field(default_factory=list)


class CatalogueError(ValueError):
    """Catalogue missing, malformed or using an unsupported schema."""


# --------------------------------------------------------------------------- helpers


def label_of(os_name: Optional[str], application: Optional[str]) -> str:
    return f"{os_name}/{application}"


def catalog_labels() -> List[str]:
    return sorted({label_of(rule.target_os, rule.application) for rule in get_all_rules()})


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ratio(numerator: int, denominator: int) -> Dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": round(numerator / denominator, 6) if denominator else None,
    }


# --------------------------------------------------------------------------- loading


def load_catalogue(path: Path) -> Dict[str, Any]:
    """Load a schema-v1 catalogue; ``{}`` is the generator's empty initial state."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CatalogueError(f"Cannot read catalogue {path}: {exc}") from exc
    if data == {}:
        return {"schema_version": 1, "runs": []}
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != 1
        or not isinstance(data.get("runs"), list)
    ):
        raise CatalogueError("Unsupported catalogue schema (expected schema_version 1)")
    for run in data["runs"]:
        if (
            not isinstance(run, dict)
            or not isinstance(run.get("run_id"), str)
            or not isinstance(run.get("samples"), list)
        ):
            raise CatalogueError("Malformed run in catalogue")
    return data


def resolve_artifact(data_dir: Path, relative: Any) -> Path:
    """Resolve a catalogue path, refusing absolute paths and traversal outside data_dir."""
    if not isinstance(relative, str) or not relative:
        raise ValueError("missing_path")
    pure = PurePosixPath(relative.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts or (pure.parts and ":" in pure.parts[0]):
        raise ValueError("unsafe_path")
    root = Path(os.path.realpath(data_dir))
    target = Path(os.path.realpath(root.joinpath(*pure.parts)))
    if os.path.commonpath([str(root), str(target)]) != str(root):
        raise ValueError("unsafe_path")
    return target


def verify_artifact(
    data_dir: Path, sample: Dict[str, Any], accepted_status: str = "generated"
) -> Tuple[Optional[bytes], Optional[str]]:
    """Return (bytes, None) for a verified artifact or (None, exclusion_reason)."""
    status = sample.get("status")
    if status != accepted_status:
        if status == "label_unverified":
            return None, "label_unverified"
        return None, f"status_{status or 'missing'}"
    expected_sha = sample.get("sha256")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        return None, "missing_checksum"
    try:
        path = resolve_artifact(data_dir, sample.get("path"))
    except ValueError as exc:
        return None, str(exc)
    if not path.is_file():
        return None, "missing_artifact"
    try:
        data = path.read_bytes()
    except OSError:
        return None, "unreadable_artifact"
    size = sample.get("size_bytes")
    if size is not None and size != len(data):
        return None, "size_mismatch"
    if _sha256_bytes(data) != expected_sha.lower():
        return None, "checksum_mismatch"
    return data, None


def load_author_manifest(path: Path) -> Dict[str, Any]:
    """Convert the PH0-REF-002 author manifest into a one-run evaluator catalogue.

    Sample paths stay relative to ``<manifest dir>/samples``. Labels come from the
    manifest's author-declared ``label``; samples whose label was not verified in
    PH0-REF-002 are kept but excluded as ``label_unverified``.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CatalogueError(f"Cannot read author manifest {path}: {exc}") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema") != AUTHOR_MANIFEST_SCHEMA
        or not isinstance(data.get("samples"), list)
    ):
        raise CatalogueError(f"Unsupported author manifest (expected {AUTHOR_MANIFEST_SCHEMA})")
    samples = []
    for entry in data["samples"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("label"), dict):
            raise CatalogueError("Malformed sample in author manifest")
        label = entry["label"]
        rel = entry.get("path")
        parts = PurePosixPath(rel).parts if isinstance(rel, str) else ()
        verified = (
            entry.get("label_verified") is True and entry.get("label_basis") == AUTHOR_LABEL_BASIS
        )
        samples.append(
            {
                "sample_id": str(entry.get("id")),
                "tool_id": None,
                "variant": parts[-2] if len(parts) >= 2 else None,
                "status": AUTHOR_VERIFIED_STATUS if verified else "label_unverified",
                "path": rel,
                "sha256": entry.get("sha256"),
                "size_bytes": entry.get("size"),
                "declared_label": {"os": label.get("os"), "application": label.get("application")},
                "tool": {"application": label.get("application"), "version": None},
            }
        )
    return {
        "schema_version": 1,
        "runs": [
            {
                "run_id": AUTHOR_RUN_ID,
                "label_source": AUTHOR_LABEL_BASIS,
                "accepted_status": AUTHOR_VERIFIED_STATUS,
                "environment": {},
                "source": data.get("source"),
                "samples": samples,
            }
        ],
    }


def ground_truth(run: Dict[str, Any], sample: Dict[str, Any], labels: Iterable[str]) -> Truth:
    if run.get("label_source") == AUTHOR_LABEL_BASIS:
        declared = sample.get("declared_label") or {}
        os_name, application = declared.get("os"), declared.get("application")
        return Truth(
            os=os_name,
            application=application,
            in_catalog=label_of(os_name, application) in set(labels),
            host_os_recorded=None,
            tool_id=None,
            source=AUTHOR_LABEL_BASIS,
        )
    host = (run.get("environment") or {}).get("os")
    tool_id = sample.get("tool_id")
    os_name = OS_LABELS.get(host) if isinstance(host, str) else None
    tool = sample.get("tool") if isinstance(sample.get("tool"), dict) else {}
    application = TOOL_LABELS.get(tool_id) or tool.get("application") or tool_id
    in_catalog = (
        os_name is not None
        and tool_id in TOOL_LABELS
        and label_of(os_name, application) in set(labels)
    )
    return Truth(
        os=os_name,
        application=application,
        in_catalog=in_catalog,
        host_os_recorded=host,
        tool_id=tool_id,
    )


# --------------------------------------------------------------------------- prediction


def default_predictor(data: bytes) -> List[Dict[str, Any]]:
    """Parse -> extract -> classify via the library API."""
    parser = ZipBinaryParser(data)
    try:
        archive = parser.parse()
    finally:
        parser.close()
    features = StructuralFeatureExtractor(archive).extract()
    return [asdict(candidate) for candidate in AutomatedClassifier().classify(features)]


def cli_predictor(data: bytes) -> List[Dict[str, Any]]:
    """Classify via ``python -m zip_fingerprint identify`` on a private copy of ``data``.

    The verified bytes are written to a fresh temporary file so the CLI sees exactly
    the bytes that were checksummed; the CLI's reported archive SHA-256 is checked.
    """
    expected = _sha256_bytes(data)
    env = dict(os.environ)
    extra = [env["PYTHONPATH"]] if env.get("PYTHONPATH") else []
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), *extra])
    env["PYTHONIOENCODING"] = "utf-8"
    with tempfile.TemporaryDirectory(prefix="zipfp-eval-") as tmp:
        target = Path(tmp) / "sample.zip"
        target.write_bytes(data)
        completed = subprocess.run(
            [sys.executable, "-m", "zip_fingerprint", "identify", str(target), "--format", "json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
            timeout=CLI_TIMEOUT_SECONDS,
            check=False,
        )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        last = detail[-1] if detail else "no output"
        raise RuntimeError(f"identify exited {completed.returncode}: {last}")
    payload = json.loads(completed.stdout)
    if payload.get("archive_sha256") != expected:
        raise RuntimeError("identify reported a different archive SHA-256 than the verified bytes")
    return list(payload["candidates"])


PREDICTORS: Dict[str, Tuple[Predictor, str]] = {
    "api": (default_predictor, "api: zip_fingerprint parser -> extractor -> AutomatedClassifier"),
    "cli": (cli_predictor, "cli: python -m zip_fingerprint identify --format json"),
}


def top_candidates(candidates: Sequence[Dict[str, Any]]) -> Tuple[Optional[float], List[str]]:
    if not candidates:
        return None, []
    best = max(float(c["confidence"]) for c in candidates)
    tops = [
        label_of(c["target_os"], c["application"])
        for c in candidates
        if float(c["confidence"]) == best
    ]
    return best, tops


def decide_top1(candidates: Sequence[Dict[str, Any]]) -> Tuple[Optional[str], str]:
    """Return (label, decision) with decision in predicted | UNKNOWN | AMBIGUOUS."""
    _, tops = top_candidates(candidates)
    if not tops:
        return None, UNKNOWN
    if len(tops) > 1:
        return None, AMBIGUOUS
    return tops[0], "predicted"


def decide_os(candidates: Sequence[Dict[str, Any]]) -> Tuple[Optional[str], str]:
    _, tops = top_candidates(candidates)
    if not tops:
        return None, UNKNOWN
    systems = {label.split("/", 1)[0] for label in tops}
    if len(systems) > 1:
        return None, AMBIGUOUS
    return systems.pop(), "predicted"


# --------------------------------------------------------------------------- per sample


def evaluate_samples(
    catalogue: Dict[str, Any],
    data_dir: Path,
    predictor: Predictor = default_predictor,
    run_ids: Optional[Iterable[str]] = None,
) -> List[SampleResult]:
    labels = catalog_labels()
    wanted = set(run_ids) if run_ids else None
    results: List[SampleResult] = []
    for run in catalogue["runs"]:
        if wanted is not None and run["run_id"] not in wanted:
            continue
        for sample in run["samples"]:
            results.append(_evaluate_one(run, sample, Path(data_dir), predictor, labels))
    return results


def _evaluate_one(
    run: Dict[str, Any],
    sample: Dict[str, Any],
    data_dir: Path,
    predictor: Predictor,
    labels: List[str],
) -> SampleResult:
    tool = sample.get("tool") if isinstance(sample.get("tool"), dict) else {}
    result = SampleResult(
        run_id=run["run_id"],
        sample_id=str(sample.get("sample_id")),
        tool_id=sample.get("tool_id"),
        recorded_application=tool.get("application"),
        tool_version=tool.get("version"),
        variant=sample.get("variant"),
        status=sample.get("status"),
        path=sample.get("path"),
        sha256=sample.get("sha256"),
    )
    data, reason = verify_artifact(data_dir, sample, run.get("accepted_status", "generated"))
    if data is None:
        result.exclusion_reason = reason
        return result
    result.included = True
    truth = ground_truth(run, sample, labels)
    result.truth = truth

    try:
        candidates = predictor(data)
    except Exception as exc:  # evaluator must record, not hide, classifier failures
        result.error = f"{type(exc).__name__}: {exc}"
        result.outcome = result.os_outcome = ERROR
        result.truth_in_candidates = False if truth.in_catalog else None
        _assign_denominators(result)
        return result

    result.candidates = [
        {
            "target_os": c["target_os"],
            "application": c["application"],
            "confidence": c["confidence"],
            "weight_tier": c.get("weight_tier"),
            "matched_rules": list(c.get("matched_rules", [])),
            "notes": list(c.get("notes", [])),
        }
        for c in candidates
    ]
    result.top_score, result.top_candidates = top_candidates(result.candidates)
    predicted, decision = decide_top1(result.candidates)
    result.predicted = predicted
    if truth.in_catalog:
        if decision != "predicted":
            result.outcome = decision
        else:
            result.outcome = "correct" if predicted == truth.label else "wrong"
        result.truth_in_candidates = truth.label in {
            label_of(c["target_os"], c["application"]) for c in result.candidates
        }
    else:
        # Any attribution of an out-of-catalog tool to a catalogue label is false.
        result.outcome = {
            UNKNOWN: UNKNOWN,
            AMBIGUOUS: "ambiguous_false_attribution",
        }.get(decision, "false_attribution")

    os_predicted, os_decision = decide_os(result.candidates)
    result.os_predicted = os_predicted
    if truth.os is None:
        result.os_outcome = "truth_os_unmapped"
    elif os_decision != "predicted":
        result.os_outcome = os_decision
    else:
        result.os_outcome = "correct" if os_predicted == truth.os else "wrong"
    _assign_denominators(result)
    return result


def _assign_denominators(result: SampleResult) -> None:
    truth = result.truth
    if truth is None:
        return
    if truth.os is not None:
        result.denominators.append("os_accuracy")
    if truth.in_catalog:
        result.denominators += ["tool_accuracy", "recall", "candidate_coverage"]
        if truth.os == "Windows":
            result.denominators.append("windows_tool_accuracy")
        if result.predicted is not None:
            result.denominators.append(f"precision:{result.predicted}")
    else:
        result.denominators.append("out_of_catalog")
        if result.predicted is not None:
            result.denominators.append(f"precision_with_out_of_catalog:{result.predicted}")


# --------------------------------------------------------------------------- aggregation


def dedupe_by_sha(
    results: Sequence[SampleResult],
) -> Tuple[List[SampleResult], List[Dict[str, Any]]]:
    """Keep one representative per SHA-256; report groups with conflicting truth."""
    groups: Dict[str, List[SampleResult]] = defaultdict(list)
    for row in results:
        if row.included and row.sha256:
            groups[row.sha256.lower()].append(row)
    unique: List[SampleResult] = []
    conflicts: List[Dict[str, Any]] = []
    for sha, rows in groups.items():
        truths = {(r.truth.os, r.truth.application) for r in rows if r.truth}
        if len(truths) > 1:
            conflicts.append({"sha256": sha, "sample_ids": [r.sample_id for r in rows]})
            continue
        unique.append(rows[0])
    return unique, conflicts


def confusion_matrix(results: Sequence[SampleResult], labels: Sequence[str]) -> Dict[str, Any]:
    columns = list(labels) + [UNKNOWN, AMBIGUOUS, ERROR]
    matrix = {row: {col: 0 for col in columns} for row in labels}
    for row in results:
        if not (row.included and row.truth and row.truth.in_catalog):
            continue
        column = row.predicted if row.predicted is not None else (row.outcome or ERROR)
        matrix[row.truth.label][column] += 1  # type: ignore[index]
    return {"rows": "truth", "columns": columns, "matrix": matrix}


def classification_metrics(
    results: Sequence[SampleResult], labels: Sequence[str]
) -> Dict[str, Any]:
    in_cat = [r for r in results if r.included and r.truth and r.truth.in_catalog]
    windows = [r for r in in_cat if r.truth and r.truth.os == "Windows"]
    out_cat = [r for r in results if r.included and r.truth and not r.truth.in_catalog]
    outcomes = Counter(r.outcome for r in in_cat)
    per_class: Dict[str, Any] = {}
    for label in labels:
        truth_hits = [r for r in in_cat if r.truth and r.truth.label == label]
        tp = sum(1 for r in truth_hits if r.predicted == label)
        predicted = sum(1 for r in in_cat if r.predicted == label)
        false_ooc = sum(1 for r in out_cat if r.predicted == label)
        support = len(truth_hits)
        per_class[label] = {
            "support": support,
            "true_positive": tp,
            "precision": _ratio(tp, predicted),
            "precision_with_out_of_catalog": _ratio(tp, predicted + false_ooc),
            "recall": _ratio(tp, support),
        }
    return {
        "tool_accuracy": _ratio(outcomes["correct"], len(in_cat)),
        "windows_tool_accuracy": _ratio(
            sum(1 for r in windows if r.outcome == "correct"), len(windows)
        ),
        "outcomes": {
            k: outcomes.get(k, 0) for k in ("correct", "wrong", UNKNOWN, AMBIGUOUS, ERROR)
        },
        "per_class": per_class,
        "confusion_matrix": confusion_matrix(results, labels),
    }


def os_metrics(results: Sequence[SampleResult]) -> Dict[str, Any]:
    scoped = [r for r in results if r.included and r.truth and r.truth.os is not None]
    outcomes = Counter(r.os_outcome for r in scoped)
    per_os: Dict[str, Any] = {}
    for os_name in sorted({r.truth.os for r in scoped if r.truth and r.truth.os}):
        rows = [r for r in scoped if r.truth and r.truth.os == os_name]
        per_os[os_name] = _ratio(sum(1 for r in rows if r.os_outcome == "correct"), len(rows))
    unmapped = sum(1 for r in results if r.included and r.truth and r.truth.os is None)
    return {
        "os_accuracy": _ratio(outcomes["correct"], len(scoped)),
        "outcomes": {
            k: outcomes.get(k, 0) for k in ("correct", "wrong", UNKNOWN, AMBIGUOUS, ERROR)
        },
        "per_os": per_os,
        "excluded_truth_os_unmapped": unmapped,
    }


def candidate_coverage(results: Sequence[SampleResult]) -> Dict[str, Any]:
    scoped = [r for r in results if r.included and r.truth and r.truth.in_catalog]
    return _ratio(sum(1 for r in scoped if r.truth_in_candidates), len(scoped))


def out_of_catalog_report(results: Sequence[SampleResult]) -> Dict[str, Any]:
    rows = [r for r in results if r.included and r.truth and not r.truth.in_catalog]
    by_app: Dict[str, Any] = {}
    for app in sorted({str(r.truth.application) for r in rows if r.truth}):
        subset = [r for r in rows if r.truth and str(r.truth.application) == app]
        by_app[app] = {
            "samples": len(subset),
            "outcomes": dict(Counter(r.outcome for r in subset)),
            "attributed_to": dict(Counter(r.predicted for r in subset if r.predicted)),
            "top_candidates_when_ambiguous": dict(
                Counter(
                    "|".join(r.top_candidates)
                    for r in subset
                    if r.outcome == "ambiguous_false_attribution"
                )
            ),
            "note": "Reported separately; not relabelled to any catalogue application.",
        }
    return {"samples": len(rows), "by_application": by_app}


def coverage_report(results: Sequence[SampleResult], labels: Sequence[str]) -> Dict[str, Any]:
    included = [r for r in results if r.included and r.truth]
    observed = sorted({r.truth.label for r in included if r.truth and r.truth.in_catalog})
    versions: Dict[str, List[str]] = defaultdict(list)
    for r in included:
        key = r.truth.label if r.truth and r.truth.in_catalog else f"out_of_catalog:{r.tool_id}"
        if r.tool_version and r.tool_version not in versions[str(key)]:
            versions[str(key)].append(r.tool_version)
    catalog_os = sorted({label.split("/", 1)[0] for label in labels})
    windows_tools = sorted(label for label in labels if label.startswith("Windows/"))
    return {
        "catalog_labels": list(labels),
        "observed_in_catalog_labels": observed,
        "missing_catalog_labels": [label for label in labels if label not in observed],
        "catalog_os": catalog_os,
        "observed_os": sorted({r.truth.os for r in included if r.truth and r.truth.os}),
        "windows_catalog_tools": windows_tools,
        "observed_windows_tools": [label for label in windows_tools if label in observed],
        "tool_versions": {k: sorted(v) for k, v in sorted(versions.items())},
        "variants": dict(Counter(str(r.variant) for r in included)),
    }


def threshold_check(
    os_ratio: Dict[str, Any], tool_ratio: Dict[str, Any], coverage: Dict[str, Any]
) -> Dict[str, Any]:
    def status(ratio: Dict[str, Any], target: float, complete: bool) -> str:
        if ratio["value"] is None:
            return "no_data"
        if ratio["value"] < target:
            return "not_met"
        return "met" if complete else "insufficient_coverage"

    os_complete = set(coverage["catalog_os"]) <= set(coverage["observed_os"])
    tools_complete = coverage["observed_windows_tools"] == coverage["windows_catalog_tools"]
    return {
        "os_accuracy": {
            "target": THRESHOLDS["os_accuracy"],
            "observed": os_ratio,
            "coverage_complete": os_complete,
            "missing": sorted(set(coverage["catalog_os"]) - set(coverage["observed_os"])),
            "status": status(os_ratio, THRESHOLDS["os_accuracy"], os_complete),
        },
        "windows_tool_accuracy": {
            "target": THRESHOLDS["windows_tool_accuracy"],
            "observed": tool_ratio,
            "coverage_complete": tools_complete,
            "missing": sorted(
                set(coverage["windows_catalog_tools"]) - set(coverage["observed_windows_tools"])
            ),
            "status": status(tool_ratio, THRESHOLDS["windows_tool_accuracy"], tools_complete),
        },
    }


def counts_report(
    results: Sequence[SampleResult], unique: Sequence[SampleResult]
) -> Dict[str, Any]:
    included = [r for r in results if r.included]
    runs_by_sha: Dict[str, set] = defaultdict(set)
    for r in included:
        runs_by_sha[str(r.sha256).lower()].add(r.run_id)
    sha_counts = Counter(str(r.sha256).lower() for r in included)
    return {
        "catalogue_samples": len(results),
        "by_status": dict(Counter(str(r.status) for r in results)),
        "included": len(included),
        "excluded": len(results) - len(included),
        "exclusion_reasons": dict(Counter(r.exclusion_reason for r in results if not r.included)),
        "unique_sha256": len(sha_counts),
        "unique_sha256_used": len(unique),
        "duplicate_sha256_groups": {sha: n for sha, n in sha_counts.items() if n > 1},
        "sha256_seen_in_multiple_runs": sum(1 for runs in runs_by_sha.values() if len(runs) > 1),
        "runs": sorted({r.run_id for r in results}),
        "included_per_run": dict(Counter(r.run_id for r in included)),
        "independence_note": (
            "Runs share machine, OS build and tool versions; repeated runs re-measure the same "
            "configuration and are not independent evidence. Byte-identical archives are counted "
            "once in the unique-SHA-256 metrics."
        ),
    }


def metric_block(results: Sequence[SampleResult], labels: Sequence[str]) -> Dict[str, Any]:
    return {
        "classification": classification_metrics(results, labels),
        "os": os_metrics(results),
        "candidate_coverage": candidate_coverage(results),
        "out_of_catalog": out_of_catalog_report(results),
    }


# --------------------------------------------------------------------------- report


def _git(*args: str) -> Optional[str]:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=10, check=True
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip()


def _file_sha(path: Path) -> Optional[str]:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError:
        return None


def build_report(
    results: Sequence[SampleResult],
    catalogue_path: Path,
    data_dir: Path,
    argv: Sequence[str],
    run_filter: Optional[Sequence[str]] = None,
    predictor_description: str = PREDICTORS["api"][1],
) -> Dict[str, Any]:
    labels = catalog_labels()
    unique, conflicts = dedupe_by_sha(results)
    raw_block = metric_block(results, labels)
    unique_block = metric_block(unique, labels)
    coverage = coverage_report(results, labels)
    status = _git("status", "--porcelain")
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "task": "PH7-EVAL-002",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "reproduction": {
            "command": [Path(sys.executable).name, *argv],
            "cwd_independent": True,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "git_commit": _git("rev-parse", "HEAD"),
            "git_dirty": bool(status) if status is not None else None,
            "catalogue_path": str(catalogue_path),
            "catalogue_sha256": _file_sha(Path(catalogue_path)),
            "data_dir": str(data_dir),
            "run_filter": list(run_filter) if run_filter else None,
            "classifier_sources_sha256": {
                name: _file_sha(ROOT / "src/zip_fingerprint" / name)
                for name in ("classifier.py", "rules.py", "extractor.py", "parser.py")
            },
            "predictor": predictor_description,
        },
        "definitions": DEFINITIONS,
        "counts": counts_report(results, unique),
        "unique_sha256_conflicts": conflicts,
        "coverage": coverage,
        "metrics": {"raw": raw_block, "unique_sha256": unique_block},
        "thresholds": threshold_check(
            unique_block["os"]["os_accuracy"],
            unique_block["classification"]["windows_tool_accuracy"],
            coverage,
        ),
        "samples": [asdict(r) for r in results],
        "limitations": LIMITATIONS,
    }


def build_author_report(
    manifest_path: Path,
    samples_dir: Path,
    predictor: Predictor,
    argv: Sequence[str],
    predictor_description: str,
) -> Dict[str, Any]:
    """Evaluate the author reference set on its own; never pooled with generated runs."""
    if not manifest_path.is_file():
        return {
            "status": "not_available",
            "manifest_path": str(manifest_path),
            "note": "Run scripts/fetch_author_samples.py to fetch the PH0-REF-002 samples.",
        }
    try:
        catalogue = load_author_manifest(manifest_path)
    except CatalogueError as exc:
        print(f"warning: {exc}", file=sys.stderr)
        return {"status": "error", "manifest_path": str(manifest_path), "error": str(exc)}
    results = evaluate_samples(catalogue, samples_dir, predictor)
    report = build_report(
        results, manifest_path, samples_dir, argv, predictor_description=predictor_description
    )
    reproduction = report["reproduction"]
    reproduction["manifest_path"] = reproduction.pop("catalogue_path")
    reproduction["manifest_sha256"] = reproduction.pop("catalogue_sha256")
    reproduction["samples_dir"] = reproduction.pop("data_dir")
    reproduction["source"] = catalogue["runs"][0].get("source")
    reproduction["fetch_command"] = "python scripts/fetch_author_samples.py"
    report["counts"]["independence_note"] = (
        "Author samples come from unknown workstations and tool versions; byte-identical "
        "archives are counted once in the unique-SHA-256 metrics."
    )
    report["definitions"] = {**report["definitions"], **AUTHOR_DEFINITIONS}
    report["limitations"] = AUTHOR_LIMITATIONS + report["limitations"][:1]
    return {"status": "evaluated", "label_basis": AUTHOR_LABEL_BASIS, **report}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data", help="Data root")
    parser.add_argument("--catalogue", type=Path, help="Default: <data-dir>/metadata.json")
    parser.add_argument("--run", action="append", dest="runs", help="Restrict to run_id")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Report JSON path")
    parser.add_argument(
        "--predictor",
        choices=sorted(PREDICTORS),
        default="api",
        help="Classify through the library API or the zip_fingerprint identify CLI",
    )
    parser.add_argument(
        "--author-manifest",
        type=Path,
        help="Default: <data-dir>/reference/author_pkzip/manifest.json",
    )
    parser.add_argument("--author-samples-dir", type=Path, help="Default: <manifest dir>/samples")
    return parser


def _summary_lines(report: Dict[str, Any], prefix: str = "") -> List[str]:
    counts = report["counts"]
    lines = [
        f"{prefix}samples={counts['catalogue_samples']} included={counts['included']} "
        f"excluded={counts['excluded']} unique_sha256={counts['unique_sha256']}",
    ]
    for name, item in report["thresholds"].items():
        observed = item["observed"]
        lines.append(
            f"{prefix}{name}: {observed['numerator']}/{observed['denominator']} "
            f"value={observed['value']} target={item['target']} status={item['status']}"
        )
    return lines


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    data_dir = Path(os.path.abspath(args.data_dir))
    catalogue_path = Path(os.path.abspath(args.catalogue or data_dir / "metadata.json"))
    try:
        catalogue = load_catalogue(catalogue_path)
    except CatalogueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    predictor, predictor_description = PREDICTORS[args.predictor]
    command = ["experiments/evaluate_classifier.py", *argv]
    results = evaluate_samples(catalogue, data_dir, predictor, run_ids=args.runs)
    report = build_report(
        results, catalogue_path, data_dir, command, args.runs, predictor_description
    )
    manifest_path = Path(
        os.path.abspath(args.author_manifest or data_dir / "reference/author_pkzip/manifest.json")
    )
    samples_dir = Path(os.path.abspath(args.author_samples_dir or manifest_path.parent / "samples"))
    report["reference_sets"] = {
        AUTHOR_SET: build_author_report(
            manifest_path, samples_dir, predictor, command, predictor_description
        )
    }
    output = Path(os.path.abspath(args.output))
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        tmp = output.with_name(output.name + ".tmp")
        tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, output)
    except OSError as exc:
        print(f"error: cannot write report: {exc}", file=sys.stderr)
        return 1
    for line in _summary_lines(report, "generated: "):
        print(line)
    author = report["reference_sets"][AUTHOR_SET]
    if author["status"] == "evaluated":
        for line in _summary_lines(author, f"{AUTHOR_SET}: "):
            print(line)
    else:
        print(f"{AUTHOR_SET}: {author['status']}")
    print(f"report: {output}")
    # Unmet thresholds are a scientific result, not a program failure.
    author_included = author.get("counts", {}).get("included", 0)
    return 0 if report["counts"]["included"] or author_included else 2


if __name__ == "__main__":
    sys.exit(main())
