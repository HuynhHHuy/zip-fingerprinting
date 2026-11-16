"""Tests for the zip-fingerprint CLI interface (PH7-CLI-001/A)."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from zip_fingerprint.classifier import AutomatedClassifier
from zip_fingerprint.cli import compute_file_sha256, main
from zip_fingerprint.extractor import StructuralFeatureExtractor
from zip_fingerprint.hasher import build_canonical_fingerprint
from zip_fingerprint.parser import ZipBinaryParser
from zip_fingerprint.schema import FingerprintSchemaV1


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that bare CLI and --help show usage without error."""
    # Running without arguments displays help and returns 0
    code = main([])
    assert code == 0
    out, err = capsys.readouterr()
    assert "usage: zip-fingerprint" in out
    assert "fingerprint" in out
    assert "identify" in out
    assert err == ""

    # --help raises SystemExit(0) in standard argparse
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    out, err = capsys.readouterr()
    assert "usage: zip-fingerprint" in out


def test_cli_fingerprint_stdout(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'fingerprint' writes valid JSON to stdout matching direct API call."""
    zip_file = tmp_path / "test.zip"
    zip_file.write_bytes(minimal_zip_bytes)

    code = main(["fingerprint", str(zip_file)])
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""

    data = json.loads(out)
    validated = FingerprintSchemaV1(**data)
    assert validated.schema_version == "1.0.0"
    assert len(validated.structural_hash) == 64
    assert validated.file_metadata.sha256_content == compute_file_sha256(zip_file)

    # Cross-check directly against Python API
    with ZipBinaryParser(zip_file) as parser:
        archive = parser.parse()
    features = StructuralFeatureExtractor(archive).extract()
    expected_fp = build_canonical_fingerprint(
        features, sha256_content=compute_file_sha256(zip_file)
    )
    assert validated.structural_hash == expected_fp.structural_hash
    assert data["structural_hash"] == expected_fp.structural_hash


def test_cli_fingerprint_output_file(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'fingerprint --output' saves JSON to file and creates directories."""
    zip_file = tmp_path / "test.zip"
    zip_file.write_bytes(minimal_zip_bytes)
    out_file = tmp_path / "nested" / "report.json"

    code = main(["fingerprint", str(zip_file), "--output", str(out_file)])
    assert code == 0
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert stderr == ""

    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["schema_version"] == "1.0.0"
    assert len(content["structural_hash"]) == 64


def test_cli_fingerprint_path_invariance(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify identical archives at different paths produce identical structural hash."""
    zip_a = tmp_path / "a.zip"
    zip_b = tmp_path / "nested" / "b.zip"
    zip_b.parent.mkdir(parents=True, exist_ok=True)
    zip_a.write_bytes(minimal_zip_bytes)
    zip_b.write_bytes(minimal_zip_bytes)

    main(["fingerprint", str(zip_a)])
    out_a, _ = capsys.readouterr()
    hash_a = json.loads(out_a)["structural_hash"]

    main(["fingerprint", str(zip_b)])
    out_b, _ = capsys.readouterr()
    hash_b = json.loads(out_b)["structural_hash"]

    assert hash_a == hash_b


def test_cli_identify_json(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'identify' outputs candidate list matching classifier directly."""
    zip_file = tmp_path / "sample.zip"
    zip_file.write_bytes(minimal_zip_bytes)

    code = main(["identify", str(zip_file)])
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""

    data = json.loads(out)
    assert data["file_path"] == str(zip_file)
    assert len(data["structural_hash"]) == 64
    assert data["archive_sha256"] == compute_file_sha256(zip_file)
    assert "candidates" in data
    assert isinstance(data["candidates"], list)

    # Compare directly with AutomatedClassifier
    with ZipBinaryParser(zip_file) as parser:
        archive = parser.parse()
    features = StructuralFeatureExtractor(archive).extract()
    expected_candidates = AutomatedClassifier().classify(features)

    assert data["total_candidates"] == len(expected_candidates)
    if expected_candidates:
        first = data["candidates"][0]
        assert first["target_os"] == expected_candidates[0].target_os
        assert first["application"] == expected_candidates[0].application
        assert first["confidence"] == expected_candidates[0].confidence
        assert first["weight_tier"] == expected_candidates[0].weight_tier


def test_cli_identify_text_format(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'identify --format text' outputs formatted textual summary."""
    zip_file = tmp_path / "sample.zip"
    zip_file.write_bytes(minimal_zip_bytes)

    code = main(["identify", str(zip_file), "--format", "text"])
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""
    assert f"Target: {zip_file}" in out
    assert "Structural Hash:" in out
    assert "Total Candidates:" in out


def test_cli_identify_output_file(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'identify -o <file>' writes result to specified destination."""
    zip_file = tmp_path / "sample.zip"
    zip_file.write_bytes(minimal_zip_bytes)
    out_file = tmp_path / "identify_out.json"

    code = main(["identify", str(zip_file), "-o", str(out_file)])
    assert code == 0
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert stderr == ""

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "candidates" in data


def test_cli_unicode_and_spaces_path(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify handling of paths with spaces and Unicode (e.g. Vietnamese)."""
    special_dir = tmp_path / "thư mục kiểm thử"
    special_dir.mkdir(parents=True, exist_ok=True)
    special_zip = special_dir / "tệp nén dấu vân tay 2026.zip"
    special_zip.write_bytes(minimal_zip_bytes)

    # fingerprint
    code_fp = main(["fingerprint", str(special_zip)])
    assert code_fp == 0
    out_fp, err_fp = capsys.readouterr()
    assert err_fp == ""
    assert json.loads(out_fp)["schema_version"] == "1.0.0"

    # identify
    code_id = main(["identify", str(special_zip)])
    assert code_id == 0
    out_id, err_id = capsys.readouterr()
    assert err_id == ""
    assert json.loads(out_id)["file_path"] == str(special_zip)


def test_cli_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify standardized exit codes and stderr reporting on error conditions."""
    # 1. Non-existent file -> Exit code 1
    code = main(["fingerprint", str(tmp_path / "missing.zip")])
    assert code == 1
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert "Error: Target ZIP file does not exist" in stderr

    code = main(["identify", str(tmp_path / "missing.zip")])
    assert code == 1
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert "Error: Target ZIP file does not exist" in stderr

    # 2. Directory instead of file -> Exit code 1
    code = main(["fingerprint", str(tmp_path)])
    assert code == 1
    stdout, stderr = capsys.readouterr()
    assert "Error: Target path is not a regular file" in stderr

    # 3. Corrupt ZIP file -> Exit code 1
    corrupt_file = tmp_path / "corrupt.zip"
    corrupt_file.write_bytes(b"corrupt header junk bytes not a zip")
    code = main(["fingerprint", str(corrupt_file)])
    assert code == 1
    stdout, stderr = capsys.readouterr()
    assert "Error analyzing ZIP file:" in stderr

    code = main(["identify", str(corrupt_file)])
    assert code == 1
    stdout, stderr = capsys.readouterr()
    assert "Error analyzing ZIP file:" in stderr

    # 4. Unimplemented subcommands (PH7-CLI-001/B) -> Exit code 1 with message
    code = main(["provenance", str(corrupt_file)])
    assert code == 1
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert "Error: Subcommand 'provenance' is not yet implemented" in stderr

    code = main(["decompress-check", "--bmac", "EEER"])
    assert code == 1
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert "Error: Subcommand 'decompress-check' is not yet implemented" in stderr

    # 5. Syntax errors -> Exit code 2
    with pytest.raises(SystemExit) as exc_missing_arg:
        main(["fingerprint"])
    assert exc_missing_arg.value.code == 2

    with pytest.raises(SystemExit) as exc_bad_flag:
        main(["identify", str(corrupt_file), "--nonexistent-flag"])
    assert exc_bad_flag.value.code == 2


def test_cli_subprocess_invocation(tmp_path: Path, minimal_zip_bytes: bytes) -> None:
    """Verify execution via python -m zip_fingerprint."""
    zip_file = tmp_path / "subproc_test.zip"
    zip_file.write_bytes(minimal_zip_bytes)

    # 1. Module entrypoint with --help
    res_help = subprocess.run(
        [sys.executable, "-m", "zip_fingerprint", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_help.returncode == 0
    assert "usage: zip-fingerprint" in res_help.stdout

    # 2. Module entrypoint with fingerprint
    res_fp = subprocess.run(
        [sys.executable, "-m", "zip_fingerprint", "fingerprint", str(zip_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_fp.returncode == 0
    data = json.loads(res_fp.stdout)
    assert data["schema_version"] == "1.0.0"
    assert len(data["structural_hash"]) == 64

    # 3. Module entrypoint with identify
    res_id = subprocess.run(
        [sys.executable, "-m", "zip_fingerprint", "identify", str(zip_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_id.returncode == 0
    data_id = json.loads(res_id.stdout)
    assert data_id["file_path"] == str(zip_file)
    assert "candidates" in data_id
