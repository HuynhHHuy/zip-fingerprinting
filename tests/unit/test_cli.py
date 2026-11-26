"""Tests for the zip-fingerprint CLI interface (PH7-CLI-001/A & PH7-CLI-001/B)."""

import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zipfile

import pytest

from tests.integration.test_provenance_tracking import (
    build_zip,
    mac_compress,
    win_7zip,
)
from zip_fingerprint.classifier import AutomatedClassifier
from zip_fingerprint.cli import compute_file_sha256, main
from zip_fingerprint.constants import (
    SIG_CENTRAL_DIRECTORY_HEADER,
    SIG_END_OF_CENTRAL_DIRECTORY,
    SIG_LOCAL_FILE_HEADER,
)
from zip_fingerprint.extractor import StructuralFeatureExtractor
from zip_fingerprint.hasher import build_canonical_fingerprint
from zip_fingerprint.parser import ZipBinaryParser
from zip_fingerprint.provenance import ProvenanceTracker
from zip_fingerprint.schema import FingerprintSchemaV1


def make_unix_zip_bytes() -> bytes:
    """Generate a minimal valid raw ZIP archive with Host OS = 3 (Unix)."""
    buf = io.BytesIO()
    filename = b"test.txt"
    data = b"Hello, Unix!"
    crc = 0x12345678

    buf.write(
        struct.pack(
            "<IHHHHHIIIHH",
            SIG_LOCAL_FILE_HEADER,
            20,
            0,
            0,
            0x5000,
            0x5000,
            crc,
            len(data),
            len(data),
            len(filename),
            0,
        )
    )
    buf.write(filename)
    buf.write(data)

    cd_offset = buf.tell()
    buf.write(
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            SIG_CENTRAL_DIRECTORY_HEADER,
            0x0314,  # Host OS = 3 (Unix)
            20,
            0,
            0,
            0x5000,
            0x5000,
            crc,
            len(data),
            len(data),
            len(filename),
            0,
            0,
            0,
            0,
            0,
            0,
        )
    )
    buf.write(filename)
    cd_size = buf.tell() - cd_offset

    buf.write(
        struct.pack(
            "<IHHHHIIH",
            SIG_END_OF_CENTRAL_DIRECTORY,
            0,
            0,
            1,
            1,
            cd_size,
            cd_offset,
            0,
        )
    )
    return buf.getvalue()


@pytest.mark.parametrize("command", ["fingerprint", "identify", "provenance"])
@pytest.mark.parametrize("alias", ["same", "relative", "hardlink", "symlink"])
def test_cli_rejects_output_aliasing_input(
    tmp_path: Path, minimal_zip_bytes: bytes, command: str, alias: str
) -> None:
    """Output aliases must never destroy the source archive."""
    source = tmp_path / "source.zip"
    source.write_bytes(minimal_zip_bytes)
    output = source
    if alias == "relative":
        output = Path("source.zip")
    elif alias in {"hardlink", "symlink"}:
        output = tmp_path / "alias.zip"
        try:
            if alias == "hardlink":
                output.hardlink_to(source)
            else:
                output.symlink_to(source)
        except OSError as exc:
            pytest.skip(f"Filesystem cannot create {alias}: {exc}")

    result = subprocess.run(
        [sys.executable, "-m", "zip_fingerprint", command, str(source), "-o", str(output)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert source.read_bytes() == minimal_zip_bytes
    assert result.returncode == 1
    assert result.stdout == b""
    assert b"Error" in result.stderr
    assert b"Traceback" not in result.stderr


def test_cli_compare_rejects_output_aliasing_either_input(
    tmp_path: Path, minimal_zip_bytes: bytes
) -> None:
    """Compare must reject output paths that match either input ZIP."""
    source1 = tmp_path / "source1.zip"
    source2 = tmp_path / "source2.zip"
    source1.write_bytes(minimal_zip_bytes)
    source2.write_bytes(minimal_zip_bytes)

    # Alias target1
    res1 = subprocess.run(
        [
            sys.executable,
            "-m",
            "zip_fingerprint",
            "compare",
            str(source1),
            str(source2),
            "-o",
            str(source1),
        ],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert res1.returncode == 1
    assert b"Error: Output file must not be an input ZIP or an alias" in res1.stderr

    # Alias target2
    res2 = subprocess.run(
        [
            sys.executable,
            "-m",
            "zip_fingerprint",
            "compare",
            str(source1),
            str(source2),
            "-o",
            str(source2),
        ],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert res2.returncode == 1
    assert b"Error: Output file must not be an input ZIP or an alias" in res2.stderr


@pytest.mark.parametrize("encoding", ["cp1252", "utf-8"])
@pytest.mark.parametrize(
    "command",
    [
        ["fingerprint"],
        ["identify"],
        ["identify", "--format", "text"],
        ["provenance"],
        ["provenance", "--format", "text"],
    ],
)
def test_cli_unicode_subprocess_output(
    tmp_path: Path, minimal_zip_bytes: bytes, encoding: str, command: list[str]
) -> None:
    """Legacy stdout must preserve JSON values or escape unencodable text."""
    source = tmp_path / "tệp nén.zip"
    source.write_bytes(minimal_zip_bytes)
    result = subprocess.run(
        [sys.executable, "-m", "zip_fingerprint", command[0], str(source), *command[1:]],
        env={**os.environ, "PYTHONIOENCODING": encoding},
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == b""
    output = result.stdout.decode(encoding)
    if "text" in command:
        expected = str(source).encode(encoding, errors="backslashreplace").decode(encoding)
        assert f"Target: {expected}" in output
    else:
        data = json.loads(output)
        path = (
            data["file_metadata"]["file_path"] if command[0] == "fingerprint" else data["file_path"]
        )
        assert path == str(source)


@pytest.mark.parametrize("command", ["fingerprint", "identify", "provenance"])
def test_cli_stdout_io_error(
    tmp_path: Path,
    minimal_zip_bytes: bytes,
    command: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A real unwritable stream returns an I/O error instead of a traceback."""
    source = tmp_path / "source.zip"
    source.write_bytes(minimal_zip_bytes)
    with source.open("r", encoding="utf-8") as stream:
        with monkeypatch.context() as patch:
            patch.setattr(sys, "stdout", stream)
            assert main([command, str(source)]) == 1
    assert "Error" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["fingerprint", "identify", "provenance"])
def test_cli_closed_stdout_pipe(tmp_path: Path, minimal_zip_bytes: bytes, command: str) -> None:
    """A closed pipe must not trigger another failing flush at interpreter exit."""
    source = tmp_path / "source.zip"
    source.write_bytes(minimal_zip_bytes)
    with subprocess.Popen(
        [sys.executable, "-m", "zip_fingerprint", command, str(source)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as child:
        assert child.stdout is not None
        assert child.stderr is not None
        child.stdout.close()
        stderr = child.stderr.read()
        assert child.wait(timeout=10) == 1
    assert b"Error writing stdout" in stderr
    assert b"Exception ignored" not in stderr
    assert b"Traceback" not in stderr


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that bare CLI and --help show usage without error."""
    code = main([])
    assert code == 0
    out, err = capsys.readouterr()
    assert "usage: zip-fingerprint" in out
    assert "fingerprint" in out
    assert "identify" in out
    assert "provenance" in out
    assert "decompress-check" in out
    assert "compare" in out
    assert err == ""

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


def test_cli_provenance_stdout_and_model(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'provenance' produces valid JSON reporting tracker results."""
    zip_file = tmp_path / "provenance_test.zip"
    zip_file.write_bytes(minimal_zip_bytes)

    code = main(["provenance", str(zip_file)])
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""

    data = json.loads(out)
    assert data["file_path"] == str(zip_file)
    assert data["is_multi_provenance"] is False
    assert data["cases"] == {"case1_mixed_fingerprints": False, "case2_cascade_rewrite": False}
    assert "groups" in data
    assert "indicators" in data
    assert "suspected_applications" in data
    assert "inference_history" in data
    assert "limitations" in data
    assert len(data["limitations"]) > 0
    assert "entries" in data

    # Cross-check directly against ProvenanceTracker
    with ZipBinaryParser(zip_file) as parser:
        archive = parser.parse()
    direct_report = ProvenanceTracker(archive).analyze()
    assert data["is_multi_provenance"] == direct_report.is_multi_provenance
    assert len(data["groups"]) == len(direct_report.groups)


def test_cli_provenance_case1_mixed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify 'provenance' detects Case 1 mixed fingerprints from multiple tools."""
    # Build a mixed archive: entry 1 from 7-Zip (Windows), entry 2 from macOS Archive Utility
    raw_zip = build_zip([win_7zip("first.txt"), mac_compress("second.txt")])
    zip_file = tmp_path / "mixed.zip"
    zip_file.write_bytes(raw_zip)

    code = main(["provenance", str(zip_file)])
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""

    data = json.loads(out)
    assert data["is_multi_provenance"] is True
    assert data["cases"]["case1_mixed_fingerprints"] is True
    assert len(data["groups"]) > 1
    assert len(data["suspected_applications"]) > 0
    assert any("heuristic" in s.lower() for s in data["inference_history"])


def test_cli_provenance_text_and_output_file(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'provenance' handles text formatting and output to file."""
    zip_file = tmp_path / "prov.zip"
    zip_file.write_bytes(minimal_zip_bytes)
    out_file = tmp_path / "prov.txt"

    code = main(["provenance", str(zip_file), "--format", "text", "-o", str(out_file)])
    assert code == 0
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert stderr == ""

    assert out_file.exists()
    text = out_file.read_text(encoding="utf-8")
    assert f"Target: {zip_file}" in text
    assert "Multi-Provenance:           False" in text
    assert "Limitations:" in text


def test_cli_decompress_check_ties_and_lookup(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'decompress-check' preserves ties and looks up Table 8 correctly."""
    # 1. Multi-candidate match (ties preserved)
    code = main(
        ["decompress-check", "--bmac", "EEER", "--entry-type", "file", "--extra-field", "0x000A"]
    )
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""
    data = json.loads(out)
    assert data["total_candidates"] == 3
    assert data["candidates"] == ["WinZip", "7-Zip", "Bandizip"]

    # 2. Single match
    code_single = main(
        ["decompress-check", "--bmac", "REER", "--entry-type", "file", "--extra-field", "0x5855"]
    )
    assert code_single == 0
    out_single, _ = capsys.readouterr()
    assert json.loads(out_single)["candidates"] == ["7-Zip"]

    # 3. No match (empty catalog match, exit 0)
    code_none = main(["decompress-check", "--bmac", "HHHH", "--entry-type", "file"])
    assert code_none == 0
    out_none, _ = capsys.readouterr()
    data_none = json.loads(out_none)
    assert data_none["total_candidates"] == 0
    assert data_none["candidates"] == []

    # 4. Text format and output file
    out_file = tmp_path / "dec_check.txt"
    code_text = main(
        [
            "decompress-check",
            "--bmac",
            "EEER",
            "--entry-type",
            "file",
            "--extra-field",
            "0x000A",
            "--format",
            "text",
            "-o",
            str(out_file),
        ]
    )
    assert code_text == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "Observed BMAC:    EEER" in content
    assert "Total Candidates: 3" in content
    assert "1. WinZip" in content


def test_cli_compare_identical_and_path_invariance(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'compare' detects structural equality and ignores file_path differences."""
    zip1 = tmp_path / "archive1.zip"
    zip2 = tmp_path / "sub" / "archive2.zip"
    zip2.parent.mkdir(parents=True, exist_ok=True)
    zip1.write_bytes(minimal_zip_bytes)
    zip2.write_bytes(minimal_zip_bytes)

    # 1. Compare same path
    code = main(["compare", str(zip1), str(zip1)])
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""
    data = json.loads(out)
    assert data["equal"] is True
    assert data["structural_match"] is True
    assert data["total_differences"] == 0
    assert data["differences"]["high_weight"] == []
    assert data["differences"]["subsidiary"] == []
    assert data["target1"]["structural_hash"] == data["target2"]["structural_hash"]

    # 2. Compare different paths (Path Invariance)
    code_inv = main(["compare", str(zip1), str(zip2)])
    assert code_inv == 0
    out_inv, _ = capsys.readouterr()
    data_inv = json.loads(out_inv)
    assert data_inv["equal"] is True
    assert data_inv["structural_match"] is True
    assert data_inv["total_differences"] == 0
    assert data_inv["target1"]["file_path"] != data_inv["target2"]["file_path"]


def test_cli_compare_different_structures(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'compare' reports structural differences between incompatible archives."""
    zip_win = tmp_path / "windows.zip"
    zip_unix = tmp_path / "unix.zip"
    zip_win.write_bytes(minimal_zip_bytes)
    zip_unix.write_bytes(make_unix_zip_bytes())

    code = main(["compare", str(zip_win), str(zip_unix)])
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""

    data = json.loads(out)
    assert data["equal"] is False
    assert data["structural_match"] is False
    assert data["total_differences"] > 0
    assert data["target1"]["structural_hash"] != data["target2"]["structural_hash"]

    # host_os should be reported as different (0 vs 3)
    hw_diffs = {d["feature"]: d for d in data["differences"]["high_weight"]}
    assert "host_os" in hw_diffs
    assert hw_diffs["host_os"]["target1"] == 0
    assert hw_diffs["host_os"]["target2"] == 3


@pytest.mark.parametrize("feature", ["double_zipping", "uid", "gid"])
@pytest.mark.parametrize("output_format", ["json", "text"])
def test_cli_compare_reports_hashed_subsidiary_differences(
    tmp_path: Path, feature: str, output_format: str
) -> None:
    """Real ZIPs differing in one hashed feature must explain that difference."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("payload.txt", b"same payload")
    paths = [tmp_path / "left.zip", tmp_path / "right.zip"]
    for index, path in enumerate(paths):
        item = zipfile.ZipInfo("inner.zip" if feature == "double_zipping" else "payload.txt")
        item.compress_type = (
            zipfile.ZIP_DEFLATED if feature == "double_zipping" and index else zipfile.ZIP_STORED
        )
        if feature in {"uid", "gid"}:
            uid = 1000 + (index if feature == "uid" else 0)
            gid = 1000 + (index if feature == "gid" else 0)
            body = struct.pack("<BBIBI", 1, 4, uid, 4, gid)
            item.extra = struct.pack("<HH", 0x7875, len(body)) + body
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(item, inner.getvalue() if feature == "double_zipping" else b"payload")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "zip_fingerprint",
            "compare",
            *map(str, paths),
            "--format",
            output_format,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    left, right = ("STORED", "RECOMPRESSED") if feature == "double_zipping" else (1000, 1001)
    if output_format == "json":
        report = json.loads(result.stdout)
        assert report["structural_match"] is False
        assert report["target1"]["structural_hash"] != report["target2"]["structural_hash"]
        assert report["total_differences"] == 1
        assert report["differences"] == {
            "high_weight": [],
            "subsidiary": [{"feature": feature, "target1": left, "target2": right}],
        }
    else:
        assert "Structural Match:   False" in result.stdout
        assert f"[subsidiary]  {feature}: {left} != {right}" in result.stdout


def test_cli_compare_text_and_output_file(
    tmp_path: Path, minimal_zip_bytes: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify 'compare' text output and file writing."""
    zip_win = tmp_path / "windows.zip"
    zip_unix = tmp_path / "unix.zip"
    zip_win.write_bytes(minimal_zip_bytes)
    zip_unix.write_bytes(make_unix_zip_bytes())
    out_file = tmp_path / "diff.txt"

    code = main(
        [
            "compare",
            str(zip_win),
            str(zip_unix),
            "--format",
            "text",
            "-o",
            str(out_file),
        ]
    )
    assert code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert f"Target 1: {zip_win}" in content
    assert f"Target 2: {zip_unix}" in content
    assert "Structural Match:   False" in content
    assert "[high_weight] host_os: 0 != 3" in content


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

    # provenance
    code_prov = main(["provenance", str(special_zip)])
    assert code_prov == 0
    out_prov, err_prov = capsys.readouterr()
    assert err_prov == ""
    assert json.loads(out_prov)["file_path"] == str(special_zip)

    # compare
    code_comp = main(["compare", str(special_zip), str(special_zip)])
    assert code_comp == 0
    out_comp, err_comp = capsys.readouterr()
    assert err_comp == ""
    assert json.loads(out_comp)["structural_match"] is True


def test_cli_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify standardized exit codes and stderr reporting on error conditions."""
    missing = tmp_path / "missing.zip"
    valid = tmp_path / "valid.zip"
    valid.write_bytes(b"PK\x05\x06" + b"\x00" * 18)  # minimal empty zip

    # 1. Non-existent file -> Exit code 1
    for cmd in (
        ["fingerprint", str(missing)],
        ["identify", str(missing)],
        ["provenance", str(missing)],
    ):
        assert main(cmd) == 1
        _, stderr = capsys.readouterr()
        assert "Error: Target ZIP file does not exist" in stderr

    assert main(["compare", str(missing), str(valid)]) == 1
    _, stderr = capsys.readouterr()
    assert "Error: Target ZIP file does not exist" in stderr

    assert main(["compare", str(valid), str(missing)]) == 1
    _, stderr = capsys.readouterr()
    assert "Error: Target ZIP file does not exist" in stderr

    # 2. Directory instead of file -> Exit code 1
    for cmd in (
        ["fingerprint", str(tmp_path)],
        ["identify", str(tmp_path)],
        ["provenance", str(tmp_path)],
    ):
        assert main(cmd) == 1
        _, stderr = capsys.readouterr()
        assert "Error: Target path is not a regular file" in stderr

    assert main(["compare", str(tmp_path), str(valid)]) == 1
    _, stderr = capsys.readouterr()
    assert "Error: Target path is not a regular file" in stderr

    # 3. Corrupt ZIP file -> Exit code 1
    corrupt_file = tmp_path / "corrupt.zip"
    corrupt_file.write_bytes(b"corrupt header junk bytes not a zip")
    for cmd in (
        ["fingerprint", str(corrupt_file)],
        ["identify", str(corrupt_file)],
        ["provenance", str(corrupt_file)],
    ):
        assert main(cmd) == 1
        _, stderr = capsys.readouterr()
        assert "Error analyzing ZIP file" in stderr

    assert main(["compare", str(corrupt_file), str(valid)]) == 1
    _, stderr = capsys.readouterr()
    assert "Error analyzing ZIP file" in stderr

    # 4. Decompress-check error inputs -> Exit code 1
    # Invalid BMAC format
    assert main(["decompress-check", "--bmac", "BMAC"]) == 1
    _, stderr = capsys.readouterr()
    assert "Error: BMAC must contain four R/H/E symbols in B-M-A-C order" in stderr

    # Invalid entry type
    assert main(["decompress-check", "--bmac", "EEER", "--entry-type", "unknown"]) == 1
    _, stderr = capsys.readouterr()
    assert "Error: Unknown entry type: unknown" in stderr

    # Invalid context (folder_no_header cannot have extra field)
    assert (
        main(
            [
                "decompress-check",
                "--bmac",
                "RRRR",
                "--entry-type",
                "folder_no_header",
                "--extra-field",
                "0x000A",
            ]
        )
        == 1
    )
    _, stderr = capsys.readouterr()
    assert "Error: A folder without a header cannot have an extra field" in stderr

    # 5. Syntax errors -> Exit code 2
    with pytest.raises(SystemExit) as exc_missing_arg:
        main(["fingerprint"])
    assert exc_missing_arg.value.code == 2

    with pytest.raises(SystemExit) as exc_bad_flag:
        main(["identify", str(corrupt_file), "--nonexistent-flag"])
    assert exc_bad_flag.value.code == 2

    with pytest.raises(SystemExit) as exc_missing_bmac:
        main(["decompress-check"])
    assert exc_missing_bmac.value.code == 2

    with pytest.raises(SystemExit) as exc_missing_comp_args:
        main(["compare", str(valid)])
    assert exc_missing_comp_args.value.code == 2


def test_cli_subprocess_invocation(tmp_path: Path, minimal_zip_bytes: bytes) -> None:
    """Verify execution via python -m zip_fingerprint for all subcommands."""
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

    # 4. Module entrypoint with provenance
    res_prov = subprocess.run(
        [sys.executable, "-m", "zip_fingerprint", "provenance", str(zip_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_prov.returncode == 0
    data_prov = json.loads(res_prov.stdout)
    assert data_prov["file_path"] == str(zip_file)
    assert "cases" in data_prov
    assert "limitations" in data_prov

    # 5. Module entrypoint with decompress-check
    res_dec = subprocess.run(
        [
            sys.executable,
            "-m",
            "zip_fingerprint",
            "decompress-check",
            "--bmac",
            "EEER",
            "--entry-type",
            "file",
            "--extra-field",
            "0x000A",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_dec.returncode == 0
    data_dec = json.loads(res_dec.stdout)
    assert data_dec["candidates"] == ["WinZip", "7-Zip", "Bandizip"]

    # 6. Module entrypoint with compare
    res_comp = subprocess.run(
        [sys.executable, "-m", "zip_fingerprint", "compare", str(zip_file), str(zip_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_comp.returncode == 0
    data_comp = json.loads(res_comp.stdout)
    assert data_comp["structural_match"] is True


# --------------------------------------------------------------------------- PH4-PROV-003 (#35)
def _baseline_pair(tmp_path: Path) -> tuple:
    from tests.integration.test_provenance_tracking import Entry, ntfs, unicode_path

    names = ["keep.txt", "target.txt", "tieng-viet-\u1ec7.txt"]
    before = [Entry(n, made_by=63, extract=10, central=[ntfs()]) for n in names]
    after = [
        Entry(
            n,
            local=[] if n.isascii() else [unicode_path(n)],
            central=[] if n.isascii() else [unicode_path(n)],
        )
        for n in names
        if n != "target.txt"
    ]
    before_path, after_path = tmp_path / "before.zip", tmp_path / "after.zip"
    before_path.write_bytes(build_zip(before))
    after_path.write_bytes(build_zip(after))
    return before_path, after_path


def test_cli_provenance_default_output_has_no_new_keys(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, after = _baseline_pair(tmp_path)
    assert main(["provenance", str(after)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "baseline_comparison" not in data
    assert "catalogs_used" not in data


def test_cli_provenance_baseline_reports_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before, after = _baseline_pair(tmp_path)
    assert main(["provenance", str(after), "--baseline", str(before)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["baseline_comparison"]["rewrite_scope"] == "all"
    assert data["baseline_comparison"]["case2_detected"] is True
    assert data["cases"]["case2_cascade_rewrite"] is False


def test_cli_provenance_observed_profiles_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, after = _baseline_pair(tmp_path)
    assert main(["provenance", str(after), "--observed-profiles"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["catalogs_used"] == ["paper", "observed"]
    assert data["cases"]["case1_mixed_fingerprints"] is False


def test_cli_provenance_text_shows_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before, after = _baseline_pair(tmp_path)
    assert main(["provenance", str(after), "--baseline", str(before), "--format", "text"]) == 0
    out = capsys.readouterr().out
    assert "Baseline Rewrite Scope:     all" in out
    assert "Case 2 (Baseline):          True" in out


def test_cli_provenance_missing_baseline_is_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, after = _baseline_pair(tmp_path)
    assert main(["provenance", str(after), "--baseline", str(tmp_path / "nope.zip")]) == 1
    assert "Baseline ZIP file does not exist" in capsys.readouterr().err
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip")
    assert main(["provenance", str(after), "--baseline", str(junk)]) == 1
    assert capsys.readouterr().err


def test_cli_provenance_duplicate_names_in_baseline_is_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, after = _baseline_pair(tmp_path)
    duplicate = tmp_path / "dup.zip"
    duplicate.write_bytes(build_zip([win_7zip("keep.txt"), win_7zip("keep.txt")]))
    assert main(["provenance", str(after), "--baseline", str(duplicate)]) == 1
    assert "Duplicate entry names" in capsys.readouterr().err
