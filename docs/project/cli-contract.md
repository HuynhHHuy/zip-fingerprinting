# Quy ước Giao diện Dòng lệnh (CLI Contract) & Mã Thoát (Exit Codes)

> **Mã công việc:** `PH7-CLI-001`  
> **Tài liệu đặc tả hợp đồng (Contract Specification) cho công cụ dòng lệnh `zip-fingerprint`**  
> **Áp dụng cho:** `PH7-CLI-001/A` (Fingerprint & Identify) và `PH7-CLI-001/B` (Provenance & Decompress-check)

---

## 1. Mục tiêu và Nguyên tắc Thiết kế

Công cụ dòng lệnh `zip-fingerprint` được xây dựng nhằm cung cấp giao diện chuẩn xác cho giám định viên pháp y số và các pipeline đánh giá tự động (`PH7-EVAL-002`).

### Nguyên tắc cốt lõi:
1. **Phân tách luồng dữ liệu (Stream Isolation):**
   - **`stdout`:** Chỉ dành cho dữ liệu đầu ra hợp lệ (JSON hoặc bảng báo cáo text). Không in thông tin log hoặc cảnh báo vào `stdout` để các script bên ngoài có thể pipe (`|`) hoặc redirect trực tiếp.
   - **`stderr`:** Chỉ dành cho thông báo lỗi (`Error: ...`) hoặc thông tin chuẩn đoán.
2. **Quy ước mã thoát chuẩn POSIX (Exit Codes):**
   - `0`: Thực thi thành công hoàn toàn.
   - `1`: Lỗi dữ liệu hoặc I/O (tệp không tồn tại, tệp ZIP hỏng/không hợp lệ, lỗi ghi tệp output, hoặc subcommand chưa được hỗ trợ).
   - `2`: Lỗi cú pháp dòng lệnh (sai cờ, thiếu tham số bắt buộc, do `argparse` kiểm soát).
3. **Bất biến cấu trúc pháp y (Forensic Structural Invariance):**
   - Mã băm cấu trúc (`structural_hash`) chỉ tính toán dựa trên các đặc trưng cấu trúc bất biến (`high_weight` và `subsidiary features`), độc lập hoàn toàn với đường dẫn tệp (`file_path`) hay vị trí lưu trữ trên đĩa.
   - Phân biệt rõ ràng giữa **Mã băm cấu trúc** (`structural_hash`) và **Mã băm nội dung nhị phân** toàn bộ archive (`sha256_content`).
4. **Bảo vệ ZIP đầu vào và encoding đầu ra:**
   - `fingerprint` và `identify` từ chối `--output` trỏ cùng file với ZIP đầu vào, kể cả đường dẫn tương đối, hardlink hoặc symlink. Trả `1`, báo lỗi qua `stderr` và giữ nguyên ZIP.
   - JSON dùng escape Unicode (`\uXXXX`); đọc bằng JSON parser vẫn nhận đúng giá trị Unicode gốc. Schema và structural hash không đổi.
   - File output được ghi bằng UTF-8. Text trên `stdout` giữ Unicode nếu encoding hỗ trợ; ký tự không biểu diễn được dùng backslash escape, ví dụ khi stdout dùng cp1252.
   - Lỗi ghi hoặc flush `stdout` được báo qua `stderr` với exit `1`.
   - Kiểm tra file trùng áp dụng tại thời điểm ghi; không bảo đảm chống process khác đổi liên kết/đường dẫn đồng thời. Người dùng phải tránh redirect shell trực tiếp vào ZIP nguồn (`> source.zip`), vì shell có thể truncate file trước khi CLI chạy.

---

## 2. Đặc tả Subcommands & Tham số

### 2.1 Subcommand: `fingerprint` (PH7-CLI-001/A)
Trích xuất đặc trưng cấu trúc nhị phân và tính toán mã băm cấu trúc SHA-256 xác định.

* **Cú pháp:**
  ```bash
  zip-fingerprint fingerprint <zip_path> [--output <file_path>]
  ```
* **Tham số:**
  - `<zip_path>` *(bắt buộc)*: Đường dẫn đến tệp ZIP cần phân tích (hỗ trợ đường dẫn có khoảng trắng và ký tự Unicode/UTF-8).
  - `-o, --output <file_path>` *(tùy chọn)*: Đường dẫn tệp để ghi dữ liệu JSON. Nếu không chỉ định, kết quả được xuất ra `stdout`.
* **Định dạng đầu ra:** JSON chuẩn tuân thủ `FingerprintSchemaV1`:
  ```json
  {
    "schema_version": "1.0.0",
    "file_metadata": {
      "file_path": "sample.zip",
      "file_size": 1024,
      "total_entries": 3,
      "total_files": 2,
      "total_folders": 1,
      "sha256_content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "high_weight_features": {
      "host_os": 0,
      "has_consistent_host_os": true,
      "data_descriptor_present": false,
      "local_extra_field_ids": [10],
      "local_extra_field_lengths": {"10": [32]},
      "local_extra_field_sequence": [10],
      "central_extra_field_ids": [10],
      "central_extra_field_lengths": {"10": [32]},
      "central_extra_field_sequence": [10]
    },
    "subsidiary_features": {
      "nanosecond_pattern": "fffffff",
      "has_macosx_folder": false,
      "unicode_normalization": "NFC",
      "filename_encoding": "UTF-8",
      "uid_gid": null,
      "double_zipping_behavior": null,
      "root_folder_header_exists": true,
      "empty_folder_headers_exist": false,
      "timezone_offset_minutes": null,
      "is_alphabetical_order": true
    },
    "structural_hash": "a1b2c3d4..."
  }
  ```

---

### 2.2 Subcommand: `identify` (PH7-CLI-001/A)
Nhận diện hệ điều hành và công cụ nén nguồn gốc dựa trên bộ luật phân cấp (Thuật toán 1, 2, 3 trong Um et al., 2021).

* **Cú pháp:**
  ```bash
  zip-fingerprint identify <zip_path> [--format {json,text}] [--output <file_path>]
  ```
* **Tham số:**
  - `<zip_path>` *(bắt buộc)*: Đường dẫn đến tệp ZIP cần phân loại.
  - `--format {json, text}` *(tùy chọn, mặc định `json`)*: Định dạng xuất kết quả.
  - `-o, --output <file_path>` *(tùy chọn)*: Đường dẫn tệp ghi kết quả.
* **Quy tắc bảo toàn ứng viên đồng hạng (Tie-Preservation):**
  - Khi có nhiều môi trường có cùng điểm bằng chứng (ví dụ Windows 7-Zip và Bandizip với tên ASCII), **toàn bộ ứng viên phải được giữ nguyên trong mảng `candidates`**, tuyệt đối không chọn tùy tiện hoặc giả định xác suất.
* **Định dạng JSON (`--format json`):**
  ```json
  {
    "file_path": "sample.zip",
    "structural_hash": "a1b2c3d4...",
    "archive_sha256": "e3b0c442...",
    "total_candidates": 1,
    "candidates": [
      {
        "target_os": "Windows",
        "application": "7-Zip",
        "confidence": 1.0,
        "weight_tier": "HIGH",
        "matched_rules": [
          "data_descriptor=False",
          "extra_fields=(0x000A/0x000A)"
        ],
        "notes": [
          "Unique structural/OS match within the supported empirical catalog."
        ]
      }
    ]
  }
  ```

---

### 2.3 Subcommand: `provenance` (PH7-CLI-001/B)
Phân tích lịch sử can thiệp tệp, phát hiện đa nguồn gốc (Case 1 mixed fingerprints vs Case 2 cascade rewrite) và xuất các giới hạn pháp y.

* **Cú pháp:**
  ```bash
  zip-fingerprint provenance <zip_path> [--format {json,text}] [--output <file_path>]
  ```
* **Tham số:**
  - `<zip_path>` *(bắt buộc)*: Đường dẫn đến tệp ZIP cần phân tích.
  - `--format {json, text}` *(tùy chọn, mặc định `json`)*: Định dạng xuất kết quả.
  - `-o, --output <file_path>` *(tùy chọn)*: Đường dẫn tệp ghi kết quả (từ chối nếu trùng input).
* **Định dạng JSON (`--format json`):**
  ```json
  {
    "file_path": "sample.zip",
    "is_multi_provenance": false,
    "requires_further_analysis": false,
    "cases": {
      "case1_mixed_fingerprints": false,
      "case2_cascade_rewrite": false
    },
    "groups": [],
    "indicators": [],
    "suspected_applications": [],
    "inference_history": [
      "Fingerprinted 1 entries independently from CDH/LFH pairs without decompression.",
      "All entries share at least one compatible environment (one group).",
      "No high-weight heterogeneity found. This does not prove single provenance: SW2 may rewrite every header, or SW1/SW2 profiles may overlap."
    ],
    "limitations": [
      "Absence of heterogeneity does not prove single provenance: SW2 may rewrite every header, or SW1/SW2 profiles may overlap.",
      "Subsidiary signals (e.g. nanosecond timestamp patterns) require further analysis and do not establish multi-provenance alone.",
      "Role assignment (ORIGINAL_CREATOR vs MODIFIER) is heuristic based on header offsets (Add operations append entries).",
      "Synthetic tests and reconstructed headers do not establish native reproduction of Case 2."
    ],
    "entries": []
  }
  ```

---

### 2.4 Subcommand: `decompress-check` (PH7-CLI-001/B)
Đối chiếu dấu vết mốc thời gian giải nén trên hệ thống tệp Windows NTFS với Bảng 8 (Um et al., 2021).

* **Cú pháp:**
  ```bash
  zip-fingerprint decompress-check --bmac <pattern> [--entry-type <type>] [--extra-field <field>] [--format {json,text}] [--output <file_path>]
  ```
* **Tham số:**
  - `--bmac <pattern>` *(bắt buộc)*: Mẫu BMAC quan sát gồm 4 ký tự R/H/E (ví dụ `EEER`, `REER`, `RERR`, `HHHR`).
  - `--entry-type <type>` *(tùy chọn, mặc định `file`)*: Loại entry (`file`, `folder_with_files`, `empty_folder`, `folder_no_header`).
  - `--extra-field <field>` *(tùy chọn, mặc định `None`)*: Mã trường mở rộng (ví dụ `0x000A`, `0x5455`, `0x5855`, `None`, `N/A`).
  - `--format {json, text}` *(tùy chọn, mặc định `json`)*: Định dạng xuất kết quả.
  - `-o, --output <file_path>` *(tùy chọn)*: Đường dẫn tệp ghi kết quả.
* **Quy tắc bảo toàn ứng viên đồng hạng (Tie-Preservation):**
  - Mọi công cụ thỏa mãn mẫu BMAC trong Bảng 8 đều được giữ nguyên theo thứ tự cột chuẩn (`WinRAR`, `WinZip`, `7-Zip`, `Bandizip`, `Compressed folder`).
  - Mẫu hợp lệ không có công cụ khớp trả về danh sách rỗng `[]` với exit code `0`.
  - Mẫu sai cú pháp hoặc ngữ cảnh không hợp lệ (ví dụ `folder_no_header` kèm `0x000A`) báo lỗi qua `stderr` với exit code `1`.
* **Định dạng JSON (`--format json`):**
  ```json
  {
    "observed_bmac": "EEER",
    "entry_type": "file",
    "extra_field": "0x000A",
    "total_candidates": 3,
    "candidates": [
      "WinZip",
      "7-Zip",
      "Bandizip"
    ]
  }
  ```

---

### 2.5 Subcommand: `compare` (PH7-CLI-001/B)
So sánh đặc trưng cấu trúc pháp y giữa hai tệp ZIP, báo cáo tính tương đương cấu trúc và danh sách khác biệt.

* **Cú pháp:**
  ```bash
  zip-fingerprint compare <zip_path1> <zip_path2> [--format {json,text}] [--output <file_path>]
  ```
* **Tham số:**
  - `<zip_path1>` *(bắt buộc)*: Đường dẫn tệp ZIP thứ nhất.
  - `<zip_path2>` *(bắt buộc)*: Đường dẫn tệp ZIP thứ hai.
  - `--format {json, text}` *(tùy chọn, mặc định `json`)*: Định dạng xuất kết quả.
  - `-o, --output <file_path>` *(tùy chọn)*: Đường dẫn tệp ghi kết quả (từ chối nếu trùng một trong hai input).
* **Quy tắc so sánh cấu trúc:**
  - Không so sánh `file_path` như sự khác biệt cấu trúc; hai tệp khác đường dẫn nhưng giống nhau về đặc trưng cấu trúc có `structural_match: true`.
  - Không tự gán điểm tương đồng tùy ý không có định nghĩa; chỉ so sánh tường minh các trường trong `high_weight_features` và `subsidiary_features`.
* **Định dạng JSON (`--format json`):**
  ```json
  {
    "target1": {
      "file_path": "sample1.zip",
      "structural_hash": "a1b2c3d4...",
      "archive_sha256": "e3b0c442..."
    },
    "target2": {
      "file_path": "sample2.zip",
      "structural_hash": "a1b2c3d4...",
      "archive_sha256": "f5a6b7c8..."
    },
    "equal": true,
    "structural_match": true,
    "total_differences": 0,
    "differences": {
      "high_weight": [],
      "subsidiary": []
    }
  }
  ```

---

## 3. Quy ước Xử lý Lỗi (Error Handling Protocol)

| Tình huống | Kênh xuất | Định dạng thông báo | Exit Code |
| :--- | :--- | :--- | :--- |
| **Thành công** | `stdout` (hoặc file) | Dữ liệu JSON hoặc văn bản báo cáo | `0` |
| **Tệp không tồn tại** | `stderr` | `Error: Target ZIP file does not exist: '<path>'` | `1` |
| **Đường dẫn là thư mục** | `stderr` | `Error: Target path is not a regular file: '<path>'` | `1` |
| **Tệp ZIP hỏng / không hợp lệ** | `stderr` | `Error analyzing ZIP file: <chi_tiết_lỗi>` | `1` |
| **Lỗi ghi tệp output** | `stderr` | `Error writing output file '<path>': <chi_tiết_lỗi>` | `1` |
| **Output trùng file input** | `stderr` | `Error: Output file must not be an input ZIP or an alias.` | `1` |
| **BMAC sai định dạng** | `stderr` | `Error: BMAC must contain four R/H/E symbols in B-M-A-C order` | `1` |
| **Ngữ cảnh decompress-check sai** | `stderr` | `Error: <chi_tiết_lỗi_từ_DecompressionAnalyzer>` | `1` |
| **Thiếu đối số bắt buộc** | `stderr` | Do `argparse` sinh (e.g. `zip-fingerprint: error: the following arguments are required...`) | `2` |
| **Cờ / tùy chọn không hợp lệ** | `stderr` | Do `argparse` sinh (e.g. `zip-fingerprint: error: unrecognized arguments: ...`) | `2` |

---

## 4. Kiểm chứng regression CLI/A & CLI/B — 2026-11-17

Môi trường: Windows, Python 3.11.9 & Python 3.13; worktree nhánh `feat/cli-provenance-decompress-compare`.

- Toàn bộ suite pytest: **204 passed, 5 skipped** (mốc ban đầu: 161 passed).
- Test riêng CLI (`test_cli.py`): **43 passed, 3 skipped**, độ bao phủ `src/zip_fingerprint/cli.py` đạt **85%**.
- Các ca skip symlink do môi trường Windows không cấp đặc quyền SeCreateSymbolicLinkPrivilege cho non-admin (`WinError 1314`); hardlink đã được kiểm tra trực tiếp.
- Mypy trên 15 source files: `Success: no issues found`.
- Black và Flake8 (max-line-length 100): 100% pass không cảnh báo.

Lệnh chạy tại worktree (dùng venv hiện có của checkout chính):

```powershell
$python = '../zip-fingerprinting/.venv-ci/Scripts/python.exe'
$env:PYTHONPATH = Join-Path (Get-Location) 'src'
$env:PYTHONDONTWRITEBYTECODE = '1'
& $python -B -m pytest -p no:cacheprovider
& $python -m mypy src
& $python -m black --check src/zip_fingerprint/cli.py tests/unit/test_cli.py
& $python -m flake8 --max-line-length=100 src/zip_fingerprint/cli.py tests/unit/test_cli.py
& $python -m pip check
git diff --check
```
