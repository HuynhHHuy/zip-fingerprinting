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

### 2.3 Subcommands dành cho Phần B (`PH7-CLI-001/B`)
Các lệnh sau đã được đăng ký trong parser nhưng chưa cài đặt logic xử lý ở Phase A:
* `provenance <zip_path>`: Phân tích lịch sử can thiệp tệp, phát hiện đa nguồn gốc (Case 1 vs Case 2).
* `decompress-check --bmac <pattern>`: Đối chiếu dấu vết mốc thời gian giải nén trên NTFS với Bảng 8.

**Quy ước bắt buộc ở Phase A:**
Khi người dùng gọi các lệnh này, CLI **bắt buộc** xuất thông báo lỗi ra `stderr` và trả về mã thoát `1`:
```text
Error: Subcommand 'provenance' is not yet implemented (PH7-CLI-001/B).
```
Tuyệt đối không trả về `0` hoặc in placeholder rỗng.

---

## 3. Quy ước Xử lý Lỗi (Error Handling Protocol)

| Tình huống | Kênh xuất | Định dạng thông báo | Exit Code |
| :--- | :--- | :--- | :--- |
| **Thành công** | `stdout` (hoặc file) | Dữ liệu JSON hoặc văn bản báo cáo | `0` |
| **Tệp không tồn tại** | `stderr` | `Error: Target ZIP file does not exist: '<path>'` | `1` |
| **Đường dẫn là thư mục** | `stderr` | `Error: Target path is not a regular file: '<path>'` | `1` |
| **Tệp ZIP hỏng / không hợp lệ** | `stderr` | `Error analyzing ZIP file: <chi_tiết_lỗi>` | `1` |
| **Lỗi ghi tệp output** | `stderr` | `Error writing output file '<path>': <chi_tiết_lỗi>` | `1` |
| **Subcommand chưa cài đặt** | `stderr` | `Error: Subcommand '<cmd>' is not yet implemented (PH7-CLI-001/B).` | `1` |
| **Thiếu đối số bắt buộc** | `stderr` | Do `argparse` sinh (e.g. `zip-fingerprint: error: the following arguments are required...`) | `2` |
| **Cờ / tùy chọn không hợp lệ** | `stderr` | Do `argparse` sinh (e.g. `zip-fingerprint: error: unrecognized arguments: ...`) | `2` |
