# Thiết kế Dữ liệu và Kế hoạch Thực nghiệm (Experimental Design)

**Dự án:** File Fingerprinting of the ZIP Format for Identifying and Tracking Provenance  
**Mục tiêu:** Thiết lập quy trình sinh mẫu khoa học, kiểm soát biến thực nghiệm và quản lý dữ liệu kiểm thử có khả năng tái lập 100%.  

---

## 1. Phân loại và Cấu trúc Nhóm Mẫu Thực nghiệm (Sample Corpora)

Để kiểm chứng toàn diện các đặc trưng được nêu trong bài báo của Um et al. (2021), tập dữ liệu mẫu tổng hợp (synthetic benchmark) được phân thành các nhóm sau:

### Nhóm A: Mẫu Tiêu chuẩn Cấu trúc Tệp (Structural Baseline Group)
* **Mục đích:** Khảo sát hành vi cơ bản của từng phần mềm đối với cây thư mục điển hình.
* **Cấu trúc nội dung chuẩn (`corpus_standard`):**
  - Tệp văn bản thuần ASCII (`plain.txt`).
  - Tệp nhị phân (`binary.dat`).
  - Thư mục con lồng nhau (`level1/level2/nested.txt`).
  - Thư mục rỗng (`empty_folder/`).
  - Tệp có tên chứa ký tự Unicode đa ngôn ngữ (tiếng Hàn `한글_문서.txt`, tiếng Việt `dữ_liệu.txt`) để kiểm tra NFD vs NFC.

### Nhóm B: Mẫu Kiểm tra Biến số Cấu hình (Configuration Variant Group)
* **Mục đích:** Đánh giá mức độ ảnh hưởng của các tùy chọn nén đến fingerprint:
  - Mức độ nén (Compression level: Store, Fast, Normal, Maximum).
  - Phương thức mã hóa mật khẩu (ZipCrypto vs AES-256).
  - Tùy chọn lưu trữ đường dẫn đầy đủ (Full path) vs chỉ lưu tên tệp.
  - Tùy chọn bật/tắt ghi nhận thời gian NTFS trong các công cụ GUI.

### Nhóm C: Mẫu Đặc biệt và Tái Nén (Corner Cases & Double Zipping)
* **Mục đích:** Tái hiện thí nghiệm "Double Zipping" và các trường hợp biên:
  - Nén một tệp ZIP đã có sẵn bên trong kho lưu trữ mới.
  - Tệp rỗng (0-byte file) và kho nén rỗng (0-entry archive).
  - Kho nén lớn vượt ngưỡng 4GB hoặc > 65,535 entry (kích hoạt định dạng ZIP64).

### Nhóm D: Mẫu Dấu vết Giải nén (Decompression Artifact Group)
* **Mục đích:** Thực hiện giải nén trên hệ thống tệp NTFS và ext4/APFS để đo lường sự thay đổi của dấu thời gian MACB.

---

## 2. Ma trận Môi trường Thực nghiệm và Các Biến Số

### 2.1 Ma trận Công cụ Nén và Hệ điều hành (3 HĐH x 6 Công cụ)

| Hệ điều hành | Ứng dụng nén | Phiên bản khảo sát | Phương thức tương tác | Nhãn môi trường (Ground Truth Label) |
| :--- | :--- | :--- | :--- | :--- |
| **Windows 11** | Windows Built-in Zip | Windows 11 Build 22H2+ | PowerShell `Compress-Archive` / Explorer | `win_builtin` |
| **Windows 11** | 7-Zip | 23.01 / 24.0x | CLI `7z a` & GUI | `win_7zip` |
| **Windows 11** | WinRAR | 6.2x / 7.0x | CLI `winrar a -afzip` & GUI | `win_winrar` |
| **Windows 11** | Bandizip | 7.3x | CLI `bc.exe c` & GUI | `win_bandizip` |
| **Linux (Ubuntu)**| Info-ZIP `zip` | 3.0-12 | CLI `zip -r` | `ubuntu_zip` |
| **Linux (Ubuntu)**| GNOME File Roller | 43.x / 44.x | CLI / GUI | `ubuntu_fileroller` |
| **macOS** *(Đối chiếu)* | Apple Archive Utility | macOS Sonoma | `ditto -c -k` / GUI "Compress" | `macos_archiveutility` |
| **macOS** *(Đối chiếu)* | Info-ZIP on Mac | Apple BSD / Info-ZIP | CLI `zip -r` | `macos_zip` |

### 2.2 Kiểm soát Biến Thực nghiệm (Variables Control)

1. **Biến kiểm soát (Controlled Variables):**
   - Nội dung dữ liệu nguồn (Source payload): Đồng nhất 100% giữa các phép thử thông qua tệp mẫu cố định được sinh tự động.
   - Mốc thời gian của tệp nguồn trước khi nén: Được gán cứng (fixed timestamps: ví dụ `2024-01-01 12:00:00 UTC`) bằng kịch bản trước khi gọi lệnh nén để tránh nhiễu do thời gian thực.
2. **Biến độc lập (Independent Variables):**
   - Hệ điều hành thực thi (Windows, Linux, macOS).
   - Ứng dụng nén và phiên bản tương ứng.
   - Tham số nén (mức nén, chế độ Unicode, mật khẩu).
3. **Biến quan sát / Phụ thuộc (Dependent Variables):**
   - Chuỗi byte Header ID trong CDH và LFH.
   - Trị số `host_os` trong `version_made_by`.
   - Cờ General Purpose Bit Flag (Bit 3, Bit 11).
   - Dạng chuẩn hóa tên tệp Unicode (NFC hay NFD).
   - Độ phân giải và sai lệch múi giờ của các mốc thời gian.
   - Thời gian MACB của tệp trên đĩa sau khi giải nén.

---

## 3. Quản lý Mẫu, Lưu trữ và Tính Khả Truy (Provenance & Traceability)

### 3.1 Cấu trúc Thư mục Dữ liệu
```text
data/
├── templates/                  # Cấu trúc thư mục nguồn dùng chung để nén
│   └── standard_corpus/
├── ground_truth/               # Các tệp ZIP mẫu sinh ra từ từng phần mềm
│   ├── windows/
│   │   ├── win_builtin.zip
│   │   ├── win_7zip.zip
│   │   ├── win_winrar.zip
│   │   └── win_bandizip.zip
│   ├── linux/
│   │   └── ubuntu_zip.zip
│   └── macos/
│       └── macos_archiveutility.zip
├── metadata.json               # Siêu dữ liệu ghi nhận nguồn gốc từng mẫu
└── README.md                   # Hướng dẫn tạo lại bộ dữ liệu
```

### 3.2 Lược đồ Siêu dữ liệu Mẫu (`metadata.json`)
Mỗi tệp ZIP mẫu được liên kết chặt chẽ với bản ghi siêu dữ liệu truy nguyên:
```json
{
  "sample_id": "win_7zip_v24_default",
  "file_path": "data/ground_truth/windows/win_7zip.zip",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "environment": {
    "os": "Windows 11 Pro 64-bit",
    "os_version": "10.0.22631",
    "application": "7-Zip",
    "app_version": "24.08 (x64)",
    "command_used": "7z a -tzip output.zip input_folder"
  },
  "generation_timestamp": "2026-10-23T10:00:00Z",
  "tags": ["standard_corpus", "high_reliability"]
}
```

### 3.3 Chính sách Tránh Rò rỉ Dữ liệu (Data Leakage Prevention)
- Khi huấn luyện hoặc tinh chỉnh các quy tắc/ngưỡng của bộ phân loại:
  * **Tập phát triển / xây dựng luật (Rule Discovery Set - 70%):** Dùng để phân tích trực quan cấu trúc byte, lập bảng quy tắc.
  * **Tập kiểm nghiệm mù (Blind Validation Set - 30%):** Được sinh từ các cây thư mục khác biệt, với các tên tệp ngẫu nhiên và người dùng thao tác độc lập, dùng để đo lường độ chính xác khách quan.

### 3.4 Chính sách Lưu trữ Git
- **Tuyệt đối không commit trực tiếp tệp nhị phân lớn vào Git.**
- Chỉ lưu mã kịch bản sinh dữ liệu (`scripts/generate_ground_truth.py`) và tệp băm xác thực `data/checksums.sha256`.
- Bất kỳ ai clone repository đều có thể chạy kịch bản để sinh lại toàn bộ tập dữ liệu mẫu trong vòng dưới 2 phút.
