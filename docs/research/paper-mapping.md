# Ánh xạ Nội dung Bài báo Khoa học sang Kế hoạch Triển khai Kỹ thuật (Paper Mapping)

**Dự án:** File Fingerprinting of the ZIP Format for Identifying and Tracking Provenance  
**Bài báo gốc:** Minji Um, Jaehyeok Han, Sangjin Lee. *Forensic Science International: Digital Investigation*, Volume 39, Article 301271, Tháng 12/2021.  
**DOI:** `10.1016/j.fsidi.2021.301271` | **Kho tham khảo chính thức:** `https://github.com/um2inji/PKZIP`  
**Cập nhật:** Ngày 25/10/2026 (Khớp nối toàn văn từ bản PDF chính thức của bài báo).

---

## 1. Bảng Ánh xạ Toàn diện từ Bài báo sang Module Kỹ thuật

| Thành phần Bài báo | Nội dung Chi tiết Từ Bài báo Gốc (PDF) | Bảng / Hình tương ứng | Module & File Kỹ thuật Triển khai |
| :--- | :--- | :--- | :--- |
| **Mục tiêu Nghiên cứu** | Xác định nguồn gốc tạo tệp (HĐH, phần mềm nén), phát hiện lịch sử can thiệp tệp đa nguồn gốc, và phân tích dấu vết thời gian giải nén trên hệ thống. | Mục 1, Mục 5 | `src/zip_fingerprint/` (classifier, provenance, decompression) |
| **Môi trường Khảo sát** | **Windows 10 v2004 (EN & KR):** WinRAR v6.00, WinZip v25.0, 7-zip v19.00, Bandizip v6.29, Compressed folder.<br>**macOS 10.15:** Bandizip v7.0, WinZip v8, native `zip`, native `Compress`.<br>**Ubuntu 20.04 LTS:** 7-zip (7zz) v21.01, native `zip`, native `Compress`. | Mục 3 | `scripts/generate_ground_truth.py`<br>`data/metadata.json` |
| **Cấu trúc Thư mục Mẫu** | Thư mục `set1/` chứa subfolder `Study` (`capture.JPG`, `Sample.docx`, `textsm.txt`), `emptyFolder`, và file `2021.JPG`. | Hình 5 | `scripts/prepare_corpus.py`<br>`data/templates/` |
| **Trường mở rộng NTFS `0x000A`** | Kích thước 32 bytes, chứa 64-bit Windows FILETIME (Mtime, Atime, Ctime). Trên Windows chỉ xuất hiện trong Central Directory (ngoại trừ Compressed folder không có). Ubuntu 7-zip cũng sinh `0x000A`. | Bảng 1, Mục 3.1.1 | `src/zip_fingerprint/extra_fields.py` (`parse_ntfs_000a`) |
| **Độ phân giải Nanosecond** | WinZip có đặc trưng 4 ký tự hex cuối bị làm tròn thành 0: `fff0000`. Các phần mềm khác (WinRAR, 7-zip, Bandizip) giữ trọn vẹn `fffffff`. | Mục 3.1.1, Bảng 6 | `src/zip_fingerprint/extractor.py` (`extract_nanosecond_pattern`) |
| **Trường Extended Timestamp `0x5455`** | Lưu 32-bit Unix time (mtime, atime, ctime). Chiều dài biến thiên theo công cụ: 13 bytes (m/a/c), 9 bytes (m/a), 5 bytes (m only). macOS/Ubuntu Compress sinh 13 bytes ở cả LFH và CDH. native `zip` sinh 9 bytes ở LFH và 5 bytes ở CDH. | Bảng 2, Bảng 7 | `src/zip_fingerprint/extra_fields.py` (`parse_extended_ts_5455`) |
| **Trường Unix UID/GID `0x7875`** | Phiên bản 1, lưu UID và GID. Mặc định macOS là UID 501 / GID 20; Ubuntu là UID 1000 / GID 1000. | Bảng 3, Mục 3.1.2 | `src/zip_fingerprint/extra_fields.py` (`parse_unix_uid_gid_7875`) |
| **Trường Unix `0x5855`** | Dùng riêng bởi Bandizip trên macOS. LFH lưu atime, mtime, UID, GID; CDH chỉ lưu atime và mtime. | Bảng 4, Mục 3.1.1 | `src/zip_fingerprint/extra_fields.py` (`parse_unix_5855`) |
| **Trường Unicode Path `0x7075` (EFS)** | Chứa CRC32 của tên file gốc và tên file mã hóa UTF-8. Xuất hiện khi tên tệp có ký tự Unicode (tiếng Hàn CP949 / tiếng Việt) khi nén bằng WinRAR, WinZip, Bandizip trên Windows. | Bảng 5, Mục 3.1.3 | `src/zip_fingerprint/extra_fields.py` (`parse_unicode_path_7075`) |
| **Thứ tự Header ID trong Central Directory** | WinRAR & Bandizip lưu: `0x000A` -> `0x7075`.<br>WinZip lưu: `0x7075` -> `0x000A`.<br>7-zip: chỉ lưu `0x000A`. | Mục 3.1.3, Bảng 6 | `src/zip_fingerprint/extractor.py` (`extra_field_sequence`) |
| **Xử lý Thư mục Gốc & Thư mục Rỗng** | WinRAR, WinZip, 7-zip, Bandizip: sinh header cho thư mục gốc (`set1/`).<br>Compressed folder: KHÔNG sinh header cho thư mục gốc, chỉ lưu đường dẫn trong tên file con.<br>Thư mục rỗng: tất cả đều sinh header riêng. | Mục 3.2.1, Bảng 6 | `src/zip_fingerprint/extractor.py` (`folder_handling_features`) |
| **Tái Nén (Double Zipping)** | WinRAR & Compressed folder nhận diện qua đuôi `.zip` và không nén lại (kể cả đổi tên file jpg thành zip). WinZip, 7-zip, Bandizip nén lại nếu mức nén tệp con thấp. | Mục 3.2.2, Bảng 6, Bảng 7 | `src/zip_fingerprint/extractor.py` (`detect_double_zipping`) |
| **Thư mục hệ thống `__MACOSX`** | Chỉ xuất hiện khi nén bằng Compress (Finder) trên macOS; KHÔNG xuất hiện khi dùng lệnh terminal `zip`. | Mục 3.3.1, Bảng 7 | `src/zip_fingerprint/extractor.py` (`has_macosx_folder`) |
| **Data Descriptor (`0x08074b50`)** | Trên macOS & Ubuntu, không tạo khi dùng `zip`, nhưng tự động tạo mặc định khi dùng `Compress` (kèm CRC32 và kích thước trong LFH để NULL). | Mục 3.3.2, Bảng 7 | `src/zip_fingerprint/parser.py` & `extractor.py` |
| **Tính toán Timezone Offset** | Độ chênh lệch giữa MS-DOS time (cục bộ) và UTC extra timestamp (`0x000A`, `0x5455`, `0x5855`) phản ánh múi giờ tạo tệp. | Mục 3.1.1 | `src/zip_fingerprint/extractor.py` (`calculate_timezone_offset`) |
| **Bộ phân loại Tự động (Flowchart & Algorithms)** | **Hình 7:** Lưu đồ phân tầng.<br>**Algorithm 1:** Bộ phân loại trọng số cao cho Phần mềm (SW) dựa trên Data descriptor và Extra field types/lengths.<br>**Algorithm 2:** Bộ phân loại trọng số cao cho HĐH (OS) dựa trên Creating version (0x00 vs 0x03).<br>**Algorithm 3:** Bộ phân loại phụ trợ (Subsidiary low-weight) dựa trên Double zipping, `__MACOSX`, pattern nanosecond, Unicode NFC/NFD, CP949 vs UTF-8, cấu trúc thư mục, UID/GID, thứ tự an-pha-bê. | Hình 7, Hình 8 | `src/zip_fingerprint/classifier.py`<br>`src/zip_fingerprint/rules.py` |
| **Đánh giá Thực nghiệm 3 Máy Trạm** | Bộ phân loại được áp dụng trên PC1 (chỉ cài Compressed folder), PC2 (7-zip, Bandizip, Compressed folder), PC3 (7-zip, Compressed folder) để phân biệt file tạo cục bộ hay tải từ ngoài vào. | Hình 9, Mục 4.1 | `experiments/evaluate_classifier.py`<br>`results/classifications/` |
| **Thí nghiệm Can thiệp Tệp (Multi-provenance)** | Khi Thêm, Sửa, Xóa tệp bằng phần mềm khác (SW2):<br>- **Case 1:** Chỉ ảnh hưởng header phần tử thao tác (tạo kho lưu trữ đa vân tay - Mixed fingerprints).<br>- **Case 2:** Ảnh hưởng dây chuyền đến header các phần tử còn lại (đổi/xóa extra field của file cũ). | Mục 4.2, Hình 10 | `src/zip_fingerprint/provenance.py`<br>`scripts/simulate_modifications.py` |
| **Dấu vết Thời gian Giải nén (BMAC)** | Ma trận thời gian giải nén trên Windows: Thứ tự BMAC (Birth, Modified, Accessed, Changed) với các giá trị R (Real decompression time), H (Header time), E (Extra field time). Hiện tượng nghịch đảo thời gian (Time-reversal) giữa file và thư mục. | Mục 4.3, Bảng 8 | `src/zip_fingerprint/decompression.py`<br>`experiments/trace_decompression.py` |

---

## 2. Các Bảng Đặc trưng Chuẩn (Ground Truth Reference Tables)

### Bảng 6: Đặc trưng Vân tay Định dạng ZIP trên Windows (Trích xuất từ Trang 7 Bài báo)
| Đặc trưng (Identifier) | WinRAR | WinZip | 7-zip | Bandizip | Compressed folder |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Local Extra Field** | EN: N/A, KR: `0x7075` | EN: N/A, KR: `0x7075` | N/A | EN: N/A, KR: `0x7075` | N/A |
| **Central Extra Field** | EN: `0x000A`<br>KR: `0x000A` + `0x7075` | EN: `0x000A`<br>KR: `0x7075` + `0x000A` | `0x000A` | EN: `0x000A`<br>KR: `0x000A` + `0x7075` | N/A |
| **Timestamp Nanoseconds (0x000A)** | `fffffff` (đầy đủ) | `fff0000` (làm tròn 4 số cuối) | `fffffff` | `fffffff` | N/A |
| **Encoding Method** | EN: UTF-8, KR: CP949 | EN: UTF-8, KR: CP949 | EN: UTF-8, KR: CP949 | EN: UTF-8, KR: CP949 | EN: UTF-8, KR: CP949 |
| **Header of a folder** | Exist | Exist | Exist | Exist | Exist |
| **Root folder Header** | Exist | Exist | Exist | Exist | **Non-exist** |
| **Root folder File name field** | Exist | Exist | Exist | Exist | Exist |
| **Double Zipping** | **X** (Không nén lại) | **O** (Có nén lại) | **O** | **O** | **X** (Không nén lại) |
| **Order of files in archive** | Alphabetical | Alphabetical | Alphabetical | Alphabetical | Alphabetical |

### Bảng 7: Đặc trưng Vân tay Định dạng ZIP trên macOS và Ubuntu (Trích xuất từ Trang 8 Bài báo)
| Đặc trưng (Identifier) | macOS WinZip | macOS Bandizip | macOS Compress | macOS zip | Ubuntu 7-zip | Ubuntu Compress | Ubuntu zip |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Local Extra Field** | N/A | `0x5855` | `0x5455`, `0x7875` | `0x5455`, `0x7875` | N/A | `0x5455`, `0x7875` | `0x5455`, `0x7875` |
| **Central Extra Field** | N/A | `0x5855` | `0x5455`, `0x7875` | `0x5455`, `0x7875` | `0x000A` | `0x5455`, `0x7875` | `0x5455`, `0x7875` |
| **Length 0x5455 (Local)** | N/A | N/A | **13 bytes** | **9 bytes** | N/A | **13 bytes** | **9 bytes** |
| **Length 0x5455 (Central)**| N/A | N/A | **13 bytes** | **5 bytes** | N/A | **13 bytes** | **5 bytes** |
| **Encoding** | UTF-8 | UTF-8 | UTF-8 | UTF-8 | UTF-8 | UTF-8 | UTF-8 |
| **Double Zipping** | O | O | O | **X** | O | O | **X** |
| **OS Folder (`__MACOSX`)** | N/A | N/A | **Exist** | N/A | N/A | N/A | N/A |
| **Data descriptor** | N/A | N/A | **Exist** | N/A | N/A | **Exist** | N/A |
