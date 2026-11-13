# ZIP Fingerprinting: Forensic Analysis & Provenance Tracking

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Nghiên cứu tái hiện và phát triển công cụ định danh nguồn gốc môi trường tạo (Hệ điều hành, Ứng dụng nén), phát hiện lịch sử can thiệp tệp (Provenance tracking) và phân tích dấu vết thời gian giải nén dựa trên cấu trúc nhị phân định dạng ZIP.

---

## 1. Cơ sở Khoa học và Công trình Nghiên cứu Gốc

Dự án này tái hiện độc lập công trình nghiên cứu khoa học:
- **Tiêu đề:** *File fingerprinting of the ZIP format for identifying and tracking provenance*
- **Tác giả:** Minji Um, Jaehyeok Han, Sangjin Lee (*Digital Forensic Research Center / Graduate School of Information Security, Korea University*)
- **Công bố:** *Forensic Science International: Digital Investigation*, Volume 39, Article 301271 (Tháng 12/2021)
- **DOI:** [`10.1016/j.fsidi.2021.301271`](https://doi.org/10.1016/j.fsidi.2021.301271)
- **Kho tham khảo của tác giả:** [`https://github.com/um2inji/PKZIP`](https://github.com/um2inji/PKZIP)
- **Tài liệu toàn văn PDF:** Đã được tích hợp trực tiếp tại thư mục gốc của repository.

---

## 2. Cấu trúc Kho Lưu trữ (Repository Structure)

```text
zip-fingerprinting/
├── docs/                               # Tài liệu học thuật và quản lý kỹ thuật
│   ├── project/                        # Kế hoạch triển khai chi tiết, cấu trúc repo, quyết định kỹ thuật
│   │   ├── implementation-plan.md      # Lộ trình 8 giai đoạn và 15 tasks chi tiết (DoD, phụ thuộc)
│   │   ├── repository-structure.md     # Bản giải trình cấu trúc thư mục
│   │   └── open-questions.md           # Nhật ký quyết định kiến trúc (ADR)
│   ├── research/                       # Phân tích phương pháp và ánh xạ bài báo
│   │   ├── paper-mapping.md            # Ánh xạ chi tiết toàn bộ Bảng 1-8, Hình 5-10
│   │   ├── experimental-design.md      # Thiết kế dữ liệu và kiểm soát biến
│   │   ├── reproduction-methodology.md # Phương pháp luận tái hiện từng bước
│   │   └── validation-plan.md          # Kế hoạch kiểm thử và đối chiếu
│   └── evaluation/
│       └── reproduction_report.md      # Báo cáo kết quả tái hiện khoa học
│
├── src/zip_fingerprint/                # Gói mã nguồn Python chính
│   ├── parser.py                       # Parser nhị phân nguyên thủy (EOCD -> CDH -> LFH)
│   ├── extra_fields.py                 # Giải mã chuyên sâu các trường mở rộng (0x000A, 0x5455, 0x7875, 0x5855, 0x7075)
│   ├── extractor.py                    # Trích xuất vector đặc trưng phân tầng (High-weight & Subsidiary)
│   ├── schema.py & hasher.py           # Lược đồ chuẩn hóa JSON và SHA-256 canonical hashing
│   ├── rules.py & classifier.py        # Động cơ phân loại tự động (Lưu đồ Hình 7, Thuật toán 1, 2, 3)
│   ├── provenance.py                   # Phân tích đa nguồn gốc và lịch sử can thiệp tệp (Mục 4.2 & Hình 10)
│   ├── decompression.py                # Phân tích dấu thời gian giải nén BMAC & Đảo ngược thời gian (Bảng 8)
│   └── cli.py & __main__.py            # Giao diện dòng lệnh CLI toàn diện
│
├── tests/                              # Bộ kiểm thử tự động (Unit, Integration, Benchmarks)
├── scripts/                            # Kịch bản sinh cây thư mục mẫu (Hình 5) và tạo mẫu nén
├── experiments/                        # Thí nghiệm đánh giá ma trận nhầm lẫn và đo thời gian giải nén
├── data/                               # Quản lý mẫu ZIP có nhãn (Ground-truth & Modified samples)
└── results/                            # Kết quả đo lường định lượng và báo cáo JSON
```

---

## 3. Cài đặt và Chạy thử nghiệm

### 3.1 Yêu cầu hệ thống
- Python 3.10 trở lên (khuyến nghị Python 3.11).
- Hệ điều hành: Windows, Linux (Ubuntu), hoặc macOS.

### 3.2 Cài đặt phụ thuộc
```powershell
# Cài đặt gói ở chế độ editable kèm phụ thuộc kiểm thử
pip install -e ".[dev]"
```

### 3.3 Chạy bộ kiểm thử tự động
```powershell
python -m pytest
```

### 3.4 Continuous Integration (CI)

GitHub Actions chạy workflow `CI` khi push vào `main`, khi mở hoặc cập nhật
pull request vào `main`, và khi chạy thủ công bằng **Actions → CI → Run workflow**
(sau khi workflow có trên nhánh mặc định).

Workflow kiểm tra bốn tổ hợp: Ubuntu và Windows, mỗi hệ điều hành với Python
3.10 và 3.11. Mỗi job cài package, kiểm tra phụ thuộc và CLI, rồi chạy toàn bộ
bộ test. Có thể chạy các lệnh tương đương trong môi trường Python riêng tại máy:

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pip check
zip-fingerprint --help
python -m pytest --cov=zip_fingerprint --cov-report=term-missing --cov-report=xml:coverage.xml --junitxml=junit.xml
```

Trong **Actions → chọn lần chạy → Artifacts**, tải
`test-reports-<os>-py<python>` để xem `coverage.xml` và `junit.xml`.
Báo cáo được giữ trong 7 ngày và vẫn được tải lên khi test thất bại nếu đã
được sinh; lần chạy bị hủy có thể không có artifact.

Coverage hiện chỉ để theo dõi, chưa đặt ngưỡng bắt buộc. Test integration cho security
hiện còn là placeholder. Classifier đã có test cho 12 profile lý thuyết và provenance
tracker đã có test tích hợp trên ZIP dựng từ byte, nhưng CI xanh chưa chứng minh độ
chính xác trên bộ ZIP thực tế hoặc kết quả tái hiện toàn bộ bài báo.
thực tế hoặc kết quả tái hiện toàn bộ bài báo.

### 3.5 Bộ phân loại nguồn gốc

`AutomatedClassifier.classify(features)` nhận dictionary từ
`StructuralFeatureExtractor.extract()` và trả danh sách `CandidateEnvironment`:

- Algorithm 1 lọc theo Data descriptor, cặp Extra Fields LFH/CDH và độ dài `0x5455`.
- Algorithm 2 lọc theo host OS. Nếu còn duy nhất một profile, trả `HIGH`, điểm `1.0`
  trong phạm vi bộ luật được hỗ trợ.
- Algorithm 3 xếp hạng các profile còn lại bằng bằng chứng phụ trợ; giữ các ứng
  viên đồng hạng và ghi lại bằng chứng khớp/mâu thuẫn. Điểm `SUBSIDIARY` là điểm
  heuristic, không phải xác suất được hiệu chuẩn.

Không đủ bằng chứng cấu trúc, OS không được hỗ trợ, archive rỗng hoặc host OS
không đồng nhất sẽ trả `[]`. Giá trị không quan sát được không được tính là bằng
chứng phủ định. Profile ASCII của Windows 7-Zip và Bandizip có thể đồng hạng;
cần thêm bằng chứng để phân biệt. CLI chưa được nối với classifier trong bước này.

### 3.6 Bộ truy vết đa nguồn gốc

`ProvenanceTracker(archive).analyze()` nhận `ZipArchiveRecord` và trả `ProvenanceReport`
(`analyze_modifications()` trả dictionary JSON tương ứng), không cần giải nén:

- Mỗi cặp CDH/LFH được lấy vân tay và phân loại độc lập bằng `AutomatedClassifier`.
  Các entry được gom nhóm khi còn ít nhất một môi trường tương thích chung; biến thể
  `0x7075` do tên non-ASCII của cùng một công cụ không bị coi là nguồn thứ hai.
- **Case 1** (vân tay hỗn hợp): nhiều nhóm không tương thích, host OS lẫn lộn hoặc cấu
  trúc ngoài catalog khác các entry còn lại.
- **Case 2** (ghi đè dây chuyền): LFH của một entry khớp profile này còn CDH khớp profile
  khác (ví dụ Extra Field bị xóa khỏi CDH sau thao tác Delete bằng SW2).
- Chỉ bằng chứng trọng số cao bật `is_multi_provenance`; mẫu nanosecond lẫn lộn chỉ là
  chỉ báo `SUBSIDIARY` (`requires_further_analysis`). Vai trò SW1/SW2 là suy luận heuristic
  theo offset LFH nhỏ nhất.

Không phát hiện được khi SW2 ghi lại toàn bộ LFH và CDH, hoặc khi hai profile trùng đặc
trưng (ví dụ Windows 7-Zip và Bandizip với tên ASCII). CLI chưa được nối trong bước này.

### 3.7 Sinh mẫu can thiệp bằng công cụ thực tế (PH4-PROV-002)

```powershell
python scripts/simulate_modifications.py
# Nghiệm thu nghiêm ngặt: exit 2 nếu chưa bao phủ cả Case 1 và Case 2
python scripts/simulate_modifications.py --require-cases
```

Script dò 7-Zip, WinRAR, Bandizip console (`bz.exe`/`bc.exe`), WinZip Command Line
Add-On (`wzzip.exe`) và Windows compressed-folder handler. Có thể chỉ định đường
dẫn bằng `--7zip`, `--winrar`, `--bandizip`, `--winzip`, chọn kịch bản bằng
`--scenario A` (lặp lại để chọn nhiều kịch bản), hoặc đổi nơi lưu bằng `--output`.
Xem chi tiết tại [hướng dẫn thí nghiệm](docs/research/modification-simulator.md).

Mỗi lần chạy tạo thư mục riêng `data/modified_samples/run-*/` chứa ZIP trước/sau,
nguồn mẫu và `metadata.json`: công cụ/phiên bản, lệnh, checksum, kiểm tra payload,
phân tích provenance và thay đổi extra fields của các entry không bị thao tác.
Các artifact được Git bỏ qua; script không ghi đè mẫu cũ. Công cụ thiếu được ghi
`skipped`, lỗi được ghi `failed`; mã thoát lần lượt là 0 khi có mẫu hợp lệ, 1 khi
có lỗi, 2 khi không có mẫu hoặc không đạt điều kiện `--require-cases`.

Đã chạy trên Windows với 7-Zip 26.04 và WinRAR 6.23.0: sinh 4 cặp mẫu, tái hiện
Case 1 qua biến thể tắt lưu timestamp của 7-Zip; chưa tái hiện Case 2. Bandizip và
WinZip CLI chưa có trên máy. **Chưa đạt đầy đủ DoD của PH4-PROV-002.**

---

### 3.8 Phân tích dấu thời gian giải nén (PH5-DEC-001)

`DecompressionAnalyzer.identify_decompressor(observed_bmac, entry_type, extra_field)`
tra Bảng 8 và trả **mọi ứng viên** phù hợp, theo thứ tự WinRAR, WinZip, 7-Zip,
Bandizip, Compressed folder. Mẫu gồm 4 ký hiệu theo B-M-A-C: `R` (giải nén thực
tế), `H` (mtime trong header DOS), `E` (timestamp trong extra field).

```python
from zip_fingerprint.decompression import DecompressionAnalyzer

analyzer = DecompressionAnalyzer()
analyzer.identify_decompressor("REER", "file", "0x5855")  # ["7-Zip"]
analyzer.identify_decompressor("ERRR", "folder_with_files", 0x000A)
# ["WinZip", "Bandizip"]
```

`entry_type` nhận `file`, `folder_with_files`, `empty_folder`, `folder_no_header`.
`extra_field` nhận ID nguyên, chuỗi hex có tiền tố `0x`, hoặc `None`/`"None"`;
`"N/A"` chỉ dành cho thư mục không header. BMAC bỏ qua hoa/thường và khoảng trắng.
Đầu vào sai báo `ValueError`; mẫu/ID hợp lệ ngoài catalog trả `[]`. API cũ
`evaluate_bmac_pattern(pattern, state, header_id)` vẫn dùng được với các nhãn
trạng thái trong bảng (`File`, `Contains file(s)`, `Empty`, `No header`).

`check_time_reversal(parent_folder_time, subfolder_time, creation_time, mod_time)`
nhận các `datetime` tùy chọn, trả mã `CREATION_AFTER_MODIFICATION` và/hoặc
`SUBFOLDER_BEFORE_PARENT`. Chỉ so sánh từng cặp đủ dữ liệu; timestamp thư mục cha/con
phải cùng loại thuộc tính. Datetime có múi giờ được so theo UTC; không trộn naive
và aware trong một cặp. Kết quả rỗng có thể do thiếu dữ liệu, không chứng minh
không có nghịch đảo. Các cảnh báo này không tự chứng minh can thiệp hoặc phần mềm
đã được sử dụng.

Đã đối chiếu **13 dòng × 5 công cụ** với PDF trang 9; đây là profile thực nghiệm
lịch sử, chưa xác thực trên phần mềm hiện hành. Đo filesystem thuộc PH5-DEC-002;
nối CLI thuộc PH7-CLI-001.

### 3.9 Corpus chuẩn có thể tái tạo (PH6-DATA-001)

```powershell
python scripts/prepare_corpus.py
python -m pytest tests/unit/test_prepare_corpus.py
```

Sinh `data/templates/set1/` đúng cây Hình 5 với JPEG/DOCX hợp lệ, kèm mẫu Hàn
NFC/NFD, payload CP949, tiếng Việt và ZIP con trong `auxiliary/`. Manifest cố định
đường dẫn và SHA-256; atime/mtime được đặt và kiểm tra tại `2021-01-11 11:30:59 UTC`.
Payload được Git bỏ qua và sinh lại trước mỗi thực nghiệm. Script hỗ trợ `--output`,
từ chối dữ liệu lạ hoặc đường dẫn liên kết, không xóa file.

Đây là corpus thay thế tự tạo, chưa phải ground truth của archiver. Creation/change
time không được cố định; đọc hoặc liệt kê thư mục có thể đổi atime. Xem cách chạy,
encoding và giới hạn timestamp tại [data/README.md](data/README.md).

### 3.10 Sinh ZIP ground truth Windows CLI (PH6-DATA-002)

```powershell
python scripts/generate_ground_truth.py
```

Tự dò công cụ và nén ba biến thể `root`, `contents`, `auxiliary`; kiểm tra CRC,
inventory/checksum và ghi catalogue `data/metadata.json` cùng báo cáo từng run.
Mỗi mẫu có nguồn riêng với timestamp được khôi phục trước khi nén; không ghi đè
run cũ. Đã xác minh 9 ZIP từ 7-Zip/WinRAR/PowerShell, Bandizip thiếu được ghi skip.
PowerShell có nhãn riêng, chưa đối chứng Explorer/GUI; xem [hướng dẫn](data/README.md).
Nghiệm thu chỉ áp dụng cho Windows/Python và các phiên bản công cụ đã đo; chưa
xác thực Bandizip native, profile CP949 do archiver tạo, accuracy hoặc BMAC. Xem
[giới hạn nghiệm thu hiện tại](docs/evaluation/reproduction_report.md#giới-hạn-nghiệm-thu-hiện-tại-13112026).

## 4. Lộ trình Thực hiện và Tiến độ

Tiến độ được theo dõi chi tiết tại [`docs/project/implementation-plan.md`](docs/project/implementation-plan.md).
- **Giai đoạn 0:** Thiết lập dự án & Khởi tạo cấu trúc thư mục `[HOÀN THÀNH]`
- **Giai đoạn 1:** Triển khai Bộ phân tích nhị phân cốt lõi (Parser & Extra fields) `[HOÀN THÀNH]`
- **Giai đoạn 2:** Trích xuất đặc trưng & Băm cấu trúc xác định `[HOÀN THÀNH]`
- **Giai đoạn 3:** Động cơ phân loại tự động 2 tầng (Algorithm 1, 2, 3) `[HOÀN THÀNH — kiểm thử lý thuyết; chưa đánh giá corpus thực]`
- **Giai đoạn 4:** Phân tích đa nguồn gốc & Lịch sử can thiệp tệp (Mục 4.2) `[PH4-PROV-001 HOÀN THÀNH; PH4-PROV-002 đã triển khai script và sinh mẫu thật — chưa đạt DoD Case 2]`
- **Giai đoạn 5:** Thẩm định dấu vết giải nén & Nghịch đảo thời gian `[PH5-DEC-001 HOÀN THÀNH — đối chiếu Bảng 8; PH5-DEC-002 chưa đo thực tế]`
- **Giai đoạn 6:** Pipeline sinh mẫu thực nghiệm (Hình 5) `[PH6-DATA-001/002 hoàn thành — nghiệm thu cục bộ Windows/Python 3.11; chưa đối chứng GUI/macOS/Linux]`
- **Giai đoạn 7:** Hoàn thiện CLI & Báo cáo đánh giá khoa học
- **Giai đoạn 8:** Mở rộng Nghiên cứu: Dấu vân tay Tài liệu Văn phòng OOXML & Java Archive ([Tài liệu đề xuất](docs/research/ooxml-provenance-extension.md)) [ĐÃ ĐỀ XUẤT]
