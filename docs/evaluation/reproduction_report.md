# Báo cáo Khoa học Tái hiện Thực nghiệm (Scientific Reproduction Report)

**Bài báo đối chiếu:**  
*File fingerprinting of the ZIP format for identifying and tracking provenance*  
Minji Um, Jaehyeok Han, Sangjin Lee. *Forensic Science International: Digital Investigation* 39 (2021) 301271.  
DOI: `10.1016/j.fsidi.2021.301271` | Kho tham khảo: `https://github.com/um2inji/PKZIP`

---

## 1. Mục tiêu Tái hiện
Xác minh độc lập các phát hiện khoa học của nhóm tác giả:
1. Tính đặc trưng của cấu trúc nhị phân ZIP (Extra fields, vị trí LFH/CDH, thứ tự header, độ phân giải nanosecond, mã hóa UTF-8/CP949, chuẩn hóa Unicode NFD/NFC).
2. Hiệu quả phân loại nguồn gốc môi trường tạo (HĐH và phần mềm) theo 3 thuật toán (Algorithm 1, Algorithm 2, Algorithm 3 trong Hình 7 & 8).
3. Khả năng phát hiện can thiệp đa nguồn gốc (Multi-provenance tracking khi thêm, sửa, xóa tệp - Mục 4.2).
4. Hiện tượng nghịch đảo thời gian (Time-reversal phenomenon) và ma trận BMAC khi giải nén (Mục 4.3 & Bảng 8).

---

## 2. Kết quả Đối chiếu Bảng Dữ liệu Chuẩn (Benchmark Results)

### 2.1 Bảng 6: Đặc trưng Vân tay trên Windows (Ground Truth)
*(Sẽ được cập nhật tự động sau khi chạy `tests/benchmarks/test_paper_matrices.py`)*

### 2.2 Bảng 7: Đặc trưng Vân tay trên macOS và Ubuntu (Ground Truth)
*(Sẽ được cập nhật tự động sau khi chạy `tests/benchmarks/test_paper_matrices.py`)*

### 2.3 Bảng 8: Ma trận Dấu thời gian Giải nén BMAC (Decompression Matrix)
Ngày 06/11/2026: `DecompressionAnalyzer` đã mã hóa **13 dòng × 5 công cụ** của
Bảng 8, PDF trang 9, gồm cả Folder/No header. Benchmark
`tests/benchmarks/test_paper_matrices.py::test_table_8_all_decompressor_candidates`
đối chiếu toàn bộ 65 ô với dữ liệu kỳ vọng chép độc lập từ PDF và kiểm tra danh
sách ứng viên đầy đủ khi nhiều công cụ có chung mẫu. Đây là kiểm chứng việc mã
hóa bảng, **không phải độ chính xác trên bộ dữ liệu thực tế**.

Kiểm thử đơn vị bao phủ hai điều kiện nghịch đảo (B > M và thời gian thư mục con
sớm hơn cha), trường hợp bằng nhau, thiếu dữ liệu và múi giờ. Việc đo timestamp
filesystem trên các phiên bản công cụ hiện hành vẫn chưa thực hiện; thuộc
`experiments/trace_decompression.py` / PH5-DEC-002.

### 2.4 Corpus nguồn tái tạo — PH6-DATA-001

Ngày 13/11/2026: `scripts/prepare_corpus.py` sinh cây `set1/` đúng cấu trúc Hình 5,
với JPEG giải mã được và DOCX OOXML đọc được bằng `python-docx` trong kiểm tra
độc lập. Mẫu phụ trợ nằm riêng trong `auxiliary/`: tên Hàn NFC/NFD, payload CP949,
tiếng Việt và ZIP con. Manifest cố định inventory và SHA-256 cho 9 file, 9 thư mục.

Kiểm chứng cục bộ Windows, Python 3.11.9:

- `python -m pytest tests/unit/test_prepare_corpus.py -p no:cacheprovider`: 8 passed.
- `python -m pytest -p no:cacheprovider`: 141 passed, không skip.
- `python -m mypy --no-incremental --cache-dir=<thư mục tạm mới> src scripts/prepare_corpus.py`:
  không có lỗi trong 16 source files.
- Black/Flake8 trên generator và test mới, `git diff --check`: đạt.

Test kiểm tra định dạng, CRC, timestamp, checksum baseline, hai lần sinh độc lập,
chạy lại, CLI và bảo vệ dữ liệu lạ/junction Windows. atime/mtime được đặt và kiểm
tra tại `2021-01-11 11:30:59 UTC`; creation/change time không được cố định.
Đọc/liệt kê thư mục có thể đổi atime; phải sinh lại ngay trước thực nghiệm.

Đây là **corpus thay thế tự tạo**, không phải payload gốc của tác giả, không xác
nhận encoding filename ZIP do archiver tạo và không phải kết quả accuracy/BMAC.
PH6-DATA-002, PH5-DEC-002 và PH7-EVAL-002 vẫn chưa hoàn thành. Chưa xác thực corpus
trên macOS/Linux. Chi tiết tại `data/README.md`.

---

## 3. Đánh giá Ma trận Nhầm lẫn và Độ chính xác (Confusion Matrix)
*(Sẽ đối chiếu với phân bố thực nghiệm 3 máy trạm PC1, PC2, PC3 từ Hình 9)*

---

## 4. Kết luận và Khác biệt Thực tế
*(Ghi nhận các quan sát trên phiên bản phần mềm hiện hành so với dữ liệu năm 2021 của bài báo)*

