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
filesystem chưa có tại mốc 06/11/2026. Kết quả native PH5-DEC-002 mới ngày
17/11/2026 được báo riêng tại Mục 2.6; không thay đổi ý nghĩa benchmark bảng.

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
Tại thời điểm nghiệm thu DATA-001, PH6-DATA-002 vẫn chưa hoàn thành (kết quả mới ở
Mục 2.5); PH5-DEC-002 và PH7-EVAL-002 còn thiếu. Chưa xác thực corpus
trên macOS/Linux. Chi tiết tại `data/README.md`.

---

### 2.5 Ground-truth Windows CLI — PH6-DATA-002

Ngày 13/11/2026: chạy `python scripts/generate_ground_truth.py` sinh **9 mẫu hợp
lệ, 3 mẫu Bandizip skipped, 0 failed** mỗi run. Công cụ: 7-Zip 26.04, WinRAR
6.23.0, Windows PowerShell 5.1.26100.9818 / Archive module 1.2.7. Phiên bản/path
module lấy từ process thực sự tạo mẫu, không suy ra từ shell khác.

Mỗi công cụ sinh ba biến thể `root`, `contents`, `auxiliary`; nguồn mới riêng từng
mẫu được đối chiếu với manifest DATA-001, atime/mtime khôi phục trước lệnh nén.
Catalogue `data/metadata.json` và báo cáo trong `ground_truth/run-*/metadata.json`
giữ invocation provenance, môi trường, checksum và kết quả validation độc lập
classifier. Đã kiểm kê báo cáo khớp catalogue và xác minh SHA-256 của chín archive.

Quan sát header không bị sửa để ép khớp lý thuyết: 7-Zip/WinRAR giữ đầy đủ directory
header trong các mẫu này; PowerShell bỏ một số header (chẳng hạn `Study/` và
`emptyFolder/` ở biến thể contents), trong khi payload file vẫn đầy đủ. Không gán
những mẫu PowerShell này thành Explorer/Compressed folder.

20 test mới kiểm tra lỗi/timeout, catalogue/history, CRC/payload, tên Unicode và
path, CLI và ba adapter native. Review độc lập phát hiện thiếu bắt `zlib.error`;
regression tái hiện stream DEFLATE hỏng đã RED rồi GREEN sau khi bổ sung xử lý,
để ghi mẫu failed và tiếp tục lưu run. Helper dùng chung giữ stdout/stderr timeout.

Kiểm tra cuối: `python -B -m pytest -p no:cacheprovider` đạt **161 passed, không
skip** trên Windows/Python 3.11.9. Mypy `src scripts/generate_ground_truth.py`
không lỗi trong 16 source files; Black/Flake8 trên ba file Python thay đổi,
`pip check` và `git diff --check` đều đạt. Reviewer xác nhận regression đã được sửa.

Đây là ground truth về **công cụ CLI tạo mẫu hiện hành**, không chứng minh tái
hiện GUI năm 2021, accuracy của classifier hoặc BMAC. Bandizip native, macOS/Linux,
GUI, creation/change time và byte-identical ZIP chưa được nghiệm thu.

#### Giới hạn nghiệm thu hiện tại (13/11/2026)

**Kết luận: PH6-DATA-002 đạt DoD cục bộ cho pipeline Windows CLI.** Kết luận này
chỉ xác nhận provenance của công cụ đã gọi, tính hợp lệ của payload/ZIP và metadata
trên môi trường đã đo; chưa xác nhận tái hiện đầy đủ thực nghiệm bài báo.

| Nội dung | Phạm vi bằng chứng hiện có | Chưa được nghiệm thu |
| --- | --- | --- |
| Môi trường | Windows build 10.0.26200, Python 3.11.9, UTC+07:00, ANSI CP1252 | Windows build khác, Python khác, macOS/Linux |
| Công cụ | 7-Zip 26.04, WinRAR 6.23.0, Windows PowerShell 5.1.26100.9818 / Archive 1.2.7 | Bandizip native (chỉ có adapter và skip), WinZip, phiên bản khác |
| Cách tương tác | CLI, ba biến thể root/contents/auxiliary | GUI, kéo thả/menu ngữ cảnh, Explorer; PowerShell không đại diện Compressed folder |
| Dữ liệu | 9 mẫu hợp lệ mỗi run từ corpus thay thế PH6-DATA-001 | Payload gốc tác giả, corpus đa dạng hoặc tập đánh giá mù/đại diện thống kê |
| Encoding | Giải mã và đối chiếu tên entry thực tế, có test tổng hợp CP949/Unicode Path | Ép hoặc chứng minh một archiver đã tạo profile CP949 như thí nghiệm tiếng Hàn |
| Thời gian | atime/mtime nguồn được khôi phục trước process, có snapshot trong metadata | Cố định creation/change time; phân biệt nanosecond từ nguồn nguyên giây; byte-identical ZIP |
| Độ chính xác khoa học | CRC, inventory, SHA-256 và tính nhất quán report/catalogue | Accuracy/confusion matrix, đo BMAC/filesystem, Case 2 thực tế, toàn bộ kết quả bài báo |

`161 passed` là bằng chứng kiểm thử phần mềm, không phải tỷ lệ phân loại đúng hoặc
độ chính xác tái hiện thực nghiệm. Mẫu PowerShell vẫn có nhãn riêng dù cấu trúc có
thể giống một profile trong bộ luật. Không sửa luật hoặc archive để ép khớp bảng.

Catalogue giữ hai run cục bộ; lần kiểm tra gần nhất đối chiếu lại CRC/payload,
checksum manifest, SHA-256 của 9 ZIP và báo cáo của `run-49gonnjf`. ZIP/source/run
report bị Git bỏ qua: checkout repository chỉ có metadata không đủ để kiểm chứng
bytes các run này. Cần chuyển cả run artifacts hoặc sinh một run mới; run mới có
provenance riêng, không được tuyên bố có cùng bytes với run đã lưu.

Tại mốc DATA-002 ngày 13/11, PH5-DEC-002 (đo giải nén), PH7-EVAL-002 (accuracy)
và Case 2 của PH4-PROV-002 chưa đạt nghiệm thu tương ứng. Kết quả DATA-002 không
mở rộng trạng thái các task này; cập nhật PH5-DEC-002 ngày 17/11 ở mục dưới.

### 2.6 BMAC filesystem native — PH5-DEC-002 (17/11/2026)

Tracer đọc đủ Birth/Modified/Accessed/Changed qua Win32 FILE_BASIC_INFO, giữ
integer ticks 100 ns và UTC bảy chữ số, snapshot toàn cây trước đọc payload.
Môi trường: Windows build 10.0.26200, NTFS, Python 3.11.9, UTC+07:00/DOS zone
Asia/Ho_Chi_Minh; 7-Zip 26.04 và WinRAR 6.23.0 thực sự được gọi. Không thay
timezone, policy last-access hoặc corpus/catalogue dùng chung.

Run `run-plhh7oml` gồm **2 ZIP native × 2 extractor × 3 repeat = 12 phép đo**,
0 failed/skipped, mỗi phép có 4 file, 2 thư mục chứa file và 1 thư mục rỗng.
Cùng bytes ZIP được dùng cho cả hai extractor; CRC/inventory/payload checksum
đều hợp lệ. Nguồn riêng có B/M/A cố định khác nhau, Changed ghi thực tế.

| Profile | File 7-Zip | File WinRAR | Kết luận giới hạn |
| --- | --- | --- | --- |
| NTFS 0x000A | EEER | RERR | Birth/Accessed khác E/R ổn định qua 3 repeat |
| Không timestamp extra | RHRR | RHRR | Chưa phân biệt hai công cụ bằng pattern file |

Có 11 cặp entry/thuộc tính khác nhãn nguồn ổn định, gồm Birth của thư mục;
khác giá trị R do clock hai process không được tính. Directory snapshot đủ raw
BMAC nhưng không đủ pattern bốn nhãn xác định; giữ unmatched/ambiguity thay vì
ép Table 8. Candidates lookup không dùng làm ground truth. Có time reversal,
song số cặp thay đổi giữa repeat, không tự chứng minh can thiệp. Bảng từng phép
đo, raw deltas, header/extra và command logs nằm trong gói evidence.

CLI `--require-dod` exit 0, `coverage.complete=true`, `coverage.dod_met=true`:
**đạt DoD đo cục bộ**, tách khỏi bàn giao/review và tái hiện môi trường lịch sử.
Xem [hướng dẫn tracer](windows-decompression-tracer.md) và
[manifest SHA-256/link bàn giao](evidence/windows-decompression-run-plhh7oml.json).
Artifact không commit trực tiếp; chưa tự đóng #20 trước reviewer kiểm chứng.
Test tổng hợp/fault injection không tính thành native measurements. Kết quả
kiểm tra phần mềm cuối ghi trong manifest; test pass không là accuracy.

Giới hạn: CLI cấu hình rõ, corpus thay thế, chỉ hai phiên bản công cụ và một
máy Windows; snapshot tức thời chịu directory enumeration/delayed NTFS access
updates/antivirus. Chưa nghiệm thu GUI/Explorer/Bandizip, Ubuntu, toàn bộ Table 8
trên phần mềm hiện hành, accuracy, hoặc đầy đủ thực nghiệm năm 2021.

### 2.7 Explorer Delete native — PH4-PROV-002 (18/11/2026)

Bandizip portable 7.47.0.1 → Explorer Delete thực tế trên Windows 10.0.26200:
xóa đúng target.txt, CRC/payload SHA-256 ba survivor nguyên vẹn; chỉ vị trí
header/local-header-offset đổi, extra fields và cấu trúc giữ nguyên.
Comparator độc lập và tracker đều không thấy Case 2. Control-add mới bằng
7-Zip 26.04 → WinRAR 6.23.0 thấy Case 1. **Kết quả âm, #19 chưa đạt DoD.**
Không chạy lần hai vì mặc định đã có Unicode Path 0x7075. Không suy diễn
CP949, GUI tạo ZIP hay tái hiện môi trường 2021. Test tổng hợp không tính
thành bằng chứng Case 2; log UI là ghi nhận operator, không telemetry xác
thực. Xem [bảng delta, cách tái chạy và giới hạn snapshot cấu hình](native-case2-2026-11-18.md)
và [manifest bàn giao](evidence/native-case2-2026-11-18.json).

## 3. Đánh giá Ma trận Nhầm lẫn và Độ chính xác (Confusion Matrix)
*(Sẽ đối chiếu với phân bố thực nghiệm 3 máy trạm PC1, PC2, PC3 từ Hình 9)*

---

## 4. Kết luận và Khác biệt Thực tế
*(Ghi nhận các quan sát trên phiên bản phần mềm hiện hành so với dữ liệu năm 2021 của bài báo)*

