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
Artifact không commit trực tiếp. #20 đã đóng trên GitHub ngày 17/11/2026;
repo chưa ghi nhận biên bản reviewer kiểm chứng artifact.
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

### 2.8 GUI tạo ZIP rồi Explorer Delete — PH4-PROV-002 (18/11/2026)

Run `run-case2-hz8kgcll`: Bandizip7.47.0.1 portable GUI tạo ZIP/Normal,
Unicode Path/NTFS on, UTF8 filename off; seal xác minh bốn entry và payload.
Explorer Delete đúng target.txt, đóng cửa sổ rồi finalize: scope none,
payload ba survivor giữ nguyên; chỉ offset đổi, tracker Case2 false.
Có ảnh và log cả hai thao tác GUI, raw INI lossless và cặp ZIP. Native
control-add mới `run-16gz65r7` xác nhận Case1. **#19 chưa đạt DoD Case2.**
Một cấu hình, không retry; kết quả âm của GUI và CLI là hai quan sát riêng,
không cam kết tương đương. Dừng host, chuẩn bị hướng dẫn VMware Windows10v2004;
chưa có media hợp lệ nên chưa dựng/chạy guest. Xem
[kết quả/giới hạn](native-case2-gui-2026-11-18.md) và
[manifest/checksums](evidence/native-case2-gui-2026-11-18.json).

### 2.9 Windows 10 v2004 + Bandizip 6.29 → Explorer Delete — PH4-PROV-002 (26/11/2026)

Run `run-case2-dlq9ulnc` trên guest VMware Windows 10 Home 2004 (19041.264,
en-US, ACP 1252), cô lập mạng. Bandizip 6.29 GUI tạo ZIP/Normal với UTF-8 filename
off, Unicode Path on, NTFS time on; Explorer Compressed Folder xóa `target.txt`.
Cả hai thao tác có log `ui_observed`. Payload ba survivor nguyên vẹn; chỉ offset
đổi; scope `none`; tracker Case 2 false. Host đọc lại ổ evidence (25/25 checksum
khớp) và tính lại comparison trùng với guest. **Kết quả âm lần thứ ba của cặp
Bandizip → Explorer; #19 chưa đạt DoD Case 2.** Lệch runbook: RAM 2 GiB, edition
Home, bỏ liên kết .zip của Bandizip trước Delete. Xem
[báo cáo](native-case2-win10-2004-2026-11-26.md) và
[manifest/checksums](evidence/native-case2-win10-2004-2026-11-26.json).

## 3. Đánh giá Ma trận Nhầm lẫn và Độ chính xác (Confusion Matrix) — PH7-EVAL-002

> **Trạng thái (25/11/2026): đã triển khai evaluator, đã kiểm thử tổng hợp, đã chạy
> trên mẫu native và mẫu tác giả. Kết quả: CHƯA ĐẠT ngưỡng.** OS 100 % và công cụ
> Windows ≥ 90 % đều không đạt trên cả hai tập (mục 3.4). DoD khoa học chưa đạt;
> #22 giữ mở. Classifier và ground truth **không** bị chỉnh theo kết quả.

### 3.1 Triển khai evaluator

`experiments/evaluate_classifier.py` đánh giá **hai tập tách biệt**, không gộp:

| Tập | Nguồn nhãn (`truth.source`) | Đầu vào | Vị trí trong JSON |
| --- | --- | --- | --- |
| Generated | `invocation_provenance`: (`run.environment.os`, `sample.tool_id`) do generator ghi lúc gọi công cụ | `data/metadata.json` (schema v1), chỉ mẫu `status=generated` | cấp gốc (`counts`, `metrics`, `thresholds`, `samples`) |
| Author reference | `author_declared_filename`: nhãn tác giả bài báo đặt qua tên file, đã chấp nhận ở #17 | `data/reference/author_pkzip/manifest.json`, chỉ mẫu `label_verified=true` | `reference_sets.author_pkzip` |

Hai loại ground truth có độ tin cậy khác nhau, nên ngưỡng được xét **riêng cho
từng tập**. Thiếu manifest tác giả thì tập đó ghi `not_available`; không phải lỗi.

Với mỗi mẫu, script đọc bytes ZIP **một lần**, kiểm tra path nằm trong thư mục
gốc, size và SHA-256, rồi phân loại chính bytes đó. Mẫu bị loại được ghi lại cùng
lý do: `status_*`, `label_unverified`, `missing_artifact`, `checksum_mismatch`,
`size_mismatch`, `unsafe_path`, `missing_checksum`.

- **Predictor:** `--predictor api` gọi `ZipBinaryParser → StructuralFeatureExtractor
  → AutomatedClassifier`. `--predictor cli` ghi bytes đã kiểm vào một file tạm
  riêng, gọi `python -m zip_fingerprint identify --format json`, rồi kiểm
  `archive_sha256` do CLI trả về khớp với bytes đó. CLI lỗi thì mẫu ghi `ERROR`.
  Lần nghiệm thu dùng `cli`. API và CLI cho kết quả trùng khớp trên cả 43 mẫu được
  đánh giá.
- **Ground truth** không bao giờ lấy từ dự đoán. `Linux` không được gán thành
  Ubuntu. `powershell` mang nhãn **PowerShell Compress-Archive**, thuộc nhóm
  *out-of-catalog*, không được gán lại thành `Windows/Compressed folder`.
- **Top-1** chỉ có khi đúng một ứng viên giữ điểm cao nhất. Đồng hạng ghi
  `AMBIGUOUS`; danh sách rỗng ghi `UNKNOWN`; exception ghi `ERROR`. Cả ba trường hợp
  vẫn **nằm trong mẫu số** và tính là sai. Candidate coverage (nhãn đúng có xuất
  hiện trong danh sách ứng viên) được báo riêng.
- Metric được tính trên tập raw và tập SHA-256 duy nhất. Run lặp và bản sao trùng
  byte được công bố, không coi là bằng chứng độc lập. Ngưỡng xét trên tập SHA-256
  duy nhất. `met` còn đòi mỗi nhãn catalogue trong phạm vi có ít nhất một mẫu;
  thiếu thì ghi `insufficient_coverage`.
- JSON ghi lệnh chạy, Python/platform, git commit/dirty, SHA-256 của catalogue hoặc
  manifest và của các file classifier, định nghĩa từng mẫu số, kết quả từng mẫu
  (truth, toàn bộ ứng viên/điểm, dự đoán, outcome, mẫu số được tính vào). Exit `0`
  khi có ít nhất một tập có mẫu được đánh giá, `2` khi không có mẫu hợp lệ, `1` khi
  lỗi catalogue/IO. Chưa đạt ngưỡng **không** phải lỗi chương trình.

Tái chạy:

```powershell
python scripts/fetch_author_samples.py                          # mẫu tác giả (không commit bytes)
python experiments/evaluate_classifier.py --predictor cli       # data/ + results/benchmarks/
python experiments/evaluate_classifier.py --data-dir <data-root> --run <run_id> --output <file>
python -m pytest tests/integration/test_classifier_evaluation.py
```

### 3.2 Kiểm thử tổng hợp

`tests/integration/test_classifier_evaluation.py` gồm 35 test. Predictor được
stub để kiểm tra phép tính metric độc lập với bộ luật. Fixture có các trường hợp
known-correct, wrong, unknown, đồng hạng (ứng viên đúng đứng đầu danh sách để
chứng minh evaluator không chọn phần tử đầu), checksum sai, thiếu artifact,
skipped, PowerShell, exception, bản sao SHA-256 giữa hai run, SHA trùng nhưng
nhãn xung đột, path traversal và host Linux. Giá trị kỳ vọng được tính tay:

- Tập raw: tool accuracy 2/6, OS 5/7, coverage 3/6.
- Tập SHA-256 duy nhất: tool accuracy 1/5, OS 4/6.

12 test bổ sung ngày 25/11/2026 kiểm tra tập tác giả và chế độ CLI:

- Nhãn lấy từ manifest (`author_declared_filename`), không từ host OS.
- Mẫu chưa xác minh nhãn, sai checksum hoặc thiếu file bị loại đúng lý do.
- Tập tác giả nằm trong `reference_sets`, không lẫn vào tập generated.
- `cli_predictor` cho kết quả giống API, và báo lỗi khi CLI thoát khác `0`.

Ngoài ra có test chạy pipeline thật trên ZIP dựng bằng `zipfile`. **Đây là test
phần mềm, không phải bằng chứng thực nghiệm.**

Môi trường kiểm tra ngày 25/11/2026: Windows 10.0.26200, Python 3.11.9:
`python -m pytest` cho **410 passed, 4 skipped**. Bị skip: 1 test cần Bandizip
portable, 3 test cần quyền tạo symlink. Pyflakes và kiểm tra độ dài dòng
(≤ 100) đạt trên hai file đã sửa; máy này không cài flake8.

### 3.3 Dữ liệu nghiệm thu

**Tập generated:** 3 run trên cùng một máy (Windows 10.0.26200, NTFS, code page
1252), cùng 7-Zip 26.04 và WinRAR 6.23.0:

| Run | Ngày (UTC) | PowerShell Archive | Generated | Ghi chú |
| --- | --- | --- | --- | --- |
| `run-xzp9n65j` | 13/11/2026 | 1.2.7 | 9 | Bandizip skipped ×3 |
| `run-49gonnjf` | 13/11/2026 | 1.2.7 | 9 | Bandizip skipped ×3 |
| `run-xvkrpl03` | 25/11/2026 | 1.0.1.0 | 8 | `powershell/auxiliary` failed: file `inner.zip` đang bị process khác giữ |

33 mẫu trong catalogue, 26 được đánh giá, 7 bị loại (6 `status_skipped`, 1
`status_failed`). Chỉ có **18 SHA-256 duy nhất**: 7-Zip cho bytes giống hệt nhau ở
cả 3 run (3 nhóm × 3), và có thêm 2 cặp trùng giữa hai run ngày 13/11. Ba run
cùng máy và cùng phiên bản công cụ **không phải bằng chứng độc lập**.

Bytes được bàn giao qua prerelease
[`evidence-ph7-eval-002-2026-11-25`](https://github.com/HuynhHHuy/zip-fingerprinting/releases/tag/evidence-ph7-eval-002-2026-11-25):

- `ph7-eval-002-native-samples-2026-11-25.zip`: 26 `sample.zip`, metadata từng
  run và `metadata.json`. SHA-256
  `58ef31965b698c73999b0b8a97e3d6fe081767d1ef74e51c4ced845023b0d660`.
- `SHA256SUMS.txt`: SHA-256 từng file trong gói.
- `reproduction_evaluation.json`: bản sao kết quả đã commit.

Đã kiểm tra lại: giải nén gói vào một thư mục trống rồi chạy
`python experiments/evaluate_classifier.py --predictor cli --data-dir <thư mục>`
cho đúng các số của tập generated ở mục 3.4. SHA-256 của `metadata.json` trong gói
(`8fdff741…3462`) khớp `catalogue_sha256` trong JSON.

**Tập author reference:** 17 mẫu của #17 (set1–set4, đủ Windows/Ubuntu/macOS),
cả 17 được đánh giá, 17 SHA-256 duy nhất. Bytes **không** nằm trong prerelease vì
repo tác giả không có giấy phép; reviewer tải bằng
`python scripts/fetch_author_samples.py` theo SWHID và SHA-256 trong manifest.

JSON nghiệm thu: `results/benchmarks/reproduction_evaluation.json`, chạy bằng
`--predictor cli` trên commit `1958c11`. `git_dirty=true` do hai nguyên nhân:

- Các file chưa track: `Nhom10_BaoCaoTienDo_…pptx`, một plan cũ và chính file JSON
  của lần chạy trước.
- `data/metadata.json` bị Git đánh dấu thay đổi chỉ vì line ending.

Code không có thay đổi chưa commit. Catalogue đã đánh giá trùng byte với blob đã
commit và với bản trong gói (SHA-256 `8fdff741…3462`).

Lưu ý tái chạy trên Windows: với `core.autocrlf=true`, checkout có thể đổi
`data/metadata.json` sang CRLF. Khi đó `catalogue_sha256` sẽ khác dù nội dung như
nhau. Hãy dùng bản trong gói prerelease để kiểm checksum.

### 3.4 Kết quả so với ngưỡng (tập SHA-256 duy nhất)

| Tập | Chỉ số | Quan sát | Ngưỡng | Trạng thái |
| --- | --- | --- | --- | --- |
| Generated | OS accuracy | 18/18 = 1.000 | 1.00 | `insufficient_coverage`: không có Ubuntu, macOS |
| Generated | Windows tool accuracy | 1/12 = 0.083 | ≥ 0.90 | `not_met`: còn thiếu Bandizip, Compressed folder, WinZip |
| Generated | Candidate coverage | 12/12 | — | nhãn đúng luôn có trong danh sách ứng viên |
| Author | OS accuracy | 15/17 = 0.882 | 1.00 | `not_met`: đủ độ phủ |
| Author | Windows tool accuracy | 5/10 = 0.500 | ≥ 0.90 | `not_met`: đủ độ phủ |
| Author | Tool accuracy (mọi OS) | 10/17 = 0.588 | — | — |
| Author | Candidate coverage | 17/17 | — | — |

**Tập generated:** 1 correct, 3 wrong, 8 AMBIGUOUS trên 12 mẫu in-catalog.

| Truth ↓ / Dự đoán → | Windows/7-Zip | AMBIGUOUS |
| --- | --- | --- |
| Windows/7-Zip (3) | 1 | 2 |
| Windows/WinRAR (9) | 3 | 6 |

- Biến thể `root` và `contents` của cả 7-Zip lẫn WinRAR đều đồng hạng 4 ứng viên
  (7-Zip, Bandizip, WinRAR, WinZip, cùng điểm 0.5).
- Biến thể `auxiliary` luôn ra 7-Zip (0.806), nên đúng với 7-Zip nhưng sai với
  WinRAR.
- Out-of-catalog: 6/6 mẫu PowerShell bị gán thành `Windows/Compressed folder`
  (`false_attribution`). Nhóm này báo riêng, không gán lại nhãn.

**Tập author reference:** 10 correct, 1 wrong, 6 AMBIGUOUS.

| Truth | Kết quả |
| --- | --- |
| Windows/Compressed folder, Windows/WinZip (2+2) | đúng 4/4 |
| Windows/7-Zip (2) | set2 đúng; set1 đồng hạng 7-Zip/Bandizip/WinRAR |
| Windows/Bandizip, Windows/WinRAR (2+2) | 4/4 AMBIGUOUS: set1 đồng hạng 3 ứng viên; set2 đồng hạng Bandizip/WinRAR |
| Ubuntu/7-Zip, Compress, zip (3) | đúng 3/3 |
| macOS/Bandizip, macOS/WinZip (2) | đúng 2/2 |
| macOS/Compress | AMBIGUOUS giữa Ubuntu/Compress và macOS/Compress (0.57); OS cũng ambiguous |
| macOS/zip | sai: dự đoán Ubuntu/zip (0.71); OS sai |

Diễn giải thận trọng:

1. **Windows:** lỗi chủ yếu là đồng hạng, không phải chọn sai. Bộ luật hiện tại
   không tách được 7-Zip, WinRAR và Bandizip khi tên file ASCII (đúng như #17 ghi
   nhận), nên cả hai tập đều dưới ngưỡng 90 %. Candidate coverage 100 % cho thấy
   nhãn đúng luôn nằm trong danh sách ứng viên.
2. **OS:** trên Windows đạt 28/28 mẫu duy nhất qua hai tập. Hai lỗi đều ở macOS
   (macOS bị nhầm hoặc đồng hạng với Ubuntu). Có thể liên quan tới việc không kiểm
   được NFD trên mẫu tải từ archive (#17 mục 3.4); **chưa xác minh**.
3. **Giới hạn:** điểm heuristic không phải xác suất đã hiệu chuẩn. Các tập nhỏ,
   không mù và không đại diện thống kê. Không suy ra kết luận về tái hiện toàn bộ
   bài báo, BMAC hay Case 2.

### 3.5 Việc còn lại trước khi nghiệm thu khoa học

1. Kết quả hiện tại **không đạt** ngưỡng. Muốn cải thiện phải sửa luật, theo hướng
   đối chiếu bảng luật `file_list.py` của tác giả (#17 mục 7). Mọi thay đổi luật
   phải đánh giá trên **tập mới chưa dùng để chỉnh luật**; không được tune trên
   chính 43 mẫu này.
2. Bổ sung mẫu native Bandizip, WinZip và Explorer "Compressed folder" (GUI), cùng
   macOS/Ubuntu, để tập generated đủ độ phủ.
3. Chưa đối chiếu với phân bố PC1/PC2/PC3 ở Hình 9; mẫu tác giả không ghi máy tạo.

---

## 4. Kết luận và Khác biệt Thực tế
*(Ghi nhận các quan sát trên phiên bản phần mềm hiện hành so với dữ liệu năm 2021 của bài báo)*

