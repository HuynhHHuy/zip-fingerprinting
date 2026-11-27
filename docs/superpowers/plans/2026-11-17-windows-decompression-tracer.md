# PH5-DEC-002 / Issue #20 — Windows Decompression Tracer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Request an independent review before delivery.

**Goal:** Đo BMAC thật trên Windows/NTFS cho 7-Zip và WinRAR, giữ bằng chứng nguyên gốc và đối chiếu Table 8/time reversal mà không ép nhãn R/H/E.

**Architecture:** Một adapter Windows nhỏ đọc timestamp thô; tracer điều phối nguồn tạm, nén, giải nén, snapshot và validation; phân tích tham chiếu thời gian bằng hàm thuần. Tái dùng parser, extra-field decoder, DecompressionAnalyzer và helper process/provenance hiện có. Không đổi classifier hoặc CLI chính.

**Tech Stack:** Python >=3.10, ctypes/Win32, pathlib, subprocess, zipfile, pytest; core không thêm dependency runtime. Thêm optional dependency group `experiments` trong pyproject.toml với `tzdata` trên Windows để zoneinfo đọc timezone IANA. Venv hiện tại đã được kiểm tra và chưa có timezone database.

**Spec:** GitHub issue https://github.com/HuynhHHuy/zip-fingerprinting/issues/20 và các quyết định trong tài liệu này. Đây là kế hoạch; chưa có kết quả đo native mới.

## Global Constraints

- Windows hiện tại, NTFS local; dùng 7-Zip 26.04 và WinRAR 6.23.0 đang có. Ghi lại phiên bản thực khi chạy, không hardcode nhãn phiên bản.
- Không cài công cụ mới, không thay cấu hình NTFS/last-access/timezone, không sửa corpus dùng chung hoặc catalogue DATA-002.
- Ubuntu, Bandizip, Explorer GUI và #19 nằm ngoài nghiệm thu đợt này. Ubuntu có thể bổ sung ZIP nguồn trong đợt sau.
- Ground truth lấy từ process thực sự được gọi. Candidate của analyzer không thay thế nhãn công cụ.
- Lưu timestamp bằng integer FILETIME 100 ns; datetime chỉ dùng hiển thị/adapter. Không dùng float và không đồng nhất creation, Unix ctime, NTFS ChangeTime.
- Không đóng issue nếu thiếu đo native, thiếu khác biệt giữa hai công cụ hoặc thiếu bằng chứng reviewer có thể kiểm chứng.

## Review Focus

1. Snapshot bị thao tác đọc payload làm nhiễu access time: đo metadata trước hash/read toàn bộ file; ghi rõ thời điểm và cách quan sát.
2. H/E/R trùng hoặc xung đột LFH/CDH: giữ toàn bộ ứng viên tham chiếu, không ưu tiên nguồn để khớp Table 8.
3. FILETIME mất phần 100 ns khi chuyển datetime: so sánh bằng integer, giữ nguyên số thô và biểu diễn UTC đủ bảy chữ số phần giây.
4. Archive đường dẫn nguy hiểm, duplicate hoặc symlink: từ chối trước khi gọi extractor; không giải nén ZIP tùy ý chưa kiểm tra.
5. Run lỗi giữa chừng, thiếu công cụ hoặc filesystem khác NTFS: lưu trạng thái/diagnostic thật và không tính vào DoD.

## Task 1 — Adapter đọc timestamp Windows

**Files:** Create `experiments/windows_filetimes.py`; create `tests/unit/test_windows_filetimes.py`.

**Interfaces:**
- `read_bmac(path: Path) -> dict[str, int]`: keys `birth`, `modified`, `accessed`, `changed`.
- `now_filetime() -> int`: GetSystemTimePreciseAsFileTime, cùng clock với bounds process.
- `filetime_utc(value: int) -> str`: UTC ISO-8601, giữ phần 100 ns; giá trị ngoài miền hiển thị được vẫn giữ raw và báo lỗi chuyển đổi rõ ràng.
- `volume_info(path: Path) -> dict`: volume root, filesystem, serial; resolve theo volume chứa đường dẫn, không suy diễn từ drive letter.
- Helper đặt Birth/Modified/Accessed trên **source tạm** bằng SetFileTime; không ghi timestamp lên cây đã giải nén.

- [ ] Viết test RED cho integer conversion, chênh lệch 1 tick và không được alias Modified thành Changed.
- [ ] Implement ctypes với argtypes/restype rõ ràng, WinError khi API lỗi, đóng handle trong finally. Dùng CreateFileW/FILE_READ_ATTRIBUTES, share read/write/delete, FILE_FLAG_BACKUP_SEMANTICS cho thư mục; GetFileInformationByHandleEx(FileBasicInfo) đọc đủ bốn trường.
- [ ] Chỉ nạp WinDLL khi thực thi trên Windows; import và unit test hàm thuần vẫn chạy trên Linux. Unsupported platform trả lỗi có nghĩa, không giả timestamp.
- [ ] Native test tạo file/thư mục tạm, đặt ba mốc cách nhau rồi đọc lại chính xác. Changed được đọc thật; không cần ép Changed thành giá trị cố định hoặc kỳ vọng luôn khác Modified.
- [ ] Chạy `python -m pytest tests/unit/test_windows_filetimes.py`; quan sát RED rồi GREEN. Commit adapter và test.

## Task 2 — Thu thập tham chiếu H/E/R và phân tích

**Files:** Modify `experiments/trace_decompression.py`; create `tests/unit/test_decompression_tracer.py`.

**Interfaces:**
- `archive_references(path: Path, dos_timezone: str) -> dict`: inventory, header hiện diện, DOS LFH/CDH thô và UTC khả dĩ, extra-field IDs/raw bytes/giá trị giải mã, checksum ZIP.
- `match_time_sources(observed: int, references: list[dict], bounds: tuple[int, int]) -> dict`: labels R/H/E, tham chiếu khớp cụ thể, trạng thái unique/ambiguous/unmatched/unavailable.
- `analyze_observations(observations: list[dict], references: dict, bounds: tuple[int, int]) -> dict`: pattern khả dụng, Table 8 candidates, time reversal và coverage.

- [ ] Test RED cho H/E trùng, không khớp, thiếu field, LFH/CDH bất đồng, extra field trùng/xấu, DOS không hợp lệ và timezone DST ambiguous/nonexistent.
- [ ] Tái dùng ZipBinaryParser, ExtraFieldParser và extractor.dos_to_datetime; giữ raw FILETIME trong NTFS 0x000A. Tách rõ trường creation của NTFS extra field khỏi filesystem ChangeTime; Unix ctime trong 0x5455 không tự chuyển thành birth.
- [ ] CLI yêu cầu `--dos-timezone` là tên IANA, dùng zoneinfo; kiểm tra khả dụng trước run. Cài môi trường Windows qua `python -m pip install -e ".[dev,experiments]"`; thiếu database phải báo prerequisite, không tự đoán offset từ timezone hiện tại. Thời điểm DST không duy nhất giữ mọi UTC khả dĩ hoặc ghi unavailable nếu không tồn tại.
- [ ] H/E khớp theo giá trị timestamp đã giải mã trên integer ticks; ghi độ phân giải nguồn (DOS 2 giây, Unix 1 giây, FILETIME 100 ns). Không dùng mặc định tolerance ±2 giây vì có thể làm H và E khác nhau bị nhập nhằng giả. Sai khác do làm tròn không xác định được giữ unmatched và ghi delta.
- [ ] R khớp nếu nằm trong bounds [trước spawn, sau process exit]; ghi cả hai mốc bằng now_filetime. Các giá trị ngoài bounds không tự mở rộng tolerance để ép R.
- [ ] Với mỗi trường B/M/A/C, xét toàn bộ timestamp H/E có thật của entry và giữ danh tính tham chiếu khớp (loại header/ID/trường); không mặc định E là mtime. Chỉ tạo pattern bốn chữ và gọi identify_decompressor khi mỗi trường có đúng một nhãn R/H/E. Nếu nhiều nguồn khớp, xuất ambiguity; không chọn ứng viên đầu.
- [ ] Phân loại entry là file/folder_with_files/empty_folder/folder_no_header từ inventory và directory header thật. Extra-field context chỉ chọn khi có một ID timestamp được hỗ trợ; nhiều ID hoặc LFH/CDH conflict thì báo context ambiguous, không ép lookup một hàng.
- [ ] Time reversal so bằng ticks thô: Modified < Birth cho từng entry; child < parent trên cùng thuộc tính B/M/A/C. Báo cả assessed/unavailable/equal/no-reversal/reversal. Gọi analyzer hiện có cho cặp datetime biểu diễn được; chênh lệch dưới microsecond được giữ trong raw report, không để datetime làm mất kết quả.
- [ ] Chạy unit test RED → GREEN. Commit phân tích và test.

## Task 3 — Native pipeline và CLI thí nghiệm

**Files:** Modify `experiments/trace_decompression.py`; create `tests/integration/test_decompression_tracer.py`.

**CLI:**
```powershell
python experiments/trace_decompression.py --dos-timezone Asia/Ho_Chi_Minh --require-dod
```
- `--output` mặc định `results/decompression_profiles/` của checkout.
- `--tool {7zip,winrar}` và `--profile {ntfs,no-extra}` cho phép lặp; mặc định cả hai.
- `--7zip PATH`, `--winrar PATH` override; executable sai là failed, thiếu công cụ là skipped, không thay thế bằng công cụ khác.
- `--repeat` integer >=1, mặc định 3; `--require-dod` kiểm tra đủ điều kiện đo của task.
- Exit 0 khi có phép đo hợp lệ và không lỗi; exit 1 khi có lỗi; exit 2 khi không có phép đo/phạm vi không hỗ trợ hoặc --require-dod chưa đạt. Parse sai dùng argparse exit 2. JSON report giữ coverage.dod_met độc lập exit mặc định.

**Data flow:**
- [ ] Test RED cho thiếu tool/override sai/process exit lỗi/timeout, output cũ, path Unicode, run lặp và artefact lỗi.
- [ ] Tái dùng discover_tools/tool_version/run_command/sha256 từ simulator, không refactor simulator diện rộng. Timeout 60 giây, CREATE_NO_WINDOW; lưu argv/cwd/stdout/stderr/return code và lỗi.
- [ ] Mỗi invocation tạo `run-*/`; mỗi profile có source riêng từ prepare_corpus trong run. Dùng set1 có file, thư mục chứa file và emptyFolder; không nén manifest/auxiliary.
- [ ] Kiểm tra source payload với baseline manifest trước, rồi đặt timestamp trên file/thư mục source tạm theo thứ tự từ con lên cha: Birth 2020-01-11T11:30:57.1234567Z, Modified 2021-01-11T11:30:59.1234567Z, Accessed 2022-01-11T11:30:55.7654321Z. Đọc lại source BMAC; Changed ghi thực tế, không cố định. Không thay manifest DATA-001 để tuyên bố birth đã được chuẩn hóa cho corpus chung.
- [ ] Tạo ZIP bằng 7-Zip thật: profile ntfs bật `-mtc=on -mta=on -mtm=on`; no-extra tắt ba cờ. Dùng ZIP, source set1 và ghi đầy đủ command. Xác minh cờ với help cài đặt khi triển khai; kiểm tra profile thực tế từ parser. Nếu công cụ không tạo đặc trưng yêu cầu, báo profile failed/unsupported; không sửa bytes ZIP để giả mẫu native.
- [ ] Lưu ZIP và source evidence; verify CRC/payload/inventory. Trước giải nén, từ chối duplicate, absolute/traversal/drive path, symlink/reparse-related entry hoặc đích có sẵn; chỉ hỗ trợ archive tự sinh trong v1.
- [ ] Giải nén cùng bytes ZIP bằng cả hai công cụ vào destination mới cho từng repeat. 7-Zip dùng x/-y/-o; WinRAR dùng x/-cfg-/-inul/-ibck/-y và destination riêng. Nêu rõ flags CLI, không tuyên bố tương đương GUI mặc định.
- [ ] Trước chạy, xác minh destination trên NTFS và không đi qua reparse point. Lưu OS/build, filesystem, timezone của hệ thống và timezone diễn giải DOS, policy last-access đọc bằng `fsutil behavior query disablelastaccess` nếu được phép; thất bại query ghi unknown, không thay policy.
- [ ] Sau process exit và đóng các process handle: snapshot metadata **toàn cây trước khi đọc payload/hash**, bao gồm thư mục suy ra thiếu header. Sau đó mới verify CRC nguồn, SHA-256 từng payload, inventory và ZIP nguồn không đổi. Không lấy os.stat().st_ctime làm Changed.
- [ ] Snapshot là quan sát sau giải nén, không tuyên bố timestamp đã ổn định vĩnh viễn; ghi thời gian từng observation và caveat delayed access-time/antivirus/indexer. Không polling hoặc chỉnh cấu hình để khớp bảng.
- [ ] Test native cho từng tool chỉ skip khi không có tool hoặc OS/filesystem không hỗ trợ; công cụ có mặt nhưng lỗi phải FAIL. Chạy hai tool trên cùng ZIP và kiểm tra timestamp thô, inventory, source checksum và report tái đọc được.
- [ ] Chạy RED → GREEN, commit pipeline và native test.

## Task 4 — Evidence, nghiệm thu và PR

**Output:** `run-*/report.json` schema_version 1 và `report.md`, ZIP nguồn, manifest payload, command logs và timestamp snapshot. JSON report được ghi atomic qua temp + os.replace trong chính run; lỗi giữa chừng lưu failed record nếu còn ghi được. Không cập nhật catalogue DATA-002.

**Report fields:** run ID/thời gian/môi trường/tools; profile và nguồn/checksum; từng measurement ID/tool/repeat/command/bounds/status; entry/header references; BMAC raw/UTC; payload validation; labels/ambiguity/Table 8 candidates; time reversal; pairwise tool differences theo cùng ZIP+entry+thuộc tính; coverage và giới hạn.

- [ ] Ignore toàn bộ `results/decompression_profiles/run-*/` trong Git; commit bản tóm tắt nhỏ và evidence manifest có SHA-256. Artifact lớn bàn giao qua một vị trí người review truy cập được, không coi đường dẫn local là download công khai. Việc chọn nơi chia sẻ dùng hạ tầng nhóm hiện có lúc bàn giao, không upload ra dịch vụ mới mặc định.
- [ ] Chạy ma trận mặc định: **2 ZIP native × 2 extractor × 3 repeat = 12 phép giải nén**, mỗi phép có file/thư mục chứa file/thư mục rỗng. Bản sao repeat ghi rõ là phép lặp, không tính thành nguồn độc lập.
- [ ] DoD đo đạt khi đủ cả hai tool, đủ raw BMAC, payload đúng, không thiếu run mặc định, report time reversal tái chạy được và quan sát khác biệt nguồn thời gian BMAC giữa hai công cụ trên cùng ZIP. Khác nhau đơn thuần vì R của hai lần chạy khác nhau không được tính là khác biệt hành vi công cụ. Nếu không phân biệt được, ghi chưa xác định và giữ DoD chưa đạt.
- [ ] Không yêu cầu mọi pattern khớp Table 8 hoặc bắt buộc có time reversal; công bố kết quả âm, các cặp không đủ dữ liệu và phiên bản thực. Nếu thí nghiệm chưa đáp ứng DoD, issue #20 giữ mở dù code/test pass.
- [ ] Cập nhật reproduction_report, implementation-plan và hướng dẫn tracer: tách triển khai, test tổng hợp, native measurement và mức tái hiện lịch sử.
- [ ] Chạy kiểm tra dưới đây, lưu lệnh/output/môi trường; review độc lập và giải quyết finding trước PR. Không sửa tests/source ngoài phạm vi chỉ để che lỗi baseline.

```powershell
python -m pytest
python -m mypy src experiments/windows_filetimes.py experiments/trace_decompression.py
python -m black --check experiments/windows_filetimes.py experiments/trace_decompression.py tests/unit/test_windows_filetimes.py tests/unit/test_decompression_tracer.py tests/integration/test_decompression_tracer.py
python -m flake8 --max-line-length=100 experiments/windows_filetimes.py experiments/trace_decompression.py tests/unit/test_windows_filetimes.py tests/unit/test_decompression_tracer.py tests/integration/test_decompression_tracer.py
python -m pip check
git diff --check
python experiments/trace_decompression.py --dos-timezone Asia/Ho_Chi_Minh --require-dod
```

**Delivery:** worktree/branch riêng từ main đã có PR #24, ví dụ `feat/ph5-dec-002-native-tracer`; một PR sang main liên kết #20. Chỉ dùng auto-close khi DoD và bàn giao artifact đều đủ. Không triển khai #19 hoặc cài công cụ mới trong nhánh này.
