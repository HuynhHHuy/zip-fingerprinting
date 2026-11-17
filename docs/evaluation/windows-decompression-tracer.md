# Windows decompression tracer — PH5-DEC-002 / #20

## Phạm vi và cách chạy

Tracer chỉ nhận nguồn riêng tự sinh từ corpus PH6-DATA-001, trên Windows/NTFS.
Không thay đổi corpus chung, catalogue DATA-002, timezone hay policy last-access.
7-Zip là dependency bắt buộc để tạo ZIP nguồn; WinRAR là extractor thứ hai.
Không tự cài hoặc thay thế công cụ thiếu.

```powershell
python -m pip install -e ".[dev,experiments]"
python experiments/trace_decompression.py --dos-timezone Asia/Ho_Chi_Minh --require-dod
```

`--output` mặc định `results/decompression_profiles/` của checkout. Mỗi lần chạy
tạo `run-*/`, không ghi đè run cũ. `--tool {7zip,winrar}` và
`--profile {ntfs,no-extra}` cho phép lặp; mặc định chọn cả hai.
`--7zip PATH`, `--winrar PATH` override executable; `--repeat` >= 1, mặc định 3.
`--dos-timezone` là IANA timezone bắt buộc để diễn giải DOS local time;
không thay đổi timezone hệ thống. Thiếu tzdata báo lỗi prerequisite.
Mỗi lần lưu ghi `report.json` và `report.md`, kể cả run đang dở/skipped/failed;
JSON là nguồn dữ liệu chi tiết có thẩm quyền. Bản Markdown trong gói nghiệm thu
được bổ sung bảng kết quả từng measurement để review thuận tiện.

Exit 0: có phép đo hợp lệ và không lỗi. Exit 1: có lỗi, kể cả override sai,
process/timeout/profile/payload lỗi. Exit 2: sai cú pháp, không đo được hoặc
`--require-dod` chưa đạt. Thiếu công cụ ghi skipped; có công cụ nhưng chạy lỗi
ghi failed. Exit 0 mặc định không đồng nghĩa `coverage.dod_met=true`.

## Phương pháp và các lệnh native

Mỗi profile sinh source riêng, kiểm tra inventory/SHA-256 với manifest baseline,
rồi đặt Birth `2020-01-11T11:30:57.1234567Z`, Modified
`2021-01-11T11:30:59.1234567Z`, Accessed `2022-01-11T11:30:55.7654321Z` trên
source tạm từ con lên cha. Đọc lại chính xác bằng integer FILETIME; Changed
được ghi thực tế. Chỉ nén `set1/`, không nén manifest hoặc auxiliary.

```text
7z a -tzip -y -mtc=on -mta=on -mtm=on SOURCE.zip set1
7z a -tzip -y -mtc=off -mta=off -mtm=off SOURCE.zip set1
7z x -y -oDEST SOURCE.zip
WinRAR x -cfg- -inul -ibck -y SOURCE.zip DEST\
```

Đường dẫn executable/argv/cwd thật nằm trong report. Các cờ timestamp được đối
chiếu help 7-Zip cài đặt (`cmdline/switches/method.htm`); `-cfg-` bỏ config/env,
`-inul` tắt thông báo được đối chiếu `Rar.txt`. Đây là cấu hình CLI được chọn,
không tuyên bố tương đương GUI mặc định. Process dùng timeout 60 giây,
CREATE_NO_WINDOW, giữ stdout/stderr/returncode, kể cả lỗi/timeout.

Trước extractor: kiểm CRC/payload/inventory/header thực, tên nguy hiểm/alias,
Unicode Path extra cả LFH/CDH, link/reparse; từ chối destination có sẵn hoặc có
reparse ancestor. Cùng ZIP bytes dùng cho hai extractor và ba lần lặp, mỗi lần
vào destination mới trên NTFS. Snapshot metadata toàn cây trước khi đọc/hash
payload giải nén; sau đó kiểm payload, inventory và ZIP nguồn không đổi.

`FILE_BASIC_INFO` đọc riêng Birth/Modified/Accessed/Changed; không dùng mtime hay
`os.stat().st_ctime` thay Changed. Raw ticks 100 ns là dữ liệu so sánh, UTC hiển
thị bảy chữ số phần giây. R khớp trong bounds trước spawn/sau exit; H/E giữ toàn
bộ tham chiếu header/extra thực có, không tự nới tolerance. Đồng hạng/xung đột/
không khớp được giữ rõ; chỉ lookup Table 8 khi pattern/context đủ xác định.

## Bằng chứng native ngày 17/11/2026

Run nghiệm thu: `run-plhh7oml`, code đo `e7e9158`. Windows build 10.0.26200,
Python 3.11.9, NTFS, timezone hệ thống UTC+07:00, DOS `Asia/Ho_Chi_Minh`.
7-Zip 26.04 và WinRAR 6.23.0 được đọc từ executable thực. Truy vấn chỉ đọc
`fsutil behavior query disablelastaccess` trả `DisableLastAccess = 2`
(system managed, updates enabled). Không chỉnh policy.

Đủ **2 ZIP nguồn × 2 extractor × 3 lần lặp = 12 phép đo**, 0 failed/skipped.
Mỗi phép đo có 4 file, 2 thư mục chứa file và 1 thư mục rỗng, đủ raw BMAC/UTC,
snapshot bounds, command, payload checksum và time-reversal analysis.

| Profile | File: 7-Zip | File: WinRAR | Quan sát qua 3 lần lặp |
| --- | --- | --- | --- |
| NTFS 0x000A | EEER | RERR | Birth/Accessed của file khác nhãn E/R |
| Không timestamp extra | RHRR | RHRR | Không phân biệt hai công cụ bằng pattern file |

Thứ tự pattern là B/M/A/C. Có 11 cặp entry/thuộc tính khác **nhãn nguồn** ổn định
cả ba lần; khác raw R clock giữa process không tính là khác hành vi.
Thư mục đủ timestamp nhưng chưa có pattern bốn nhãn xác định trong run này;
không ép Table 8. Table 8 candidates không được dùng làm ground truth hoặc
accuracy. Time reversal có quan sát, song số cặp thay đổi giữa các lần lặp;
xem bảng 12 phép đo và raw deltas trong evidence, không suy ra can thiệp.

`coverage.complete=true`, `coverage.dod_met=true`, CLI `--require-dod` exit 0
xác nhận **DoD đo cục bộ**. Trạng thái bàn giao được ghi riêng trong
[evidence manifest](evidence/windows-decompression-run-plhh7oml.json).
Report Markdown, report JSON, source/ZIP/output payload và command logs được
đóng gói cùng nhau. Không commit run artifacts vào Git.

Đã [bàn giao prerelease evidence](https://github.com/HuynhHHuy/zip-fingerprinting/releases/tag/evidence-ph5-dec-002-2026-11-17),
tải lại gói qua URL công khai và kiểm SHA-256/size khớp. Gói 82,257 bytes,
72 file; SHA-256 `88c82086bdaa8d9b7901d8aae100a8244ae2e23b791511d5d32d9e1526c34e45`.
Đây là release chứa evidence, không phải bản phát hành package.

## Tái kiểm chứng và giới hạn

Tải gói theo URL trong manifest, kiểm SHA-256 gói trước khi mở; kiểm mỗi file
theo `files[].path/size/sha256`. `report.json` giữ raw filesystem snapshot tại
thời điểm đo; timestamp của file sau tải/giải nén gói evidence không thay thế
snapshot đó. Đường dẫn tuyệt đối trong report mô tả máy đo, không phải download
URL. Sinh run mới có timestamp/checksum/provenance mới, không yêu cầu cùng bytes.

Không tái hiện đầy đủ môi trường năm 2021, GUI, Explorer/Bandizip, Ubuntu hoặc
accuracy classifier. Payload là corpus thay thế. Changed nguồn không cố định.
Snapshot ngay sau process không bảo đảm access time ổn định lâu dài; directory
enumeration, delayed NTFS updates, antivirus/indexer có thể ảnh hưởng quan sát.
Nguồn có 100 ns không tự chứng minh khả năng classifier phân biệt nanosecond.
V1 chưa nhận ZIP tùy ý: directory header cần slash/backslash cuối; decoder chung
bỏ timestamp NTFS/0x5855 bằng zero (raw extra vẫn giữ). Không sửa lookup Table 8
để khớp tập đo. #20 chỉ được đóng sau review và bàn giao artifact kiểm chứng được.

## Kiểm tra phần mềm

Task 1–3 đã quan sát RED rồi GREEN. Review độc lập phát hiện và đã sửa DEFLATE
hỏng thoát failure reporting và Unicode Path override chưa được preflight;
5 regression cases đã RED → GREEN. Test tổng hợp/fault injection không được
tính thành native measurements. Test native chỉ skip khi thiếu công cụ hoặc
Windows/NTFS không hỗ trợ; công cụ có mặt mà lỗi thì fail.
Task 4 thêm Markdown tự động: bốn trường hợp missing tool/native hai extractor/
process failed đã RED → GREEN. Review toàn nhánh không phát hiện lỗi nghiêm trọng
đã xác minh. Kiểm tra cuối: **286 passed, 2 skipped** (hai test CLI tạo symlink
thiếu quyền Windows WinError1314; native tracer không skip), mypy 18 source files
không lỗi, Black/Flake8 sáu file Python thay đổi đạt, `pip check` và diff sạch.

Chạy từ checkout, Python trong venv; đặt `PYTHONPATH` gồm root và `src` nếu chưa
editable-install. Lệnh kiểm tra cuối và kết quả nằm trong evidence manifest:

```powershell
python -B -m pytest -p no:cacheprovider
python -B -m mypy src experiments/windows_filetimes.py experiments/trace_decompression.py experiments/decompression_pipeline.py
python -B -m black --check experiments/windows_filetimes.py experiments/trace_decompression.py experiments/decompression_pipeline.py tests/unit/test_windows_filetimes.py tests/unit/test_decompression_tracer.py tests/integration/test_native_decompression_tracer.py
python -B -m flake8 --max-line-length=100 experiments/windows_filetimes.py experiments/trace_decompression.py experiments/decompression_pipeline.py tests/unit/test_windows_filetimes.py tests/unit/test_decompression_tracer.py tests/integration/test_native_decompression_tracer.py
python -B -m pip check
git diff --check
```
