# Thí nghiệm can thiệp ZIP — PH4-PROV-002

## Chạy lại

```powershell
python scripts/simulate_modifications.py --require-cases
python scripts/simulate_modifications.py --scenario A --scenario control-add
python scripts/simulate_modifications.py --7zip "C:/Program Files/7-Zip/7z.exe"
python -m pytest tests/integration/test_modification_simulator.py
```

Chạy được trực tiếp từ checkout, không cần cài package. Dùng Python ≥3.10;
công cụ native cần Windows. Không tự cài phần mềm. WinZip cần Command Line
Support Add-On (`wzzip.exe`); chỉ cài ứng dụng giao diện chưa đủ.

## Kịch bản và nhãn

| ID | SW1 → SW2 | Thao tác | Cấu hình |
|---|---|---|---|
| A | 7-Zip → WinRAR | Add `added.txt` | ZIP mặc định; WinRAR bỏ cấu hình người dùng (`-cfg-`) |
| B | Bandizip → Windows shell | Loại `target.txt` | Shell `MoveHere` ra thư mục riêng |
| C | WinZip CLI → 7-Zip | Modify `target.txt` | Nội dung và timestamp mới |
| control-add | 7-Zip → WinRAR | Add | SW1 dùng `-mtc=off -mta=off -mtm=off` |
| control-modify | 7-Zip → WinRAR | Modify | SW1 dùng `-mtc=off -mta=off -mtm=off` |
| control-delete | WinRAR → Windows shell | Loại `target.txt` | Biến thể B khi không có Bandizip |

Nguồn nhỏ gồm `keep.txt`, `target.txt`, `tieng-viet-ệ.txt`, mtime/atime cố định
2021-01-11 11:30:59.1234567 UTC. Đây là corpus tối thiểu cho thí nghiệm can thiệp,
không thay thế corpus Hình 5 của PH6. Birth/change time không được cố định.

Mọi lần chạy có thư mục riêng, giữ `before.zip` nguyên vẹn và chỉ thao tác trên
`after.zip`. `zipfile` đọc/kiểm tra CRC và payload của các mẫu nhỏ do script tự
sinh; không dùng để tạo vân tay hoặc sửa header. So sánh payload xác nhận đúng
entry được thêm/sửa/xóa và các entry còn lại giữ nguyên. Parser và tracker hiện
có phân tích cả hai archive. Không vá header để buộc kết quả khớp kỳ vọng.

Shell helper dùng Windows `Shell.Application` và `MoveHere` với các cờ silent,
no-confirmation, no-error-UI. Entry được chuyển ra thư mục `removed/` trong run.
**Đây không phải thao tác Delete trong giao diện Explorer** và không được dùng
để khẳng định tái hiện chính xác kịch bản B của bài báo. Helper chạy trong tiến
trình PowerShell với ExecutionPolicy Bypass chỉ cho tiến trình đó, không đổi
chính sách hệ thống. Hết 30 giây mà chưa loại được entry thì ghi lỗi; lệnh native
có timeout 60 giây. Không giải nén archive của người dùng.

## Metadata và kết quả đo

`metadata.json` lưu hệ điều hành, thời gian UTC, đường dẫn/phiên bản công cụ,
argv/cwd/stdout/stderr/mã thoát của mỗi lệnh, SHA-256/size và phân tích từng ZIP.
`expected_case` là giả thuyết theo loại thí nghiệm; `after.analysis.cases` là kết
quả tracker. `untouched_entries_with_header_changes` so sánh host OS và raw extra
fields LFH/CDH trước/sau, không suy diễn từ tên phần mềm.

`coverage.dod_met` chỉ bật khi có ít nhất hai cặp mẫu hợp lệ và tracker quan sát
được cả hai Case. Cờ `--require-cases` trả mã 2 nếu chưa đạt; lỗi công cụ trả mã 1,
không có mẫu nào cũng trả mã 2. Mã 0 mặc định chỉ xác nhận đã tạo mẫu không lỗi,
không chứng minh tái hiện toàn bộ nghiên cứu. Mẫu lỗi và skip vẫn có trong manifest.

Kết quả ngày **06/11/2026**, Windows, 7-Zip **26.04**, WinRAR **6.23.0**:

| Kịch bản | Tạo mẫu | Tracker Case 1 | Tracker Case 2 |
|---|---|---|---|
| A | Có | Không | Không |
| B | Skip: thiếu Bandizip | — | — |
| C | Skip: thiếu WinZip CLI | — | — |
| control-add | Có | Có | Không |
| control-modify | Có | Có | Không |
| control-delete | Có | Không | Không |

Mẫu mặc định A có các profile chồng lấn nên tracker không nhận ra nhiều nguồn.
Các control tắt timestamp cho SW1 tạo cấu trúc khác biệt rõ với WinRAR; tracker
phát hiện Case 1 nhưng có thể gọi nhóm SW1 là `Compressed folder` vì cấu hình
7-Zip này nằm ngoài profile mặc định trong catalog. Nhãn ground truth phải dựa
vào lệnh đã ghi, không thay bằng tên ứng viên tracker.

Thao tác shell removal trên phiên bản Windows hiện tại giữ extra fields ở entry
còn lại; không quan sát thấy Case 2. Không có đủ bằng chứng để nghiệm thu toàn
bộ PH4-PROV-002. Cần chạy lại với Bandizip/WinZip CLI và môi trường/phiên bản phù
hợp, đồng thời đối chứng thao tác Delete thực tế trong Explorer. Code hỗ trợ B/C
chưa được kiểm chứng với các executable thiếu trên máy này.

## Explorer Delete thực tế — workflow mới (18/11/2026)

```powershell
# Chạy từ root checkout, package đã cài editable hoặc PYTHONPATH=src
python -m experiments.explorer_delete prepare --bandizip "C:/private/Bandizip.x64.exe"
# exit 2, status awaiting_gui: chưa có thao tác Delete, chưa nghiệm thu
# Mở RUN/after.zip trong Explorer; chỉ xóa target.txt; quan sát trước/sau,
# đóng cửa sổ ZIP rồi lưu gui-before.json, gui-after.json và gui-log.json.
python -m experiments.explorer_delete finalize RUN --gui-log RUN/gui-log.json
python -m experiments.explorer_delete finalize OTHER_RUN --gui-log OTHER_RUN/gui-log.json --require-case2
```

Không sửa `before.zip`, source hoặc metadata để retry. Mỗi lần prepare tạo
`run-case2-*` mới; `finalize` chỉ nhận state awaiting_gui và không ghi đè
observed-after.zip. JSON là báo cáo authoritative; lỗi được lưu thành failed.
Exit 0 nghĩa quan sát hợp lệ (kể cả âm), 1 lỗi, 2 pending/skipped hoặc âm khi
dùng `--require-case2`. Không gọi lại finalize trên run đã kết thúc.

`--configuration default|unicode-path` chỉ là nhãn cấu hình do operator đã
thiết lập trong profile portable riêng, **không tự bật tùy chọn**. Kiểm tra
raw header/config snapshot để xác nhận hành vi thực; không gán nhãn bằng
classifier. Không dùng workflow này để sửa ZIP của người dùng.

GUI log phải nằm trong run, là JSON object có `run_id`, `archive` (đường dẫn
tuyệt đối after.zip), `target: "target.txt"`, `action: "Delete"`,
`application: "explorer.exe"`, `started_utc`, `ended_utc` (ISO có timezone),
`archive_closed: true`, `evidence_level` và `observations`. Thời gian phải
sau prepared_utc, trước hiện tại. `operator_assertion` ghi nhận thao tác
nhưng không xác nhận native Case 2. `ui_observed` cần hai file quan sát:

```json
{"observations": [
  {"path": "gui-before.json", "sha256": "<SHA-256 file>"},
  {"path": "gui-after.json", "sha256": "<SHA-256 file>"}
]}
```

Mỗi file là object với cùng run_id/archive/application, `observed_utc` nằm
trong khoảng thao tác, `phase` before/after, `window_title`,
`accessibility_tree` thực tế; before thêm `selected_target: "target.txt"`.
Các record là bằng chứng operator, không chống giả mạo; reviewer cần đối
chiếu cặp ZIP và log, không chỉ nhìn evidence_level.

Reader hỗ trợ STORE/DEFLATE, từ chối codec khác, size khai báo sai hoặc
deflate thừa/thiếu dữ liệu; kiểm tra output thực với giới hạn trước CRC read.
Reader từ chối tên trùng/unsafe, reparse/link, ZIP hoặc tổng payload >16 MiB,
UTF-8/Unicode Path CRC sai hoặc LFH/CDH identity xung đột. Payload chỉ đọc
trong bộ nhớ. So sánh độc lập tracker: all/partial/none theo version/method,
UTF8/descriptor bits, raw name và extra ID/order/length. Offset/timestamp
values/CRC/size không đủ xác nhận Case 2. Layout bên trong extra cùng ID và
length chưa được phân loại; raw bytes vẫn giữ để review.

Đối chứng 18/11: Bandizip portable 7.47.0.1 → Explorer Delete thực tế cho
scope none; Case 1 mới có bằng chứng. Unicode Path đã bật mặc định nên không
lặp cùng cấu hình. **#19 vẫn chưa đạt DoD Case 2.** Xem
[kết quả, giới hạn và bằng chứng](../evaluation/native-case2-2026-11-18.md).

## Tạo baseline bằng GUI rồi seal

CLI tạo ZIP vẫn là mặc định, run cũ không có creation_mode được xử lý như CLI.
Chế độ GUI không chạy lệnh nén; version helper vẫn đọc phiên bản executable.

```powershell
python -m experiments.explorer_delete prepare --creation-mode gui --configuration unicode-path --bandizip "C:/private/Bandizip.x64.exe"
# exit2 awaiting_creation: source/manifest sẵn, chưa có ZIP
# GUI Bandizip chọn bốn file source, output RUN/before.zip; nén xong, đóng ZIP
python -m experiments.explorer_delete seal-creation RUN --gui-log RUN/creation-log.json
# exit2 awaiting_gui: before.zip đã kiểm chứng, after.zip mới được sao chép
# Explorer Delete target.txt trên after.zip; đóng ZIP
python -m experiments.explorer_delete finalize RUN --gui-log RUN/delete-log.json --require-case2
```

Creation-log dùng schema GUI observation ở trên, thay các trường bằng:
`archive` = absolute RUN/before.zip, `action: "Create"`, `application` = tên
executable Bandizip, `executable` = đường dẫn tuyệt đối đúng metadata,
`source_directory` = absolute RUN/source, `selected_entries` = danh sách tên
bốn file sort theo Python. Không có target trong creation-log.
Thời gian bắt đầu phải sau creation_ready_utc; archive_closed phải true.

Hai observation before/after cùng run/archive/application/executable và
source_directory; before ghi selected_entries đúng bốn file, mỗi observation
có observed_utc/window_title/accessibility_tree. Ghi ảnh và setting thật để
review thêm; cấu hình GUI không được suy từ nhãn --configuration. File log và
observations phải nằm trong run, checksum khớp; xem run evidence để có ví dụ
native. GUI log được operator ghi, không tự chứng minh tác giả của thao tác.

Seal kiểm source anchors, inventory/CRC/payload/identity, executable hash và
lưu raw INI sau tạo ZIP; không ghi đè after.zip tồn tại, không seal lặp.
ZIP tăng kích thước/đổi bytes trong lúc seal bị từ chối. Lỗi lưu failed kèm
reason; không chỉnh metadata để retry, dùng prepare mới. Finalize kiểm lại
creation-log cùng checksum observations và baseline; nhánh GUI chỉ xác nhận
native Case2 khi cả creation và Delete đều ui_observed và global rewrite.
Operator-only creation có thể seal để phân tích, nhưng không đạt native DoD.

Đợt GUI18/11: run-case2-hz8kgcll scope none; không retry; source/baseline và
payload survivor nguyên vẹn. Case1 control mới run-16gz65r7 hợp lệ. Xem
[báo cáo GUI](../evaluation/native-case2-gui-2026-11-18.md) và
[hướng dẫn VM](case2-windows10-vm.md). Không chạy thêm cấu hình
host hoặc tự dùng Ubuntu/Wine để thay Windows Explorer.

Đợt VM 26/11: Windows 10 v2004 + Bandizip 6.29 GUI → Explorer Delete,
run-case2-dlq9ulnc scope none, kết quả âm. Script guest nằm ở
[scripts/case2_guest](../../scripts/case2_guest/README.md); xem
[báo cáo](../evaluation/native-case2-win10-2004-2026-11-26.md).

## Sàng lọc SW2 (đăng ký trước)

`python -m experiments.sw2_screening run --bandizip PATH\Bandizip.x64.exe` chạy đúng
6 ô trong [bản đăng ký](sw2-screening-preregistration.md); `confirm --cell Sx` chạy
lần xác nhận ở run mới. SW1 tạo `before.zip`, SW2 sửa bản sao `after.zip`;
`compare_survivors` chấm mọi entry được giữ lại, tracker chạy riêng. Exit 0 khi hoàn
tất, 1 khi có ô lỗi, 2 khi không ô nào chạy được hoặc `--require-case2` mà không có
`all`. Đợt 26/11: 7-Zip → Bandizip xóa cho Case 2 native; xem
[báo cáo](../evaluation/sw2-screening-2026-11-26.md).

## Tài liệu công cụ

- [Bandizip command line](https://www.bandisoft.com/bandizip/help/parameter/)
- [WinZip Command Line Support Add-On](https://kb.winzip.com/en/130423)
- Cú pháp 7-Zip/WinRAR đối chiếu với help cài trên máy; mọi argv thực tế nằm trong
  manifest. Không đồng nhất cấu hình CLI với mặc định kéo-thả/menu ngữ cảnh.
