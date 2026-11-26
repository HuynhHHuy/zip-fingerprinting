# Script guest cho Case 2 trên Windows 10 v2004 (#19)

Bộ script này đã dùng cho lần đo ngày 26/11/2026
([báo cáo](../../docs/evaluation/native-case2-win10-2004-2026-11-26.md)).
Guest bị cô lập: không có mạng, không có VMware Tools, không có clipboard, kéo-thả
hoặc shared folder. Vì vậy mọi đầu vào được đưa vào bằng một ISO dữ liệu chỉ đọc
(nhãn `CASE2DATA`), còn kết quả được đưa ra bằng một ổ đĩa ảo riêng (`CASE2EVID`).

Script chạy bằng Windows PowerShell 5.1 có sẵn trong guest. Mỗi bước có một file
`RUN-0x-*.cmd`; người thao tác chuột phải vào file đó và chọn **Run as
administrator**. Log transcript và `environment.txt` được ghi vào `C:\case2` trong
guest.

| Bước | Script | Việc làm |
| --- | --- | --- |
| 01 | `01-verify-and-record.ps1` | Tắt hibernation, kiểm SHA-256 của toàn bộ đĩa dữ liệu, ghi edition/build, ACP, locale, timezone, phiên bản `zipfldr.dll`/`explorer.exe` |
| 02 | `02-install-python-and-test.ps1` | Cài Python 3.11.9 offline, chép checkout vào `C:\case2`, cài wheel offline, chạy `pytest` |
| 03 | `03-install-bandizip.ps1` | Chạy bộ cài Bandizip 6.29 (tương tác), ghi đường dẫn, phiên bản, SHA-256 và chữ ký |
| 04 | `04-case2-experiment.ps1` | Chạy `prepare` → `seal-creation` → `finalize --require-case2` của `experiments.explorer_delete` |
| 05 | `05-export-evidence.ps1` | Format ổ evidence trống thành FAT32 `CASE2EVID`, chép thư mục run và log, đối chiếu và ghi `SHA256SUMS.txt` |

Chụp snapshot máy ảo khi đã tắt, sau bước 03 và trước bước 04.

## Bước 04 ghi nhận những gì

Người thao tác tự thực hiện mọi thao tác GUI. Script không click, không gõ phím
và không sửa archive. Tại mỗi điểm dừng, script chỉ đọc và ghi lại:

- cây UI Automation của các cửa sổ Bandizip hoặc Explorer liên quan, gồm tên
  control, trạng thái checkbox và giá trị ô nhập;
- lựa chọn thực tế trong Explorer qua `Shell.Application`, lấy tên file thật từ
  đường dẫn vì Explorer có thể ẩn đuôi file;
- thời điểm UTC và trạng thái archive đã được đóng (mở độc quyền được);
- registry `HKCU\Software\Bandizip` trước và sau khi tạo ZIP.

Từ đó script ghi `creation-log.json` và `delete-log.json` ở mức `ui_observed`,
mỗi file kèm hai observation trước/sau có SHA-256, theo đúng schema mà
`experiments/explorer_delete.py` kiểm tra. Đây là bằng chứng do người thao tác ghi
nhận, không phải telemetry có xác thực.

## Bố cục đĩa dữ liệu

Trên ISO, các file `RUN-0x-*.cmd` nằm ở thư mục gốc và gọi
`%~dp0scripts\<tên>.ps1`. Vì vậy các file `.ps1` phải được đặt trong thư mục
`scripts\`. Bố cục đã dùng:

```text
CASE2DATA\
  RUN-01..05-*.cmd
  scripts\common.ps1, 01..05-*.ps1
  checkout\zip-fingerprinting\     git archive của commit đo
  installers\python-3.11.9-amd64.exe, BANDIZIP6-SETUP-6.29.exe
  wheels\                          pip download --platform win_amd64 --python-version 3.11
  README-GUEST.txt
  SHA256SUMS.txt                   "<SHA256 viết hoa>  <đường dẫn tương đối>" mỗi dòng, ASCII
```

Tạo ISO trên host bằng `host/make_iso.ps1`. Script dùng IMAPI2 với ISO9660 +
Joliet + UDF, và phải chạy bằng `powershell.exe` 5.1 vì PowerShell 7 không
marshal được `IStream`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\case2_guest\host\make_iso.ps1 `
  -Source <thư mục đã dựng> -Output <đường dẫn>\case2-data.iso
```

Không commit hoặc phân phối ISO Windows, ổ đĩa VM, hay bộ cài Bandizip/Python.

## Đọc ổ evidence trên host

Tắt guest trước, sau đó đọc `case2-evidence.vmdk` bằng 7-Zip (vmdk → MBR → FAT32)
và đối chiếu với `SHA256SUMS.txt` trên ổ. Danh sách của 7-Zip có thể hiển thị tên
Unicode thành `_`, nhưng khi giải nén thì tên file vẫn đúng.
