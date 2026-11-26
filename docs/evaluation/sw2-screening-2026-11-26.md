# Sàng lọc SW2 cho Case 2 — 26/11/2026

**Kết quả dương ở một ô: 7-Zip 26.04 → Bandizip 7.47.0.1 xóa entry tạo ra Case 2
native.** Khi Bandizip xóa `target.txt`, nó ghi lại header của **cả ba** entry còn
lại theo kiểu của mình. Payload vẫn nguyên vẹn. Lần xác nhận đã đăng ký cho cùng kết
quả. Năm ô còn lại âm.

Thí nghiệm theo đúng [bản đăng ký trước](../research/sw2-screening-preregistration.md)
(commit `8c4975d`, đăng trên #19 trước khi có code đo). Code đo là commit `063530e`.
Mỗi ô chạy một lần, không có lần chạy lại vì lỗi vận hành, và không đổi lệnh hay cấu
hình.

## Kết quả

| Ô | SW1 → SW2 | Thao tác | Scope | Trường thay đổi trên survivor | Tracker sau |
| --- | --- | --- | --- | --- | --- |
| S1 | Bandizip → 7-Zip 26.04 | Xóa | `none` | Chỉ offset | Không Case 1/2 |
| S2 | Bandizip → WinRAR 6.23 | Xóa | `none` | Chỉ offset | Không Case 1/2 |
| S3 | Bandizip → Windows PowerShell 5.1 `Compress-Archive -Update` | Thêm | `none` | Chỉ vị trí CDH | Case 1 |
| S4 | Bandizip → PowerShell 7.6 `Compress-Archive -Update` | Thêm | `none` | Chỉ vị trí CDH | Case 1 |
| S5 | Bandizip → `zipfldr` (`CopyHere`) | Thêm | `none` | Chỉ vị trí CDH | Case 1 |
| **S6** | **7-Zip 26.04 → Bandizip 7.47.0.1** | **Xóa** | **`all`** | **version, extra layout trên mọi survivor** | Case 1 (không phải Case 2) |
| S6 xác nhận | như S6, run `run-sw2-gtjtd6ue` | Xóa | `all` | giống hệt S6 | Case 1 |

Run chính: `run-sw2-_kiollnq`. Với S1–S5, các entry cũ được chép nguyên khối; chỉ
offset đổi. Ở S3–S5, entry `added.txt` mang dấu vết của SW2 (version 20, không có
extra field; `zipfldr` lưu kiểu STORE). Tracker nhận ra điều này là Case 1. Đây là
các mẫu Case 1 native mới, bổ sung cho mẫu 7-Zip → WinRAR ngày 18/11.

## Ô S6: header trước và sau

| Survivor | Trước (7-Zip) | Sau (Bandizip xóa `target.txt`) |
| --- | --- | --- |
| `keep.txt` | made by 63, need 10; LFH không extra; CDH `0x000A` (NTFS) | made by 20, need 20; không extra ở cả LFH và CDH |
| `tieng-viet-ệ.txt` | made by 63, need 10, cờ UTF-8; LFH không extra; CDH `0x000A` | made by 20, need 20, cờ UTF-8; LFH và CDH `0x7075` (23 byte) |
| `가나다.txt` | made by 63, need 10, cờ UTF-8; LFH không extra; CDH `0x000A` | made by 20, need 20, cờ UTF-8; LFH và CDH `0x7075` (18 byte) |

Tên file thô, phương thức nén (DEFLATE), CRC, size và SHA-256 payload giữ nguyên.
Nói cách khác, Bandizip bỏ extra NTFS của 7-Zip, thêm Unicode Path của nó, và ghi
version của nó lên mọi entry còn lại. Đây đúng là "cascade rewrite" mà Case 2 mô tả.

Lần xác nhận cho ra `before.zip` và `after.zip` trùng từng byte với lần đầu, vì cả hai
công cụ đều tất định với cùng input. Lần xác nhận chứng minh kết quả tái lập được, nhưng
không phải một quan sát có biến thiên độc lập.

## Tracker không nhận ra Case 2 ở S6

Tracker (`ProvenanceTracker`) chỉ đọc một archive, và quy tắc Case 2 của nó cần LFH
và CDH của cùng một entry *mâu thuẫn* nhau. Bandizip ghi lại cả LFH lẫn CDH một cách
nhất quán, nên trong `after.zip` không còn dấu vết mâu thuẫn nào. Thay vào đó, tracker
báo Case 1 và chia entry thành hai nhóm:

- `keep.txt` (version 20, không extra) khớp profile Windows "Compressed folder" và bị
  gán `ORIGINAL_CREATOR_SUSPECT`;
- hai tên Unicode (chỉ có `0x7075`) không khớp profile nào trong catalog và bị gán
  `MODIFIER_SUSPECT`.

Thực tế cả ba entry đều do Bandizip ghi, còn SW1 là 7-Zip. Như vậy tracker sai Case,
sai công cụ SW1 và sai vai trò. Nguyên nhân là header Bandizip ghi khi xóa khác với
header nó ghi khi tạo archive:

| | Bandizip tạo (`S1/before.zip`) | Bandizip ghi lại khi xóa (`S6/after.zip`) |
| --- | --- | --- |
| `keep.txt` | 20/20, extra `0x000A` (32 byte) | 20/20, không extra |
| Tên Unicode | 20/20, cờ UTF-8, `0x000A` + `0x7075` | 20/20, cờ UTF-8, chỉ `0x7075` |
| Tracker | không Case 1/2 | Case 1, SW1 bị gán là "Compressed folder" |

Catalog chưa có profile cho bố cục ghi lại này. Trên ZIP do Bandizip tạo, tracker không
báo Case 1, nghĩa là mẫu sạch không bị báo nhầm.

Đây là giới hạn của phát hiện trên một archive đơn lẻ và của catalog hiện hành, không
phải lỗi đã được tái hiện độc lập theo phạm vi #19. Vì vậy tracker không được sửa
trong đợt này. Việc phát hiện Case 2 khi có bản trước để so sánh, cùng lỗi gán nhầm
SW1, được theo dõi ở
[#35](https://github.com/HuynhHHuy/zip-fingerprinting/issues/35).

## Môi trường và công cụ

| Thành phần | Phiên bản | SHA-256 (rút gọn) | Chữ ký |
| --- | --- | --- | --- |
| Host | Windows 10.0.26200, Python 3.11.9, ACP 1252 | | |
| Bandizip portable | 7.47.0.1 (`Bandizip.x64.exe`) | `2d733a26…591dc8` | Valid, Bandisoft International Inc. |
| 7-Zip | 26.04 | `95fff19b…` | Không ký |
| WinRAR | 6.23.0 | `9e08abde…` | Valid, win.rar GmbH |
| Windows PowerShell | 10.0.26100.9818 | `d8f18256…` | Valid, Microsoft Windows |
| PowerShell 7 | 7.6.10 | `e94166ed…` | Valid, Microsoft Corporation |
| `zipfldr.dll` | 10.0.26100.8117 | `81aa82eb…` | Valid, Microsoft Windows |

Bandizip được tải từ trang chính thức (`dl.php?portable`). File ZIP phân phối có SHA-256
`97e57526…3bda32c9`, được giải nén ngoài repo và dùng profile mặc định. Không có binary
nào được phân phối. Hash đầy đủ, argv, stdout/stderr của mọi lệnh nằm trong
`metadata.json` của từng run.

## Kiểm chứng

- Tính lại `read_evidence` + `compare_survivors` từ bytes ZIP cho cả 7 lần đo (6 ô +
  xác nhận): kết quả trùng với metadata; hash `before`/`after` khớp; CRC ZIP hợp lệ.
- Test: 430 passed, 5 skipped. `mypy` sạch. Black/Flake8 sạch trên các file đã đổi.
- `compare_delete` sau khi tổng quát hóa cho kết quả trùng từng byte với run thật
  `run-case2-dlq9ulnc`.

## Giới hạn

- Một host, các phiên bản công cụ hiện hành, bốn file nhỏ không có thư mục.
- Cặp gây Case 2 là 7-Zip → Bandizip, **không phải** cặp Bandizip → Explorer mà bài
  báo nêu làm ví dụ. Cặp đó vẫn âm trên cả ba lần đo trước.
- Kết quả âm của S1–S5 chỉ đúng cho phiên bản và thao tác đã thử.
- Chưa thử Bandizip 6.29 làm SW2. Hành vi ghi lại toàn bộ có thể khác theo phiên bản.

## Kết luận cho #19

Theo điểm dừng đã đăng ký, S6 và lần xác nhận đều `all`, nên **7-Zip 26.04 →
Bandizip 7.47.0.1 (xóa)** là mẫu Case 2 native.

Đối chiếu với checklist nghiệm thu của #19:
- **Đã có:** mẫu thật xác nhận Case 2 bằng thay đổi header của các entry còn lại;
  payload nguyên vẹn và bảng header trước/sau; Case 1 native (7-Zip → WinRAR, cùng
  S3–S5); provenance, phiên bản, cách thao tác, checksum và artifact tải được; test
  tổng hợp tách khỏi bằng chứng native.
- **Cần reviewer quyết:** checklist yêu cầu "bộ mẫu chung bao phủ Case 1 và Case 2".
  Các mẫu hiện nằm trong evidence bundle, chưa được đưa vào corpus hay catalogue dùng
  chung.

Đề nghị reviewer xem xét nghiệm thu #19. Issue chưa được đóng.

Xem [manifest và checksum](evidence/sw2-screening-2026-11-26.json). Bundle
`sw2-screening-2026-11-26-evidence.zip` (42 635 byte, SHA-256 `17fb4445…894c40`) gồm
hai run, toàn bộ ZIP trước/sau, source và metadata. Bundle có trên
[prerelease riêng](https://github.com/HuynhHHuy/zip-fingerprinting/releases/tag/evidence-ph4-prov-002-sw2-2026-11-26);
bản tải công khai đã được kiểm lại: size, SHA-256 và 49 file thành phần đều khớp.
