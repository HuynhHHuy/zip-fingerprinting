# Đăng ký trước: sàng lọc SW2 cho Case 2 (#19, PH4-PROV-002)

**Ngày đăng ký:** 26/11/2026. **Trạng thái:** đăng ký trước. Chưa có code chạy thí
nghiệm và chưa có lần đo nào của các ô dưới đây. Mọi thay đổi với tài liệu này sau
khi đo đều phải được ghi là sửa đổi, kèm lý do; không được sửa lặng lẽ.

## Vì sao làm thí nghiệm này

Cặp Bandizip → Explorer Delete đã cho kết quả âm ba lần:
- CLI và GUI trên Windows 11, ngày 18/11;
- GUI trên Windows 10 v2004 với Bandizip 6.29, ngày 26/11
  ([báo cáo](../evaluation/native-case2-win10-2004-2026-11-26.md)).

Lần nào Explorer cũng chép nguyên header của các entry còn lại và chỉ dời offset.

DoD của #19 không gắn riêng với cặp đó. DoD yêu cầu một **mẫu thật** trong đó phần
mềm thứ hai (SW2) thay đổi header hoặc extra field của **mọi** entry còn lại, kèm
nhãn theo công cụ thực sự đã dùng. Thí nghiệm này tìm xem trong số các SW2 sẵn có,
phần mềm nào ghi lại toàn bộ archive thay vì chép nguyên từng khối.

## Môi trường và công cụ

- **Host:** Windows 11 (10.0.26100/26200), Python 3.11.9, ACP 1252.
- **Bandizip 7.47.0.1 portable:**
  - tải ngày 26/11 từ `bandisoft.com/bandizip/dl.php?portable`
    (→ `bandisoft.app/bandizip/BANDIZIP-PORTABLE.ZIP`);
  - file ZIP phân phối: SHA-256 `97e575262b2ecb0a403cb9d878c878a540a3fa03b189e1979c16f93b3bda32c9`;
  - `Bandizip.x64.exe`: SHA-256 `2d733a26500a8cff7db04291c396b3d48e9d7275753e2a06bf3564c9f9591dc8`,
    Authenticode Valid (Bandisoft International Inc.);
  - giải nén ngoài repo, dùng profile mặc định của bản portable. Cùng phiên bản với
    lần 18/11, nhưng chưa đối chiếu hash với executable của lần đó;
  - bản portable không có `bz.exe`, nên dùng `Bandizip.x64.exe` ở chế độ dòng lệnh
    như lần 18/11.
- **7-Zip 26.04**, **WinRAR 6.23.0**.
- **Windows PowerShell 5.1** (`powershell.exe` 10.0.26100.9818, .NET Framework),
  **PowerShell 7.6.10** (.NET 10), **`zipfldr.dll` 10.0.26100.8117**.

## Source

Dùng đúng 4 file của `experiments/explorer_delete.SOURCES`: `keep.txt`,
`target.txt`, `tieng-viet-ệ.txt`, `가나다.txt`. atime/mtime cố định
2021-01-11T11:30:59.1234567Z. Khi thao tác là thêm file, SW2 thêm `added.txt`
(nội dung `added payload\n`).

## Ma trận (6 ô, mỗi ô chạy 1 lần)

| Ô | SW1 (tạo ZIP) | SW2 | Thao tác | Lệnh SW2 |
| --- | --- | --- | --- | --- |
| S1 | Bandizip `c -y` | 7-Zip 26.04 | Xóa `target.txt` | `7z.exe d -tzip after.zip target.txt` |
| S2 | Bandizip `c -y` | WinRAR 6.23 | Xóa `target.txt` | `WinRAR.exe d -ibck -inul -y after.zip target.txt` |
| S3 | Bandizip `c -y` | Windows PowerShell 5.1 `Compress-Archive` | Thêm `added.txt` | `Compress-Archive -LiteralPath added.txt -DestinationPath after.zip -Update` (đường dẫn truyền qua biến môi trường) |
| S4 | Bandizip `c -y` | PowerShell 7.6 `Compress-Archive` | Thêm `added.txt` | như S3, chạy bằng `pwsh.exe` |
| S5 | Bandizip `c -y` | Windows compressed folder (`zipfldr`) qua `Shell.Application.CopyHere`, không qua UI | Thêm `added.txt` | `scripts/add_zip_entry_shell.ps1` |
| S6 | 7-Zip 26.04 `a -tzip` | Bandizip | Xóa `target.txt` | `Bandizip.x64.exe d -y after.zip target.txt` |

SW1 tạo `before.zip`. Bản sao `after.zip` là thứ SW2 sửa; `before.zip` không bao
giờ bị sửa.

## Tiêu chí

Dùng nguyên comparator hiện có (`experiments/modification_evidence.py`), mở rộng
để nhận thêm thao tác thêm file. Survivor là mọi entry của `before.zip` không bị
xóa. Một survivor **có thay đổi cấu trúc** khi ở LFH hoặc CDH có ít nhất một trong
các trường sau thay đổi:
- `version_made_by`, `extract_version`, `compression_method`;
- `provenance_flags` (bit 11 UTF-8 và bit 3 data descriptor);
- `raw_name_hex`;
- `extra_layout` (ID, thứ tự, độ dài extra field).

Các trường offset, CRC, size hay timestamp đổi một mình thì không tính.

Kết quả của mỗi ô:
- `all`: mọi survivor có thay đổi cấu trúc. Đây là **ứng viên Case 2**.
- `partial`: chỉ một số survivor có.
- `none`: không survivor nào có.

Payload của survivor phải nguyên vẹn (size, SHA-256); inventory phải đúng thao
tác. Sai một trong hai thì ô bị tính `failed`, không tính kết quả.

Tracker (`ProvenanceTracker`) chạy độc lập trên cả hai file và được báo cáo cạnh
comparator. Kết quả tracker không quyết định ô đạt hay không.

## Quy tắc chạy

1. Mỗi ô chạy đúng 1 lần, trong cùng một run.
2. Chỉ được chạy lại 1 lần khi có **lỗi vận hành**: công cụ trả mã lỗi, timeout,
   hoặc file bị khóa. Lần lỗi vẫn được giữ trong metadata.
3. Không đổi lệnh, cờ, cấu hình hay source sau khi đã thấy kết quả của bất kỳ ô
   nào.
4. Mọi kết quả (`all`, `partial`, `none`, `failed`, `skipped`) đều được công bố.

## Điểm dừng

- Ô có kết quả `all` → chạy **một lần xác nhận** cho đúng ô đó, ở run mới, cùng
  lệnh. Cả hai lần đều `all` thì đó là mẫu Case 2 native cho #19, gắn nhãn
  "SW1 → SW2" theo công cụ thực. Đây mới là căn cứ đề nghị nghiệm thu, và không tự
  đóng issue.
- Ô có kết quả `partial` → báo cáo, không tính đạt, không chạy thêm.
- Không ô nào đạt `all` sau lần xác nhận → dừng và báo cáo âm. Sau đó người hướng
  dẫn chọn: thử guest Windows tiếng Hàn (thí nghiệm mới, đăng ký riêng), hoặc đóng
  #19 bằng kết quả âm kèm sửa DoD.

## Giới hạn đã biết trước

- Một host, phiên bản công cụ hiện hành, ZIP nhỏ không có thư mục.
- S3–S5 dùng thao tác thêm file, vì `Compress-Archive` và `CopyHere` không có lệnh
  xóa. Case 2 trong bài báo mô tả thao tác sửa archive nói chung, không riêng xóa.
- S5 gọi `zipfldr` qua Shell API, không qua giao diện Explorer.
- Kết quả dương ở một cặp không chứng minh cặp Bandizip → Explorer của bài báo; kết
  quả âm không bác bỏ bài báo.
