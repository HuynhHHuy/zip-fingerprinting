# Data Directory

Thư mục này quản lý dữ liệu kiểm nghiệm và mẫu nén ZIP phục vụ tái hiện nghiên cứu:
- `templates/`: Cây thư mục nguồn tiêu chuẩn (dựa trên Hình 5 trong bài báo của Minji Um et al.).
- `ground_truth/`: Chứa các tệp ZIP được nén bằng các phần mềm khác nhau trên Windows, Linux, macOS.
- `modified_samples/`: Chứa các mẫu ZIP được can thiệp (thêm/xóa/sửa đổi tệp) để kiểm tra tính năng truy vết đa nguồn gốc (Provenance tracking - Mục 4.2).
- `metadata.json`: Bản ghi thông tin nguồn gốc, môi trường tạo, checksum SHA-256 của từng mẫu.

## Corpus chuẩn — PH6-DATA-001

Từ repository root, chạy:

```powershell
python scripts/prepare_corpus.py
# Hoặc chọn thư mục khác; đường dẫn tương đối tính từ working directory:
python scripts/prepare_corpus.py --output C:/Temp/zip-corpus
```

Mặc định luôn là `data/templates/` của checkout, kể cả khi gọi script từ working
directory khác. Generator chỉ dùng thư viện chuẩn Python. `Pillow` thuộc nhóm
`dev` để test giải mã JPEG độc lập, không cần để sinh corpus.

```text
templates/
├── manifest.json
├── set1/
│   ├── Study/
│   │   ├── capture.JPG
│   │   ├── Sample.docx
│   │   └── textsm.txt
│   ├── emptyFolder/
│   └── 2021.JPG
└── auxiliary/
    ├── double_zip/inner.zip
    ├── encodings/korean-cp949.txt
    ├── korean_nfc/가나다.txt
    ├── korean_nfd/가나다.txt
    └── vietnamese/tiếng-Việt.txt
```

`set1/` giữ đúng cấu trúc Hình 5. Hai JPEG 16×16 dùng cùng fixture hợp lệ;
DOCX là gói OOXML tối thiểu với một đoạn văn. Đây là payload thay thế tự tạo,
**không phải nội dung gốc của tác giả hoặc mẫu ground truth do archiver tạo**.
Không suy ra đã tái hiện bài báo từ việc sinh được cây thư mục này.

Các mẫu Hàn NFC/NFD đặt trong hai thư mục riêng để tránh va chạm tên. Nội dung
hai file này là UTF-8; `korean-cp949.txt` có payload CP949. Filename trên Windows
là Unicode: các mẫu nguồn này chưa chứng minh archiver ghi tên ZIP bằng CP949.
Việc kiểm soát encoding ZIP thuộc PH6-DATA-002. Nén thêm cây `auxiliary/` để tạo
biến thể double zipping; không trộn các mẫu phụ trợ vào baseline `set1/`.

`manifest.json` phiên bản 1 liệt kê 9 thư mục và 9 file, đường dẫn tương đối dùng
`/`, size và SHA-256 của từng payload. Không chứa đường dẫn máy, thời gian chạy
hay checksum của chính manifest. Thứ tự entry và bytes đầu ra ổn định; manifest
được lưu trong Git để làm baseline checksum. Payload và thư mục rỗng được sinh
lại bằng script, không lưu vào Git. ZIP nội bộ dùng STORE, thứ tự entry và metadata
cố định, không phụ thuộc phiên bản compressor hoặc host OS.

**Timestamp và giới hạn:**

- Ngay khi generator hoàn tất, atime/mtime của file, thư mục, manifest và output
  root là `2021-01-11 11:30:59 UTC` (`1610364659000000000` ns).
- Generator kiểm tra lại timestamp và báo lỗi nếu filesystem không giữ được đúng
  giá trị. Không cố định creation time hoặc NTFS change time; không dùng corpus
  này như bằng chứng đã đo đủ BMAC.
- DOS timestamp trong DOCX/ZIP con là `2021-01-11 11:30:58`, không chứa timezone;
  định dạng DOS có độ phân giải 2 giây. Timestamp do archiver ghi khi nén cây nguồn
  còn phụ thuộc timezone/cấu hình của archiver và phải ghi nhận ở PH6-DATA-002.
- Đọc file, liệt kê thư mục, copy hoặc checkout có thể đổi timestamp. Sinh lại
  corpus ngay trước thực nghiệm; Git không bảo toàn filesystem timestamp.
- Filesystem cần giữ được tên NFC/NFD được yêu cầu. Trường hợp tự chuẩn hóa tên
  sẽ bị kiểm tra inventory từ chối; chưa xác thực trên macOS hoặc filesystem khác
  NTFS của máy phát triển.

Chạy lại khôi phục nội dung/timestamp của các đường dẫn do generator quản lý.
Nếu có đường dẫn lạ, sai kiểu, symlink, Windows reparse point hoặc hard link,
script từ chối trước khi ghi và không xóa dữ liệu. Hãy chọn output trống thay vì
đặt dữ liệu cá nhân trong cây corpus. Lỗi trả exit `1`; thành công trả exit `0`.

Kiểm chứng:

```powershell
python -m pytest tests/unit/test_prepare_corpus.py
```

Test giải mã JPEG, kiểm tra content types/relationships/XML và CRC DOCX, đọc
ZIP con, kiểm tra timestamp trước khi truy cập payload/thư mục, đối chiếu manifest,
sinh ở hai thư mục độc lập và chạy lại. Nghiệm thu cục bộ: Windows, Python 3.11;
chưa coi đó là kết quả kiểm thử đa nền tảng hoặc tái hiện thực nghiệm bài báo.

## Ground-truth Windows CLI — PH6-DATA-002

```powershell
python scripts/generate_ground_truth.py
python scripts/generate_ground_truth.py --data-dir C:/Temp/zip-data --tool 7zip --variant root
python scripts/generate_ground_truth.py --tool winrar --variant root --variant contents --winrar "C:/Program Files/WinRAR/WinRAR.exe"
python -m pytest tests/integration/test_ground_truth_generator.py
```

`--data-dir` là data root, mặc định `data/` của checkout, không phụ thuộc working
directory. `--tool` chọn `7zip`, `winrar`, `bandizip`, `powershell`; `--variant` chọn
`root`, `contents`, `auxiliary`. Hai option đều lặp lại được; mặc định chạy cả bốn
adapter × ba biến thể. Có override executable `--7zip`, `--winrar`, `--bandizip`,
`--powershell`; path không tồn tại bị từ chối trước khi tạo catalogue.

| Biến thể | Nguồn nén | Tên file bên trong ZIP |
| --- | --- | --- |
| `root` | `set1/` | Giữ prefix `set1/` |
| `contents` | Các phần tử trực tiếp của `set1/` | Không có prefix `set1/` |
| `auxiliary` | `auxiliary/` | Giữ prefix `auxiliary/`, gồm ZIP con và Unicode |

Mỗi mẫu có source riêng được sinh từ PH6-DATA-001 và kiểm tra theo manifest
baseline trong Git. Generator được gọi lại ngay trước process để khôi phục
atime/mtime sau bước kiểm tra checksum; không sửa `data/templates/` dùng chung.
Không có cấu hình ép CP949: metadata ghi nhận tên entry thực tế được giải mã bằng
UTF-8 flag, Unicode Path `0x7075` có CRC tên gốc hợp lệ, rồi Windows ANSI code page.
Tên không khớp inventory nguồn được báo lỗi, không tự thay encoding để làm test pass.

7-Zip dùng `a -tzip -y`, WinRAR dùng `a -afzip -cfg- -inul -ibck -y`, Bandizip dùng
`c -y`. Không thay mức nén/timestamp để ép profile lý thuyết. PowerShell dùng
`Compress-Archive -LiteralPath ... -CompressionLevel Optimal`; probe ghi engine,
phiên bản và đường dẫn module, rồi import đúng module đó khi nén. Không cài công
cụ/module hoặc thay cấu hình hệ thống. Bandizip adapter chưa được xác thực native
trên máy này vì thiếu executable.

Mỗi run tạo thư mục mới `ground_truth/run-*/`, chứa ZIP, source và `metadata.json`.
Toàn bộ run artifacts bị Git bỏ qua. `data/metadata.json` là catalogue phiên bản 1:

```json
{"schema_version": 1, "runs": []}
```

`{}` được chấp nhận duy nhất như trạng thái khởi tạo. JSON hỏng hoặc schema không
hỗ trợ bị từ chối trước khi nén. Run mới được append, không thay thế run cũ; ghi
JSON qua file tạm cùng thư mục và `os.replace`. Đây là giao diện chỉ có một writer,
không hỗ trợ nhiều process cập nhật catalogue đồng thời. Run report được ghi trước
catalogue; nếu cập nhật catalogue lỗi, artifact vẫn còn để kiểm tra thủ công.

Metadata lưu OS/build, timezone/UTC offset, ANSI code page, công cụ/executable/
phiên bản, biến thể, timestamp UTC, argv/cwd/stdout/stderr/returncode, source times,
checksum manifest nguồn, đường dẫn ZIP tương đối với data root, size/SHA-256 và
validation. Lệnh PowerShell còn lưu script đã giải mã để có thể đọc lại.
Không lấy nhãn ground truth từ classifier; PowerShell mang nhãn **PowerShell
Compress-Archive**, không phải Explorer/Compressed folder.

Validation dùng `zipfile`, đọc payload trong RAM, kiểm tra CRC, size/SHA-256,
inventory, entry trùng và đường dẫn nguy hiểm; không giải nén ra đĩa. Thiếu directory
header được ghi trong `missing_directory_headers`, không tự thêm/sửa archive.
Ví dụ native trên máy này: PowerShell `contents` không có header `Study/` và
`emptyFolder/`, nhưng bốn payload file vẫn đầy đủ. Đây là quan sát CLI hiện hành,
không phải kết quả Explorer hoặc đối chiếu GUI năm 2021.

- `generated`: process thành công và ZIP vượt validation.
- `skipped`: thiếu công cụ hoặc OS không được hỗ trợ.
- `failed`: không xác minh được phiên bản, process lỗi/timeout, nguồn/ZIP không hợp lệ.
- Exit `0`: có mẫu hợp lệ và không có lỗi; `1`: có lỗi; `2`: không sinh được mẫu.

Process chạy không mở cửa sổ, timeout 60 giây; giữ stdout/stderr kể cả timeout.
Không ghi đè run cũ hoặc đi qua output symlink/reparse point. Nguồn/output từng
mẫu nằm trong run mới; file ngoài phạm vi được giữ nguyên. Lỗi giữa chừng có thể
để lại source/ZIP chưa hợp lệ; chỉ dùng mẫu có `status=generated`. Catalogue không
chứa bytes ZIP: muốn chia sẻ dataset phải chuyển cả các run artifacts tương ứng.

Nghiệm thu cục bộ 13/11/2026: mỗi run đủ **9 generated, 3 Bandizip skipped, 0 failed**;
7-Zip 26.04, WinRAR 6.23.0, Windows PowerShell 5.1.26100.9818 với Archive module
**1.2.7** thực sự được resolve trong process Python. Việc probe từ shell ngoài có
thể thấy module khác; lấy version/path trong metadata làm bằng chứng cho mẫu.
20 test mới gồm test tổng hợp/lỗi và ba integration native. Chưa kiểm chứng GUI,
macOS/Linux, accuracy hoặc BMAC; ZIP không được cam kết giống byte giữa các lần chạy
vì creation/change time và môi trường không được cố định.

**Giới hạn nghiệm thu hiện tại:** chỉ nghiệm thu pipeline Windows CLI trên build
10.0.26200/Python 3.11.9 với ba công cụ và phiên bản nêu trên, ba biến thể và 9 mẫu
hợp lệ mỗi run. Chưa xác thực Bandizip native, WinZip, môi trường/phiên bản khác,
GUI/Explorer, profile CP949 do archiver tạo, accuracy, BMAC hoặc Case 2 thực tế.
Corpus thay thế nhỏ này chưa phải tập đánh giá mù hoặc đại diện thống kê. Test pass
không xác nhận tái hiện toàn bộ bài báo; xem [bảng phạm vi nghiệm thu](../docs/evaluation/reproduction_report.md#giới-hạn-nghiệm-thu-hiện-tại-13112026).
Git chỉ giữ catalogue, không giữ bytes ZIP/source của run; muốn kiểm chứng run
cũ cần có artifacts tương ứng, còn sinh lại tạo một run có provenance/checksum mới.

