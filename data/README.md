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

