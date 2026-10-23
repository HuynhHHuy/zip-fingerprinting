# Kế hoạch Kiểm thử và Xác thực Tái hiện (Validation & Testing Plan)

**Dự án:** File Fingerprinting of the ZIP Format for Identifying and Tracking Provenance  
**Mục tiêu:** Thiết lập các tầng kiểm thử nghiêm ngặt từ đơn vị đến thực nghiệm khoa học, đảm bảo tính đúng đắn kỹ thuật và khả năng kiểm chứng khách quan của nghiên cứu tái hiện.  

---

## 1. Các Lớp Kiểm thử Kỹ thuật (Technical Testing Levels)

### 1.1 Tầng 1: Kiểm thử Đơn vị Phân tích Cấu trúc Nhị phân (Binary Parser Unit Tests)
- **Tệp kiểm thử:** `tests/test_parser.py`
- **Mục tiêu:** Đảm bảo parser đọc đúng từng trường byte theo đặc tả PKWARE APPNOTE mà không phụ thuộc vào thư viện bên ngoài.
- **Các ca kiểm thử cụ thể:**
  * `test_parse_eocd_standard`: Đọc đúng vị trí và số lượng entry từ EOCD chuẩn.
  * `test_parse_zip64`: Phân tích kho nén ZIP64 với trường mở rộng 8-byte offsets.
  * `test_parse_extra_fields`: Tách chính xác chuỗi byte Extra Field thành các khối `(Header_ID, Data_Size, Data)` cho các ID `0x5455`, `0x7875`, `0x7075`, `0x000a`.
  * `test_parse_data_descriptor`: Xử lý đúng trường hợp có chữ ký `0x08074b50` và trường hợp không có chữ ký.
  * `test_malformed_archive`: Phát hiện và ném ngoại lệ tường minh `CorruptZipError` khi file bị cắt cụt (truncated) hoặc sai magic number, không gây sập chương trình.

### 1.2 Tầng 2: Kiểm thử Tính Nhất quán và Khả năng Tái lập (Reproducibility Tests)
- **Tệp kiểm thử:** `tests/test_fingerprint.py`
- **Mục tiêu:** Kiểm tra tính xác định (determinism) của lược đồ fingerprint.
- **Các ca kiểm thử:**
  * `test_fingerprint_determinism`: Chạy trích xuất fingerprint 100 lần trên cùng một tệp ZIP phải cho ra chuỗi JSON và mã băm cấu trúc đồng nhất 100%.
  * `test_schema_serialization`: Tuân thủ chuẩn định dạng JSON, sắp xếp khóa có thứ tự (canonical ordering), biểu diễn nhất quán các trường rỗng/không khả dụng (`null`).

### 1.3 Tầng 3: Kiểm thử Độc lập Cấu trúc với Nội dung (Orthogonality Tests)
- **Tệp kiểm thử:** `tests/test_structural_features.py`
- **Mục tiêu:** Xác minh giả thuyết của bài báo: Fingerprint cấu trúc phản ánh môi trường tạo lập chứ không bị thay đổi bởi nội dung tệp được nén.
- **Các ca kiểm thử:**
  * `test_different_payloads_same_tool`: Hai tệp ZIP nén hai tập tin hoàn toàn khác nhau (1 file ảnh và 1 file text) bằng cùng một phiên bản 7-Zip phải có cùng vector đặc trưng cấu trúc (cùng Extra Field IDs, cùng host OS, cùng cờ).

### 1.4 Tầng 4: Kiểm thử An toàn và Khả năng Chống chịu (Security & Robustness Tests)
- **Tệp kiểm thử:** `tests/test_security.py`
- **Mục tiêu:** Bảo vệ hệ thống phân tích trước các mối đe dọa từ tệp ZIP độc hại.
- **Các ca kiểm thử:**
  * `test_zip_bomb_safety`: Tuyệt đối không tự động giải nén toàn bộ tệp vào RAM hoặc đĩa (chỉ đọc siêu dữ liệu và băm stream có giới hạn dung lượng byte tối đa).
  * `test_path_traversal_detection`: Cảnh báo và vô hiệu hóa các đường dẫn nguy hiểm chứa `../`, `..\\` hoặc đường dẫn tuyệt đối `C:\Windows\...`.
  * `test_zero_length_and_infinite_loops`: Xử lý an toàn các entry có kích thước 0 hoặc các trường offset trỏ vòng lặp.

---

## 2. Kế hoạch Xác thực Thực nghiệm Khoa học (Scientific Validation)

### 2.1 Ma trận Đối chiếu với Nghiên cứu Gốc (Paper Comparison Matrix)

| Đặc trưng / Quy tắc theo Bài báo | Điều kiện Kỳ vọng Từ Bài báo | Phương pháp Kiểm chứng Thực nghiệm | Tiêu chí Đạt (Pass Criteria) |
| :--- | :--- | :--- | :--- |
| **Windows Native Zip** | - Không có Extra Field ở Local File Header (chỉ có ở Central Directory).<br>- Không lưu trường Unix timestamp `0x5455`. | Nén mẫu bằng `Compress-Archive` hoặc Explorer trên Windows 11. | Parser xác nhận `len(lfh_extra_fields) == 0` và `0x5455` không xuất hiện. |
| **Ubuntu / Linux Info-ZIP** | - Xuất hiện `0x5455` (Extended timestamp) và `0x7875` (New Unix UID/GID).<br>- `host_os == 3` (UNIX). | Nén mẫu bằng CLI `zip` trên Ubuntu 22.04. | Parser trích xuất đúng cặp ID `[0x5455, 0x7875]` và `host_os == 3`. |
| **macOS Archive Utility** | - Xuất hiện `0x5455` và `0x7875`.<br>- Tên tệp Unicode tuân theo chuẩn phân rã NFD.<br>- `host_os == 19` (OS X) hoặc `3` (UNIX). | Nén mẫu tiếng Hàn/tiếng Việt bằng Archive Utility trên macOS. | Hàm `detect_unicode_normalization` trả về `NFD`. |
| **Bandizip** | - Lưu trữ Unicode Path Extra Field (`0x7075`) khi tên tệp có ký tự đặc biệt.<br>- Lưu trữ `0x000a` (NTFS timestamp) trên Windows. | Nén mẫu bằng Bandizip 7.x. | Parser trích xuất đúng khối `0x7075` và `0x000a`. |
| **WinRAR** | - Thứ tự duyệt tệp đặc thù trong kho nén.<br>- Thiết lập cờ và thứ tự Extra Field riêng biệt. | Nén mẫu thư mục phân cấp bằng WinRAR 6.x/7.x. | Trích xuất vector thứ tự và đối chiếu với chữ ký của WinRAR. |
| **Ước lượng Múi giờ** | Chênh lệch giữa DOS local time và UTC `0x5455`/`0x000a` phản ánh đúng Timezone của máy tạo tệp. | Tạo tệp tại máy trạm có múi giờ GMT+7, đọc và giải mã bằng thuật toán. | Thuật toán tính ra chính xác độ lệch `+07:00` (sai số tối đa 2 giây do độ phân giải DOS time). |
| **Dấu vết Giải nén** | Hành vi thiết lập Creation Time và Last Write Time trên đĩa khác biệt giữa các trình giải nén. | Giải nén tự động trên đĩa NTFS sạch, đo mốc thời gian bằng Windows API. | Ghi nhận ma trận khác biệt thời gian giữa Explorer, 7-Zip, WinRAR và Bandizip. |

### 2.2 Tiêu chí Đánh giá Mức độ Thành công của Tái hiện

1. **Tái hiện thành công hoàn toàn (Full Reproduction):**
   - 100% các quy tắc định danh HĐH (Windows, Linux, macOS) và phần mềm nén (Built-in, 7-Zip, Bandizip, WinRAR, Info-ZIP) hoạt động chính xác trên tập dữ liệu kiểm nghiệm.
   - Thuật toán tính toán Timezone và phân loại Unicode NFD/NFC đạt độ chính xác 100%.
   - Hiện tượng thay đổi dấu thời gian sau giải nén được tái lập nhất quán với mô tả của bài báo.
2. **Tái hiện thành công một phần (Partial Reproduction):**
   - Phân biệt chính xác hệ điều hành và các họ phần mềm chính, nhưng có sai khác nhỏ về số hiệu phiên bản mới (ví dụ 7-Zip v24 thay đổi nhẹ cấu trúc Extra Field so với v19 của bài báo năm 2021).
   - Mọi sai khác đều được giải trình bằng nguyên nhân kỹ thuật cụ thể (Format Drift).
3. **Thất bại trong tái hiện (Reproduction Failure):**
   - Các đặc trưng lý thuyết của bài báo không xuất hiện trong các tệp sinh ra từ phần mềm tương ứng, hoặc parser không thể trích xuất được đặc trưng một cách ổn định.

---

## 3. Quy trình Xử lý và Phân tích Sai lệch (Discrepancy Analysis Protocol)

Nếu kết quả thực nghiệm không khớp với lý thuyết bài báo:
1. **Bước 1: Cô lập nhị phân (Binary Hex Dump Isolation):** Xuất hex dump chi tiết của các header liên quan (`0x504b0304`, `0x504b0102`).
2. **Bước 2: Kiểm tra phiên bản (Version Regression):** Tải phiên bản phần mềm đúng vào năm 2020-2021 từ kho lưu trữ lịch sử để chạy lại thí nghiệm đối chứng.
3. **Bước 3: Ghi nhận minh bạch:** Báo cáo sai lệch vào tài liệu `docs/evaluation/discrepancies.md`, chỉ rõ sự khác biệt giữa phiên bản nghiên cứu gốc và phiên bản phần mềm hiện tại.
