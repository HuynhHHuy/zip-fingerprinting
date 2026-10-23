# Ánh xạ Nội dung Bài báo Khoa học sang Kế hoạch Triển khai (Paper Mapping)

**Dự án:** File Fingerprinting of the ZIP Format for Identifying and Tracking Provenance  
**Bài báo gốc:** Minji Um, Jaehyeok Han, Sangjin Lee. *Forensic Science International: Digital Investigation*, 39, 2021, 301271.  
**Tài liệu đối chiếu bổ trợ:** Interpol Digital Evidence Review (PMC10311174, Sec 5.10.4); KIISC 2020.  

---

## 1. Bảng Ánh xạ Toàn diện (Comprehensive Mapping Matrix)

| Thành phần | Nội dung từ Nghiên cứu gốc | Phân loại Trạng thái | Ánh xạ sang Thành phần Triển khai Kỹ thuật |
| :--- | :--- | :--- | :--- |
| **Mục tiêu nghiên cứu** | Nhận diện môi trường tạo tệp (HĐH, phần mềm nén) và lịch sử thao tác/giải nén của tệp ZIP dựa trên đặc trưng cấu trúc nội tại. | `[Đã xác minh từ bài báo]` | Module trích xuất đặc trưng cấu trúc (`extractor.py`), phân loại nguồn gốc (`classifier.py`) và bộ ước lượng hành vi giải nén (`provenance.py`). |
| **Hệ điều hành khảo sát** | 1. Windows (Windows 10/11)<br>2. macOS (macOS 10.x / 11.x)<br>3. Linux (Ubuntu Desktop) | `[Đã xác minh từ bài báo]` | Môi trường ma trận kiểm thử tự động, container hoá (Docker cho Linux) và máy trạm Windows / macOS. |
| **Phần mềm nén khảo sát** | 1. Windows Built-in (Compressed Folder / `zipfldr.dll`)<br>2. WinRAR (Windows)<br>3. 7-Zip (Windows)<br>4. Bandizip (Windows & macOS)<br>5. macOS Archive Utility / native `zip`<br>6. Ubuntu native `zip` / File Roller (Archive Manager)<br>7. ALZip (trên Windows, đề cập trong nghiên cứu tiền đề) | `[Đã xác minh từ bài báo & trích yếu]` | Bộ tạo mẫu thử nghiệm tự động hoá (`dataset_generator.py`) gọi các công cụ CLI tương ứng trên từng HĐH. |
| **Đặc trưng cấu trúc: Header IDs** | - `0x5455`: Extended Timestamp (Info-ZIP: Unix 32-bit mtime, atime, ctime) — dùng phổ biến trên macOS và Ubuntu.<br>- `0x7875`: Info-ZIP UNIX UID/GID (New Unix Extra Field).<br>- `0x7075`: Unicode Path Extra Field (chứa UTF-8 name + CRC32 của tên file ban đầu).<br>- `0x000a`: NTFS Extra Field (Mtime, Atime, Ctime với độ phân giải 100ns) — xuất hiện trong môi trường Windows. | `[Đã xác minh từ bài báo & trích yếu]` | Parser phân tích trường Extra Field nhị phân trong Local File Header (LFH) và Central Directory Header (CDH) (`extra_fields.py`). |
| **Đặc trưng: Thứ tự Header ID** | Thứ tự lưu trữ các thẻ Extra Field ID trong LFH và CDH khác biệt tùy theo từng phần mềm (ví dụ: thứ tự `0x5455` đứng trước `0x7875` hay ngược lại). | `[Đã xác minh từ bài báo & trích yếu]` | Thuộc tính `extra_field_sequence` lưu danh sách có thứ tự `[0x5455, 0x7875, ...]` trong cấu trúc Fingerprint. |
| **Đặc trưng: Version Made By** | Byte cao (Host OS) trong Central Directory Header: 0 (MS-DOS/FAT), 3 (UNIX/Linux), 10 (NTFS), 19 (OS X). Byte thấp biểu thị phiên bản đặc tả ZIP tối thiểu. | `[Đã xác minh từ bài báo & trích yếu]` | Trường `version_made_by` và trích xuất `host_os = (value >> 8) & 0xFF` trong parser CDH. |
| **Đặc trưng: Chuẩn hóa Unicode** | - macOS sử dụng chuẩn phân rã NFD (Normalization Form D / Korean phoneme jamo).<br>- Windows và Ubuntu sử dụng chuẩn hợp nhất NFC (Normalization Form C). | `[Đã xác minh từ bài báo & trích yếu]` | Trình kiểm tra `detect_unicode_normalization(filename_bytes)` phân biệt NFC, NFD và cờ EFS (Bit 11 của General Purpose Bit Flag). |
| **Đặc trưng: Tính toán Timezone** | Chênh lệch giữa mtime trong MS-DOS format (lưu theo giờ cục bộ của máy tạo) và mtime trong Extended Timestamp `0x5455` / NTFS `0x000a` (lưu theo chuẩn UTC) cho phép tính ra múi giờ (Timezone offset) của hệ thống tạo tệp. | `[Đã xác minh từ bài báo & trích yếu]` | Hàm `calculate_creation_timezone(dos_time, utc_extra_time)` ước tính độ lệch múi giờ `UTC±HH:MM`. |
| **Đặc trưng: Data Descriptor** | Chữ ký Data Descriptor (`0x08074b50` / `PK\x07\x08`) xuất hiện hay bị lược bỏ; cờ Bit 3 trong General Purpose Bit Flag được bật. Một số phần mềm nén dạng stream tạo trường này mặc định. | `[Đã xác minh từ bài báo & trích yếu]` | Trường boolean `has_data_descriptor` và `data_descriptor_has_signature`. |
| **Đặc trưng: Thứ tự nén tệp** | Thứ tự ghi các entry vào ZIP: theo tên an-pha-bê, thư mục trước tệp sau, hay theo thứ tự chọn trong Explorer (WinRAR có thứ tự duyệt file đặc trưng khác với cấu trúc cây thư mục). | `[Đã xác minh từ bài báo & trích yếu]` | Vector thứ tự `entry_traversal_pattern` đo mối tương quan giữa thứ tự ghi thực tế và thứ tự sắp xếp theo bảng chữ cái. |
| **Đặc trưng: Cấu trúc thư mục rỗng và Root Folder** | Việc tệp ZIP có sinh entry riêng cho thư mục rỗng (kết thúc bằng `/`) hay không; và đường dẫn tệp có bao gồm thư mục gốc (Root folder) hay chỉ gồm tệp con bên trong. | `[Đã xác minh từ bài báo & trích yếu]` | Các cờ boolean `stores_empty_directories`, `includes_root_folder_entry`. |
| **Đặc trưng: Double Zipping** | Hành vi khi nén một tệp ZIP lồng trong một tệp ZIP khác (nén lại hay lưu nguyên trạng - stored; sự thay đổi cấu trúc). | `[Đã xác minh từ bài báo & trích yếu]` | Phân tích trường `compression_method` (Store=0 vs Deflate=8) đối với các entry con có định dạng nén. |
| **Thuật toán phân loại** | Cây quyết định / Bộ phân loại quy tắc (Rule-based classifier) kết hợp các đặc trưng có độ tin cậy cao (HĐH, phần mềm) và đặc trưng phụ thuộc đối tượng nén. | `[Đã xác minh từ bài báo & trích yếu]` | Xây dựng động cơ luật (`rules_engine.py`) trả về danh sách ứng viên (candidate environments) kèm điểm số bằng chứng (confidence score). |
| **Thí nghiệm giải nén & Dấu thời gian** | Đo lường sự thay đổi của các mốc thời gian MACB (Modified, Accessed, Created, Birth) của tệp và thư mục khi được giải nén bằng các phần mềm khác nhau trên các hệ điều hành khác nhau. | `[Đã xác minh từ bài báo & trích yếu]` | Kịch bản tự động hoá giải nén và kiểm tra thuộc tính hệ thống tệp cục bộ (`decompression_tracer.py`). |
| **Quy mô tập dữ liệu gốc** | Tổng số mẫu ZIP thực nghiệm, tỷ lệ phân chia tập huấn luyện/kiểm thử trong bài báo gốc. | `[Chưa xác minh — Cần đối chiếu full text]` | Đề xuất tập dữ liệu tổng hợp tối thiểu 150 mẫu chuẩn (25 kịch bản cấu hình x 6 công cụ chính) phục vụ giai đoạn thẩm định kỹ thuật ban đầu. |
| **Chỉ số đánh giá định lượng** | Ma trận nhầm lẫn (Confusion Matrix), Độ chính xác (Accuracy), F1-Score của bộ phân loại trong bài báo gốc. | `[Chưa xác minh — Cần đối chiếu full text]` | Thiết lập khung đánh giá chuẩn với Precision, Recall, Accuracy trên tập dữ liệu kiểm nghiệm có gán nhãn thực địa. |

---

## 2. Phân loại Mức độ Đáng tin cậy của các Đặc trưng (Feature Reliability Hierarchy)

Theo kết luận khoa học của bài báo (được phản ánh qua báo cáo Interpol Review):
1. **Nhóm đặc trưng độ tin cậy cao (High-Reliability Features):**
   - Thuộc tính cấu trúc do chính công cụ sinh ra bất biến với nội dung:
     * Mã Header ID của Extra Field (`0x5455`, `0x7875`, `0x7075`, `0x000a`).
     * Vị trí lưu Extra Field: Chỉ lưu trong CDH (Windows) hay lưu cả trong LFH (macOS, Ubuntu).
     * Thứ tự các khối Extra Field.
     * Host OS trong `version_made_by`.
     * Dạng thức chuẩn hóa Unicode (NFC vs NFD) khi gặp ký tự phi ASCII.
     * Dấu thời gian độ phân giải nano giây (chỉ Ubuntu hỗ trợ trong một số phiên bản info-zip mở rộng).
2. **Nhóm đặc trưng độ tin cậy trung bình / phụ thuộc ngữ cảnh (Context-Dependent Features):**
   - Tùy thuộc vào thao tác của người dùng hoặc cấu trúc cây thư mục gốc:
     * Sự hiện diện của thư mục rỗng.
     * Bao gồm hay không bao gồm tên thư mục gốc.
     * Thứ tự ghi các tệp tin (bị ảnh hưởng nếu nén từ dòng lệnh so với kéo thả GUI).
3. **Nhóm đặc trưng cần phối hợp chứng cứ hệ thống (Low-Reliability / System-Artifact-Dependent):**
   - Dấu vết thời gian trên máy tính sau giải nén: Cần kết hợp phân tích Prefetch, LNK, Jump Lists và USN Journal trên hệ điều hành nghi phạm để xác nhận chắc chắn công cụ thực thi.

---

## 3. Khoảng trống Cần Xác minh Bổ sung từ Bài báo Toàn văn

Để việc tái hiện đạt độ trung thực tuyệt đối so với công trình của Minji Um et al., các câu hỏi sau cần được đối chiếu ngay khi tiếp cận được bản PDF:
1. *Mã nguồn gốc của nhóm tác giả:* Tác giả có phát hành công cụ dưới dạng mã nguồn mở (GitHub/GitLab) hay chỉ mô tả thuật toán bằng giả mã/lưu đồ?
2. *Danh mục chính xác các phần mềm và phiên bản:* Số hiệu phiên bản cụ thể (ví dụ: Bandizip 7.x, WinRAR 5.x/6.x, 7-Zip 19.x/21.x) được thử nghiệm trong nghiên cứu năm 2021.
3. *Cấu trúc ma trận phân loại (Decision Matrix/Table):* Các bảng quy tắc chi tiết (thường là Table 2, Table 3, Table 4 trong bài báo gốc) biểu diễn mối tương quan giữa từng công cụ và vector đặc trưng.
