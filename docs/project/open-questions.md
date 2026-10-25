# Các Vấn đề Tồn đọng và Nhật ký Quyết định Kỹ thuật (Open Questions & Decision Register)

**Dự án:** File Fingerprinting of the ZIP Format for Identifying and Tracking Provenance  
**Bài báo đối chiếu:** Minji Um, Jaehyeok Han, Sangjin Lee. *Forensic Science International: Digital Investigation*, 39, 2021, 301271.  
**Cập nhật:** Ngày 25/10/2026 (Sau khi tiếp nhận và thẩm định bản PDF chính thức của bài báo).

---

## 1. Bảng Kiểm soát Thông tin và Trạng thái Thẩm định Đối chiếu

| Nội dung / Vấn đề | Tình trạng Ban đầu | Trạng thái Hiện tại | Kết quả Xác minh từ Bản Toàn văn PDF (Um et al., 2021) |
| :--- | :--- | :--- | :--- |
| **Bản toàn văn PDF của bài báo** | `Chưa thể truy cập trực tiếp` | `ĐÃ GIẢI QUYẾT (RESOLVED)` | Người dùng đã tải bản PDF chính thức lên thư mục gốc của repository. Toàn văn 10 trang đã được trích xuất và đối chiếu toàn diện. |
| **Kho mã nguồn gốc của tác giả** | `Chưa công bố công khai` | `ĐÃ XÁC MINH (CONFIRMED)` | Bài báo công bố rõ ràng liên kết mã nguồn tham khảo tại Footnote 1 (Trang 3): `https://github.com/um2inji/PKZIP`. |
| **Danh mục và phiên bản phần mềm** | `Xác minh một phần` | `ĐÃ XÁC MINH CHÍNH XÁC` | **HĐH:** Windows 10 v2004 (EN & KR), macOS 10.15 Catalina, Ubuntu 20.04 LTS.<br>**Phần mềm:** WinRAR v6.00, WinZip v25.0, 7-zip v19.00, Bandizip v6.29, Windows Built-in; macOS Bandizip v7.0, WinZip v8, native zip & Compress; Ubuntu 7-zip (7zz) v21.01, native zip & Compress. |
| **Bảng đặc trưng cấu trúc vân tay** | `Suy luận từ tài liệu thứ cấp` | `ĐÃ XÁC MINH CHI TIẾT 100%` | **Bảng 1:** Cấu trúc NTFS `0x000A` (32 bytes).<br>**Bảng 2:** Cấu trúc Extended Timestamp `0x5455` (13, 9, 5 bytes).<br>**Bảng 3:** Cấu trúc Unix UID/GID `0x7875`.<br>**Bảng 4:** Cấu trúc Info-ZIP Unix `0x5855` (Bandizip trên macOS).<br>**Bảng 5:** Cấu trúc Info-ZIP Unicode Path `0x7075` (EFS).<br>**Bảng 6 & 7:** Toàn bộ ma trận vân tay trên Windows, macOS, Ubuntu. |
| **Thuật toán phân loại & Lưu đồ** | `Giả định sơ bộ` | `ĐÃ XÁC MINH TOÀN VĂN` | Bài báo định nghĩa rõ ràng **Lưu đồ Hình 7** và **3 Thuật toán (Hình 8)** phân tầng theo trọng số: **Algorithm 1** (High weight SW), **Algorithm 2** (High weight OS), **Algorithm 3** (Subsidiary low weight). |
| **Hành vi thao tác sửa đổi ZIP (Tampering/Multi-provenance)** | `Chưa có thông tin` | `ĐÃ XÁC MINH MỤC 4.2 & HÌNH 10` | Xác minh 2 kịch bản khi thêm/xóa/sửa đổi tệp bằng phần mềm khác: Case 1 (chỉ ảnh hưởng phần tử thao tác -> tạo vân tay hỗn hợp); Case 2 (ảnh hưởng dây chuyền toàn bộ kho lưu trữ). |
| **Dấu vết thời gian khi giải nén (BMAC)** | `Ước tính sơ bộ` | `ĐÃ XÁC MINH MỤC 4.3 & BẢNG 8` | Xác minh toàn bộ ma trận thời gian BMAC (Birth, Modified, Accessed, Changed) của 5 công cụ giải nén trên Windows đối với File, Folder có file và Folder rỗng; hiện tượng đảo ngược thời gian (Time reversal). |

---

## 2. Nhật ký Quyết định Kỹ thuật (Architectural Decision Records - ADR)

### ADR-01: Tự phát triển Parser Nhị phân thay vì dùng `zipfile` của Python
- **Bối cảnh:** Thư viện chuẩn `zipfile` tự động che giấu chuỗi byte thô của Extra Fields, không lưu vị trí offset chính xác của từng Header, không bảo toàn thứ tự các khối Header ID, và tự động bỏ qua các trường nhị phân không phổ biến.
- **Quyết định:** Tự phát triển `ZipBinaryParser` bằng thư viện `struct` chuẩn.
- **Trạng thái:** `Đã phê duyệt (Approved)`.

### ADR-02: Phân tầng Luật Phân loại theo đúng Thiết kế 2 Tầng của Bài báo
- **Bối cảnh:** Hình 7 & 8 bài báo phân chia rõ hai tầng thuật toán: Tầng đặc trưng có độ tin cậy cao (High-weight: Algorithm 1 & 2) và Tầng đặc trưng phụ thuộc đối tượng (Subsidiary: Algorithm 3).
- **Quyết định:** Triển khai bộ phân loại theo cấu trúc 2 tầng:
  1. Thẩm định qua Algorithm 1 (SW) và Algorithm 2 (OS). Nếu xác định được duy nhất thì xuất kết quả.
  2. Nếu không đủ dữ kiện hoặc có nhiều ứng viên trùng lặp, chuyển tiếp qua Algorithm 3 (Double zipping, pattern nanosecond `fff0000`/`fffffff`, NFC/NFD, UID/GID, v.v.).
- **Trạng thái:** `Đã phê duyệt (Approved)`.

### ADR-03: Bổ sung Module Phân tích Đa Nguồn gốc (Multi-Provenance Analyzer)
- **Bối cảnh:** Mục 4.2 của bài báo chỉ ra rằng một tệp ZIP có thể chứa nhiều vân tay của các phần mềm khác nhau nếu người dùng thực hiện thao tác Thêm, Sửa, Xóa tệp bằng phần mềm thứ hai (SW2) trên nền kho nén tạo bởi SW1.
- **Quyết định:** Thêm module `zip_fingerprint.provenance` để phát hiện sự không đồng nhất giữa các entry trong cùng một kho lưu trữ.
- **Trạng thái:** `Đã phê duyệt (Approved)`.

### ADR-04: Bổ sung Module Thẩm định Dấu vết Giải nén và Nghịch đảo Thời gian (Decompression Analyzer)
- **Bối cảnh:** Mục 4.3 và Bảng 8 chứng minh các phần mềm giải nén (WinRAR, WinZip, 7-zip, Bandizip, Explorer) xử lý dấu thời gian MFT (BMAC) hoàn toàn khác nhau.
- **Quyết định:** Thêm module `zip_fingerprint.decompression` để tra cứu và suy luận công cụ giải nén dựa trên dấu vết BMAC quan sát được.
- **Trạng thái:** `Đã phê duyệt (Approved)`.

---

## 3. Các Điểm Cần Lưu ý và Thống nhất Khi Thực thi

1. **Phiên bản công cụ thử nghiệm cục bộ:** Các phiên bản thử nghiệm năm 2021 (WinRAR 6.00, 7-zip 19.00, Bandizip 6.29, WinZip 25.0) sẽ được đối chiếu với các phiên bản hiện hành trên máy tính của người dùng (Windows 11) để ghi nhận những điểm kế thừa và thay đổi của nhà phát triển.
2. **Khả năng kiểm thử macOS và Ubuntu:** Sẽ tận dụng mẫu đối chứng từ repo tham khảo của tác giả (`um2inji/PKZIP`), môi trường WSL/Docker cho Ubuntu, và các mẫu mock nhị phân tổng hợp cho macOS.
