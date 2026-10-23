# Các Vấn đề Tồn đọng và Quyết định Cần Thống nhất (Open Questions & Decision Register)

**Dự án:** File Fingerprinting of the ZIP Format for Identifying and Tracking Provenance  
**Mục tiêu:** Ghi nhận minh bạch các nội dung chưa thể xác minh tuyệt đối do hạn chế tài liệu, các giả định kỹ thuật tạm thời và các quyết định kiến trúc cần người giám sát xác nhận.  

---

## 1. Bảng Kiểm soát Thông tin và Trạng thái Xác minh

| Nội dung / Vấn đề | Tình trạng Hiện tại | Căn cứ / Nguồn hiện có | Giả định Kỹ thuật Tạm thời | Biện pháp Xác minh Tiếp theo |
| :--- | :--- | :--- | :--- | :--- |
| **Bản toàn văn PDF của bài báo** | `Chưa thể truy cập trực tiếp` | `citation-355132401.ris`, ScienceDirect DOI paywall, Báo cáo Interpol PMC10311174 | Dựa trên bản trích yếu chuẩn xác từ Báo cáo Interpol Review (Sec 5.10.4) và bài báo KIISC 2020 của chính tác giả. | Người dùng hỗ trợ tải bản PDF hoặc cấp quyền truy cập cơ sở dữ liệu Elsevier. |
| **Bảng số liệu kiểm thử gốc (Baseline Benchmark Metrics)** | `Chưa xác minh được số liệu chính xác` | Abstract nêu phương pháp đạt kết quả khả quan, không ghi con số % cụ thể | Tạm thời không đưa ra con số độ chính xác giả định; thiết lập hệ thống benchmark tự đo lường. | Đối chiếu với Table thực nghiệm trong bài báo toàn văn khi có PDF. |
| **Mã nguồn gốc của nhóm tác giả (DFRC)** | `Chưa công bố công khai` | Không tìm thấy kho lưu trữ GitHub/GitLab chính thức của tác giả | Xây dựng mã nguồn độc lập từ đầu (Clean-room implementation) theo đúng đặc tả thuật toán. | Liên hệ tác giả (Minji Um / Jaehyeok Han) qua ResearchGate nếu cần mã nguồn đối chiếu. |
| **Phiên bản phần mềm chính xác năm 2021** | `Xác minh một phần` | Xác định được các phần mềm: 7-Zip, WinRAR, Bandizip, native Windows, Ubuntu zip, macOS Archive Utility | Sử dụng các phiên bản hiện hành trên máy thử nghiệm kết hợp tải bản lưu trữ cũ (legacy versions). | Xác minh danh sách phiên bản chi tiết trong phần Experimental Setup của bài báo. |
| **Chi tiết thuật toán giải quyết xung đột luật** | `Suy luận phục vụ triển khai` | Interpol Review nêu "An automatic classifier... was constructed" | Sử dụng cây quyết định có trọng số ưu tiên đặc trưng độ tin cậy cao (Host OS, Header ID position) trước. | Kiểm tra lưu đồ thuật toán (Algorithm/Flowchart) trong bài báo gốc. |

---

## 2. Nhật ký Quyết định Kỹ thuật (Architectural Decision Records - ADR)

### ADR-01: Tự phát triển Parser Nhị phân thay vì dùng `zipfile` của Python
- **Bối cảnh:** Thư viện chuẩn `zipfile` trong Python tự động che giấu chuỗi byte thô của Extra Fields, không lưu vị trí offset chính xác của từng Header, và tự động bỏ qua các trường nhị phân không phổ biến.
- **Quyết định:** Tự phát triển `ZipBinaryParser` bằng thư viện `struct` chuẩn.
- **Đánh giá ưu/nhược điểm:**
  * *Ưu điểm:* Đọc được 100% các byte siêu dữ liệu pháp y, giữ nguyên thứ tự khối Header ID, phát hiện được chữ ký Data Descriptor bị ẩn.
  * *Nhược điểm:* Tốn thêm công sức lập trình ban đầu.
- **Trạng thái:** `Đã phê duyệt (Approved)`.

### ADR-02: Phân tách rõ ràng giữa Băm Cấu trúc và Băm Nội dung
- **Bối cảnh:** Nhiều công cụ nhầm lẫn giữa việc băm nội dung tệp (Payload Hash) và băm cấu trúc bao gói (Structural Fingerprint).
- **Quyết định:** Định nghĩa 2 định danh riêng biệt:
  * `content_manifest_hash`: Băm danh mục payload (đại diện cho nội dung).
  * `structural_fingerprint_hash`: Băm vector cấu trúc nhị phân (đại diện cho môi trường tạo).
- **Trạng thái:** `Đã phê duyệt (Approved)`.

### ADR-03: Xử lý An toàn đối với Tệp Nén Độc hại (Forensic Safety)
- **Bối cảnh:** Tệp ZIP trong điều tra số có thể là mồi nhử (Zip bomb, Path traversal exploit) nhằm tấn công công cụ phân tích.
- **Quyết định:**
  * Tuyệt đối không tự động trích xuất payload ra đĩa cứng khi chỉ phân tích fingerprint.
  * Mọi thao tác tính toán hash payload chỉ thực hiện qua bộ đệm luồng (streaming memory buffer) với giới hạn kích thước tối đa (ví dụ 100MB cho mỗi entry).
- **Trạng thái:** `Đã phê duyệt (Approved)`.

---

## 3. Các Điểm nghẽn Cần Người dùng Phê duyệt hoặc Hỗ trợ

1. **Cung cấp bản toàn văn PDF (nếu có):** Nếu người dùng hoặc trường đại học có tài khoản ScienceDirect, hãy tải bản PDF và đặt vào thư mục `docs/research/paper.pdf` để agent kiểm tra chéo các bảng số liệu chi tiết.
2. **Xác nhận phạm vi thử nghiệm môi trường:** Xác nhận việc thử nghiệm trên máy trạm Windows hiện tại kết hợp Linux (qua WSL/Docker) đã đủ đáp ứng yêu cầu của đề tài, hay bắt buộc phải có máy trạm vật lý macOS.
3. **Phê duyệt kế hoạch triển khai:** Đánh giá lộ trình trong `docs/project/implementation-plan.md` để bắt đầu thực thi nhiệm vụ đầu tiên `DOC-001`.
