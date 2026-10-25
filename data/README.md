# Data Directory

Thư mục này quản lý dữ liệu kiểm nghiệm và mẫu nén ZIP phục vụ tái hiện nghiên cứu:
- `templates/`: Cây thư mục nguồn tiêu chuẩn (dựa trên Hình 5 trong bài báo của Minji Um et al.).
- `ground_truth/`: Chứa các tệp ZIP được nén bằng các phần mềm khác nhau trên Windows, Linux, macOS.
- `modified_samples/`: Chứa các mẫu ZIP được can thiệp (thêm/xóa/sửa đổi tệp) để kiểm tra tính năng truy vết đa nguồn gốc (Provenance tracking - Mục 4.2).
- `metadata.json`: Bản ghi thông tin nguồn gốc, môi trường tạo, checksum SHA-256 của từng mẫu.

