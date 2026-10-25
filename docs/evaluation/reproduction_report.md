# Báo cáo Khoa học Tái hiện Thực nghiệm (Scientific Reproduction Report)

**Bài báo đối chiếu:**  
*File fingerprinting of the ZIP format for identifying and tracking provenance*  
Minji Um, Jaehyeok Han, Sangjin Lee. *Forensic Science International: Digital Investigation* 39 (2021) 301271.  
DOI: `10.1016/j.fsidi.2021.301271` | Kho tham khảo: `https://github.com/um2inji/PKZIP`

---

## 1. Mục tiêu Tái hiện
Xác minh độc lập các phát hiện khoa học của nhóm tác giả:
1. Tính đặc trưng của cấu trúc nhị phân ZIP (Extra fields, vị trí LFH/CDH, thứ tự header, độ phân giải nanosecond, mã hóa UTF-8/CP949, chuẩn hóa Unicode NFD/NFC).
2. Hiệu quả phân loại nguồn gốc môi trường tạo (HĐH và phần mềm) theo 3 thuật toán (Algorithm 1, Algorithm 2, Algorithm 3 trong Hình 7 & 8).
3. Khả năng phát hiện can thiệp đa nguồn gốc (Multi-provenance tracking khi thêm, sửa, xóa tệp - Mục 4.2).
4. Hiện tượng nghịch đảo thời gian (Time-reversal phenomenon) và ma trận BMAC khi giải nén (Mục 4.3 & Bảng 8).

---

## 2. Kết quả Đối chiếu Bảng Dữ liệu Chuẩn (Benchmark Results)

### 2.1 Bảng 6: Đặc trưng Vân tay trên Windows (Ground Truth)
*(Sẽ được cập nhật tự động sau khi chạy `tests/benchmarks/test_paper_matrices.py`)*

### 2.2 Bảng 7: Đặc trưng Vân tay trên macOS và Ubuntu (Ground Truth)
*(Sẽ được cập nhật tự động sau khi chạy `tests/benchmarks/test_paper_matrices.py`)*

### 2.3 Bảng 8: Ma trận Dấu thời gian Giải nén BMAC (Decompression Matrix)
*(Sẽ được cập nhật sau khi chạy `experiments/trace_decompression.py`)*

---

## 3. Đánh giá Ma trận Nhầm lẫn và Độ chính xác (Confusion Matrix)
*(Sẽ đối chiếu với phân bố thực nghiệm 3 máy trạm PC1, PC2, PC3 từ Hình 9)*

---

## 4. Kết luận và Khác biệt Thực tế
*(Ghi nhận các quan sát trên phiên bản phần mềm hiện hành so với dữ liệu năm 2021 của bài báo)*

