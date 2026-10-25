# ZIP Fingerprinting: Forensic Analysis & Provenance Tracking

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Nghiên cứu tái hiện và phát triển công cụ định danh nguồn gốc môi trường tạo (Hệ điều hành, Ứng dụng nén), phát hiện lịch sử can thiệp tệp (Provenance tracking) và phân tích dấu vết thời gian giải nén dựa trên cấu trúc nhị phân định dạng ZIP.

---

## 1. Cơ sở Khoa học và Công trình Nghiên cứu Gốc

Dự án này tái hiện độc lập công trình nghiên cứu khoa học:
- **Tiêu đề:** *File fingerprinting of the ZIP format for identifying and tracking provenance*
- **Tác giả:** Minji Um, Jaehyeok Han, Sangjin Lee (*Digital Forensic Research Center / Graduate School of Information Security, Korea University*)
- **Công bố:** *Forensic Science International: Digital Investigation*, Volume 39, Article 301271 (Tháng 12/2021)
- **DOI:** [`10.1016/j.fsidi.2021.301271`](https://doi.org/10.1016/j.fsidi.2021.301271)
- **Kho tham khảo của tác giả:** [`https://github.com/um2inji/PKZIP`](https://github.com/um2inji/PKZIP)
- **Tài liệu toàn văn PDF:** Đã được tích hợp trực tiếp tại thư mục gốc của repository.

---

## 2. Cấu trúc Kho Lưu trữ (Repository Structure)

```text
zip-fingerprinting/
├── docs/                               # Tài liệu học thuật và quản lý kỹ thuật
│   ├── project/                        # Kế hoạch triển khai chi tiết, cấu trúc repo, quyết định kỹ thuật
│   │   ├── implementation-plan.md      # Lộ trình 8 giai đoạn và 15 tasks chi tiết (DoD, phụ thuộc)
│   │   ├── repository-structure.md     # Bản giải trình cấu trúc thư mục
│   │   └── open-questions.md           # Nhật ký quyết định kiến trúc (ADR)
│   ├── research/                       # Phân tích phương pháp và ánh xạ bài báo
│   │   ├── paper-mapping.md            # Ánh xạ chi tiết toàn bộ Bảng 1-8, Hình 5-10
│   │   ├── experimental-design.md      # Thiết kế dữ liệu và kiểm soát biến
│   │   ├── reproduction-methodology.md # Phương pháp luận tái hiện từng bước
│   │   └── validation-plan.md          # Kế hoạch kiểm thử và đối chiếu
│   └── evaluation/
│       └── reproduction_report.md      # Báo cáo kết quả tái hiện khoa học
│
├── src/zip_fingerprint/                # Gói mã nguồn Python chính
│   ├── parser.py                       # Parser nhị phân nguyên thủy (EOCD -> CDH -> LFH)
│   ├── extra_fields.py                 # Giải mã chuyên sâu các trường mở rộng (0x000A, 0x5455, 0x7875, 0x5855, 0x7075)
│   ├── extractor.py                    # Trích xuất vector đặc trưng phân tầng (High-weight & Subsidiary)
│   ├── schema.py & hasher.py           # Lược đồ chuẩn hóa JSON và SHA-256 canonical hashing
│   ├── rules.py & classifier.py        # Động cơ phân loại tự động (Lưu đồ Hình 7, Thuật toán 1, 2, 3)
│   ├── provenance.py                   # Phân tích đa nguồn gốc và lịch sử can thiệp tệp (Mục 4.2 & Hình 10)
│   ├── decompression.py                # Phân tích dấu thời gian giải nén BMAC & Đảo ngược thời gian (Bảng 8)
│   └── cli.py & __main__.py            # Giao diện dòng lệnh CLI toàn diện
│
├── tests/                              # Bộ kiểm thử tự động (Unit, Integration, Benchmarks)
├── scripts/                            # Kịch bản sinh cây thư mục mẫu (Hình 5) và tạo mẫu nén
├── experiments/                        # Thí nghiệm đánh giá ma trận nhầm lẫn và đo thời gian giải nén
├── data/                               # Quản lý mẫu ZIP có nhãn (Ground-truth & Modified samples)
└── results/                            # Kết quả đo lường định lượng và báo cáo JSON
```

---

## 3. Cài đặt và Chạy thử nghiệm

### 3.1 Yêu cầu hệ thống
- Python 3.10 trở lên (khuyến nghị Python 3.11).
- Hệ điều hành: Windows, Linux (Ubuntu), hoặc macOS.

### 3.2 Cài đặt phụ thuộc
```powershell
# Cài đặt gói ở chế độ editable kèm phụ thuộc kiểm thử
pip install -e ".[dev]"
```

### 3.3 Chạy bộ kiểm thử tự động
```powershell
python -m pytest
```

---

## 4. Lộ trình Thực hiện và Tiến độ

Tiến độ được theo dõi chi tiết tại [`docs/project/implementation-plan.md`](docs/project/implementation-plan.md).
- **Giai đoạn 0:** Thiết lập dự án & Khởi tạo cấu trúc thư mục `[HOÀN THÀNH]`
- **Giai đoạn 1:** Triển khai Bộ phân tích nhị phân cốt lõi (Parser & Extra fields) `[SẴN SÀNG THỰC HIỆN]`
- **Giai đoạn 2:** Trích xuất đặc trưng & Băm cấu trúc xác định
- **Giai đoạn 3:** Động cơ phân loại tự động 2 tầng (Algorithm 1, 2, 3)
- **Giai đoạn 4:** Phân tích đa nguồn gốc & Lịch sử can thiệp tệp (Mục 4.2)
- **Giai đoạn 5:** Thẩm định dấu vết giải nén & Nghịch đảo thời gian (Bảng 8)
- **Giai đoạn 6:** Pipeline sinh mẫu thực nghiệm (Hình 5)
- **Giai đoạn 7:** Hoàn thiện CLI & Báo cáo đánh giá khoa học
