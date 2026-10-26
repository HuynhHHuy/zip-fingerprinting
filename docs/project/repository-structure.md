# Cấu trúc Kho Lưu trữ và Thiết kế Thư mục (Repository Structure)

**Dự án:** File Fingerprinting of the ZIP Format for Identifying and Tracking Provenance  
**Bài báo gốc:** Minji Um, Jaehyeok Han, Sangjin Lee (*FSI: Digital Investigation*, 2021).  
**Mục tiêu:** Cung cấp cấu trúc dự án chuẩn mực, phân tách rõ ràng giữa mã nguồn, kiểm thử, script dữ liệu, thực nghiệm khoa học và tài liệu đối chiếu.

---

## 1. Cây Thư mục Toàn diện Đã Khởi tạo (Current Repository Layout)

```text
zip-fingerprinting/
├── .gitignore                          # Cấu hình loại trừ cache, môi trường ảo, dữ liệu nhị phân lớn
├── README.md                           # Giới thiệu dự án, hướng dẫn cài đặt và sử dụng
├── pyproject.toml                      # Cấu hình gói Python, dependencies (pydantic), pytest, mypy, black
├── File fingerprinting of the ZIP format for identifying and tracking provenance.pdf  # Bản PDF toàn văn bài báo gốc
│
├── src/                                # Gói mã nguồn chính (Production Source Code)
│   └── zip_fingerprint/                # Package `zip_fingerprint`
│       ├── __init__.py                 # Khởi tạo package và metadata phiên bản
│       ├── __main__.py                 # Entry point khi chạy `python -m zip_fingerprint`
│       ├── cli.py                      # Giao diện dòng lệnh CLI (fingerprint, identify, provenance, ...)
│       ├── constants.py                # Hằng số chuẩn (Signatures, Header IDs, Host OS, UID/GID)
│       ├── models.py                   # Dataclasses biểu diễn LFH, CDH, EOCD, Extra Fields
│       ├── exceptions.py               # Lớp ngoại lệ đặc thù (CorruptZipError, ...)
│       ├── parser.py                   # Parser luồng nhị phân nguyên thủy (EOCD -> CDH -> LFH)
│       ├── extra_fields.py             # Parser chuyên sâu các trường mở rộng (0x000A, 0x5455, 0x7875, 0x5855, 0x7075)
│       ├── extractor.py                # Trích xuất vector đặc trưng cấu trúc (High-weight & Subsidiary)
│       ├── schema.py                   # Lược đồ chuẩn hóa JSON fingerprint (Pydantic models)
│       ├── hasher.py                   # Sinh mã băm cấu trúc xác định (SHA-256 canonical hashing)
│       ├── rules.py                    # Ma trận cơ sở tri thức (Bảng 6, 7 bài báo)
│       ├── classifier.py               # Động cơ phân loại nguồn gốc tự động (Algorithm 1, 2, 3)
│       ├── provenance.py               # Phân tích đa nguồn gốc và lịch sử can thiệp tệp (Mục 4.2 & Hình 10)
│       └── decompression.py            # Phân tích dấu thời gian giải nén BMAC và đảo ngược thời gian (Mục 4.3 & Bảng 8)
│
├── tests/                              # Bộ kiểm thử tự động toàn diện
│   ├── __init__.py
│   ├── conftest.py                     # Fixtures tạo kho lưu trữ nhị phân mẫu trong RAM
│   ├── unit/                           # Kiểm thử đơn vị các thành phần độc lập
│   │   ├── __init__.py
│   │   ├── test_parser.py              # Kiểm thử bộ phân tích nhị phân (EOCD, CDH, LFH)
│   │   ├── test_extra_fields.py        # Kiểm thử giải mã các khối trường mở rộng
│   │   ├── test_extractor.py           # Kiểm thử trích xuất đặc trưng cấu trúc
│   │   └── test_hasher.py              # Kiểm thử tính xác định của mã băm cấu trúc
│   ├── integration/                    # Kiểm thử tích hợp luồng xử lý
│   │   ├── __init__.py
│   │   ├── test_classifier_algorithms.py # Kiểm thử phân loại theo Algorithm 1, 2, 3
│   │   ├── test_provenance_tracking.py   # Kiểm thử truy vết lịch sử thêm/xóa/sửa tệp
│   │   └── test_security.py              # Kiểm thử an toàn (Zip bomb, path traversal, corrupt data)
│   └── benchmarks/                     # Kiểm thử đối chiếu dữ liệu bài báo
│       ├── __init__.py
│       └── test_paper_matrices.py      # Kiểm chứng ma trận Bảng 6, 7, 8
│
├── scripts/                            # Kịch bản hỗ trợ nghiên cứu và tự động hóa
│   ├── prepare_corpus.py               # Sinh cây thư mục tiêu chuẩn theo Hình 5 bài báo
│   ├── generate_ground_truth.py        # Tự động nén mẫu bằng các công cụ hệ thống (Windows/Linux/macOS)
│   └── simulate_modifications.py       # Tự động can thiệp tệp (Add/Delete/Modify) theo Mục 4.2
│
├── experiments/                        # Kịch bản thực nghiệm khoa học
│   ├── evaluate_classifier.py          # Chạy phân loại trên tập mẫu, xuất ma trận nhầm lẫn (Hình 9)
│   └── trace_decompression.py          # Thí nghiệm đo lường dấu thời gian giải nén MFT BMAC (Bảng 8)
│
├── data/                               # Quản lý dữ liệu nghiên cứu
│   ├── README.md                       # Hướng dẫn tái tạo dữ liệu
│   ├── metadata.json                   # Siêu dữ liệu mô tả môi trường sinh từng mẫu
│   ├── templates/                      # Thư mục chứa cây tệp mẫu gốc (Hình 5)
│   ├── ground_truth/                   # Chứa các tệp ZIP mẫu có nhãn chuẩn
│   │   └── .gitkeep
│   └── modified_samples/               # Chứa các mẫu ZIP bị can thiệp đa nguồn gốc
│       └── .gitkeep
│
├── results/                            # Lưu trữ kết quả đo đạc định lượng
│   ├── classifications/                # Kết quả phân loại dạng JSON
│   │   └── .gitkeep
│   ├── decompression_profiles/         # Hồ sơ đo thời gian giải nén BMAC
│   │   └── .gitkeep
│   └── benchmarks/                     # Bảng so sánh và ma trận nhầm lẫn
│       └── .gitkeep
│
└── docs/                               # Tài liệu học thuật và quản lý kỹ thuật
    ├── evaluation/
    │   └── reproduction_report.md      # Báo cáo khoa học đối chiếu định lượng
    ├── project/
    │   ├── implementation-plan.md      # Lộ trình triển khai chi tiết từng giai đoạn & breakdown tasks
    │   ├── repository-structure.md     # Bản giải trình cấu trúc kho lưu trữ này
    │   └── open-questions.md           # Nhật ký quyết định kiến trúc và giải quyết vấn đề
    └── research/
        ├── citation-355132401.ris      # Bản ghi trích dẫn chuẩn RIS
        ├── comprehensive-paper-guide.md# Cẩm nang phân tích bài báo & hướng dẫn kỹ thuật toàn diện
        ├── paper-mapping.md            # Ánh xạ toàn diện nội dung bài báo sang kỹ thuật
        ├── reproduction-methodology.md # Phương pháp luận tái hiện từng bước
        ├── experimental-design.md      # Thiết kế dữ liệu và kiểm soát biến thực nghiệm
        └── validation-plan.md          # Kế hoạch kiểm thử kỹ thuật và đối chiếu khoa học
```

---

## 2. Bảng Phân nhiệm Thư mục và Nguyên tắc Quản lý

| Thư mục | Trọng tâm Nghiên cứu / Kỹ thuật | Nguyên tắc Quản lý |
| :--- | :--- | :--- |
| `src/zip_fingerprint/` | Mã nguồn sản xuất, tuân thủ Clean Architecture, không có phụ thuộc bên ngoài ngoài Pydantic. | Có type annotations 100%, tuân thủ PEP 8, kiểm tra bằng `mypy`. |
| `tests/` | Kiểm thử đa tầng (Unit, Integration, Benchmarks). | Tự động hóa hoàn toàn với `pytest`, thời gian chạy < 5 giây đối với unit test. |
| `scripts/` | Tạo dữ liệu có tính xác định (Deterministic corpus). | Cố định mốc thời gian và checksum để đảm bảo tính tái lập độc lập với thời gian chạy. |
| `experiments/` | Tái hiện các thí nghiệm trong bài báo (Phân loại, Can thiệp, Giải nén). | Xuất báo cáo có cấu trúc JSON/CSV sang thư mục `results/`. |
| `data/` | Dữ liệu kiểm nghiệm. | Tuyệt đối không commit tệp nhị phân `.zip` lớn; quản lý thông qua metadata và scripts sinh mẫu. |
| `docs/` | Tri thức pháp y số và hồ sơ khoa học. | Cập nhật song song với tiến độ thực thi code. |
