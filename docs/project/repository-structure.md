# Cấu trúc Kho Lưu trữ và Lý do Thiết kế (Repository Structure)

**Dự án:** File Fingerprinting of the ZIP Format for Identifying and Tracking Provenance  
**Mục tiêu:** Thiết lập cấu trúc dự án chuẩn mực cho nghiên cứu khoa học tái hiện, phân tách rành mạch giữa mã nguồn, tài liệu, dữ liệu thực nghiệm và kết quả kiểm chứng.  

---

## 1. Cây Thư mục Dự kiến Toàn diện (Target Repository Layout)

```text
zip-fingerprinting/
├── .gitignore                          # Cấu hình bỏ qua tệp nhị phân lớn, cache, kết quả tạm
├── README.md                           # Giới thiệu dự án, hướng dẫn cài đặt và chạy thử
├── pyproject.toml                      # Quản lý phụ thuộc, công cụ đóng gói và cấu hình test
├── citation-355132401.ris              # Bản ghi trích dẫn RIS của bài báo gốc
├── docs.txt                            # Liên kết bài báo gốc trên ScienceDirect
│
├── docs/                               # Toàn bộ tài liệu kỹ thuật và khoa học
│   ├── research/                       # Phân tích phương pháp và thiết kế nghiên cứu
│   │   ├── source-audit.md             # Báo cáo kiểm kê tài liệu và hiện trạng repo
│   │   ├── paper-mapping.md            # Ánh xạ chi tiết nội dung bài báo sang kỹ thuật
│   │   ├── reproduction-methodology.md # Phương pháp luận tái hiện từng bước
│   │   ├── experimental-design.md      # Thiết kế dữ liệu, kiểm soát biến thực nghiệm
│   │   └── validation-plan.md          # Kế hoạch kiểm thử kỹ thuật và đối chiếu khoa học
│   ├── project/                        # Quản lý dự án và lộ trình phát triển
│   │   ├── implementation-plan.md      # Danh mục nhiệm vụ (Backlog), phụ thuộc, DoD
│   │   ├── repository-structure.md     # Bản giải trình cấu trúc kho lưu trữ này
│   │   └── open-questions.md           # Các vấn đề tồn đọng cần xác minh
│   └── evaluation/                     # Báo cáo kết quả thực nghiệm và sai lệch
│       └── reproduction_report.md      # Báo cáo đối chiếu định lượng với bài báo
│
├── src/                                # Mã nguồn triển khai phương pháp cốt lõi
│   └── zip_fingerprint/                # Gói Python chính (Package)
│       ├── __init__.py                 # Export các interface công khai
│       ├── __main__.py                 # Điểm vào thực thi dòng lệnh
│       ├── cli.py                      # Bộ phân tích tham số dòng lệnh CLI
│       ├── constants.py                # Hằng số đặc tả ZIP (Magic, Header IDs, Host OS)
│       ├── models.py                   # Dataclasses biểu diễn cấu trúc tệp ZIP
│       ├── exceptions.py               # Lớp định nghĩa ngoại lệ đặc thù
│       ├── parser.py                   # Trình phân tích luồng nhị phân nguyên thủy
│       ├── extra_fields.py             # Bộ giải mã chuyên biệt các trường Extra Field
│       ├── extractor.py                # Bộ trích xuất vector đặc trưng cấu trúc
│       ├── schema.py                   # Lược đồ JSON Fingerprint có phiên bản
│       ├── hasher.py                   # Tính toán mã băm xác thực SHA-256
│       ├── rules.py                    # Cơ sở tri thức và tập luật nhận diện
│       └── classifier.py               # Động cơ phân loại nguồn gốc môi trường
│
├── tests/                              # Bộ kiểm thử tự động
│   ├── __init__.py
│   ├── conftest.py                     # Fixtures tạo kho lưu trữ mẫu trong bộ nhớ
│   ├── test_parser.py                  # Kiểm thử đơn vị bộ phân tích nhị phân
│   ├── test_extra_fields.py            # Kiểm thử giải mã các khối trường mở rộng
│   ├── test_extractor.py               # Kiểm thử trích xuất đặc trưng
│   ├── test_classifier.py              # Kiểm thử bộ phân loại nguồn gốc
│   ├── test_security.py                # Kiểm thử an toàn (Zip bomb, path traversal)
│   └── test_reproducibility.py         # Kiểm thử tính nhất quán của mã băm
│
├── scripts/                            # Kịch bản hỗ trợ nghiên cứu và tạo mẫu
│   ├── prepare_corpus.py               # Tạo cây thư mục tiêu chuẩn với timestamp cố định
│   └── generate_ground_truth.py        # Tự động nén mẫu bằng các công cụ hệ thống
│
├── experiments/                        # Các kịch bản chạy thực nghiệm khoa học
│   ├── evaluate_benchmark.py           # Chạy phân loại trên tập mẫu và tính ma trận nhầm lẫn
│   └── trace_decompression.py          # Thí nghiệm theo dõi dấu thời gian giải nén
│
├── data/                               # Quản lý dữ liệu (không lưu tệp nhị phân lớn trên Git)
│   ├── templates/                      # Cây thư mục nguồn mẫu
│   ├── ground_truth/                   # Thư mục đích chứa mẫu ZIP (chỉ lưu `.gitkeep`)
│   │   └── .gitkeep
│   ├── metadata.json                   # Siêu dữ liệu mô tả nguồn gốc các mẫu
│   └── README.md                       # Hướng dẫn tạo lại bộ dữ liệu mẫu
│
└── results/                            # Kết quả sinh ra từ thực nghiệm (JSON, CSV, plots)
    └── .gitkeep
```

---

## 2. Giải thích Mục đích Từng Thư mục và Lộ trình Khởi tạo

| Thư mục / Tệp tin | Mục đích và Vai trò | Thời điểm Khởi tạo Phù hợp |
| :--- | :--- | :--- |
| `docs/` | Lưu trữ tài liệu phân tích bài báo, thiết kế, kế hoạch và các quyết định kiến trúc. | **Tạo ngay lập tức** (đã khởi tạo trong giai đoạn lập kế hoạch). |
| `src/zip_fingerprint/` | Chứa mã nguồn sản xuất, độc lập với dữ liệu mẫu và kịch bản thực nghiệm. | Khởi tạo khi bắt đầu Phase 2 (`DOC-001`, `CORE-001`). |
| `tests/` | Chứa toàn bộ các bộ kiểm thử tự động (`pytest`). | Khởi tạo song song với `src/` theo phương pháp Test-Driven Development. |
| `scripts/` | Các script tiện ích hỗ trợ sinh dữ liệu chuẩn và kiểm tra môi trường. | Khởi tạo trong Phase 2 (`DATA-001`). |
| `data/` | Quản lý mẫu ZIP và cấu hình thử nghiệm. Chỉ lưu file metadata nhẹ và hướng dẫn. | Khởi tạo khi xây dựng pipeline tạo mẫu (`DATA-001`). |
| `experiments/` | Chứa các kịch bản thực nghiệm đo lường hiệu năng, độ chính xác, truy vết giải nén. | Khởi tạo khi bước vào giai đoạn thực nghiệm (`EXP-001`). |
| `results/` | Lưu trữ ma trận nhầm lẫn, bảng số liệu định lượng phục vụ viết báo cáo. | Khởi tạo khi chạy thực nghiệm đánh giá (`EVAL-001`). |

---

## 3. Chính sách Quản lý Dữ liệu và Kiểm soát Phiên bản (Data Management Policy)

1. **Nguyên tắc "Không cam kết tệp nhị phân lớn" (No Binary Blobs in Git):**
   - Tệp ZIP mẫu có thể làm phình to lịch sử Git và gây xung đột nhị phân không giải quyết được.
   - Thư mục `data/ground_truth/*.zip` được thêm vào `.gitignore`.
2. **Khả năng Tái tạo Dữ liệu (Data Reproducibility as Code):**
   - Thay vì lưu các file `.zip`, dự án lưu trữ mã nguồn sinh ra chúng (`scripts/prepare_corpus.py` và `scripts/generate_ground_truth.py`).
   - Mọi tệp ZIP sinh ra đều được kiểm tra tính toàn vẹn bằng tệp băm SHA-256 (`data/checksums.sha256`).
3. **Bảo mật và An toàn Chứng cứ số:**
   - Dữ liệu thực nghiệm là dữ liệu giả lập (synthetic data), không chứa thông tin cá nhân, không chứa mã độc thật.
   - Tuyệt đối không đưa chứng cứ số vụ án thực tế vào kho lưu trữ công khai.
