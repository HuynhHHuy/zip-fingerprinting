# Đăng ký trước: tập kiểm tra độc lập và profile Windows tự đo (#22, #42)

**Ngày đăng ký:** 28/11/2026. **Trạng thái:** đăng ký trước. Chưa có mẫu nào của tập
kiểm tra (mục 4), và chưa có code cho các profile ở mục 3. Mọi thay đổi với tài liệu này
phải được commit thành một sửa đổi có ghi lý do, không sửa lặng lẽ. Sau khi tập kiểm tra
có mẫu đầu tiên thì mục 3 và mục 5 không được đổi nữa.

## 1. Vì sao làm lại đánh giá

Lần nghiệm thu ngày 25/11 ([báo cáo §3.4](../evaluation/reproduction_report.md#34-kết-quả-so-với-ngưỡng-tập-sha-256-duy-nhất))
không đạt ngưỡng:

- trên tập tự sinh, công cụ Windows đúng 1/12;
- trên tập tác giả, công cụ Windows đúng 5/10 và OS đúng 15/17.

Phần lớn lỗi là đồng hạng giữa 7-Zip, WinRAR và Bandizip. Trong bộ luật Bảng 6 của bài
báo, ba profile này có cùng extra field và cùng mẫu nanosecond, nên với tên file ASCII
classifier không có căn cứ nào để tách chúng.

Ngày 28/11, khi xem byte của các mẫu đó, nhóm thấy một số trường header **không có trong
Bảng 6** lại khác nhau rõ giữa các công cụ (mục 2). Các trường này được tìm ra trên chính
các mẫu đã dùng để đánh giá. Vì vậy, theo §3.5 của báo cáo:

- các mẫu cũ trở thành **tập phát triển** và không được dùng cho con số nghiệm thu;
- con số nghiệm thu chỉ lấy từ một **tập kiểm tra mới**, sinh sau commit này.

## 2. Tập phát triển

| Tập | Mẫu | Vị trí bytes |
| --- | --- | --- |
| Tự sinh, 3 run Windows (`run-xzp9n65j`, `run-49gonnjf`, `run-xvkrpl03`) | 26 được đánh giá, 18 SHA-256 khác nhau | prerelease `evidence-ph7-eval-002-2026-11-25` |
| Mẫu tác giả (#17), set1–set4 | 17 | tải bằng `scripts/fetch_author_samples.py` |

Các giá trị dưới đây quan sát trên **mọi** mẫu Windows của tập phát triển, cả mẫu tác giả
(2021) lẫn mẫu tự sinh (2026). Giá trị của Bandizip và WinZip chỉ có từ mẫu tác giả.

| Công cụ | `version_made_by` (CDH) | `extract_version` của entry thư mục | Cờ gp của entry deflate (mask `0x0006`) | External attributes của file | Extra NTFS `0x000A` | Có entry thư mục |
| --- | --- | --- | --- | --- | --- | --- |
| 7-Zip | 63 | 20 | `0x0` | `0x20` | có | có |
| WinRAR | 31 | 10 | `0x0` | `0x20` | có | có |
| Bandizip | 20 | 20 | `0x0` | `0x20` | có | có |
| WinZip | 20 | 10 | `0x2` | `0x20` | có | có |
| Compressed folder | 20 | 20 | `0x0` | `0x20` | không | có, trừ thư mục gốc |
| PowerShell `Compress-Archive` (.NET) | 20 | 20 (chỉ khi có entry thư mục) | `0x0` | `0x0` | không | module 1.2.7: chỉ thư mục rỗng; module 1.0.1.0: không |

Cách kiểm: một script đọc CDH của mọi mẫu Windows đã sinh và mọi mẫu `WIN_*` của tác
giả. Mỗi công cụ cho đúng một bộ giá trị trên tất cả mẫu của nó. Ngoại lệ duy nhất là
PowerShell: module Archive 1.2.7 (hai run ngày 13/11) ghi `emptyFolder/` với
`extract_version` 20, còn module 1.0.1.0 (run ngày 25/11) không ghi entry thư mục nào.

## 3. Profile tự đo được chốt

Profile tự đo nằm trong `observed_rules.py` và chỉ được dùng khi bật cờ, theo cách #35 đã
làm. `rules.py` (Bảng 6/7) không đổi.

### 3.1 Trường mới

Thêm các trường tùy chọn vào `FingerprintRule`. Mặc định của chúng là `None`, nghĩa là không
chấm, nên điểm của mọi profile bài báo giữ nguyên.

| Trường | Đọc từ archive | Trọng số | Khi nào bỏ qua |
| --- | --- | --- | --- |
| `version_made_by` | Giá trị 16-bit của CDH. Chỉ tính khi mọi entry có cùng giá trị; nếu các entry khác nhau thì ghi là không khớp | 3 | Không bao giờ (archive luôn có CDH) |
| `directory_extract_version` | `extract_version` của các entry thư mục trong CDH (tên kết thúc bằng `/`). Chỉ tính khi mọi entry thư mục có cùng giá trị | 3 | Archive không có entry thư mục |
| `deflate_option_flags` | `gp_bit_flag & 0x0006` của các entry nén bằng deflate (method 8), nếu mọi entry cùng giá trị | 3 | Không có entry deflate |
| `file_external_attributes_zero` | `True` khi mọi entry file có external attributes bằng 0 | 2 | Không có entry file |

Cách tính điểm giữ nguyên Algorithm 3 hiện có: trường khớp thì cộng, không khớp thì trừ,
`0.5 + 0.49 × cân bằng / tổng trọng số`.

### 3.2 Profile

Mỗi profile giữ nguyên các tiêu chí HIGH của profile bài báo cùng tên. Hai profile không có
trong bài báo lấy tiêu chí HIGH từ mục 2. Dưới đây chỉ ghi phần thêm vào:

| Profile (nhãn công cụ) | `version_made_by` | `directory_extract_version` | `deflate_option_flags` | `file_external_attributes_zero` |
| --- | --- | --- | --- | --- |
| 7-Zip | 63 | 20 | 0 | False |
| WinRAR | 31 | 10 | 0 | False |
| Bandizip | 20 | 20 | 0 | False |
| WinZip | 20 | 10 | 2 | False |
| Compressed folder | 20 | 20 | 0 | False |
| PowerShell `Compress-Archive` (.NET), **mới** | 20 | 20 | 0 | True |

Profile PowerShell có host Windows, không có extra field ở LFH và CDH, và không có data
descriptor. Việc có hay không có entry thư mục không được dùng làm tiêu chí, vì hai phiên
bản module khác nhau ở điểm này.

Nhãn dự đoán của một profile tự đo là tên công cụ trong cột đầu, không kèm hậu tố
"observed". Nhờ vậy evaluator so được nhãn này với nhãn ground truth.

### 3.3 Điều kiện của bản triển khai (#43)

- Không bật cờ thì kết quả phải giống hệt `main` trên cả hai tập phát triển.
- Nếu khi triển khai phát hiện định nghĩa ở mục 3 sai (ví dụ trường đọc nhầm), được sửa
  tài liệu này **trước** khi sinh mẫu kiểm tra đầu tiên, kèm lý do.

## 4. Tập kiểm tra

### 4.1 Cây nguồn

Cây mới `heldout`, sinh bằng script xác định (deterministic). Mtime cố định, nội dung và tên
khác hẳn set1/set2:

```text
heldout/
├── report-2026.txt          (ASCII, khoảng 6 KB văn bản)
├── data/
│   ├── table.csv            (ASCII)
│   ├── photo.png            (khoảng 20 KB, không nén được nhiều)
│   └── empty/               (thư mục rỗng)
├── archive/inner.zip        (ZIP lồng, tạo bằng zipfile của Python, method 8)
├── ghi-chú-tiếng-Việt.txt   (NFC)
└── 문서.txt                  (NFC)
```

Mỗi công cụ chạy hai biến thể:
- `folder`: nén cả thư mục `heldout`;
- `contents`: nén nội dung bên trong thư mục.

### 4.2 Ma trận

| Môi trường | Công cụ (nhãn) | Cách chạy |
| --- | --- | --- |
| **Host:** Windows 11 10.0.26200 | 7-Zip 26.04 | lệnh của `scripts/simulate_modifications.py:archive_command` |
| | WinRAR 6.23 | như trên (`-afzip`) |
| | Bandizip 7.47.0.1 portable | như trên (`bz c -y`) |
| | WinZip 29 (bản dùng thử) | CLI nếu có; nếu không thì GUI theo checklist, chụp màn hình |
| | Compressed folder | shell `CopyHere` vào ZIP rỗng (zipfldr), cộng **một** lần GUI "Send to → Compressed folder" cho mỗi biến thể để đối chiếu |
| | PowerShell 5.1 và PowerShell 7 | `Compress-Archive -LiteralPath`, như `scripts/generate_ground_truth.py` |
| **VM:** Windows 10 v2004 build 19041 | 7-Zip 19.00, WinRAR 5.91, Bandizip 6.29 | CLI |
| | Compressed folder | như trên |
| | PowerShell 5.1 | `Compress-Archive` |
| **VM:** Ubuntu (ghi phiên bản thực tế) | `zip` (Info-ZIP) | `zip -r` |
| | 7-Zip (`7z` hoặc `7za`) | `7z a -tzip` |
| | Compress (GNOME Files) | chỉ khi VM có desktop; nếu không thì `skipped` |
| **macOS:** runner GitHub Actions, label image được ghi | `zip` | `zip -r` |
| | `ditto` (**ngoài catalog**, báo riêng, không gán thành Compress) | `ditto -c -k --sequesterRsrc --keepParent` |

Mọi phiên bản, đường dẫn công cụ, SHA-256 file thực thi, argv, stdout/stderr, OS, code page
và UID/GID (với Unix) đều được ghi. Nếu phiên bản thực tế khác bảng thì ghi lại, không đổi
công cụ.

### 4.3 Quy tắc chạy

- Mỗi ô chạy một lần cho mỗi biến thể.
- Chỉ chạy lại **một** lần khi có lỗi vận hành (mã lỗi khác 0, timeout, file bị khóa); lần
  lỗi vẫn được giữ trong metadata.
- Không đổi lệnh hay cấu hình sau khi đã thấy kết quả phân loại.
- Ô thiếu công cụ thì ghi `skipped` kèm lý do.
- Mẫu đưa vào đánh giá phải có payload khớp với cây nguồn (kiểm CRC và nội dung).

## 5. Chỉ số, ngưỡng và điểm dừng

### 5.1 Cách đếm

Giữ định nghĩa của #22:
- đếm trên tập SHA-256 khác nhau;
- top-1 chỉ đúng khi ứng viên điểm cao nhất là duy nhất và khớp nhãn;
- đồng hạng ghi là ambiguous;
- candidate coverage báo riêng;
- ứng dụng ngoài catalog báo riêng.

### 5.2 Hai catalog, chấm riêng

1. **Chỉ bài báo:** con số **tái hiện**. PowerShell và `ditto` là ngoài catalog.
2. **Bài báo + tự đo:** con số **mở rộng**. PowerShell thành trong catalog, `ditto` vẫn ngoài
   catalog.

### 5.3 Ngưỡng (DoD #22)

- OS accuracy = 100 % trên mọi mẫu trong catalog.
- Windows tool accuracy ≥ 90 % trên năm công cụ Bảng 6 (WinRAR, WinZip, 7-Zip, Bandizip,
  Compressed folder). PowerShell được báo thêm thành một dòng riêng và không vào mẫu số này.
- Độ phủ tối thiểu để kết luận:
  - mỗi công cụ trong năm công cụ trên có ít nhất một SHA-256;
  - có ít nhất một mẫu Ubuntu và một mẫu macOS.

  Thiếu phần nào thì trạng thái là `insufficient_coverage` cho chỉ số liên quan.

### 5.4 Điểm dừng

- **Catalog mở rộng đạt cả hai ngưỡng và đủ độ phủ:** đề xuất đóng #22, ghi rõ ngưỡng đạt
  nhờ profile tự đo. Con số của catalog bài báo vẫn được công bố là kết quả tái hiện.
- **Không đạt:** công bố kết quả, giữ #22 mở. Không chỉnh luật trên tập kiểm tra này. Muốn
  sửa luật thì phải có đăng ký trước mới và một tập kiểm tra mới khác.
- **Thiếu độ phủ:** công bố phần đo được. Người hướng dẫn quyết định có chấp nhận hay không.

Mỗi catalog chỉ được chạy evaluator **một lần** trên tập kiểm tra. Lần chạy lại chỉ được
phép khi có lỗi vận hành, và lần lỗi phải được ghi lại.

## 6. Giới hạn đã biết trước

- Điểm heuristic không phải xác suất đã hiệu chuẩn. Tập nhỏ và không mù.
- Các công cụ chạy trên cùng một host không phải bằng chứng hoàn toàn độc lập. VM Windows
  10 với phiên bản cũ hơn làm giảm, nhưng không loại bỏ, giới hạn này.
- `version_made_by` có thể đổi theo phiên bản công cụ. Kết quả trên VM Windows 10 sẽ cho
  biết điều đó, đúng hay sai đều được công bố.
- Shell `CopyHere` và GUI "Send to" có thể không cho cùng một bố cục. Lần GUI đối chiếu ở
  4.2 dùng để kiểm điều này.
- Runner macOS là môi trường CI, không phải máy người dùng: UID/GID và locale có thể khác.
