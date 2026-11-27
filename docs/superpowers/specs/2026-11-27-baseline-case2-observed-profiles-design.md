# Thiết kế: phát hiện Case 2 khi có bản trước và catalog profile tự đo (#35)

## Mục tiêu và lý do

Issue #35 (PH4-PROV-003). Đợt sàng lọc SW2 ngày 26/11 có một mẫu Case 2 native:
7-Zip 26.04 tạo archive, rồi Bandizip 7.47.0.1 xóa một entry. Bandizip ghi lại cả LFH
lẫn CDH của mọi entry còn lại, và ghi nhất quán. Trên `after.zip`, tracker gặp hai vấn
đề:

1. Không báo Case 2. Quy tắc hiện tại cần LFH và CDH của cùng entry mâu thuẫn nhau,
   mà ở đây không còn mâu thuẫn nào để thấy.
2. Báo Case 1 và gán SW1 là Windows "Compressed folder". `keep.txt` không còn extra nên
   khớp profile Explorer của bài báo. Hai tên Unicode chỉ còn `0x7075` nên không khớp
   profile nào.

Thành công nghĩa là:
- khi có bản trước, tracker báo Case 2 đúng cho S6;
- khi người dùng bật catalog tự đo, S6 không còn bị báo Case 1;
- mọi kết quả mặc định, kể cả các số đánh giá PH7-EVAL, giữ nguyên.

## Mục tiêu, ngoài phạm vi, điều cấm

- **Mục tiêu:**
  - chế độ so sánh trước/sau trong package `src/zip_fingerprint` và CLI;
  - catalog profile tự đo, tách khỏi catalog bài báo và chỉ bật khi người dùng yêu cầu;
  - profile đầu tiên là "Bandizip 7.47 khi ghi lại";
  - test và tài liệu đi kèm.
- **Ngoài phạm vi:**
  - phát hiện Case 2 khi chỉ có một archive mà SW2 đã ghi lại nhất quán;
  - cảnh báo heuristic cho một archive đơn lẻ (mục 3 tùy chọn của #35, để lại sau);
  - thêm profile ngoài trường hợp S6;
  - `identify` và evaluator PH7-EVAL không dùng catalog tự đo.
- **Điều cấm (dù code chạy được vẫn là thất bại):**
  - sửa `rules.py` hay `ALL_RULES`. Catalog bài báo (Table 6/7, Um et al. 2021) giữ
    đúng nguyên văn;
  - output mặc định thay đổi so với `main` trên bất kỳ archive nào;
  - trình bày kết quả có dùng profile tự đo như thể đó là kết luận của bài báo;
  - sửa code đo đã đăng ký trước (`experiments/sw2_screening.py`,
    `experiments/modification_evidence.py`) hay dữ liệu đã công bố;
  - commit ZIP native hoặc binary vào Git.

## Ràng buộc

- Python ≥ 3.10. mypy, Black và Flake8 sạch trên file đổi. CI có 6 job.
- Tracker không giải nén (theo docstring của `ProvenanceTracker`). Chế độ trước/sau
  cũng không giải nén: chỉ dùng record của `ZipBinaryParser`.
- Mẫu native (`data/modified_samples/run-sw2-*`, `run-case2-dlq9ulnc`, run Case 1
  7-Zip → WinRAR) bị gitignore. Trên host có bản sao; ngoài ra có thể lấy lại từ
  prerelease `evidence-ph4-prov-002-sw2-2026-11-26` (SHA-256 `17fb4445…894c40`).
  CI không có các mẫu này.
- Không ghi công Claude trong commit hay PR.

## Các phương án đã cân nhắc

Phần chung cho mọi phương án là chế độ so sánh trước/sau. Các phương án chỉ khác nhau
ở cách xử lý lỗi gán nhầm SW1 của S6:

- **A. Chỉ ghi giới hạn.** Không có profile mới, chỉ thêm test khóa hành vi hiện tại.
  Nhỏ nhất, nhưng lỗi vẫn còn.
- **B. Catalog tự đo, chỉ bật khi yêu cầu** (người dùng chọn). Mặc định chỉ dùng catalog
  bài báo, nên PH7-EVAL không đổi. Khi bật cờ, tracker dùng thêm profile tự đo, và
  output ghi rõ nguồn của từng profile.
- **C. Catalog tự đo luôn chạy, báo ở mục riêng.** Không cần nhớ bật cờ, nhưng output
  mặc định thay đổi và mỗi lần đánh giá phải kiểm xem có lẫn kết quả tự đo không.

Người dùng chọn giữ catalog đúng như bài báo và đặt profile tự đo riêng, theo phương án
B.

## Thiết kế

### 1. Catalog profile tự đo: `src/zip_fingerprint/observed_rules.py` (mới)

- Dataclass `ObservedProfile` gồm:
  - `rule: FingerprintRule`, dùng lại kiểu đã có;
  - `source`: run id, cặp công cụ và phiên bản, thao tác, ngày, SHA-256 của ZIP mẫu,
    và link tới báo cáo hoặc prerelease.
- Danh sách `OBSERVED_PROFILES` có đúng một profile:
  - target `Windows`, application `Bandizip 7.47 (rewrite, observed)`;
  - host 0, không data descriptor;
  - tên ASCII: LFH `()`, CDH `()`;
  - tên Unicode: LFH `(0x7075,)`, CDH `(0x7075,)`;
  - các trường phụ để `None`.
- Tên application khác hẳn `"Bandizip"` của bài báo, để không lẫn với profile bài báo
  khi tra cứu bằng `get_rule`.
- Hàm `get_observed_rules() -> List[FingerprintRule]`.
- Hàm `catalog_of(rule) -> Literal["paper", "observed"]`. Hàm này dùng để gắn nhãn
  trong output.
- `rules.py` không bị sửa.

### 2. Cho tracker và classifier nhận danh sách rule

- `AutomatedClassifier.__init__(self, rules: Optional[Sequence[FingerprintRule]] = None)`:
  - `None` nghĩa là dùng `get_all_rules()`, đúng hành vi hiện tại;
  - mọi chỗ đang gọi `get_all_rules()` bên trong classifier đổi sang `self._rules`.
- `ProvenanceTracker.__init__(self, archive, rules=None)`: truyền `rules` cho classifier,
  và dùng `rules` thay cho `get_all_rules()` trong `_fingerprint_entry`.
- Khi `rules` có profile tự đo:
  - `ProvenanceReport.to_dict()` có thêm khóa `catalogs_used: ["paper", "observed"]`;
  - mỗi suspected application và group candidate có thêm khóa `catalog`.
- Vì sao S6 thôi bị báo Case 1 khi bật catalog tự đo:
  - `estimate_program_3` giữ lại mọi ứng viên, chỉ xếp hạng chúng;
  - `keep.txt` có hai ứng viên: Compressed folder và Bandizip rewrite;
  - hai tên Unicode chỉ có ứng viên Bandizip rewrite;
  - `_group_entries` lấy giao của các ứng viên, nên ra một nhóm duy nhất.

  Không cần sửa logic nhóm.
- Các trường phụ không đo được của profile tự đo để `None`. Riêng `is_alphabetical_order`
  là `bool` nên giữ mặc định. Trường này chỉ có ý nghĩa ở mức archive.
- **Khi không bật, `to_dict()` không có khóa mới nào.** Nhờ vậy output mặc định trùng
  từng byte với `main`.

### 3. So sánh trước/sau: `src/zip_fingerprint/baseline.py` (mới)

`compare_archives(before: ZipArchiveRecord, after: ZipArchiveRecord) -> BaselineComparison`.

- **Ghép entry** theo `file_name` của CDH:
  - `survivors` là tên có ở cả hai bản;
  - `removed` và `added` là phần chênh lệch;
  - đổi tên sẽ hiện thành một `removed` và một `added`.
- **Nội dung một survivor** coi là giữ nguyên khi CRC-32, compressed size và
  uncompressed size ở CDH của hai bản bằng nhau. Không giải nén.
- **Thay đổi đủ điều kiện**, xét ở cả LFH và CDH:
  - `version_made_by` (chỉ có ở CDH);
  - `extract_version`;
  - `compression_method`;
  - `gp_bit_flag & 0x0808`;
  - `file_name_length`;
  - bố cục extra field, tức danh sách `(header_id, data_size)` theo thứ tự.

  Tập này giống tập `structural` của `compare_survivors`. Record của parser không giữ
  tên dạng byte, nên `raw_name_hex` được xấp xỉ bằng cờ UTF-8 cùng độ dài tên. Đây là
  giới hạn, phải ghi trong docstring.
- **Không tính** offset, CRC, size, timestamp hay comment khi đứng một mình. Chúng vẫn
  được liệt kê trong `changes` để người đọc thấy.
- **`rewrite_scope`**, tính trên các survivor có nội dung giữ nguyên:
  - `all` nếu mọi survivor có ít nhất một thay đổi đủ điều kiện;
  - `partial` nếu chỉ một số có;
  - `none` nếu không có survivor nào có;
  - `not_applicable` nếu không có survivor.
- **`case2_detected = (scope == "all")`.** Nếu có survivor đổi nội dung thì vẫn tính
  scope trên phần còn lại, nhưng đặt `content_changed: [...]`, và `case2_detected`
  luôn là `False` (call của mình, bảo thủ).
- **Kết quả là dataclass** có `to_dict()`, gồm:
  - `survivors`, `removed`, `added`, `content_changed`;
  - `entries`: mỗi entry có `changes` và `qualifying_changes`;
  - `rewrite_scope`, `case2_detected`;
  - `basis: "baseline_comparison"`.

**Call của mình:** không chuyển `compare_survivors` vào `src`. Hàm đó băm payload sau
khi giải nén, và là code đo đã đăng ký trước. Package `src` có một bản so sánh riêng,
chỉ đọc header. Hai bản phải cho cùng `rewrite_scope` trên mọi mẫu native (mục
Kiểm chứng).

### 4. CLI

- `provenance` thêm hai cờ:
  - `--baseline BEFORE.zip`: output JSON có thêm khóa `baseline_comparison`. Bản text
    in thêm scope và các survivor đổi;
  - `--observed-profiles`: dùng catalog bài báo cộng catalog tự đo.
- Hai cờ độc lập với nhau. Khi không có cờ nào, output giữ nguyên như hiện tại.
- Kết luận Case 2 khi chỉ có một archive (`case2_detected` cũ) giữ nguyên tên và ý
  nghĩa. Kết quả từ bản trước nằm riêng trong `baseline_comparison.case2_detected`.

### 5. Tài liệu

- Tài liệu provenance hoặc README CLI giải thích ba điểm:
  - hai cờ mới;
  - không phát hiện Case 2 trên một archive **không** chứng minh archive chưa bị sửa;
  - profile tự đo không phải dữ liệu của bài báo.
- Cập nhật `reproduction_report.md` và `implementation-plan.md` cho PH4-PROV-003.

## Kiểm chứng và nghiệm thu

1. **Bất biến mặc định:**
   - test so `to_dict()` của tracker mặc định trên các ZIP tổng hợp hiện có trước và
     sau thay đổi;
   - chạy `experiments/evaluate_classifier.py` trên `main` và trên nhánh: output phải
     trùng nhau.
2. **Test đơn vị** cho `baseline.py`, dùng ZIP tổng hợp dựng bằng `zipfile` và
   `struct` trong `tmp_path`, ghi rõ đây không phải bằng chứng:
   - các scope `all`, `partial`, `none`, `not_applicable`;
   - trường hợp thêm, xóa, đổi tên;
   - survivor đổi nội dung;
   - chỉ offset hay timestamp đổi thì không tính.
3. **Test catalog tự đo:**
   - profile không nằm trong `get_all_rules()`;
   - có nhãn `catalog` khi bật;
   - tên application không trùng tên nào của bài báo.
4. **Test tích hợp native**, tự `skip` khi không có `data/modified_samples` (CI sẽ skip).
   Chạy trên host và ghi số pass/skip vào PR:
   - S6 và lần xác nhận: baseline `all`; với `--observed-profiles` không còn Case 1;
   - S1–S5: baseline `none`;
   - S3–S5 và mẫu 7-Zip → WinRAR: vẫn Case 1 khi bật catalog tự đo, tức không có
     báo thiếu mới;
   - ZIP sạch do từng công cụ tạo (`before.zip` của các ô): không Case 1, dù bật
     hay tắt catalog tự đo;
   - `run-case2-dlq9ulnc` (Explorer xóa): baseline `none`.
5. `rewrite_scope` của `baseline.py` trùng `compare_survivors` trên cả 7 lần đo SW2 và
   `run-case2-dlq9ulnc`.
6. Toàn bộ `python -m pytest`, mypy, Black và Flake8 trên file đổi; CI đạt 6 job.

## Để lại cho người triển khai

- Tên file test và cách sắp test trong `tests/unit` và `tests/integration`.
- Định dạng chi tiết của bản text CLI.
- Cách tìm mẫu native: tham số `ZIP_PROV_NATIVE_SAMPLES` hoặc đường dẫn mặc định
  `data/modified_samples`.
