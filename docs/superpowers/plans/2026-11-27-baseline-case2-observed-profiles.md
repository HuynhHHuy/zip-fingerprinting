# Baseline Case 2 và catalog profile tự đo: kế hoạch triển khai

> **Cho agent thực thi:** BẮT BUỘC dùng superpowers:executing-plans (người dùng giao
> triển khai trong phiên). Các bước dùng checkbox `- [ ]`.

**Mục tiêu:** phát hiện Case 2 khi có bản trước, và thêm một catalog profile tự đo chỉ
bật khi được yêu cầu. Catalog bài báo và output mặc định giữ nguyên.

**Kiến trúc:**
- `baseline.py` so header của hai `ZipArchiveRecord`.
- `observed_rules.py` chứa các `FingerprintRule` tự đo kèm nguồn.
- Classifier và tracker nhận thêm tham số `rules`; khi tham số là `None` thì hành vi
  như cũ.
- CLI `provenance` có thêm `--baseline` và `--observed-profiles`.

**Stack:** Python ≥ 3.10, dataclasses, pytest, mypy, Black, Flake8.

**Spec:** `docs/superpowers/specs/2026-11-27-baseline-case2-observed-profiles-design.md`

## Ràng buộc chung

- Không sửa `src/zip_fingerprint/rules.py` hay `ALL_RULES`.
- Không đổi output mặc định: `ProvenanceTracker(archive).analyze().to_dict()`,
  `AutomatedClassifier().classify()` và `provenance` khi không có cờ.
- Không sửa `experiments/sw2_screening.py`, `experiments/modification_evidence.py` hay
  dữ liệu đã công bố.
- Không giải nén trong `baseline.py`.
- Không commit ZIP native hay binary.
- Không ghi công Claude trong commit hay PR.
- Application của profile tự đo: `"Bandizip 7.47 (rewrite, observed)"`.
- Các trường đủ điều kiện:
  - `version_made_by` (chỉ CDH);
  - `extract_version`;
  - `compression_method`;
  - `gp_bit_flag & 0x0808`;
  - `file_name_length`;
  - `extra_layout`, tức danh sách `(header_id, data_size)`.

## Trọng tâm review

1. Tên entry trùng nhau trong một archive (archive bị can thiệp): `compare_archives`
   ném `ValueError("Duplicate entry names: ...")`; CLI trả 1 và in lỗi ra stderr.
   Test ở Task 3 và Task 4.
2. CDH trỏ tới offset không có LFH: các trường LFH được coi là `None`. Nếu chỉ một bên
   thiếu thì tính là thay đổi đủ điều kiện, không crash. Test ở Task 3.
3. `--baseline` trỏ tới file không tồn tại hoặc ZIP hỏng: trả 1 với thông báo giống lỗi
   của `zip_path`. Test ở Task 4.
4. `before` và `after` là cùng một file: scope `none`, `case2_detected` là False. Test ở
   Task 3.
5. Không còn entry nào (xóa hết, hoặc archive rỗng): scope `not_applicable`,
   `case2_detected` là False. Test ở Task 3.

---

### Task 1: Catalog profile tự đo

**File:**
- Tạo `src/zip_fingerprint/observed_rules.py`
- Test `tests/unit/test_observed_rules.py`

**Interface:**
- Cung cấp:
  - `ObservedProfile(rule: FingerprintRule, source: Dict[str, str])` (frozen dataclass);
  - `OBSERVED_PROFILES: Tuple[ObservedProfile, ...]`;
  - `get_observed_rules() -> List[FingerprintRule]`;
  - `catalog_of(environment: Tuple[str, str]) -> str`, trả `"observed"` hoặc `"paper"`.

- [ ] **Bước 1: test RED**
  - `test_observed_rules_are_not_in_paper_catalog`:
    - không rule tự đo nào nằm trong `get_all_rules()`;
    - `len(get_all_rules())` bằng 12 như hiện tại;
    - không có `(target_os, application)` nào trùng giữa hai catalog.
  - `test_bandizip_rewrite_profile_values`:
    - `target_os == "Windows"`;
    - `host_os_code == 0`;
    - `data_descriptor_required is False`;
    - `local_extra_ids == ()` và `central_extra_ids == ()`;
    - `local_extra_ids_unicode == (0x7075,)` và `central_extra_ids_unicode == (0x7075,)`;
    - `nanosecond_pattern is None` và `root_folder_header_exists is None`.
  - `test_profile_source_names_run_and_hashes`: `source` có các khóa `run`, `sw1`, `sw2`,
    `operation`, `date`, `after_sha256`, `evidence`, với `run == "run-sw2-_kiollnq"`.
    Giá trị `after_sha256` lấy từ manifest
    `docs/evaluation/evidence/sw2-screening-2026-11-26.json`, ô S6.
  - `test_catalog_of`: trả `"observed"` cho profile tự đo, `"paper"` cho
    `("Windows", "Bandizip")`.
- [ ] **Bước 2:** `python -m pytest tests/unit/test_observed_rules.py -q`. Kỳ vọng FAIL
  (ImportError).
- [ ] **Bước 3:** viết module. Docstring ghi rõ: không phải dữ liệu của Um et al. (2021),
  chỉ dùng khi được yêu cầu, kèm link báo cáo sàng lọc SW2.
- [ ] **Bước 4:** chạy lại. Kỳ vọng PASS.
- [ ] **Bước 5:** commit `feat(provenance): add opt-in observed profile catalog (#35)`.

### Task 2: Classifier và tracker nhận `rules`

**File:**
- Sửa `src/zip_fingerprint/classifier.py`:
  - `__init__` mới;
  - `estimate_program_1` dùng `self._rules`.
- Sửa `src/zip_fingerprint/provenance.py`:
  - `ProvenanceTracker.__init__`;
  - `_fingerprint_entry` dùng `self._rules`;
  - `ProvenanceReport.catalogs_used`;
  - gắn nhãn `catalog` trong `to_dict`.
- Test `tests/integration/test_observed_profiles_tracking.py`

**Interface:**
- Dùng `get_observed_rules` và `catalog_of` từ Task 1.
- Cung cấp:
  - `AutomatedClassifier(rules: Optional[Sequence[FingerprintRule]] = None)`;
  - `ProvenanceTracker(archive, rules: Optional[Sequence[FingerprintRule]] = None)`;
  - `ProvenanceReport.catalogs_used: Optional[List[str]] = None`;
  - khi `catalogs_used` khác None, `to_dict()` có:
    - `"catalogs_used"`;
    - khóa `"catalog"` trong mỗi phần tử `groups[*].candidates` và
      `suspected_applications[*]`.

Dựng ZIP bằng `Entry`, `parse` và `unicode_path` của
`tests.integration.test_provenance_tracking`. Một entry "Bandizip rewrite" là
`Entry(name)` nếu tên ASCII, hoặc `Entry(name, local=[unicode_path(name)],
central=[unicode_path(name)])` nếu không.

- [ ] **Bước 1: test RED**
  - `test_default_output_is_unchanged`: trên các bộ entry sau, `to_dict()` mặc định
    không có khóa `catalogs_used`, và bằng output của
    `ProvenanceTracker(a, rules=get_all_rules())`:
    - homogeneous của mọi profile bài báo;
    - Case 1 7-Zip + WinRAR;
    - Case 2 discrepancy (dùng lại tham số của test sẵn có);
    - bộ S6 tổng hợp.
  - `test_s6_shape_is_case1_with_paper_catalog`: S6 tổng hợp (`keep.txt` ASCII, hai tên
    Unicode) cho `case1_detected is True`, và có suspect
    `("Windows", "Compressed folder")` với role `ORIGINAL_CREATOR_SUSPECT`. Test này khóa
    lỗi đã ghi.
  - `test_s6_shape_is_single_group_with_observed_profiles`:
    - với `rules=get_all_rules() + get_observed_rules()`: `case1_detected is False`,
      `len(groups) == 1`;
    - candidates của nhóm là `[("Windows", "Bandizip 7.47 (rewrite, observed)")]`;
    - `to_dict()["catalogs_used"] == ["paper", "observed"]`;
    - candidate có `catalog == "observed"`.
  - `test_observed_profiles_keep_real_case1`: Bandizip bài báo (`win_bandizip_unicode`
    cho tên Unicode, `Entry(name, central=[ntfs()])` cho tên ASCII), cộng một entry
    Compressed folder được thêm vào: vẫn `case1_detected is True` khi bật catalog tự đo.
  - `test_classifier_default_rules_unchanged`: `AutomatedClassifier()._rules` bằng
    `get_all_rules()`.
- [ ] **Bước 2:** chạy file test. Kỳ vọng FAIL (TypeError khi truyền `rules`).
- [ ] **Bước 3:** triển khai.
  - `rules=None` nghĩa là `get_all_rules()`, giữ thứ tự.
  - Tracker truyền `rules` cho classifier.
  - `catalogs_used` chỉ được đặt khi có rule tự đo trong `rules`, theo thứ tự
    `["paper", "observed"]`.
- [ ] **Bước 4:** chạy file test, `tests/integration/test_provenance_tracking.py` và
  `tests/integration/test_classifier_*.py`. Kỳ vọng PASS hết, không test cũ nào đổi.
- [ ] **Bước 5:** commit `feat(provenance): let classifier and tracker take a rule set (#35)`.

### Task 3: So sánh trước/sau

**File:**
- Tạo `src/zip_fingerprint/baseline.py`
- Sửa `tests/integration/test_provenance_tracking.py`: `Entry` có thêm
  `made_by: int = 20`, `extract: int = 20` và `method: int = 0`. Giá trị mặc định giữ
  bytes như cũ.
- Test `tests/unit/test_baseline.py`

**Interface:**
- Cung cấp:
  - `compare_archives(before: ZipArchiveRecord, after: ZipArchiveRecord) -> BaselineComparison`;
  - `BaselineComparison` (dataclass) có các trường:
    - `survivors: List[str]`, `removed: List[str]`, `added: List[str]`, đã sort;
    - `content_changed: List[str]`;
    - `entries: List[Dict[str, Any]]`, mỗi phần tử là
      `{"path", "changes", "qualifying_changes"}`;
    - `rewrite_scope: str`, một trong `all`, `partial`, `none`, `not_applicable`;
    - `case2_detected: bool`;
    - `basis: str = "baseline_comparison"`;
    - `to_dict() -> Dict[str, Any]`.
- `changes` có khóa `"LFH.<field>"` / `"CDH.<field>"` và giá trị
  `{"before": ..., "after": ...}`.
  - Các field được liệt kê: các trường đủ điều kiện trong Ràng buộc chung, cộng `offset`,
    `crc32`, `compressed_size`, `uncompressed_size`, `last_mod_time`, `last_mod_date`,
    `file_comment`.
  - `extra_layout` là list các list `[header_id, data_size]`, để serialize ra JSON.

- [ ] **Bước 1: test RED.** Dùng `Entry` và `parse`.
  - `test_cascade_rewrite_of_every_survivor_is_all`: before có 4 entry kiểu 7-Zip
    (`made_by=63`, `extract=10`, CDH `ntfs()`); after bỏ `target.txt` và ghi lại ba
    entry theo kiểu Bandizip rewrite. Kỳ vọng:
    - `rewrite_scope == "all"`, `case2_detected is True`;
    - `removed == ["target.txt"]`;
    - `"CDH.version_made_by"` có trong `qualifying_changes` của mỗi entry.
  - `test_offset_only_changes_are_none`: after là before bỏ một entry ở giữa, nên
    offset đổi. Kỳ vọng `"none"`, có `"LFH.offset"` trong `changes`, và
    `qualifying_changes == []`.
  - `test_some_survivors_rewritten_is_partial`: kỳ vọng `"partial"`,
    `case2_detected is False`.
  - `test_added_entry_is_listed_not_scored`: after có thêm `added.txt`. Kỳ vọng
    `added == ["added.txt"]` và `added.txt` không có trong `entries`.
  - `test_rename_is_removed_plus_added`.
  - `test_survivor_content_change_blocks_case2`: một survivor đổi `data`, mọi survivor
    đổi version. Kỳ vọng `content_changed == [name]`, `case2_detected is False`, và
    scope được tính trên các survivor còn lại (`"all"`).
  - `test_identical_archives_are_none` (Trọng tâm 4).
  - `test_no_survivors_is_not_applicable` (Trọng tâm 5).
  - `test_duplicate_names_are_refused` (Trọng tâm 1): `pytest.raises(ValueError,
    match="Duplicate entry names")`.
  - `test_missing_local_header_is_a_change_not_a_crash` (Trọng tâm 2): sửa
    `local_file_headers` của bản `after` đã parse thành `[]`. Kỳ vọng mọi survivor có
    `"LFH.extract_version"` trong `qualifying_changes`, giá trị after là `None`.
  - `test_to_dict_is_json_serializable`.
- [ ] **Bước 2:** chạy file test. Kỳ vọng FAIL (ImportError).
- [ ] **Bước 3:** viết `baseline.py`.
  - Ghép LFH với CDH theo `cdh.local_header_offset`, giống `_pair_headers`.
  - Nội dung giữ nguyên khi CRC và hai size ở CDH đều bằng nhau.
  - `case2_detected = scope == "all" and not content_changed`.
  - Docstring ghi rõ: không giải nén; tên dạng byte được xấp xỉ bằng cờ UTF-8 và
    `file_name_length`; không suy ra Case 2 khi chỉ có một archive.
- [ ] **Bước 4:** chạy lại file test và `tests/integration/test_provenance_tracking.py`.
  Kỳ vọng PASS.
- [ ] **Bước 5:** commit `feat(provenance): compare survivors against a baseline archive (#35)`.

### Task 4: CLI

**File:**
- Sửa `src/zip_fingerprint/cli.py`: `handle_provenance` và parser `provenance`.
- Test: thêm vào `tests/unit/test_cli.py`.

**Interface:**
- Dùng `compare_archives` (Task 3), `ProvenanceTracker(rules=...)` (Task 2) và
  `get_observed_rules` (Task 1).
- Cờ mới:
  - `--baseline PATH`;
  - `--observed-profiles` (`store_true`).
- JSON có thêm khóa `"baseline_comparison"` (giá trị là `to_dict()`) khi có
  `--baseline`. Bản text in thêm hai dòng:
  - `Baseline Rewrite Scope:     <scope>`;
  - `Case 2 (Baseline):          <bool>`.

- [ ] **Bước 1: test RED**
  - `test_cli_provenance_default_output_has_no_new_keys`: output không có
    `baseline_comparison` và `catalogs_used`.
  - `test_cli_provenance_baseline_reports_scope`: ghi before/after kiểu Task 3 vào
    `tmp_path`. Kỳ vọng `data["baseline_comparison"]["rewrite_scope"] == "all"` và
    `data["cases"]["case2_cascade_rewrite"] is False` (kết luận trên một archive vẫn
    giữ nguyên).
  - `test_cli_provenance_observed_profiles_flag`: archive kiểu S6. Kỳ vọng
    `catalogs_used == ["paper", "observed"]` và
    `cases["case1_mixed_fingerprints"] is False`.
  - `test_cli_provenance_text_shows_baseline`: có hai dòng text nói trên.
  - `test_cli_provenance_missing_baseline_is_error` (Trọng tâm 3): trả 1, stderr chứa
    `"Baseline ZIP file does not exist"`. Với file không phải ZIP, cũng trả 1.
  - `test_cli_provenance_duplicate_names_in_baseline_is_error` (Trọng tâm 1): trả 1.
- [ ] **Bước 2:** chạy các test mới. Kỳ vọng FAIL (argparse báo cờ lạ, exit 2).
- [ ] **Bước 3:** triển khai. Kiểm tra `--baseline` giống `zip_path`; `ValueError` từ
  `compare_archives` được bắt và trả 1.
- [ ] **Bước 4:** `python -m pytest tests/unit/test_cli.py -q`. Kỳ vọng PASS.
- [ ] **Bước 5:** commit `feat(cli): add --baseline and --observed-profiles to provenance (#35)`.

### Task 5: Kiểm chứng trên mẫu native

**File:**
- Test `tests/integration/test_native_baseline_samples.py`, tự skip khi không có mẫu.

**Interface:**
- Dùng `compare_archives`, `ProvenanceTracker(rules=...)` và `get_observed_rules`.
- Thư mục mẫu lấy từ biến môi trường `ZIP_PROV_NATIVE_SAMPLES`; mặc định là
  `ROOT/data/modified_samples`. Mẫu thật nằm ở worktree chính, nên khi chạy trên host
  đặt biến này trỏ tới đó.

- [ ] **Bước 1: viết test**, đọc `metadata.json` của các run:
  - `test_s6_runs_are_baseline_all`: với `run-sw2-_kiollnq/S6` và
    `run-sw2-gtjtd6ue/S6`, scope là `all` và `case2_detected` là True.
  - `test_bandizip_sw1_cells_are_baseline_none`: S1–S5 cho scope `none`.
  - `test_baseline_scope_matches_preregistered_comparator`: với mọi ô đã chạy,
    `rewrite_scope` bằng `cell["comparison"]["rewrite_scope"]` trong metadata.
  - `test_explorer_delete_run_is_baseline_none`: run `run-case2-dlq9ulnc`. Đọc đường
    dẫn before/after từ metadata của run đó.
  - `test_observed_profiles_fix_s6_without_new_misses`:
    - S6 `after.zip` với catalog tự đo: `case1_detected` là False;
    - S3–S5 `after.zip`: vẫn True;
    - mọi `before.zip` của S1–S6: False, dù bật hay tắt catalog tự đo.
  - `test_native_case1_7zip_winrar_still_detected`: tìm cặp 7-Zip → WinRAR trong
    `run-0fjyoqhr` hoặc `run-qeaq7kx8` qua metadata. Kỳ vọng Case 1 vẫn được báo khi
    bật catalog tự đo.
- [ ] **Bước 2:** trên host, chạy với `ZIP_PROV_NATIVE_SAMPLES` trỏ tới mẫu thật. Kỳ vọng
  PASS và không có skip. Ghi số pass vào PR. Nếu có test FAIL, dừng và báo; không sửa
  kỳ vọng cho khớp.
- [ ] **Bước 3:** kiểm tra evaluator bất biến.
  - Chạy `python experiments/evaluate_classifier.py` với cùng tham số mặc định trên
    `origin/main` (worktree tạm) và trên nhánh này, rồi `diff` hai output.
  - Kỳ vọng không có khác biệt, ngoài timestamp hoặc đường dẫn nếu có; ghi rõ những
    phần đó.
- [ ] **Bước 4:** commit `test(provenance): check baseline and observed profiles on native samples (#35)`.

### Task 6: Tài liệu, kiểm chứng tổng và PR

**File:**
- Sửa `docs/research/modification-simulator.md` (hoặc tài liệu provenance đang mô tả
  tracker): thêm mục hai cờ mới.
- Sửa `docs/evaluation/reproduction_report.md` và `docs/project/implementation-plan.md`:
  thêm mục PH4-PROV-003.
- Sửa README nếu README có liệt kê lệnh `provenance`.

- [ ] **Bước 1:** viết tài liệu. Nội dung bắt buộc:
  - không phát hiện Case 2 khi chỉ có một archive không chứng minh archive chưa bị sửa;
  - profile tự đo không phải dữ liệu bài báo, và mặc định tắt;
  - kết quả `--baseline` dựa trên header, không giải nén.
- [ ] **Bước 2:** kiểm chứng tổng:
  - `python -m pytest -q` (ghi số pass và skip);
  - `mypy src`;
  - `black --check` và `flake8` trên file đổi;
  - `git diff --check origin/main`.
- [ ] **Bước 3:** commit tài liệu, push, rồi mở PR "Liên quan #19, đóng #35 khi được
  duyệt".
  - Body có lệnh kiểm chứng và kết quả, cùng kết quả Task 5 bước 2 và 3.
  - Không dùng từ khóa auto-close nếu reviewer cần xem trước. Ghi "Closes #35" chỉ khi
    mọi mục nghiệm thu của #35 đã đạt.
- [ ] **Bước 4:** theo dõi CI đến khi đạt cả 6 job.
