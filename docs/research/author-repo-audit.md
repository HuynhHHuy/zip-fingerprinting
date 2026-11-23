# Kiểm toán kho tham khảo của tác giả — PH0-REF-002 / #17

**Trạng thái:** bản nháp audit, gồm bước 1 (thu thập) và bước 2 (kiểm kê). Chưa làm
manifest nhãn có căn cứ, chưa có test trên mẫu, chưa đối chiếu parser. **DoD của
#17 chưa đạt.**
**Ngày kiểm tra:** 23/11/2026 (UTC).

## 1. Hiện trạng nguồn gốc

Bài báo (Footnote 1) dẫn tới `https://github.com/um2inji/PKZIP`. Kết quả kiểm tra
ngày 23/11/2026:

| Nguồn | Kết quả |
| --- | --- |
| `GET api.github.com/repos/um2inji/PKZIP` | **404 Not Found** |
| Tài khoản GitHub `um2inji` | Vẫn tồn tại (tạo 14/10/2020), **0 repo công khai** |
| Wayback Machine (`archive.org/wayback/available`) | Không có snapshot |
| **Software Heritage** | **Có bản lưu đầy đủ**, xem mục 2 |

Repo gốc không còn truy cập được qua GitHub. Không xác định được repo bị xoá hay
chuyển sang private. Mọi tham chiếu `github.com/um2inji/PKZIP` trong tài liệu dự
án nên hiểu là URL lịch sử.

## 2. Bản lưu Software Heritage

| Thuộc tính | Giá trị |
| --- | --- |
| Origin | `https://github.com/um2inji/PKZIP` |
| Lần lưu | 1 lần, `2023-08-07T20:28:58Z`, trạng thái `full` |
| Snapshot | `swh:1:snp:ebaf8f340566cccb0184952eaddf4cc0085ea392` |
| Nhánh | `refs/heads/main` (HEAD) |
| Commit cuối | `swh:1:rev:51fe33c5c395fe6c0f8038f15cad41858a051903` (23/09/2021, "samples") |
| Thư mục gốc | `swh:1:dir:3092b1128a94b47c8ecdc1ec54dffdf7009b3077` |
| Giấy phép | **Không có file LICENSE**; không thấy dòng license/copyright trong mã |

Trình duyệt: <https://archive.softwareheritage.org/swh:1:snp:ebaf8f340566cccb0184952eaddf4cc0085ea392>

### 2.1 Lịch sử commit (28 commit, 22/03/2021 → 23/09/2021)

Tác giả commit dưới hai danh tính: `um2inji` (web GitHub) và `DESKTOP-TH5SKEK\m2in`
(máy cục bộ). Các mốc đáng chú ý:

| Ngày | Commit | Nội dung |
| --- | --- | --- |
| 22/03/2021 | `049770bad3`, `82b936efc9` | Initial commit, First commit |
| 06–12/04/2021 | `431b6286f4`…`1d041b8e15` | Có file `total.py` (không còn ở HEAD) |
| 15/04/2021 | `96f1f24050`…`dfc8b5757f` | Xoá thư mục `set2`, `set3`, `set4`, `set5`, `set7`, `set8`, `set9` |
| 15/04–18/04/2021 | `ecffc975eb`, `46f206e774` | Thêm và cập nhật mẫu |
| 21/04/2021 | `3fa05719fb` | `file_list.py`: `nanoseconds → .fffffff`, `no_nanoseconds → .0000000` |
| 14/06/2021 | `967c620450`…`d5d0b946fa` | Sửa code, thêm mẫu |
| 22/09/2021 | `77e3725efa` | "Samples to be changed" |
| 23/09/2021 | `51fe33c5c3` | "samples": trạng thái HEAD đã kiểm kê |

Bài báo xuất bản tháng 12/2021, nên HEAD (09/2021) là trạng thái gần bản công bố
nhất. Các bộ mẫu bị xoá ngày 15/04/2021 vẫn còn trong lịch sử, **chưa kiểm kê**.

## 3. Kiểm kê nội dung tại HEAD

Đã tải 21 file qua API `content/sha1_git:<id>/raw/`. Mỗi file được kiểm **git blob
id (sha1_git) và kích thước** khớp với bản lưu trước khi giữ lại; tất cả khớp.
Bytes **không** được commit vào repo này (xem mục 5).

### 3.1 Mã nguồn

| File | Vai trò quan sát được |
| --- | --- |
| `README.md` | Chỉ có `# PKZIP`, không có hướng dẫn |
| `custom_zipfile.py` | Bản sửa module `zipfile` của Python (dòng đầu: `#customize the zipfile.py(Lib)`); có thêm `min_lfh`, `encoding_method` |
| `zip_fingerprint.py` | Lớp `check_source` với 16 phương thức kiểm tra đặc trưng: creating system, tên tiếng Hàn (UTF8/CP949), extra field LFH/CDH, ZIP lồng, thư mục rỗng, header thư mục, thứ tự nén, nanosecond, UID, thư mục OS, data descriptor, độ dài extra field, rồi `presume_program()`. CLI: `-f <file>`, `-d <dir>`, `-v <volume>` |
| `file_list.py` | Lớp `rtn_program`: **bảng luật dạng liệt kê**, 114 tổ hợp đặc trưng cho 11 nhãn |

Số luật theo nhãn trong `file_list.py`:

| Nhãn | Số luật | Nhãn | Số luật |
| --- | --- | --- | --- |
| Windows_WinRAR | 24 | macOS_zip | 4 |
| Windows_Bandizip | 18 | macOS_Compress | 4 |
| Windows_WinZip | 18 | macOS_Bandizip | 4 |
| Windows_7zip | 18 | macOS_WinZip | 4 |
| Windows_Compressed_folder | 12 | Ubuntu_zip | 4 |
| | | Ubuntu_Compress | 4 |

Nhận xét cần kiểm chứng tiếp:
- Bảng luật **không có nhãn Ubuntu_7zip**, dù bài báo và mẫu `UBUNTU_7zip.zip` có.
- Mỗi luật là vector 9 phần tử (extra field ID, số, có/không tên tiếng Hàn, thứ tự
  extra field, nanosecond, mã hoá tên, header thư mục, double zipping, thứ tự nén).
  Đây là tài liệu tham chiếu trực tiếp để đối chiếu `src/zip_fingerprint/rules.py`
  và để giải thích kết quả WinRAR 0/3 trong #22.
- **Chưa chạy** mã của tác giả. Mã được coi là dữ liệu tham chiếu, không thực thi.

### 3.2 Mẫu ZIP (17 file)

Nhãn ở bảng dưới **chỉ suy ra từ tên file**, chưa phải ground truth. Phiên bản công
cụ, ngôn ngữ Windows (EN/KR) và máy (PC1–PC3) không được ghi trong repo.

| File | Bytes | Entry (thư mục) | Tên non-ASCII | `create_system` | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `set1/WIN_7zip.zip` | 12768 | 7 (3) | 0 | 0 (MS-DOS) | `0999917ba07d04360ecc024ad3f8f602ac7df5d6cc142ff72c3e0a1735621f67` |
| `set1/WIN_bandizip.zip` | 12805 | 7 (3) | 0 | 0 | `026706c1a98b8dc89ff967d001daa9a4f8df14d78aa409b2d8295959e455e377` |
| `set1/WIN_compress.zip` | 12479 | 6 (2) | 0 | 0 | `ab1f20287d4ee7f09fa369fd8c5b13028bfa4ec3446c5437a98fa3b5d803a916` |
| `set1/WIN_winrar.zip` | 12856 | 7 (3) | 0 | 0 | `16186edfedaeade3f4b1bc792240434211d5198332a34390c0fb46ac0791d1b5` |
| `set1/WIN_winzip.zip` | 12752 | 7 (3) | 0 | 0 | `1a31dc4a74266860f489d6b021b47d39f4b32622d24316dd47c88708b072d4f9` |
| `set2/WIN_7zip.zip` | 13910 | 8 (3) | 1 | 0 | `0787691073e04a164102c9c0427ad1df91b8fd3181cd55844afb50a514218374` |
| `set2/WIN_bandizip.zip` | 14004 | 8 (3) | 1 | 0 | `a0dce00a8cfa75dfdd81bb1f9f8141e636447da53ee74cb7f87602189e0a0795` |
| `set2/WIN_compress.zip` | 13606 | 7 (2) | 1 | 0 | `e256d6f946473c604486a0eaaff4621a48bec57b2afe4281fd495428fbbba1a4` |
| `set2/WIN_winrar.zip` | 14078 | 8 (3) | 1 | 0 | `20c3a237c7cd471fad90408bfe847f714ec46829e0758729c39ecbd81f11d680` |
| `set2/WIN_winzip.zip` | 13935 | 8 (3) | 1 | 0 | `6b9c1330b9056c0d90a9d6b196ad6758744d394463b8349f716ad1db9cbe1bd0` |
| `set3/UBUNTU_7zip.zip` | 13914 | 8 (3) | 1 | 3 (Unix) | `3a9003ed069d86159e058c028cf348de866b72a2601697303dc239bb4e6391cd` |
| `set3/UBUNTU_compress.zip` | 14264 | 8 (3) | 1 | 3 | `ea9f399b437528bfe2a3031e4dc829c769982a9fb5c146afc816a664cb2e2b61` |
| `set3/UBUNTU_zip.zip` | 14086 | 8 (3) | 1 | 3 | `96c92af9c515b9348810fbf48761d122fa74f8f75ce4c48b137ae2bc72135478` |
| `set4/MAC_bandizip.zip` | 13904 | 8 (3) | 1 | 3 | `ec4981520fd60a2e987fa42b61bf31c7f18360e5a6e94217ffc3ed506f8c8aa9` |
| `set4/MAC_compress.zip` | 17039 | 16 (3) | 2 | 3 | `1515d41d810201fbb2928b58208e85cdde9d1f93c33d8f32c9ef64c7c62f6a4f` |
| `set4/MAC_winzip.zip` | 13611 | 8 (3) | 1 | 3 | `cd5e4db3e6583104f197e8158c90bb03ee12236ae10c69cd2741f1b885c1e3f6` |
| `set4/MAC_zip.zip` | 14094 | 8 (3) | 1 | 3 | `ccfc51356e6d12d5052e42cac8f99f3e6635bc9c9cdbb82dab7fb529bd04f158` |

Đường dẫn đầy đủ trong bản lưu là `sample/<set>/<file>`. Kích thước và sha1_git
từng file nằm ở [phụ lục](#phụ-lục-định-danh-software-heritage).

Quan sát nhất quán với bài báo (chưa phải xác minh nhãn):
- Bộ mẫu khớp đúng danh sách công cụ ở Mục 3 bài báo: Windows 5 công cụ, Ubuntu 3
  (7-zip, zip, Compress), macOS 4 (Bandizip, WinZip, zip, Compress).
- `set1` có 7 entry, khớp cây Hình 5: `set1/`, `Study/`, `emptyFolder/` và 4 file.
  Các mẫu `WIN_compress` thiếu đúng 1 thư mục và bắt đầu bằng `set1/2021.JPG`, khớp
  Mục 3.2.1 (Compressed folder không sinh header thư mục gốc).
- `set2` có thêm file `한글.JPG`. Trong cả 5 mẫu `set2/WIN_*`, tên này lưu bằng
  **CP949**, không bật cờ UTF-8 (bit 11). Ở `UBUNTU_zip.zip`, cùng tên lưu UTF-8 và
  có bật cờ.
- Extra field đầu tiên trong Central Directory của entry tên tiếng Hàn: `0x000A` với
  7-Zip, Bandizip và WinRAR; `0x7075` với WinZip; không có extra với Compressed
  folder. Khớp thứ tự header ID ở Bảng 6 (WinZip: `0x7075 → 0x000A`).
- `create_system` là 0 cho mọi mẫu `WIN_*` và 3 cho mọi mẫu Ubuntu/macOS, khớp
  Algorithm 2.
- `MAC_compress.zip` có 16 entry: 8 entry thuộc `__MACOSX/`, khớp Mục 3.3.1. Các mẫu
  macOS khác không có `__MACOSX/`.
- Tên non-ASCII trong các mẫu macOS **chưa giải mã được** thành tiếng Hàn (thử
  CP949 và UTF-8 trên bytes gốc đều không ra `한글`). Cần đọc bytes thô bằng parser
  của dự án.
- Tên thư mục trong mẫu không trùng tên set: `set3/UBUNTU_*` chứa `set1/`,
  `set4/MAC_*` chứa `set2/`. Thư mục `set1/` trong mẫu Ubuntu lại có file tiếng Hàn,
  khác với `set1/` của mẫu Windows. Vậy tên set trong repo không phải là định danh
  cây thư mục nguồn; cần ghi rõ điều này trong manifest.

## 4. Cách tải lại và kiểm chứng

Không cần tài khoản. Tải từng file theo sha1_git trong phụ lục:

```bash
API=https://archive.softwareheritage.org/api/1
curl -s "$API/content/sha1_git:<sha1_git>/raw/" -o <file>
git hash-object <file>      # phải in ra đúng <sha1_git>
sha256sum <file>            # phải khớp cột SHA-256
```

Có thể tải cả thư mục qua Vault (`POST $API/vault/flat/swh:1:dir:3092b1128a94b47c8ecdc1ec54dffdf7009b3077/`).
API ẩn danh có giới hạn tần suất; tải 21 file hết khoảng 30 request.

## 5. Điều kiện sử dụng

Repo không có giấy phép, nên mặc định tác giả giữ mọi quyền. Software Heritage chỉ
lưu trữ, không cấp quyền phân phối lại. Do đó:
- Dùng mẫu để nghiên cứu, kiểm thử cục bộ và trích dẫn kèm SWHID: chấp nhận được.
- **Không commit bytes ZIP hoặc mã của tác giả vào repo này.** Test phải tải theo
  SWHID và kiểm SHA-256 lúc chạy, hoặc dùng thư mục cục bộ được bỏ qua bởi git.
- Muốn phân phối lại, cần xin phép tác giả (email tác giả liên hệ trong bài báo).

## 6. Việc còn lại để đạt DoD #17

- [ ] Manifest nhãn: căn cứ nhãn cho từng mẫu (đối chiếu Bảng 6/7 bằng parser của
      dự án), đánh dấu rõ trường chưa biết (phiên bản, EN/KR, PC).
- [ ] Chạy `ZipBinaryParser` và extractor trên 17 mẫu; ghi khác biệt với
      `custom_zipfile.py` / `zip_fingerprint.py` của tác giả.
- [ ] Test tích hợp tải mẫu theo SWHID (skip khi offline), không commit bytes.
- [ ] Đối chiếu bảng luật `file_list.py` với `src/zip_fingerprint/rules.py`.
- [ ] Kiểm kê các bộ mẫu bị xoá ngày 15/04/2021 trong lịch sử (tuỳ chọn).
- [ ] Cập nhật paper mapping và README: URL GitHub đã 404, nguồn thay thế là SWH.
- [ ] Bàn giao danh sách mẫu đủ điều kiện cho #22.

## Phụ lục: định danh Software Heritage

| Đường dẫn | Bytes | SHA-256 | sha1_git (`swh:1:cnt:`) |
| --- | --- | --- | --- |
| `README.md` | 7 | `352b000fcd947c2b025d1e79aba304222fc89e4061e14965dd7f6e10c6fa0969` | `123274f1672e6c46f19cb35163b96dc7db244c19` |
| `custom_zipfile.py` | 91642 | `f3f3702a6fbe6dd90b9a6933a1247f2bea79c9ae25b4d596b07d653a6dcb4e2d` | `2d9bebb53ac2c85bedc057990d33db308bf225a2` |
| `file_list.py` | 18085 | `b138b9b44799775a27a1fe56bb1d0bc18a7eca22d61a5a834a19ea3b0765cbc0` | `65dab4586bc40a8fa684180e14a1dffddd815e4d` |
| `zip_fingerprint.py` | 15034 | `d952a42978570c79b66b2f5e7a8f6dc1bbd099302d8abfa50e786b80c4d20fd3` | `26537907f886070e925acd4da5d62be036c7dc11` |
| `sample/set1/WIN_7zip.zip` | 12768 | `0999917ba07d04360ecc024ad3f8f602ac7df5d6cc142ff72c3e0a1735621f67` | `58ec67108fda5f15eb4e81f8186917fe47722c1a` |
| `sample/set1/WIN_bandizip.zip` | 12805 | `026706c1a98b8dc89ff967d001daa9a4f8df14d78aa409b2d8295959e455e377` | `b385cd9939801449e34663986fd059fd6728ab5d` |
| `sample/set1/WIN_compress.zip` | 12479 | `ab1f20287d4ee7f09fa369fd8c5b13028bfa4ec3446c5437a98fa3b5d803a916` | `b4b643fc744b7ebef55e6a7ab1ab4bb59cc90c76` |
| `sample/set1/WIN_winrar.zip` | 12856 | `16186edfedaeade3f4b1bc792240434211d5198332a34390c0fb46ac0791d1b5` | `9af52b007f5d83eb176e925b2936efc889fdd806` |
| `sample/set1/WIN_winzip.zip` | 12752 | `1a31dc4a74266860f489d6b021b47d39f4b32622d24316dd47c88708b072d4f9` | `c080c5c9b5e48be2ff0e80d02f2a4e7e348fb649` |
| `sample/set2/WIN_7zip.zip` | 13910 | `0787691073e04a164102c9c0427ad1df91b8fd3181cd55844afb50a514218374` | `e53cdebb07c9da4d74af56f519f47c411c0cd2d7` |
| `sample/set2/WIN_bandizip.zip` | 14004 | `a0dce00a8cfa75dfdd81bb1f9f8141e636447da53ee74cb7f87602189e0a0795` | `a55fd100c8fa0e5cec85de4737ebc35507335519` |
| `sample/set2/WIN_compress.zip` | 13606 | `e256d6f946473c604486a0eaaff4621a48bec57b2afe4281fd495428fbbba1a4` | `9e79d8775427bb5ae8cd4f334c795d39faff2216` |
| `sample/set2/WIN_winrar.zip` | 14078 | `20c3a237c7cd471fad90408bfe847f714ec46829e0758729c39ecbd81f11d680` | `6704dfc06aac4588ddad5f53e66282871d5ec520` |
| `sample/set2/WIN_winzip.zip` | 13935 | `6b9c1330b9056c0d90a9d6b196ad6758744d394463b8349f716ad1db9cbe1bd0` | `454ec72048198577cc24750f7b6e63ef8f43a41f` |
| `sample/set3/UBUNTU_7zip.zip` | 13914 | `3a9003ed069d86159e058c028cf348de866b72a2601697303dc239bb4e6391cd` | `9c16461bf2b3eea2a89ce3a4c38194baabb161dc` |
| `sample/set3/UBUNTU_compress.zip` | 14264 | `ea9f399b437528bfe2a3031e4dc829c769982a9fb5c146afc816a664cb2e2b61` | `f263a3cb7cb7ca4bd50255b6533c395d0bbf9f1d` |
| `sample/set3/UBUNTU_zip.zip` | 14086 | `96c92af9c515b9348810fbf48761d122fa74f8f75ce4c48b137ae2bc72135478` | `4cf765aa2fa80d988c909f5863763bab2bc4b37c` |
| `sample/set4/MAC_bandizip.zip` | 13904 | `ec4981520fd60a2e987fa42b61bf31c7f18360e5a6e94217ffc3ed506f8c8aa9` | `35b7dfd656528c69d0e479b8d675035f05d37ca5` |
| `sample/set4/MAC_compress.zip` | 17039 | `1515d41d810201fbb2928b58208e85cdde9d1f93c33d8f32c9ef64c7c62f6a4f` | `1587bd728850693399909d354f4c2f72b4ef9f04` |
| `sample/set4/MAC_winzip.zip` | 13611 | `cd5e4db3e6583104f197e8158c90bb03ee12236ae10c69cd2741f1b885c1e3f6` | `011b620203fd539be0f7bda7f2110240655dd274` |
| `sample/set4/MAC_zip.zip` | 14094 | `ccfc51356e6d12d5052e42cac8f99f3e6635bc9c9cdbb82dab7fb529bd04f158` | `b2d2c3bea8d73921ed8d47815b08f2777ec7009d` |
