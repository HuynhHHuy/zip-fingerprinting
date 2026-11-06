# Thí nghiệm can thiệp ZIP — PH4-PROV-002

## Chạy lại

```powershell
python scripts/simulate_modifications.py --require-cases
python scripts/simulate_modifications.py --scenario A --scenario control-add
python scripts/simulate_modifications.py --7zip "C:/Program Files/7-Zip/7z.exe"
python -m pytest tests/integration/test_modification_simulator.py
```

Chạy được trực tiếp từ checkout, không cần cài package. Dùng Python ≥3.10;
công cụ native cần Windows. Không tự cài phần mềm. WinZip cần Command Line
Support Add-On (`wzzip.exe`); chỉ cài ứng dụng giao diện chưa đủ.

## Kịch bản và nhãn

| ID | SW1 → SW2 | Thao tác | Cấu hình |
|---|---|---|---|
| A | 7-Zip → WinRAR | Add `added.txt` | ZIP mặc định; WinRAR bỏ cấu hình người dùng (`-cfg-`) |
| B | Bandizip → Windows shell | Loại `target.txt` | Shell `MoveHere` ra thư mục riêng |
| C | WinZip CLI → 7-Zip | Modify `target.txt` | Nội dung và timestamp mới |
| control-add | 7-Zip → WinRAR | Add | SW1 dùng `-mtc=off -mta=off -mtm=off` |
| control-modify | 7-Zip → WinRAR | Modify | SW1 dùng `-mtc=off -mta=off -mtm=off` |
| control-delete | WinRAR → Windows shell | Loại `target.txt` | Biến thể B khi không có Bandizip |

Nguồn nhỏ gồm `keep.txt`, `target.txt`, `tieng-viet-ệ.txt`, mtime/atime cố định
2021-01-11 11:30:59.1234567 UTC. Đây là corpus tối thiểu cho thí nghiệm can thiệp,
không thay thế corpus Hình 5 của PH6. Birth/change time không được cố định.

Mọi lần chạy có thư mục riêng, giữ `before.zip` nguyên vẹn và chỉ thao tác trên
`after.zip`. `zipfile` đọc/kiểm tra CRC và payload của các mẫu nhỏ do script tự
sinh; không dùng để tạo vân tay hoặc sửa header. So sánh payload xác nhận đúng
entry được thêm/sửa/xóa và các entry còn lại giữ nguyên. Parser và tracker hiện
có phân tích cả hai archive. Không vá header để buộc kết quả khớp kỳ vọng.

Shell helper dùng Windows `Shell.Application` và `MoveHere` với các cờ silent,
no-confirmation, no-error-UI. Entry được chuyển ra thư mục `removed/` trong run.
**Đây không phải thao tác Delete trong giao diện Explorer** và không được dùng
để khẳng định tái hiện chính xác kịch bản B của bài báo. Helper chạy trong tiến
trình PowerShell với ExecutionPolicy Bypass chỉ cho tiến trình đó, không đổi
chính sách hệ thống. Hết 30 giây mà chưa loại được entry thì ghi lỗi; lệnh native
có timeout 60 giây. Không giải nén archive của người dùng.

## Metadata và kết quả đo

`metadata.json` lưu hệ điều hành, thời gian UTC, đường dẫn/phiên bản công cụ,
argv/cwd/stdout/stderr/mã thoát của mỗi lệnh, SHA-256/size và phân tích từng ZIP.
`expected_case` là giả thuyết theo loại thí nghiệm; `after.analysis.cases` là kết
quả tracker. `untouched_entries_with_header_changes` so sánh host OS và raw extra
fields LFH/CDH trước/sau, không suy diễn từ tên phần mềm.

`coverage.dod_met` chỉ bật khi có ít nhất hai cặp mẫu hợp lệ và tracker quan sát
được cả hai Case. Cờ `--require-cases` trả mã 2 nếu chưa đạt; lỗi công cụ trả mã 1,
không có mẫu nào cũng trả mã 2. Mã 0 mặc định chỉ xác nhận đã tạo mẫu không lỗi,
không chứng minh tái hiện toàn bộ nghiên cứu. Mẫu lỗi và skip vẫn có trong manifest.

Kết quả ngày **06/11/2026**, Windows, 7-Zip **26.04**, WinRAR **6.23.0**:

| Kịch bản | Tạo mẫu | Tracker Case 1 | Tracker Case 2 |
|---|---|---|---|
| A | Có | Không | Không |
| B | Skip: thiếu Bandizip | — | — |
| C | Skip: thiếu WinZip CLI | — | — |
| control-add | Có | Có | Không |
| control-modify | Có | Có | Không |
| control-delete | Có | Không | Không |

Mẫu mặc định A có các profile chồng lấn nên tracker không nhận ra nhiều nguồn.
Các control tắt timestamp cho SW1 tạo cấu trúc khác biệt rõ với WinRAR; tracker
phát hiện Case 1 nhưng có thể gọi nhóm SW1 là `Compressed folder` vì cấu hình
7-Zip này nằm ngoài profile mặc định trong catalog. Nhãn ground truth phải dựa
vào lệnh đã ghi, không thay bằng tên ứng viên tracker.

Thao tác shell removal trên phiên bản Windows hiện tại giữ extra fields ở entry
còn lại; không quan sát thấy Case 2. Không có đủ bằng chứng để nghiệm thu toàn
bộ PH4-PROV-002. Cần chạy lại với Bandizip/WinZip CLI và môi trường/phiên bản phù
hợp, đồng thời đối chứng thao tác Delete thực tế trong Explorer. Code hỗ trợ B/C
chưa được kiểm chứng với các executable thiếu trên máy này.

## Tài liệu công cụ

- [Bandizip command line](https://www.bandisoft.com/bandizip/help/parameter/)
- [WinZip Command Line Support Add-On](https://kb.winzip.com/en/130423)
- Cú pháp 7-Zip/WinRAR đối chiếu với help cài trên máy; mọi argv thực tế nằm trong
  manifest. Không đồng nhất cấu hình CLI với mặc định kéo-thả/menu ngữ cảnh.
