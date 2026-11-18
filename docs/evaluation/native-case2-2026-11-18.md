# Đối chứng native Case 2 — 18/11/2026

**Kết quả âm: PH4-PROV-002 / #19 chưa đạt DoD.** Có cặp Case 1 mới và
cặp Bandizip → Explorer Delete thực tế, nhưng không có rewrite cấu trúc toàn
bộ survivor. Không đóng issue bằng test tổng hợp hoặc cờ dự đoán tracker.

| Phép đo | Run | Kết quả |
| --- | --- | --- |
| Bandizip 7.47.0.1 portable → Explorer Delete | `run-case2-je0_bndz` | Xóa target.txt; 3 survivor, CRC/SHA-256 payload hợp lệ; rewrite scope `none`; tracker Case 2 false |
| 7-Zip 26.04 (timestamp off) → WinRAR 6.23.0 add | `run-h7agwli8/control-add` | Payload hợp lệ; tracker Case 1 true; nhãn công cụ theo command logs |

Windows build 10.0.26200, Python 3.11.9, UTC+07:00, ANSI CP1252. Nguồn riêng
gồm keep.txt, target.txt, tên Việt và Hàn; atime/mtime đặt
2021-01-11T11:30:59.1234567Z. Birth/change không cố định. Không sửa corpus hoặc
catalogue dùng chung. ZIP được tạo bởi CLI `Bandizip.x64.exe c -y before.zip
keep.txt target.txt tieng-viet-ệ.txt 가나다.txt`; không đồng nhất CLI với GUI.

Explorer mở đúng after.zip, chọn target.txt, Delete rồi Yes trong hộp Delete
File, quan sát còn 3 file, đóng cửa sổ trước finalize. Không dùng MoveHere.
Helper có accessibility focus/index cũ, nên lựa chọn và hộp thoại được đối
chiếu trực tiếp qua screenshot rồi kiểm tra archive trên đĩa. JSON quan sát
lưu cây accessibility và ghi chú đương thời, không lưu screenshot; đây là
bằng chứng do operator ghi, không phải telemetry được xác thực độc lập.

| Survivor | Thay đổi LFH | Thay đổi CDH | Cấu trúc đủ điều kiện |
| --- | --- | --- | --- |
| keep.txt | Không | Offset vị trí CDH | Không |
| tieng-viet-ệ.txt | Offset | Offset CDH và local-header-offset | Không |
| 가나다.txt | Offset | Offset CDH và local-header-offset | Không |

Extra IDs/order/length, host/version, method, UTF8/descriptor flags và raw
filename giữ nguyên. Raw-header bytes CDH đổi do offset, không chứng minh
rewrite nguồn gốc. Snapshot đầy đủ và tracker trước/sau nằm trong metadata.

Portable Compression Settings mặc định: UTF-8 filename unchecked; Unicode
filename in extra header checked; NTFS time checked. Hai entry Unicode thực
tế có UTF8 flag và 0x7075; không suy ra raw legacy CP949 từ tên Hàn. Không
thay setting, không chạy cấu hình thứ hai vì Unicode Path đã hiện diện.
Không cài tool, đổi association/code page/timezone, hoặc thử môi trường cũ.

Bandizip tải từ [trang chính thức](https://www.bandisoft.com/bandizip/) qua
liên kết portable; SHA-256 ZIP phân phối và executable, chữ ký Authenticode
Valid (Bandisoft International Inc.) được ghi trong manifest. Không phân
phối binary phần mềm. Snapshot INI của lần đo ban đầu giữ SHA gốc nhưng text
UTF-16 bị giải mã sai thành UTF-8; giữ nguyên bằng chứng này, kèm snapshot raw
sau quan sát có nhãn thời điểm riêng. Workflow đã sửa để những lần sau lưu
raw bytes lossless (test RED → GREEN), không hồi tố sửa metadata lần đo.

Giới hạn: một máy, một phiên bản, CLI tạo ZIP, file phẳng nhỏ. Comparator
nhận thay đổi layout ngoài của extra field (ID/order/length), chưa phân loại
thay đổi layout bên trong cùng ID/length. Không có byte extra nào đổi trong
lần đo này. Kết quả âm không bác bỏ Case 2 trên môi trường lịch sử và không
tái hiện đầy đủ thực nghiệm bài báo. Muốn tiếp tục cần một thí nghiệm môi
trường/phiên bản khác được duyệt riêng; không sửa header/luật để tạo kết quả.

Xem [manifest và bàn giao](evidence/native-case2-2026-11-18.json) để tải cặp
ZIP, source, UI logs, raw headers, commands, bảng delta và checksum từng file.
Checkout chỉ có tài liệu/manifest; các run artifacts bị Git bỏ qua.
