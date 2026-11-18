# Case 2: ZIP tạo bằng GUI — 18/11/2026

**Kết quả âm; #19 chưa đạt DoD Case2.** Lần đo bổ sung dùng đúng một cấu hình
Bandizip7.47.0.1 portable GUI -> Explorer Delete, không dùng CLI nén hoặc
MoveHere. Không retry, không thử thêm cấu hình sau kết quả âm.

| Phép đo | Run | Kết quả |
| --- | --- | --- |
| GUI tạo ZIP/Normal -> Explorer Delete | run-case2-hz8kgcll | finalized_negative; rewrite_scope none, native_case2 false, tracker_agrees true |
| 7-Zip26.04 timestamp-off -> WinRAR6.23.0 add | run-16gz65r7/control-add | generated, CRC/payload hợp lệ, tracker Case1 true |

Host Windows10.0.26200, Python3.11.9, ACP1252, UTC+07:00. Portable giải nén
từ distribution ZIP đã kiểm SHA; executable7.47.0.1 có Authenticode Valid,
signer Bandisoft International Inc. Dùng profile mới, không đổi associations,
code page/timezone/security hoặc corpus/catalogue dùng chung.

GUI được quan sát: ZIP, 2-Normal Compression, UTF8 filename unchecked,
Unicode Path checked, NTFS timestamps checked. Bốn file được chọn trực tiếp,
không prefix thư mục, không manifest: keep.txt, target.txt, tieng-viet-ệ.txt,
가나다.txt; 71bytes tổng payload. before.zip745bytes được tạo xong qua GUI,
Bandizip đóng trước seal; inventory/CRC/payload/identity khớp source anchors.

Explorer mở after.zip, chỉ target.txt17bytes được chọn; Delete -> Yes trong
Delete File; UI còn ba survivor, đóng cửa sổ trước finalize. Có ảnh setting,
New Archive/Normal, nén thành công, selection, confirmation và sau Delete;
có cây accessibility/log cùng run/path/time/checksum. Helper có focus/index
stale nên thao tác được đối chiếu bằng ảnh và archive thực tế. Các record do
operator ghi nhận, không phải telemetry được xác thực độc lập.

| Survivor | Thay đổi LFH | Thay đổi CDH | Qualifying rewrite |
| --- | --- | --- | --- |
| keep.txt | Không | Vị trí CDH | Không |
| tieng-viet-ệ.txt | Vị trí LFH | Vị trí CDH, local_header_offset | Không |
| 가나다.txt | Vị trí LFH | Vị trí CDH, local_header_offset | Không |

Cả ba payload nguyên vẹn. Extra bytes, host/version, method, encoding và
UTF8/descriptor flags không đổi; raw CDH bytes đổi do offset. Baseline dùng
DEFLATE(method8); ASCII entries CDH có0x000A, Unicode có0x000A rồi0x7075 và
UTF8 flag. Không suy ra CP949 từ tên Hàn hoặc checkbox GUI. Việc tạo bằng GUI
không làm cặp công cụ này xuất hiện Case2 trên host hiện tại.

So sánh với [lần tạo CLI trước](native-case2-2026-11-18.md): cả hai đều âm,
nhưng là hai quan sát riêng có provenance và hash riêng, không đồng nhất
bytes/cấu hình CLI với GUI. Metadata lần trước giữ nguyên; lần này lưu raw
INI trước và sau tạo archive lossless.

Giới hạn: một host, một phiên bản Bandizip, một cấu hình, bốn file phẳng nhỏ.
Chưa kiểm Windows10v2004/Bandizip6.29; comparator chưa phân loại layout bên
trong extra cùng ID/length, nhưng không có extra bytes đổi trong mẫu này.
Mục4.2/Fig10 bài báo mô tả Case2 tổng quát, không cam kết cặp công cụ này.
Không coi kết quả âm là bác bỏ bài báo hoặc nghiệm thu accuracy.

Theo điểm dừng, bước tiếp là [bàn giao VM Windows10v2004](../research/case2-windows10-vm.md).
**Chưa có ISO/VM Windows hợp lệ: chỉ chuẩn bị hướng dẫn, chưa tạo/cài guest
hay chạy phần mềm cũ.** Issue#19 giữ mở.

Xem [manifest bàn giao và kết quả kiểm tra phần mềm](evidence/native-case2-gui-2026-11-18.json).
Run artifacts và ảnh bị Git bỏ qua, có trong prerelease riêng; test tổng hợp
chỉ kiểm logic/phát hiện lỗi, không tính thành bằng chứng Case2 native.
