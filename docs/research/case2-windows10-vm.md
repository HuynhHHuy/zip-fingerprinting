# Case 2: bàn giao thí nghiệm Windows 10 v2004

**Trạng thái 18/11/2026: chờ media Windows hợp lệ; chưa tạo guest, chưa chạy
Bandizip 6.29.** Máy có VMware Workstation và các guest Linux; Ubuntu/Wine
không thay bằng chứng native Explorer. Không dùng guest Linux đang có làm nền
để kết luận hành vi Windows.

Hai quan sát host đều âm: Bandizip 7.47.0.1 CLI và GUI tạo ZIP, sau đó Explorer
Delete trên Windows 10.0.26200 đều chỉ đổi offset. Xem
[báo cáo GUI](../evaluation/native-case2-gui-2026-11-18.md).

## Điều kiện đầu vào trước khi thực hiện

- Người phụ trách cung cấp Windows 10 v2004 English x64 ISO hoặc guest có
  quyền sử dụng hợp lệ, đường dẫn và nguồn nhận. Ghi SHA-256/size; không lấy
  ISO không rõ nguồn hoặc dùng ISO Windows hiện hành rồi gọi là v2004.
- Xác minh phiên bản VMware và đủ dung lượng cho VM mới; không sửa guest cũ.
  Nếu guest có sẵn, dùng bản clone thí nghiệm và giữ nguyên bản gốc.
- Bộ cài Bandizip 6.29 chỉ từ
  [trang phiên bản cũ chính thức](https://www.bandisoft.com/bandizip/old/6/).
  Ghi URL cuối, SHA-256/size, file version và trạng thái chữ ký; không thay
  bằng phiên bản khác nếu không lấy được bản này.
- Bandisoft cảnh báo lỗ hổng giải nén ở dòng 6.x. Chỉ dùng trong guest cô lập,
  chỉ mở ZIP tự sinh, không cài lên host hoặc tải archive ngoài để thử.

Thiếu media, nguồn công cụ hoặc cấu hình guest không phù hợp thì ghi blocker,
không đánh dấu đã tái hiện môi trường bài báo. Không bỏ qua cảnh báo bảo mật
hoặc tự thay chính sách bảo vệ hệ thống.

## Cấu hình guest đã chọn

| Thuộc tính | Cấu hình |
| --- | --- |
| Hypervisor | VMware Workstation hiện có |
| Guest | Windows 10 v2004 English x64, xác minh Version 2004 / build 19041 và revision thực tế |
| CPU / RAM | 2 vCPU / 4 GiB |
| Disk | 64 GiB thin, filesystem NTFS |
| Network | Disconnected khi chạy thí nghiệm |
| Integration | Không shared folders, clipboard hoặc drag/drop hai chiều |
| Snapshot | Sau cài Windows/công cụ, trước tạo source/ZIP thử nghiệm |

Giữ locale/code page/timezone gốc của guest, ghi giá trị thực; không đổi host.
Nếu thiếu tài nguyên thì dừng để điều chỉnh kế hoạch, không âm thầm đổi môi
trường. Ghi winver/build, ACP, timezone, Explorer/zipfldr version, Python,
Bandizip và mọi cấu hình nén. Các bản vá/revision khác môi trường bài báo phải
được nêu rõ; English edition không được suy diễn là môi trường CP949.

Đưa checkout/source và bộ cài đã xác minh vào guest qua ISO dữ liệu chỉ đọc.
Khi cần chuyển evidence ra, dùng ổ dữ liệu riêng: chỉ chứa output thí nghiệm,
ngắt khỏi guest trước khi đọc trên host; đối chiếu checksum hai đầu. Không
đưa mật khẩu guest hoặc dữ liệu cá nhân vào metadata/bundle.

## Kịch bản sau khi có đủ đầu vào

1. Kiểm tra lại trạng thái #19, checkout có workflow GUI đã review. Chạy test
   phần mềm trong guest; test tổng hợp không chứng minh Case 2 native.
2. Chạy `python -m experiments.explorer_delete prepare --creation-mode gui
   --configuration unicode-path --bandizip PATH_TO_629_EXE`. Source riêng gồm
   đúng bốn file hiện có; giữ checksum và timestamp đã đặt.
3. Qua GUI chọn ZIP/Normal, UTF8 filename off, Unicode Path on, NTFS time on.
   Nếu bản 6.29 không có tùy chọn này, ghi không hỗ trợ và dừng cấu hình; không
   đổi phiên bản hay vá archive. Ghi ảnh/log tên công cụ, file nguồn, setting,
   đường dẫn before.zip và thông báo hoàn thành; đóng archive.
4. Seal với creation-log đúng schema, kiểm CRC/inventory/payload/identity và
   source anchors. Không nhận archive bị mất tên Unicode hoặc sai payload.
5. Explorer mở after.zip, chỉ chọn target.txt, Delete -> Yes, ghi trước/sau và
   đóng cửa sổ. Chạy finalize với delete-log và `--require-case2`.
6. Đọc bảng LFH/CDH/extra của tất cả survivor, payload SHA, rewrite scope và
   tracker riêng biệt. Xuất cả kết quả âm/partial/failed; không ép nhãn theo
   dự đoán. Một cấu hình, chỉ retry cùng cấu hình một lần nếu lỗi thao tác.

Trước khi dùng lệnh GUI với executable 6.29, cần smoke-test khả năng đọc
version và chuẩn bị source; workflow GUI không cần ép CLI nén của 6.29.

## Nghiệm thu và bàn giao

Giữ ZIP trước/sau, source manifest, logs/ảnh GUI có thời gian và run/path,
phiên bản/build/code page, raw header/extra/name, bảng delta, kết quả tracker,
CRC/payload checksums và checksum từng file. Có cặp native Case1 mới hoặc
bằng chứng Case1 đã bàn giao được đối chiếu rõ nguồn trong cùng báo cáo.

Chỉ đề nghị đóng #19 khi mọi survivor có thay đổi cấu trúc đủ điều kiện,
payload giữ nguyên, thao tác native được quan sát và artifacts kiểm chứng
được; offset/timestamp-value-only không đủ. Nếu âm, báo cáo kết quả âm,
giữ DoD false và dừng tìm cấu hình. Mục4.2/Fig10 của bài báo mô tả Case2 tổng
quát, không bảo đảm cặp Bandizip -> Explorer sẽ tái hiện trên mọi phiên bản.

Không publish ISO/VM disk hoặc proprietary installer. Bàn giao evidence ZIP
và SHA trên prerelease riêng; không ghi đè evidence host ngày18/11.
