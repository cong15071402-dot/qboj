# QBOJ – Hệ thống chấm bài C++ trực tuyến

Web tĩnh (1 file `index.html`), chạy hoàn toàn trên trình duyệt.

## Đăng lên Render (miễn phí)
1. Tạo repo GitHub mới, upload 3 file: `index.html`, `render.yaml`, `README.md`.
2. Vào https://render.com → đăng nhập bằng GitHub.
3. **New +** → **Static Site** → chọn repo vừa tạo.
4. Điền:
   - Build Command: để trống (hoặc `echo ok`)
   - Publish Directory: `.`
5. **Create Static Site** → chờ 1–2 phút, nhận link `https://<tên>.onrender.com`.

Mỗi lần `git push`, Render tự deploy lại.

## Lưu ý
- Tài khoản, bài nộp, bài tự đăng lưu trong `localStorage` của từng trình duyệt: người khác không thấy dữ liệu của bạn.
- Bộ chấm chạy bằng JSCPP (thông dịch C++ một phần), không hỗ trợ đầy đủ STL/thuật toán nặng.
