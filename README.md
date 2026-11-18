# QBOJ – Hệ thống chấm bài C++ trực tuyến (có server)

- `server.js`: máy chủ Node.js (không cần thư viện, trừ `pg` khi dùng Postgres)
- `index.html`: giao diện
- `problems.json`: các bài có sẵn (kèm test ẩn, chỉ nằm trên server)

Server lo: tài khoản (mật khẩu băm scrypt), bài nộp, bài đăng thêm, bảng xếp hạng dùng chung,
và chấm bài bằng g++ thật qua Judge0 CE (dự phòng Wandbox).

## Chạy trên Render (Web Service, Free)
1. Đưa toàn bộ file trong thư mục này lên GitHub.
2. Render → New + → Web Service → chọn repo. Runtime: Node, Build: `npm install`, Start: `node server.js`, Instance: Free.
3. Để dữ liệu không bị mất: tạo DB miễn phí ở neon.tech, copy connection string,
   thêm vào Render → Environment: `DATABASE_URL` = chuỗi đó.
   (Không có DATABASE_URL thì dữ liệu lưu vào file và MẤT khi Render khởi động lại.)
