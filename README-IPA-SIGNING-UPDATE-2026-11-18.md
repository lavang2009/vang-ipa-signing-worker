# VANG STORE – cập nhật công cụ ký IPA (18/11/2026)

Bản cập nhật gồm hai dự án độc lập: website Next.js và signing worker.

## Thay đổi

### Website `vang-store`
- Giao diện tiếp nhận 3 tệp: ứng dụng `.ipa`, chứng chỉ `.p12`/`.pfx`, và provisioning profile `.mobileprovision`.
- Không yêu cầu ZIP chứa chứng chỉ nữa.
- Mật khẩu P12/PFX là tùy chọn; để trống khi tệp không có mật khẩu. Mật khẩu chỉ gửi trong HTTPS request ký và không ghi vào audit log.
- Upload từng phần 3 MiB vào Vercel Blob Private Store.
- Giới hạn: IPA 512 MiB; P12/PFX 20 MiB; `.mobileprovision` 10 MiB.
- Khi bật bảo trì: người dùng thường bị chặn; Admin được xác minh từ Firebase token claim, `ADMIN_EMAILS` hoặc `users/{uid}.role == "admin"` vẫn được vào trang.
- Quy tắc bảo trì được kiểm tra lại ở API upload từng phần, không chỉ ẩn giao diện.

### Worker `vang-ipa-signing-worker`
- Cả `/v1/sign-blob` và endpoint multipart `/v1/sign` nhận P12/PFX và `.mobileprovision` riêng.
- Không còn giải nén ZIP chứng chỉ. Việc đọc cấu trúc ZIP chỉ dùng với chính tệp `.ipa`.
- Worker tự xác minh Firebase token và quyền Admin; Admin tiếp tục ký được trong lúc bảo trì, user thường bị chặn ở API ký.
- Dọn các Blob tạm IPA/P12/profile sau khi xử lý.
- Health build hiện tại trong bản sửa parser P12/PFX: `ipa-signing-pkcs12-reader-fix-2026-11-19`.

## Cách triển khai

Hai ZIP là hai repository khác nhau, không chép worker vào website hoặc ngược lại.

1. Giải nén `VANG-IPA-SIGNING-WORKER-SEPARATE-CREDENTIALS-ADMIN-MAINTENANCE-2026-11-18.zip` vào bản làm việc của repository worker. Commit/push repository worker và đợi Vercel Worker báo Ready trước.
2. Giải nén `VANG-STORE-IPA-SEPARATE-CREDENTIALS-ADMIN-MAINTENANCE-2026-11-18.zip` vào gốc repository website `lavang2009/vang-store`, chép đè khi được hỏi. Commit/push website và đợi Vercel báo Ready.
3. Hai dự án phải dùng cùng Firebase project và cùng một Vercel Blob Private Store. `BLOB_READ_WRITE_TOKEN` ở hai project phải thuộc cùng store.
4. Nếu dùng `ADMIN_EMAILS` để cấp quyền Admin, đặt cùng danh sách email ở cả Website và Worker. Nếu dùng custom claim `admin: true` hoặc Firestore role `admin`, service account của worker phải đọc được Firestore project tương ứng.
5. Biến worker tùy chọn:
   - `SIGNING_MAX_CREDENTIAL_FILE_BYTES=20971520` (P12/PFX, 20 MiB)
   - `SIGNING_MAX_PROFILE_FILE_BYTES=10485760` (profile, 10 MiB)

Không cần thêm package/dependency mới. Bản cập nhật không yêu cầu sửa cấu trúc Firebase hoặc thay Blob Store.

## Kiểm tra sau triển khai

- Mở `/sign-ipa` với tài khoản thường khi bảo trì tắt: trang hiển thị biểu mẫu đăng nhập và ký bình thường.
- Bật bảo trì: tài khoản thường thấy thông báo bảo trì; Admin đã đăng nhập vẫn thấy biểu mẫu và có thể gửi ký. Cả API chunk và Worker cũng kiểm tra quyền này.
- Với phiên ký: chọn IPA, P12/PFX riêng, `.mobileprovision` riêng; nhập mật khẩu P12 nếu có; để trống nếu không có.
- Kiểm tra `/healthz` trên Worker. Trường `build` phải là `ipa-signing-pkcs12-reader-fix-2026-11-19`.

## Kiểm định đã chạy

- `node --check` cho `src/server.js` và `src/maintenance.js`: đạt.
- 21 test CORS, iOS distribution và maintenance: đạt; gồm test Admin được bypass khi bật bảo trì.
- TypeScript transpile syntax cho 4 file website đã chỉnh sửa (và bản mirrored trong `vang-store-main/`): đạt.

Chưa chạy production build hoặc ký thực tế bằng P12/profile của người dùng. Full TypeScript typecheck cần cài các dependencies của website; test decoder provisioning profile cần package `plist` của worker. Không có credentials trong gói này.
