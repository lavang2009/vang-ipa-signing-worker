# VANG STORE — IPA Signing Worker (Vercel 2)

Dự án HTTP container độc lập chạy ZSign thật, Firebase Admin để xác thực Firebase ID token, ghi quota và audit vào Firestore.

## Deploy trên Vercel

1. Giải nén ZIP này và đưa toàn bộ nội dung thư mục `vang-ipa-signing-worker` vào repository riêng (hoặc thư mục gốc của repository worker).
2. Import repository vào Vercel.
3. Vercel phải nhận `Dockerfile.vercel` tại thư mục gốc. File `vercel.json` đã đặt `framework: container` để chọn Container runtime thay vì Node/Next preset.
4. Deploy. Sau khi có domain, kiểm tra:

```text
https://WORKER-DOMAIN.vercel.app/healthz
```

Đáp ứng thành công cần JSON có `ok: true`, `engine: "zsign"`, `firebase: true`, `zsign: true`.

## Environment Variables của worker

```env
FIREBASE_SERVICE_ACCOUNT={JSON_SERVICE_ACCOUNT_CUA_DU_AN_FIREBASE}
ALLOWED_ORIGINS=https://DOMAIN-WEBSITE-CUA-BAN
SIGNING_DAILY_LIMIT=10
SIGNING_MAX_IPA_BYTES=536870912
SIGNING_MAX_CERT_ZIP_BYTES=20971520
SIGNING_TIMEOUT_MS=240000
```

- `FIREBASE_SERVICE_ACCOUNT`: JSON service account của đúng Firebase project mà website dùng. Dán JSON dạng một dòng vào Vercel Environment Variables; không commit vào GitHub.
- `ALLOWED_ORIGINS`: origin đầy đủ của website, không thêm dấu `/` cuối; có thể liệt kê nhiều origin, phân cách bằng dấu phẩy.
- `SIGNING_DAILY_LIMIT`: số lượt ký tối đa mỗi user/ngày.
- `SIGNING_TIMEOUT_MS`: mặc định 240 giây; ứng dụng dừng tiến trình ZSign trước mốc 270 giây để chừa thời gian dọn tệp và trả kết quả. Không tăng nếu chưa xác minh giới hạn thực tế của plan/runtime.

Sau khi worker đã deploy, quay lại website Vercel và đặt:

```env
NEXT_PUBLIC_IPA_SIGNING_WORKER_URL=https://WORKER-DOMAIN.vercel.app
```

Sau đó redeploy website.

## Build fixes ngày 12/11/2026

1. Sửa thứ tự tạo thư mục tạm: `ca-certificates` được cài khi `TMPDIR` vẫn là `/tmp`; chỉ tạo `/tmp/vang-signing` và đặt `ENV TMPDIR` sau khi cài package. Việc này tránh lỗi `mktemp` / `dpkg exit code 100`.
2. Builder và runtime hiện cùng dùng `node:22-bookworm-slim` (Debian 12). Trước đây ZSign được biên dịch trong Ubuntu 24.04 rồi chép sang Debian 12, khiến binary yêu cầu `GLIBC_2.38` và `GLIBCXX_3.4.32` mà runtime không có. Bản mới biên dịch trên cùng họ Debian 12 với runtime để tương thích ABI.
3. Docker build kiểm tra `ldd`, từ chối binary có thư viện hoặc symbol phiên bản bị thiếu, và chạy `zsign --version` trước khi image được chấp nhận.

## Kiểm thử cục bộ

```bash
npm install
npm test
npm start
```

Cần có `zsign`, `unzip` và Firebase service account. Docker local:

```bash
docker build -t vang-ipa-signing-worker .
docker run --rm -p 8080:8080 \
  -e FIREBASE_SERVICE_ACCOUNT='...' \
  -e ALLOWED_ORIGINS='https://DOMAIN-WEBSITE-CUA-BAN' \
  vang-ipa-signing-worker
```

## Giới hạn quan trọng khi chạy trên Vercel

Vercel Container runtime chạy dưới dạng Vercel Function và tuân theo giới hạn Functions. Request body tối đa 4.5 MB. API `/v1/sign` hiện nhận IPA và ZIP bằng multipart trực tiếp, vì vậy upload thực tế bị giới hạn bởi tổng payload 4.5 MB dù `SIGNING_MAX_IPA_BYTES` đặt cao hơn. Nâng giới hạn env không vượt qua được giới hạn nền tảng.

Để ký IPA lớn, cần bước phát triển tiếp theo: dùng Vercel Blob client upload (private store) cho IPA và ZIP, sau đó gửi metadata/URL đã xác thực đến worker; worker tải file từ Blob, ký, đưa IPA kết quả lên Blob và trả URL tải xuống. Luồng Blob này chưa có trong gói hiện tại, nên không được xem là đã hỗ trợ IPA 512 MB trên Vercel.

## Bảo mật

- Chỉ nhận Firebase ID token hợp lệ.
- CORS chỉ cho phép origin liệt kê trong `ALLOWED_ORIGINS`.
- Không ghi mật khẩu P12 vào audit log.
- Worker xóa thư mục làm việc tạm sau khi hoàn thành hoặc lỗi.
- Chỉ dùng certificate/P12 và provisioning profile mà bạn có quyền sử dụng.

## ZSign readiness troubleshooting

The current `/healthz` endpoint returns a `zsignVersion` field after the engine starts successfully. If it cannot start, it returns a safe `zsignError` code:

- `ENOENT`: the configured executable path does not exist. Check that the active deployment was built from the latest commit and includes `/usr/local/bin/zsign`.
- `EACCES`: the executable is not accessible to the unprivileged runtime user. The Dockerfile now enforces mode `0755`.
- A non-zero numeric exit code: the executable started but exited during `--version`; inspect the Vercel Runtime Logs for the full loader or startup error.

The Dockerfile now verifies the copied binary, checks its dynamic library dependencies with `ldd`, and runs `zsign --version` during image build. This deliberately fails the build when ZSign is missing or cannot execute, rather than publishing an unhealthy worker.

Important: if a new deployment fails to build, Vercel continues serving the previous successful production deployment. Confirm the production deployment's commit is the latest `main` commit before interpreting `/healthz`.
