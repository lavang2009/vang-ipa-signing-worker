# VANG STORE — IPA Signing Worker (Vercel Container)

Worker chạy ZSign thật, xác thực Firebase ID Token, ghi quota/audit vào Firestore và đọc/ghi tệp IPA thông qua cùng một Vercel Blob Private Store với website.

## Deploy

1. Repository worker phải có `Dockerfile.vercel`, `vercel.json`, `package.json` và `src/` tại thư mục gốc.
2. Import repository vào Vercel. Framework/Runtime phải nhận `Container` từ `vercel.json`.
3. Tạo hoặc kết nối Worker với **cùng Private Blob Store** đã kết nối vào Vercel Project website `vang-store`. Không tạo store riêng cho Worker.
4. Thêm các biến môi trường bên dưới rồi deploy Production.
5. Kiểm tra `https://WORKER-DOMAIN/healthz`.

## Environment Variables của Worker

```env
FIREBASE_SERVICE_ACCOUNT={JSON_SERVICE_ACCOUNT_CUA_FIREBASE_VANG_STORE}
BLOB_READ_WRITE_TOKEN={TOKEN_CUA_CUNG_PRIVATE_BLOB_STORE}
ALLOWED_ORIGINS=https://luavang.store
SIGNING_DAILY_LIMIT=10
SIGNING_MAX_IPA_BYTES=536870912
SIGNING_MAX_CERT_ZIP_BYTES=20971520
SIGNING_TIMEOUT_MS=240000
```

- `FIREBASE_SERVICE_ACCOUNT`: JSON service account của đúng Firebase project mà website sử dụng. Chỉ lưu trong Vercel Environment Variables; không commit JSON lên GitHub.
- `BLOB_READ_WRITE_TOKEN`: token được tạo khi kết nối cùng Private Blob Store. Worker và website phải đọc/ghi cùng một store.
- `ALLOWED_ORIGINS`: origin chính xác của website, phân cách bằng dấu phẩy, chấm phẩy hoặc xuống dòng. Với domain hiện tại dùng `https://luavang.store`; chỉ thêm `https://www.luavang.store` nếu domain www thực sự đang phục vụ website. Worker từ chối wildcard, path, query, fragment và credential; mỗi hostname cần được cho phép riêng.
- `SIGNING_DAILY_LIMIT`: giới hạn lượt ký mỗi người dùng mỗi ngày.
- `SIGNING_TIMEOUT_MS`: timeout ZSign mặc định 240 giây.

## Endpoint

- `GET /`: trả thông tin dịch vụ và các endpoint.
- `GET /healthz`: trạng thái Firebase Admin, ZSign và Blob.
- `POST /v1/sign-blob`: nhận JSON metadata sau khi website upload các phần file vào Private Blob.
- `POST /v1/sign`: endpoint multipart cũ để tương thích; không dùng endpoint này cho IPA lớn qua Vercel vì request body có giới hạn 4.5 MB.

Health check sẵn sàng chỉ khi Firebase Admin, ZSign và `BLOB_READ_WRITE_TOKEN` đã được cấu hình. Trường `blob: true` xác nhận Worker có token; phải bảo đảm token này thuộc cùng Private Blob Store với Website. `corsConfigured: true` chỉ ra allow-list có ít nhất một origin; kiểm tra `/api/ipa-signing/health` trên Website để xác minh chính xác origin đang truy cập có được phép hay không.

Health check sẵn sàng chỉ khi có:

```json
{
  "ok": true,
  "engine": "zsign",
  "firebase": true,
  "zsign": true,
  "blob": true,
  "signBlob": true,
  "corsConfigured": true,
  "build": "ipa-sign-blob-cors-diagnostics-2026-11-13",
  "zsignVersion": "..."
}
```

## Luồng upload Blob riêng tư

Website chia IPA thành phần 3 MiB, gửi từng phần tới API cùng domain `/api/ipa-signing/chunk`. Route website xác thực Firebase ID Token và gọi `put(..., { access: "private" })`. ZIP chứng chỉ được xử lý tương tự. Sau đó website gửi ID phiên tải qua JSON nhỏ đến `POST /v1/sign-blob`.

Worker xác minh lại Firebase UID, dựng pathname từ UID và ID phiên (không tin pathname do client gửi), tải các phần riêng tư, ghép vào vùng tạm, xác thực cấu trúc IPA/ZIP, giải nén P12 và provisioning profile rồi chạy ZSign. Worker ghi IPA đầu ra vào Private Blob, trả presigned URL GET 20 phút và xóa các Blob đầu vào sau xử lý.

Kết nối **một Private Blob Store duy nhất** vào cả hai Vercel Projects. Nếu website và Worker dùng hai store/token khác nhau, Worker không tìm thấy phần upload. Cấu hình `BLOB_READ_WRITE_TOKEN` trong cả hai project phải có mặt sau khi kết nối store.

Việc chia phần tránh giới hạn request body 4.5 MB cho từng upload chunk. Nó không loại bỏ giới hạn thời gian chạy, RAM, vùng tạm, quota hoặc chi phí của Vercel. Mức 512 MiB là giới hạn ứng dụng, không phải bảo đảm mọi IPA 512 MiB đều có thể ký trong mọi gói Vercel.

## CORS

Worker xử lý preflight `OPTIONS` và chỉ cho phép origin được chỉ định trong `ALLOWED_ORIGINS`. Website kiểm tra Worker qua API cùng domain `/api/ipa-signing/health`; API chuyển tiếp origin trình duyệt đến Worker để phát hiện CORS. Lệnh ký `POST /v1/sign-blob` vẫn gọi trực tiếp Worker, vì vậy phải cho phép chính xác origin đang mở website (không phải URL `/sign-ipa`). Sau khi sửa biến, redeploy Worker.

## Kiểm thử cục bộ

```bash
npm install
npm test
npm start
```

Docker build sử dụng Debian Bookworm cho cả Builder và Runtime để tránh sai khác GLIBC/GLIBCXX. Build kiểm tra `ldd` và chạy `zsign --version`, từ chối image nếu binary không thể chạy.

## Bảo mật

- Chỉ nhận Firebase ID Token hợp lệ; Worker xác minh lại token.
- Chỉ đọc các Blob nằm dưới prefix UID của người gửi.
- IPA, ZIP chứng chỉ và kết quả đều dùng Private Blob.
- Không ghi mật khẩu P12 vào Firestore audit log.
- Xóa tệp tạm và các Blob đầu vào sau xử lý; TTL một ngày dọn các phiên bỏ dở.
- Chỉ dùng ứng dụng, P12 và provisioning profile mà người dùng có quyền sử dụng.
