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
ALLOWED_ORIGINS=https://luavang.store,https://www.luavang.store
SIGNING_DAILY_LIMIT=10
SIGNING_MAX_IPA_BYTES=536870912
SIGNING_MAX_CREDENTIAL_FILE_BYTES=20971520
SIGNING_MAX_PROFILE_FILE_BYTES=10485760
SIGNING_TIMEOUT_MS=240000
```

- `FIREBASE_SERVICE_ACCOUNT`: JSON service account của đúng Firebase project mà website sử dụng. Chỉ lưu trong Vercel Environment Variables; không commit JSON lên GitHub.
- `BLOB_READ_WRITE_TOKEN`: token được tạo khi kết nối cùng Private Blob Store. Worker và website phải đọc/ghi cùng một store.
- `ALLOWED_ORIGINS`: các origin bổ sung/chính xác, phân cách bằng dấu phẩy, chấm phẩy hoặc xuống dòng. Worker luôn cho phép mặc định đúng hai domain Production `https://luavang.store` và `https://www.luavang.store`; biến này có thể liệt kê lại hai origin đó và thêm staging origin nếu cần. Worker từ chối wildcard, path, query, fragment và credential.
- `SIGNING_DAILY_LIMIT`: giới hạn lượt ký mỗi người dùng mỗi ngày.
- `SIGNING_TIMEOUT_MS`: timeout ZSign mặc định 240 giây.

## Endpoint

- `GET /`: trả thông tin dịch vụ và các endpoint.
- `GET /healthz`: trạng thái Firebase Admin, ZSign và Blob.
- `POST /v1/sign-blob`: nhận JSON metadata sau khi website upload các phần file vào Private Blob.
- `POST /v1/sign`: endpoint multipart cũ để tương thích; không dùng endpoint này cho IPA lớn qua Vercel vì request body có giới hạn 4.5 MB.

Health check sẵn sàng chỉ khi Firebase Admin, ZSign và `BLOB_READ_WRITE_TOKEN` đã được cấu hình. Trường `blob: true` xác nhận Worker có token; phải bảo đảm token này thuộc cùng Private Blob Store với Website. `corsConfigured: true` chỉ ra allow-list có ít nhất một origin; `firebaseProjectId` giúp so sánh Firebase project của Website và Worker; kiểm tra `/api/ipa-signing/health` trên Website để xác minh chính xác origin đang truy cập có được phép hay không.

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
  "firebaseProjectId": "your-firebase-project-id",
  "build": "ipa-signing-profile-plist-payload-fix-2026-11-26",
  "zsignVersion": "..."
}
```

## Luồng upload Blob riêng tư

Website chia IPA, P12/PFX và `.mobileprovision` thành các phần 3 MiB riêng biệt, gửi từng phần tới API cùng domain `/api/ipa-signing/chunk`. Route website xác thực Firebase ID Token và gọi `put(..., { access: "private" })`. Sau đó website gửi ba ID phiên tải qua JSON nhỏ đến `POST /v1/sign-blob`; mật khẩu P12 chỉ được gửi trong body của lần ký và không được ghi log.

Worker xác minh lại Firebase UID, dựng pathname từ UID và ID phiên (không tin pathname do client gửi), tải các phần riêng tư, ghép IPA, P12/PFX và provisioning profile vào vùng tạm, xác thực IPA và CMS của profile rồi chạy ZSign trực tiếp với hai tệp chứng chỉ. Worker ghi IPA đầu ra vào Private Blob, trả presigned URL GET và xóa các Blob đầu vào sau xử lý.

**Định dạng chứng chỉ:** Chọn trực tiếp hai tệp riêng biệt: một `.p12`/`.pfx` và một `.mobileprovision`. Không tạo ZIP chứng chỉ. Nếu P12/PFX có mật khẩu, nhập mật khẩu trong biểu mẫu; nếu không có mật khẩu thì để trống. Worker kiểm tra CMS của provisioning profile và chuyển trực tiếp các đường dẫn tệp cho ZSign.

Kết nối **một Private Blob Store duy nhất** vào cả hai Vercel Projects. Nếu website và Worker dùng hai store/token khác nhau, Worker không tìm thấy phần upload. Cấu hình `BLOB_READ_WRITE_TOKEN` trong cả hai project phải có mặt sau khi kết nối store.

Việc chia phần tránh giới hạn request body 4.5 MB cho từng upload chunk. Nó không loại bỏ giới hạn thời gian chạy, RAM, vùng tạm, quota hoặc chi phí của Vercel. Mức 512 MiB là giới hạn ứng dụng, không phải bảo đảm mọi IPA 512 MiB đều có thể ký trong mọi gói Vercel.

## CORS

Worker xử lý preflight `OPTIONS`, mặc định cho phép chính xác hai origin Production `https://luavang.store` và `https://www.luavang.store`, đồng thời cho phép thêm origin chính xác từ `ALLOWED_ORIGINS`. Website kiểm tra Worker qua API cùng domain `/api/ipa-signing/health`; API chuyển tiếp origin trình duyệt đến Worker để phát hiện CORS. Lệnh ký `POST /v1/sign-blob` vẫn gọi trực tiếp Worker, vì vậy phải cho phép chính xác origin đang mở website (không phải URL `/sign-ipa`). Sau khi sửa biến, redeploy Worker.

## Chẩn đoán lỗi HTTP 500

Mỗi request có `X-Request-ID`; lỗi JSON cũng trả `requestId` để đối chiếu với Runtime Logs. Worker thử `SIGNING_TMPDIR`, `os.tmpdir()` rồi `/tmp` khi tạo vùng tạm. Lỗi parser JSON, request metadata quá lớn và lỗi tạo thư mục tạm có mã HTTP riêng. Xem `WORKER-500-DIAGNOSTICS-2026-11-15.md` để tra log an toàn. Không chia sẻ token, service-account JSON, P12, provisioning profile hoặc mật khẩu.

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
- IPA, P12/PFX, Provisioning Profile và kết quả đều dùng Private Blob tạm thời.
- Không ghi mật khẩu P12 vào Firestore audit log.
- Xóa tệp tạm và các Blob đầu vào sau xử lý; TTL một ngày dọn các phiên bỏ dở.
- Chỉ dùng ứng dụng, P12 và provisioning profile mà người dùng có quyền sử dụng.


## Multi-profile signing and OTA manifest update (2026-11-16)

The worker now requires the `openssl` CLI and the `plist` Node package to inspect the CMS-wrapped `.mobileprovision` and the IPA `Info.plist`. The Docker runtime installs OpenSSL. `GET /healthz` reports `openssl` and `provisioningProfileInspector`. Use Node.js 24.12.0 or newer; the current Firebase database dependency declares that minimum runtime.

The signing endpoint accepts valid Apple iOS provisioning profiles across the common categories: Ad Hoc, In-House/Enterprise, Development, and App Store, plus structurally valid variants that ZSign may support. A profile must still pass CMS verification, required-field validation, expiry checks, App ID compatibility, and final ZSign certificate/profile compatibility.

The signing Website asks the user to copy a 25-character or 40-character UDID from UDID CodeVN and paste it into the form. The Website does not generate a UDID configuration file. For Ad Hoc and Development profiles, the Worker checks a submitted UDID against the profile's `ProvisionedDevices` list; this check does not filter the P12/PFX certificate. Enterprise and App Store profiles do not use that device list.

Only Ad Hoc and eligible In-House/Enterprise profiles receive an `itms-services` manifest link. Development profiles use registered-device development workflows; App Store profiles are for App Store Connect and are not directly installable through an OTA manifest. Every successful signing result retains a private IPA download link as fallback.

Signed IPA and manifest URLs expire after 60 minutes. The underlying private Blob objects expire after one day. The download link remains available as a fallback. OTA behavior should be verified on the intended iOS versions; Apple documents Ad Hoc installation for registered devices through Xcode Device Hub or Apple Configurator, and its wireless web-distribution guide describes In-House profiles.


## Provisioning Profile CMS decoder fix (2026-11-15)

The worker decodes `.mobileprovision` using OpenSSL `cms -verify -binary -inform DER -noverify` first, then falls back to `smime` and PEM input compatibility. `-noverify` skips certificate-chain trust lookup only; OpenSSL still checks the CMS signed content. The decoded plist is parsed and checked for expected provisioning-profile fields.

If decoding fails, Runtime Logs include the OpenSSL strategy, exit code and a shortened diagnostic, without logging the profile content, UDIDs, P12, token or password. The API distinguishes CMS failure, malformed plist and incomplete profile. The profile itself remains private in the worker's temporary directory and is deleted after signing.

Test locally with `npm test`; the CMS decoder tests generate a temporary synthetic profile signed by a disposable test certificate and never use production credentials.

Expected Worker health build: `ipa-signing-pkcs12-reader-fix-2026-11-19`.


## Provisioning profile plist payload compatibility (2026-11-26)

After CMS verification, the Worker now recognizes XML plist, binary plist, UTF-8 BOM-prefixed XML, Base64-encoded plist, and a complete DER OCTET STRING wrapper. If an inner CMS SignedData payload is encountered, the Worker verifies that inner CMS before parsing its content. Runtime diagnostics report only payload format and byte count. If the payload still cannot be parsed, compare the `requestId` from the browser with Worker Runtime Logs; no profile contents, certificate values, UDIDs, or secrets are logged.

The `plist` dependency is constrained to `^5.1.1`, and the Docker builder/runtime use Node 24.12+ to match the Firebase database dependency engine requirement. Run `npm ci` and `npm test` after deploying with Node 24.12 or newer.
