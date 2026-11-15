# Worker HTTP 500 diagnostics — 2026-11-15

## What changed

- Every request receives an `X-Request-ID` response header.
- The same request ID is included in JSON error responses.
- Temporary work-directory creation tries `SIGNING_TMPDIR`, Node's `os.tmpdir()`, and `/tmp` in order.
- Failed temp-directory attempts log only the directory, OS error code, and message. No request body, Authorization header, Firebase token, Blob token, or P12 password is logged.
- The Express error handler now logs request ID, method, path, safe error code/message, and cause metadata.
- JSON parsing errors return HTTP 400; oversized metadata returns HTTP 413; a temp-directory failure returns HTTP 503 rather than a misleading generic 500.

## Verify after deploying this Worker

1. Open the Vercel project for `vang-ipa-signing-worker`.
2. Open Runtime Logs / Logs for the latest Production deployment.
3. Submit one signing request and note the request ID displayed in the website error.
4. Search the Worker logs for the exact request ID.
5. Read the `Signing worker request error` or `Signing temp directory unavailable` entry.

The log includes `method` and `path`. For the current website it should be `POST /v1/sign-blob`.

## Interpret common outcomes

- `code: WORKDIR_UNAVAILABLE` / status 503: container temp storage is not writable. The log's `causeCode` and `causeMessage` show the operating-system reason.
- `type: entity.too.large` / status 413: the JSON metadata request exceeded its 64 KiB limit; the browser should not be sending the IPA itself to this endpoint.
- `SyntaxError` / status 400: malformed JSON reached the Worker.
- A 500 with another error code: inspect the matching request ID and safe message to locate the middleware/runtime failure.

The worker's `/v1/sign-blob` handler catches normal Firebase, Blob, archive-validation, and ZSign errors itself and returns a specific error response. A generic Express 500 therefore points to an error before or outside that handler (for example request parsing or temp-directory middleware), not by itself to a bad P12 or provisioning profile.

Do not share environment-variable values, tokens, service-account JSON, P12 files, provisioning profiles, or passwords when sharing logs. The request ID and the single matching log entry are sufficient for diagnosis.
