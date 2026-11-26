# Bundle ID / Provisioning Profile matching fix — 2026-11-26

## Problem

`POST /v1/sign-blob` compared the post-ZSign `CFBundleIdentifier` against the `application-identifier` App ID in the provisioning profile only after signing and after the daily quota had already been consumed. The resulting error did not disclose which values differed. The direct `/v1/sign` endpoint did not perform equivalent validation.

## Changes

- Validate the effective Bundle ID before invoking ZSign and before consuming quota, for both `/v1/sign` and `/v1/sign-blob`.
- The effective Bundle ID is the requested override (`bundleId`) when supplied, otherwise the source IPA's `CFBundleIdentifier`.
- Keep the post-sign validation: the output IPA must retain the exact effective Bundle ID and it must still match the profile.
- Return safe diagnostic values (`bundleIdentifier`, `applicationIdentifier`) with the dedicated code `BUNDLE_ID_PROFILE_MISMATCH` when the pair is incompatible.
- Return `BUNDLE_ID_NOT_APPLIED` if ZSign does not apply the requested Bundle ID exactly.
- Support exact App IDs, global wildcard App IDs (`PREFIX.*`), and suffix wildcard App IDs (`PREFIX.com.example.*`). Malformed wildcard patterns and malformed Bundle IDs are rejected.
- Match using the App ID Prefix contained in `application-identifier`. Do not assume this prefix always equals the Team ID; legacy App ID prefixes may differ.
- Read `com.apple.application-identifier` as a fallback entitlement where applicable.
- Bundle ID mismatches are rejected rather than bypassed. A mismatched signed app/profile pair cannot be made valid by suppressing this check.

## Validation

Run on Node.js 24.12 or newer:

```bash
npm ci
npm test
```

In this workspace:

- `node --check src/server.js`: passed.
- `node --check src/ios-distribution.js`: passed.
- `node --test src/ios-distribution.test.js`: 18/18 passed.
- Full test suite/build: not run here because the workspace does not have installed dependencies and the available Node runtime is 22.x.

## Interpreting `BUNDLE_ID_PROFILE_MISMATCH`

The response's `details.bundleIdentifier` is the Bundle ID selected from the IPA or requested override. `details.applicationIdentifier` is the profile's App ID in the form `<App ID Prefix>.<Bundle ID pattern>`.

Use a provisioning profile created for that app's explicit Bundle ID, or choose a Bundle ID permitted by the profile's wildcard App ID. Do not alter or bypass the profile's Apple-signed entitlements. If the source IPA's Bundle ID must change, make sure its other app capabilities, keychain groups, push, app groups, and extensions are also compatible before distributing it.
