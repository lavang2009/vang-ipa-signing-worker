# Provisioning Profile CMS Decoder Fix — 2026-11-15

## What changed

- Replaced the single `openssl smime` decode attempt with `openssl cms -verify -binary -inform DER -noverify` as the primary decoder.
- Added `smime` compatibility fallback and PEM input fallback.
- Writes decoded plist to a private temporary file instead of buffering the complete plist in the child-process stdout buffer.
- Separates CMS signature/format errors from malformed plist and incomplete provisioning-profile errors.
- Emits a shortened, sanitized OpenSSL diagnostic into Worker Runtime Logs without logging profile contents, P12 files, UDIDs, Firebase tokens, Blob tokens, or passwords.
- Adds a synthetic CMS fixture test for successful decode, tampered signature rejection, and rejection of a raw unsigned plist.
- Updates `/healthz` build string to `ipa-profile-cms-decoder-fix-2026-11-15`.

## Important interpretation

The previous user-facing message did not prove that the profile was corrupt. The previous code wrapped OpenSSL verification failures and plist parser failures in the same generic error. Health reporting `openssl: true` confirms that the CLI exists, not that a particular `.mobileprovision` can be decoded.

The new decoder requires the Apple CMS wrapper. It does not accept a raw, unsigned plist as a valid profile. OpenSSL `-noverify` skips certificate-chain trust lookup only; CMS content/signature integrity is still checked.

## Tests

- Existing archive, CORS and iOS distribution tests: 23/23 passed.
- OpenSSL CMS integration fixture: valid signed fixture decoded successfully.
- Tampered CMS fixture: rejected as expected.
- JavaScript syntax checks: passed.

The full Node test suite including `provisioning-profile.test.js` requires the package dependency `plist`; dependency installation timed out in the audit environment, so that new Node test was not run here. The actual `.mobileprovision` from the user's ZIP was not supplied, so this package cannot certify that specific file as valid or corrupted.

## Deploy

Deploy this Worker source to `lavang2009/vang-ipa-signing-worker` and wait for Vercel Production to become Ready. Then check:

`https://vang-ipa-signing-worker.vercel.app/healthz`

Expected build:

`ipa-profile-cms-decoder-fix-2026-11-15`

Re-run signing. If it fails, inspect Worker Runtime Logs at the same timestamp for `Provisioning profile CMS decode failed`. The log contains the CMS strategy, exit code and shortened error diagnostic.

## Local profile check (do not upload secrets)

With OpenSSL installed locally, run:

```bash
openssl cms -verify -binary -inform DER -noverify -in "your-profile.mobileprovision" -out "decoded-profile.plist"
```

`CMS Verification successful` means the CMS content signature validates and a plist payload was decoded. It does not mean OpenSSL has checked the Apple signer certificate chain, because `-noverify` skips that trust-chain step. Keep `your-profile.mobileprovision` and the decoded file private; they may contain device identifiers and developer-account details.
