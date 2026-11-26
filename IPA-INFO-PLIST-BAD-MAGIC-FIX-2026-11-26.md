# IPA Info.plist format detection fix — 2026-11-26

## Root cause

The `/v1/sign-blob` endpoint signs the IPA and then reads `Payload/*.app/Info.plist` to build installation metadata. The previous implementation passed every `unzip -p` result to `plist.parse()` as a `Uint8Array`. In `plist.js`, a byte-array input is the binary-plist path; an XML Info.plist therefore raised `Invalid binary plist: bad magic`. The endpoint then fell back to the generic `VALIDATION_OR_SIGNING_ERROR` code.

## Changes

- Detect the `bplist00` magic before sending bytes to the binary plist parser.
- Parse XML and OpenStep property lists as UTF-8 text, including XML with BOM/leading whitespace.
- Require an Info.plist root dictionary.
- Return `INVALID_IPA_INFO_PLIST` with a safe format/length diagnostic rather than a generic validation error.
- Preserve the existing CMS verification, profile validation, P12 handling, ZSign invocation, Firebase and Blob workflows.

## Verification

- `node --check src/ipa-info-plist.js`: passed.
- `node --check src/ipa-info-plist.test.js`: passed.
- `node --check src/server.js`: passed.
- Parser tests were added for XML, XML BOM/whitespace, binary plist, unknown header and non-dictionary root. They require `npm ci` with Node 24.12+ and were not executed in this environment because dependencies are not installed.
- No real IPA was provided, so an end-to-end ZSign run has not been performed.

## Build identifier

`ipa-signing-preserve-original-bundle-id-zsign-preflight-2026-11-26` is the current build; the Info.plist parser fix remains included.
