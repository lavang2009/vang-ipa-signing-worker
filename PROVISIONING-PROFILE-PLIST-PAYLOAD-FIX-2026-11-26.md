# Provisioning Profile Payload Decoder Fix — 2026-11-26

## What changed

- Keep CMS signature-integrity verification through OpenSSL before parsing any profile content.
- Parse provisioning payloads as XML or binary plist, with UTF-8 BOM handling for XML.
- Add narrowly-scoped support for complete DER OCTET STRING wrappers and Base64-wrapped plist payloads.
- If a verified outer CMS contains another CMS SignedData object as its payload, verify the inner CMS too before parsing its content.
- Runtime diagnostics now report only the payload classification and byte count, not profile contents, certificates, UDIDs, or secrets.
- Worker health build identifier is now `ipa-signing-profile-plist-payload-fix-2026-11-26`.
- Raise the minimum `plist` dependency to `5.1.1` and the Node runtime to `24.12.0`; both Dockerfiles now use Node 24.

## Verification

- `node --check src/provisioning-profile.js`: passed.
- `node --check src/provisioning-profile.test.js`: passed.
- `node --check src/server.js`: passed.
- Existing non-profile tests: 34 passed.
- The 34 non-profile tests passed.
- The full test suite could not complete in this environment because `npm ci` timed out while fetching dependencies; the profile decoder test module could not resolve `plist` after the incomplete install. New profile decoder tests for XML, binary, Base64, DER OCTET STRING and nested CMS are included and must be run after installing dependencies with Node 24.12+.
- No real `.mobileprovision` file was included with the Worker ZIP, so this package cannot certify the exact profile that triggered request `06686011-bd97-4caa-a2d3-368c5557e3e8`.

## Important distinction

Apple documents a provisioning profile as a property list wrapped in CMS, with a separate `DER-Encoded-Profile` CMS payload held within the plist on modern profiles. The outer plist and nested DER content are different layers; the nested DER payload must not be passed to the plist parser as though it were XML/binary plist.
