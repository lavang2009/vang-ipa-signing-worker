# P12/PFX reader fix — 2026-11-19

- Validate modern PKCS#12 files with OpenSSL before passing them to ZSign.
- If OpenSSL 3 cannot read a legacy P12/PFX cipher, retry with the legacy provider and re-export the same key and certificates using current defaults.
- Read passwords through the child process stdin pipe; do not place the P12 password in OpenSSL arguments or logs.
- Keep the temporary decrypted PEM inside the private per-request work directory with mode `0600`, then remove it immediately after conversion. The request work directory is removed after processing.
- No certificate issuer or UDID filter is applied to P12/PFX parsing. A successful iOS signature still requires a compatible signing identity and Provisioning Profile.
- Error responses now include a safe error code and request ID; the request ID is also recorded in the signing audit entry.

Health build identifier: `ipa-signing-pkcs12-reader-fix-2026-11-19`.

No production signing with user credentials was performed from this source bundle.
