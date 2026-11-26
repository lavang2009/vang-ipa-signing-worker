# Preserve original IPA Bundle ID + ZSign OSS preflight

## Selected deployment policy

VANG STORE keeps its current Next.js/Firebase/Vercel Blob architecture. The Worker continues using the upstream MIT-licensed `zhlynn/zsign` engine built from source in Docker. The public `aoyn1xw/ipa-signer` project was reviewed as an architectural reference only; its independent Express application is not copied because it would replace VANG STORE's Firebase authentication, Blob upload contract, quota, audit, and endpoints.

## Bundle ID policy

- The source IPA `Payload/*.app/Info.plist` `CFBundleIdentifier` is authoritative.
- A requested `bundleId` value may be omitted or equal the source Bundle ID. A different value is rejected with `BUNDLE_ID_OVERRIDE_DISABLED`.
- The Worker does not pass ZSign's `-b` option. ZSign therefore re-signs using the original app Bundle ID.
- The source Bundle ID is checked against the signed profile's `Entitlements.application-identifier` before quota is consumed and before ZSign starts.
- Explicit App IDs and valid trailing-wildcard App IDs are supported. The App ID Prefix is parsed from the entitlement itself; it is not assumed to equal Team ID.
- A mismatch returns `BUNDLE_ID_PROFILE_MISMATCH` with safe diagnostics (`sourceBundleIdentifier`, `applicationIdentifier`, `appIdPrefix`, `profileBundlePattern`, profile name/UUID and next action). The Worker never strips or rewrites Apple's signed entitlement to suppress the mismatch.

## Certificate/profile pairing

Before quota consumption, the Worker extracts only public X.509 certificate blocks from the selected P12/PFX via OpenSSL, calculates SHA-256 fingerprints over the DER certificates, and compares them with the `DeveloperCertificates` entries in the Apple-signed profile. It rejects a P12 that is not authorized by the selected profile using `SIGNING_CERTIFICATE_NOT_IN_PROFILE`. The private key is not returned, logged, or written to a certificate output file.

## ZSign source integration

Docker builds the official upstream ZSign source from `https://github.com/zhlynn/zsign.git` and uses its CLI for signing. VANG STORE keeps the engine's supported profile/P12 handling while its own preflight enforces the product policy. See `THIRD_PARTY_NOTICES.md` and `licenses/ZSIGN-MIT-LICENSE.txt`.

## Current known mismatch

For the reported IPA, the original Bundle ID is `p3.xyz.yyyue.esign`, while the uploaded profile authorizes `2FRGLDX9FA.com.Azor255588.Azor`. These are different App IDs. Under the preserve-original policy, the required input is a valid, unexpired profile whose App ID entitlement matches `p3.xyz.yyyue.esign` (or a valid wildcard that covers it), and whose `DeveloperCertificates` contains the certificate from the selected P12/PFX. That profile must be generated/downloaded by an Apple Developer account authorized for that App ID. The Worker cannot manufacture or grant that Apple authorization.

## Verification

Run with Node.js 24.12 or newer:

```sh
npm ci
npm test
```

A successful Worker `/healthz` confirms components are loaded; it does not prove that a particular IPA/profile/P12 triplet is compatible. A real signing test with an authorized matching profile is still required.
