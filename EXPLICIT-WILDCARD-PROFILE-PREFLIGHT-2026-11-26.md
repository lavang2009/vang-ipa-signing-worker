# Explicit + Wildcard Provisioning Profile Preflight (2026-11-26)

## Behaviour

- Preserve the original IPA `CFBundleIdentifier`. The Worker never adds ZSign's `-b` option.
- Automatically classify profile App IDs as `explicit`, `wildcard`, `mixed` (when both Catalyst identifier entitlements are present with different forms), or `unknown`.
- Explicit App IDs require an exact Bundle ID match.
- Wildcard App IDs are accepted only with a terminal wildcard: `PREFIX.*` or `PREFIX.com.example.*`.
- A scoped wildcard matches only Bundle IDs beginning with the fixed prefix plus a dot and at least one further component.
- If both `application-identifier` and `com.apple.application-identifier` are present, every supplied value must authorize the same Bundle ID.
- App ID Prefix is read from the profile's own application identifier; it is not assumed to be the Team ID.
- P12 certificate SHA-256 must still match a certificate in the profile's `DeveloperCertificates`.
- App Store Connect profiles with Wildcard App IDs are rejected because App Store Connect requires an Explicit App ID.
- The checks run before daily quota is consumed and before ZSign is invoked. The Bundle ID is checked again in the signed IPA.
- `/v1/sign-blob` returns `appIdType` and `appIdMatchMode` in its `installation` details; logs include match reasons without exposing private key material.

## Apple limitations

Wildcard App IDs cannot use capabilities that require an Explicit App ID. Apple-signed profile entitlements, certificate authorization, expiration, and registered-device restrictions remain authoritative. A wildcard match does not bypass those restrictions. The current upload contract accepts one profile per signing request; bundles whose extensions require separate explicit profiles need a future multi-profile API/UI workflow.

## Tests

`src/ios-distribution.test.js` covers exact Explicit matches, scoped Wildcard matches, global trailing wildcard, component boundaries, malformed wildcard patterns, both application-identifier entitlement keys, legacy App ID Prefix handling, and the previously reported incompatible IPA/profile pair.
