# Provisioning Profile CMS and Multi-Profile Update — 2026-11-16

## CMS decoder

- Uses OpenSSL `cms -verify -binary` as the primary decoder and `smime -verify -binary` as a compatibility fallback.
- Tries the DER, PEM and S/MIME input encodings and recognizes base64-wrapped DER CMS data.
- Verifies the outer Apple CMS signature before parsing the plist payload.
- Verifies the nested `DER-Encoded-Profile` CMS payload when that property is present and checks the decoded ASN.1 structure.
- Separates CMS signature/format errors, malformed plist, unsigned raw plist, incomplete profile and invalid nested-DER errors.
- Writes only shortened, sanitized diagnostics to Runtime Logs. Profile contents, P12, password, device list, Firebase tokens and Blob tokens are not logged.
- Supports the XML/binary plist input interface exposed by `plist@5`; raw unsigned plist files are deliberately rejected.

## Profile categories

The Worker classifies and attempts ZSign processing for valid iOS provisioning profiles in common categories:

- Ad Hoc
- Development
- In-House / Enterprise
- App Store
- Other structurally valid variants, subject to ZSign compatibility checks

Signing still requires a valid CMS signature, required profile fields, a non-expired profile, a compatible application identifier/Bundle ID and a P12/profile pairing accepted by ZSign. The update does not convert an invalid, expired or revoked credential into a valid one.

OTA manifests are generated only for Ad Hoc and eligible In-House/Enterprise profiles. Development profiles are not presented as general OTA distribution. App Store profiles are not offered as direct OTA installs; they are intended for the App Store Connect workflow.

## UDID input removed

The Website no longer collects or sends a manual UDID. The original `ProvisionedDevices` list remains embedded in Ad Hoc/Development profiles and iOS enforces that device allow-list at installation/runtime. Removing the input field does not add devices to a profile or authorize a device that is not listed. Enterprise and App Store profiles do not use this device allow-list.

## Build identifier

`ipa-all-profiles-cms-compatible-no-udid-input-2026-11-16`

## Tests and verification

- Worker test harness: 32/32 passed, including OpenSSL-generated CMS fixtures for DER, PEM, S/MIME, base64-wrapped DER, nested `DER-Encoded-Profile`, tamper rejection and unsigned-plist rejection.
- Worker JavaScript syntax: passed.
- Website `SignIpaClient.tsx` syntax: passed.
- The local CMS test harness used a temporary plist-compatible test stub because a normal dependency installation timed out in the audit environment. The stub is not included in the release. `plist@5` documents XML, binary and OpenStep plist support with `Uint8Array` input; the complete test suite should be run after `npm install` in the deployment environment.
- No actual user `.mobileprovision` was supplied, so this release does not certify a particular profile file. Production signing and OTA installation on a physical iPhone remain to be verified.

## Apple references

- Apple TN3125 explains that a provisioning profile is a plist wrapped in a CMS signature, and that modern profiles include `DER-Encoded-Profile` as the DER source of truth: https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
- Apple states that Ad Hoc profiles are created for registered devices: https://developer.apple.com/help/account/provisioning-profiles/create-an-ad-hoc-provisioning-profile/
