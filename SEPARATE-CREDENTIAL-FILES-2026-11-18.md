# Separate signing credential files – 2026-11-18

The signing worker no longer accepts a certificate ZIP. Both signing endpoints accept three files/inputs: IPA, P12/PFX, and `.mobileprovision`. P12 password is optional and must be omitted when the file has no password.

The IPA is still an archive internally, so the worker inspects the IPA package structure. This is unrelated to certificate packaging.

When IPA signing maintenance is enabled, Firebase-authenticated admins (custom `admin` claim, `ADMIN_EMAILS`, or `users/{uid}.role == admin`) may continue using the tool. Regular users are blocked by the worker middleware.


## Optional target-device UDID check

The signing endpoint accepts an optional legacy 40-character hexadecimal `targetUdid` or a modern 25-character UDID in `8-16` form (eight hexadecimal characters, a hyphen, then sixteen hexadecimal characters). For Ad Hoc and Development provisioning profiles, if supplied, it must exactly match one value in the signed profile's `ProvisionedDevices` array (case-insensitive). The Worker never writes the UDID into its audit log or stores it as a device record. If omitted, existing behavior is preserved and iOS enforces the embedded list at installation. Enterprise/App Store/other profiles do not require a target UDID match.
