# IPA Worker UDID format update

The Worker accepts both 40-character hexadecimal UDIDs and 25-character UDIDs in `XXXXXXXX-XXXXXXXXXXXXXXXX` form in both signing endpoints. The submitted identifier is still checked against the signed profile's registered device list for Ad Hoc and Development profiles.

Health endpoint build identifier: `ipa-signing-udid-25-40-2026-11-19`.

The CORS, maintenance, and iOS distribution suite passed 26 tests, including matching a 25-character UDID for Ad Hoc and Development profiles. A production signing run requires valid user supplied IPA, P12/PFX, and `.mobileprovision` files plus the configured Worker environment.
