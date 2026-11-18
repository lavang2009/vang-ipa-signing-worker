# Separate signing credential files – 2026-11-18

The signing worker no longer accepts a certificate ZIP. Both signing endpoints accept three files/inputs: IPA, P12/PFX, and `.mobileprovision`. P12 password is optional and must be omitted when the file has no password.

The IPA is still an archive internally, so the worker inspects the IPA package structure. This is unrelated to certificate packaging.

When IPA signing maintenance is enabled, Firebase-authenticated admins (custom `admin` claim, `ADMIN_EMAILS`, or `users/{uid}.role == admin`) may continue using the tool. Regular users are blocked by the worker middleware.
