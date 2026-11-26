# Third-party notices

## ZSign

VANG STORE IPA Signing Worker builds and invokes the upstream ZSign command-line engine.

- Project: https://github.com/zhlynn/zsign
- License: MIT
- Integration: the Docker build clones the upstream repository and builds its Linux binary; the Worker invokes that binary for IPA re-signing.
- This repository does not replace or fork the ZSign signing implementation. Its own code performs input validation, Apple provisioning-profile inspection, Firebase authentication, private Blob handling, and audit/quota management.

The upstream MIT license is included at `licenses/ZSIGN-MIT-LICENSE.txt` and copied into the runtime image at `/usr/share/doc/zsign/LICENSE`.

## IPA Signer reference

The architecture was also reviewed against https://github.com/aoyn1xw/ipa-signer as a public reference for web/API-based IPA signing and worker-thread isolation. Its application server is not copied into VANG STORE because VANG STORE retains its Firebase, Vercel Blob, and existing API contract.
