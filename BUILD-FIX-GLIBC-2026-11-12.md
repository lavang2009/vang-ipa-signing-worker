# ZSign GLIBC compatibility fix — 2026-11-12

## Root cause from Vercel build 5725051

The build stage used `ubuntu:24.04`, while the runtime stage used `node:22-bookworm-slim` (Debian 12). ZSign was compiled against newer system libraries and required:

- `GLIBC_2.38`
- `GLIBCXX_3.4.32`

The Debian 12 runtime could not provide these symbols. The image build correctly failed at its `ldd` verification step rather than deploying a broken signing service.

## Change

Both `Dockerfile` and `Dockerfile.vercel` now use `node:22-bookworm-slim` for the ZSign builder stage as well as the runtime stage. The builder installs the compiler and OpenSSL headers on Debian 12, compiles ZSign there, and copies the binary into a runtime based on the same distribution family.

The existing runtime checks remain enabled:

- `ldd /usr/local/bin/zsign`
- fail if output contains `not found`
- execute `/usr/local/bin/zsign --version`

The earlier TMPDIR ordering fix is retained: apt installs certificates before switching `TMPDIR` to `/tmp/vang-signing`.

## Verification performed in this workspace

- JavaScript syntax checks: run separately against worker source files.
- Archive validation tests: run with Node's built-in test runner.
- Docker Build: not run in this workspace because Docker/Podman is not installed. The Vercel deployment must complete the real image build and pass the `ldd` plus `zsign --version` checks before `/healthz` can report ZSign ready.
