# Health check / ZSign diagnostic update

## Finding from the provided Vercel log

The ZSign builder stage succeeded: `/src/zsign/bin/zsign` was compiled. The final image stage then failed during `apt-get install ca-certificates` because the older deployed Dockerfile set `TMPDIR=/tmp/vang-signing` before that directory existed. Vercel therefore did not publish that build, and the production alias continued serving the previous deployment.

## Changes in this update

- Keep TMPDIR unset until after apt packages are installed and `/tmp/vang-signing` is created.
- Set `ZSIGN_BIN=/usr/local/bin/zsign` explicitly.
- Install required runtime C++ and OpenSSL libraries.
- Run `ldd` and `zsign --version` during Docker build. A missing executable or shared library now fails the build instead of deploying a broken worker.
- `/healthz` now includes `zsignVersion` when ready, or a safe error code in `zsignError` when unavailable.

## Deploy

Push this version to the `main` branch and let Vercel build the new commit. Verify the Build Logs contain the lines for `ldd /usr/local/bin/zsign` and `/usr/local/bin/zsign --version`, followed by a successful deployment. Then check `/healthz`. Expected: `ok: true`, `firebase: true`, `zsign: true`, and a `zsignVersion` field.

The previous log's deployment failed; a failed deployment does not replace the previous production deployment.
