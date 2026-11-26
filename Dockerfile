# Build ZSign on the same Debian 12 base as the runtime image.
# This prevents Ubuntu 24.04 binaries (GLIBC_2.38 / newer GLIBCXX symbols)
# from being copied into Debian 12, which ships older runtime libraries.
FROM node:24-bookworm-slim AS zsign-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git g++ make pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
ARG ZSIGN_REF=master
RUN git clone --depth 1 --branch ${ZSIGN_REF} https://github.com/zhlynn/zsign.git /src/zsign \
    && cd /src/zsign/build/linux \
    && make clean && make \
    && test -x /src/zsign/bin/zsign

FROM node:24-bookworm-slim
# Do not set TMPDIR to a non-existent path before apt installs ca-certificates:
# its post-install script uses mktemp and fails when TMPDIR does not exist.
ENV NODE_ENV=production PORT=8080 DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates unzip openssl libssl3 libstdc++6 libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /tmp/vang-signing \
    && chown appuser:appuser /tmp/vang-signing
ENV TMPDIR=/tmp/vang-signing
WORKDIR /app
COPY package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src
COPY --from=zsign-builder /src/zsign/bin/zsign /usr/local/bin/zsign
ENV ZSIGN_BIN=/usr/local/bin/zsign
# Verify the copied binary and all dynamic libraries during image build,
# so a broken image cannot be deployed as a seemingly healthy worker.
RUN set -eux; \
    chmod 0755 /usr/local/bin/zsign; \
    ldd /usr/local/bin/zsign | tee /tmp/zsign-ldd.txt; \
    if grep -q "not found" /tmp/zsign-ldd.txt; then echo "ZSign has missing runtime libraries"; exit 1; fi; \
    /usr/local/bin/zsign --version; \
    mkdir -p /tmp/vang-signing; \
    chown -R appuser:appuser /app /tmp/vang-signing
USER appuser
EXPOSE 8080
CMD ["node", "src/server.js"]
