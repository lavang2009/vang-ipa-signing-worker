FROM ubuntu:24.04 AS zsign-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git g++ make pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
ARG ZSIGN_REF=master
RUN git clone --depth 1 --branch ${ZSIGN_REF} https://github.com/zhlynn/zsign.git /src/zsign \
    && cd /src/zsign/build/linux \
    && make clean && make \
    && test -x /src/zsign/bin/zsign

FROM node:22-bookworm-slim
ENV NODE_ENV=production PORT=8080 TMPDIR=/tmp/vang-signing
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates unzip libssl3 && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home appuser
WORKDIR /app
COPY package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src
COPY --from=zsign-builder /src/zsign/bin/zsign /usr/local/bin/zsign
RUN chmod 0755 /usr/local/bin/zsign && mkdir -p /tmp/vang-signing && chown -R appuser:appuser /app /tmp/vang-signing
USER appuser
EXPOSE 8080
CMD ["node", "src/server.js"]
