FROM alpine:3.24 AS base

RUN apk update && apk upgrade

WORKDIR /app

ENV PATH="/app:${PATH}"

FROM base AS arkd

ARG TARGETARCH

COPY --chmod=0755 build/arkd-linux-${TARGETARCH} /app/arkd
COPY --chmod=0755 pkg/ark-cli/build/ark-linux-${TARGETARCH} /app/ark

ENV ARKD_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "arkd" ]

FROM base AS arkd-wallet

ARG TARGETARCH

COPY --chmod=0755 build/arkd-wallet-linux-${TARGETARCH} /app/arkd-wallet

ENV ARKD_WALLET_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "arkd-wallet" ]

FROM base AS arkd-signer

ARG TARGETARCH

COPY --chmod=0755 build/arkd-signer-linux-${TARGETARCH} /app/arkd-signer

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -q --spider "http://127.0.0.1:${ARKD_SIGNER_PORT:-6061}/healthz" || exit 1

ENTRYPOINT [ "arkd-signer" ]
