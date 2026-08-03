# First stage: build the ark-wallet binary.
# Pinned to BUILDPLATFORM so the Go toolchain runs natively on the builder and cross-compiles to
# TARGETOS/TARGETARCH below. Without this the whole stage runs under QEMU emulation when the target
# architecture differs from the builder, which is far slower for compilation.
FROM --platform=$BUILDPLATFORM golang:1.26.5 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o /app/bin/arkd-wallet ./cmd/arkd-wallet/main.go

# Second stage: minimal runtime image
FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/arkd-wallet /app/

ENV PATH="/app:${PATH}"
ENV ARKD_WALLET_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "arkd-wallet" ]
