# First stage: build the arkd-signer binary.
# Pinned to BUILDPLATFORM so the Go toolchain runs natively on the builder and cross-compiles to
# TARGETOS/TARGETARCH below. Without this the whole stage runs under QEMU emulation when the target
# architecture differs from the builder, which is far slower for compilation.
FROM --platform=$BUILDPLATFORM golang:1.27.3 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
COPY api-spec/go.mod api-spec/go.sum ./api-spec/
COPY pkg/ark-lib/go.mod pkg/ark-lib/go.sum ./pkg/ark-lib/
COPY pkg/arkd-wallet/go.mod pkg/arkd-wallet/go.sum ./pkg/arkd-wallet/
COPY pkg/arkd-signer/go.mod pkg/arkd-signer/go.sum ./pkg/arkd-signer/
COPY pkg/macaroons/go.mod pkg/macaroons/go.sum ./pkg/macaroons/
COPY pkg/kvdb/go.mod pkg/kvdb/go.sum ./pkg/kvdb/
COPY pkg/errors/go.mod pkg/errors/go.sum ./pkg/errors/
COPY pkg/client-lib/go.mod pkg/client-lib/go.sum ./pkg/client-lib/
COPY pkg/client-wallet/go.mod pkg/client-wallet/go.sum ./pkg/client-wallet/

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o /app/bin/arkd-signer ./cmd/arkd-signer/main.go

# Second stage: minimal runtime image
FROM alpine:3.24 AS runtime

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/arkd-signer /app/

ENV PATH="/app:${PATH}"

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -q --spider "http://127.0.0.1:${ARKD_SIGNER_PORT:-6061}/healthz" || exit 1

ENTRYPOINT [ "arkd-signer" ]
