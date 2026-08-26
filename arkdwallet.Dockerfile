# First stage: build the ark-wallet binary.
# Pinned to BUILDPLATFORM so the Go toolchain runs natively on the builder and cross-compiles to
# TARGETOS/TARGETARCH below. Without this the whole stage runs under QEMU emulation when the target
# architecture differs from the builder, which is far slower for compilation.
FROM --platform=$BUILDPLATFORM golang:1.26.6 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
COPY api-spec/go.mod api-spec/go.sum ./api-spec/
COPY pkg/ark-lib/go.mod pkg/ark-lib/go.sum ./pkg/ark-lib/
COPY pkg/arkd-wallet/go.mod pkg/arkd-wallet/go.sum ./pkg/arkd-wallet/
COPY pkg/macaroons/go.mod pkg/macaroons/go.sum ./pkg/macaroons/
COPY pkg/kvdb/go.mod pkg/kvdb/go.sum ./pkg/kvdb/
COPY pkg/errors/go.mod pkg/errors/go.sum ./pkg/errors/
COPY pkg/client-lib/go.mod pkg/client-lib/go.sum ./pkg/client-lib/
COPY pkg/client-wallet/go.mod pkg/client-wallet/go.sum ./pkg/client-wallet/

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o /app/bin/arkd-wallet ./cmd/arkd-wallet/main.go

# Second stage: minimal runtime image
FROM alpine:3.24

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/arkd-wallet /app/

ENV PATH="/app:${PATH}"
ENV ARKD_WALLET_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "arkd-wallet" ]
