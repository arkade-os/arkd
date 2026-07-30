# First stage: build the arkd-signer binary
FROM golang:1.26.5 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o /app/bin/arkd-signer ./cmd/arkd-signer/main.go

# Second stage: minimal runtime image
FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/arkd-signer /app/

ENV PATH="/app:${PATH}"

# /healthz maps a NOT_SERVING health response to 503, and the signer reports
# NOT_SERVING until its key is usable, so this gates on readiness rather than on
# the process having started.
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -q --spider "http://127.0.0.1:${ARKD_SIGNER_PORT:-6061}/healthz" || exit 1

ENTRYPOINT [ "arkd-signer" ]
