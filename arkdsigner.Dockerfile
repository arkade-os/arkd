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

ENTRYPOINT [ "arkd-signer" ]
