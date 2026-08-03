# First image used to build the sources.
# Pinned to BUILDPLATFORM so the Go toolchain runs natively on the builder and cross-compiles to
# TARGETOS/TARGETARCH below. Without this the whole stage runs under QEMU emulation when the target
# architecture differs from the builder, which is far slower for compilation.
FROM --platform=$BUILDPLATFORM golang:1.26.5 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

# ENV GOPROXY=https://goproxy.io,direct
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o ./bin/arkd ./cmd/arkd
RUN cd pkg/ark-cli && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o ../../bin/ark main.go

# Second image, running the arkd executable
FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/* /app/

ENV PATH="/app:${PATH}"
ENV ARKD_DATADIR=/app/data

# Expose volume containing all 'arkd' data
VOLUME /app/data

ENTRYPOINT [ "arkd" ]
