# First image used to build the sources.
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
COPY pkg/ark-cli/go.mod pkg/ark-cli/go.sum ./pkg/ark-cli/

RUN go mod download && cd pkg/ark-cli && go mod download

COPY . .

# ENV GOPROXY=https://goproxy.io,direct
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o ./bin/arkd ./cmd/arkd
RUN cd pkg/ark-cli && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o ../../bin/ark main.go

# Second image, running the arkd executable
FROM alpine:3.24 AS runtime

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/* /app/

ENV PATH="/app:${PATH}"
ENV ARKD_DATADIR=/app/data

# Expose volume containing all 'arkd' data
VOLUME /app/data

ENTRYPOINT [ "arkd" ]
