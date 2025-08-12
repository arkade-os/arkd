FROM golang:1.24.6-alpine3.20 as builder

RUN apk add --no-cache git

RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26.0
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0

FROM bufbuild/buf

COPY --from=builder /go/bin/protoc-gen-openapiv2 /usr/local/bin/protoc-gen-openapiv2
COPY --from=builder /go/bin/protoc-gen-grpc-gateway /usr/local/bin/protoc-gen-grpc-gateway
COPY --from=builder /go/bin/protoc-gen-go /usr/local/bin/protoc-gen-go
COPY --from=builder /go/bin/protoc-gen-go-grpc /usr/local/bin/protoc-gen-go-grpc

ENTRYPOINT ["/usr/local/bin/buf"]
