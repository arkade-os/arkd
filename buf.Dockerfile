FROM golang:1.24-alpine3.20 as builder

RUN apk add --no-cache git
RUN wget -qO /usr/local/bin/buf https://github.com/bufbuild/buf/releases/download/v1.55.1/buf-Linux-armv7
RUN chmod u+x /usr/local/bin/buf

RUN go install github.com/meshapi/grpc-api-gateway/codegen/cmd/protoc-gen-grpc-api-gateway@latest
RUN go install github.com/meshapi/grpc-api-gateway/codegen/cmd/protoc-gen-openapiv3@latest
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.9
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

ENTRYPOINT ["/usr/local/bin/buf"]