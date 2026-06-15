package grpcclient

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	// clientVersionHeader is the gRPC metadata key carrying the client build version.
	// It must match the key the arkd server reads via md.Get on the version interceptor
	// (internal/interface/grpc/interceptors/version.go).
	// gRPC normalises all metadata keys to lowercase.
	clientVersionHeader = "x-sdk-version"
)

// unaryClientVersionInterceptor returns a gRPC unary client interceptor that sets
// clientVersionHeader=version to the outgoing metadata of every unary RPC.
func unaryClientVersionInterceptor(version string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context, method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
	) error {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(clientVersionHeader, version)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// streamClientVersionInterceptor returns a gRPC stream client interceptor that sets
// clientVersionHeader=version to the outgoing metadata of every streaming RPC
func streamClientVersionInterceptor(version string) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
		method string, streamer grpc.Streamer, opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(clientVersionHeader, version)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return streamer(ctx, desc, cc, method, opts...)
	}
}
