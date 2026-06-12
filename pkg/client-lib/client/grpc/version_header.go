package grpcclient

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	// buildVersionHeader is the gRPC metadata key carrying the client build
	// version. It must match the key the arkd server reads via md.Get on the
	// version interceptor (internal/interface/grpc/interceptors/version.go).
	// gRPC normalises all metadata keys to lowercase.
	buildVersionHeader = "x-build-version"
	buildVersion       = "0.9.9"
)

// unaryVersionInterceptor returns a gRPC unary client interceptor that appends
// buildVersionHeader=buildVersion to the outgoing metadata of every unary RPC.
// version is captured once in the closure at dial time, so there is no
// per-call lookup cost beyond the metadata append.
//
// AppendToOutgoingContext (not NewOutgoingContext) is used so that any metadata
// already set by a caller above this interceptor (e.g. auth tokens) is
// preserved rather than overwritten.
func unaryVersionInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context, method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
	) error {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(buildVersionHeader, buildVersion)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// streamVersionInterceptor returns a gRPC stream client interceptor that
// appends BuildVersionHeader=version to the outgoing metadata of every
// streaming RPC, including reconnecting streams dispatched through the same
// connection. version is captured once in the closure at dial time.
//
// As with the unary interceptor, AppendToOutgoingContext preserves any
// caller-provided outgoing metadata.
func streamVersionInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
		method string, streamer grpc.Streamer, opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(buildVersionHeader, buildVersion)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return streamer(ctx, desc, cc, method, opts...)
	}
}
