package grpcclient

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	// digestHeader is the gRPC metadata key carrying the latest digest fetched from GetInfo.
	// If outdated, the client receives DIGEST_MISMATCH error and so it can fetch the new config
	// params, update the header and try again.
	digestHeader = "x-digest"
)

// unaryDigestInterceptor returns a gRPC unary client interceptor that sets digestHeader=digest to
// the outgoing metadata of every unary RPC.
func unaryDigestInterceptor(getDigest func() string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context, method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
	) error {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(digestHeader, getDigest())
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// streamVersionInterceptor returns a gRPC stream client interceptor that sets dogestHeader=version
// to the outgoing metadata of every streaming RPC, including reconnecting streams dispatched
// through the same connection.
func streamDigestInterceptor(getDigest func() string) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
		method string, streamer grpc.Streamer, opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(digestHeader, getDigest())
		ctx = metadata.NewOutgoingContext(ctx, md)
		return streamer(ctx, desc, cc, method, opts...)
	}
}
