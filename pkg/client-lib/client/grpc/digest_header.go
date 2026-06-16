package grpcclient

import (
	"context"
	"strings"

	"github.com/arkade-os/arkd/pkg/errors"
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

// isDigestMismatch reports whether err is the server's DIGEST_MISMATCH error.
//
// TODO: decode the gRPC status details (arkv1.ErrorDetails) instead of matching
// the error message, once that path works end to end. Until then this matches the
// structured error's name in the message.
func isDigestMismatch(err error) bool {
	return err != nil && strings.Contains(err.Error(), errors.DIGEST_MISMATCH.Name)
}

// withDigestRefresh runs call and, if it fails with the server's DIGEST_MISMATCH
// error (the client's cached digest is stale because the server's config
// changed), refreshes the digest via GetInfo — which is exempt from the digest
// guard — and retries once. A persisting mismatch, or a GetInfo failure, returns
// the original error. At worst the call runs twice with a GetInfo in between.
func withDigestRefresh[T any](
	a *grpcClient, ctx context.Context, call func() (T, error),
) (T, error) {
	res, err := call()
	if !isDigestMismatch(err) {
		return res, err
	}
	if _, infoErr := a.GetInfo(ctx); infoErr != nil {
		var zero T
		return zero, err
	}
	return call()
}
