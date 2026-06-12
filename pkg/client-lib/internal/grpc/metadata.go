// Package internalgrpc provides shared gRPC client plumbing for client-lib,
// notably the x-build-version metadata interceptors that advertise the client
// build version to arkd on every outgoing RPC.
package internalgrpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// BuildVersionHeader is the gRPC metadata key carrying the client build
// version. It must match the key the arkd server reads via md.Get on the
// version interceptor (internal/interface/grpc/interceptors/version.go).
// gRPC normalises all metadata keys to lowercase.
const BuildVersionHeader = "x-build-version"

// ClientBuildVersion is the value injected into the BuildVersionHeader on every
// outgoing gRPC call made through client-lib. It defaults to "0.0.0" and is
// intended to be overridden at link time by downstream consumers.
//
// Override at build time via ldflags:
//
//	-ldflags "-X github.com/arkade-os/arkd/pkg/client-lib/internal/grpc.ClientBuildVersion=1.2.3"
//
// Or set it programmatically before calling NewWallet/LoadWallet/Init.
//
// WARNING: the default "0.0.0" is safe only while the server keeps
// MIN_BUILD_VERSION_HEADER_REQUIRED=false (the current default). Once an
// operator enables MIN_BUILD_VERSION_HEADER_REQUIRED=true on a v0.9.x+ server
// (PR #1096), a "0.0.0" header is rejected under the default "minor" guard
// level because clientMinor(0) < serverMinor(9), failing every ArkService and
// IndexerService RPC. Production builds (go-sdk, fulmine) MUST inject their
// real semver version via the ldflags pattern above before that flag is
// enabled. ArkService and IndexerService are NOT exempt from the guard.
var ClientBuildVersion = "0.0.0"

// BuildVersionUnaryInterceptor returns a gRPC unary client interceptor that
// appends BuildVersionHeader=version to the outgoing metadata of every unary
// RPC. version is captured once in the closure at dial time, so there is no
// per-call lookup cost beyond the metadata append.
//
// AppendToOutgoingContext (not NewOutgoingContext) is used so that any metadata
// already set by a caller above this interceptor (e.g. auth tokens) is
// preserved rather than overwritten.
func BuildVersionUnaryInterceptor(version string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(BuildVersionHeader, version)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// BuildVersionStreamInterceptor returns a gRPC stream client interceptor that
// appends BuildVersionHeader=version to the outgoing metadata of every
// streaming RPC, including reconnecting streams dispatched through the same
// connection. version is captured once in the closure at dial time.
//
// As with the unary interceptor, AppendToOutgoingContext preserves any
// caller-provided outgoing metadata.
func BuildVersionStreamInterceptor(version string) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(BuildVersionHeader, version)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return streamer(ctx, desc, cc, method, opts...)
	}
}
