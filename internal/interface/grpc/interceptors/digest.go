package interceptors

import (
	"context"
	"strings"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const digestHeader = "x-digest"

func unaryDigestHandler(getDigest func() (string, bool, error)) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		if strings.Contains(info.FullMethod, arkv1.ArkService_ServiceDesc.ServiceName) {
			expectedDigest, guardEnabled, err := getDigest()
			if err != nil {
				return nil, errors.INTERNAL_ERROR.New(
					"failed to verify digest header, retry later",
				)
			}
			if guardEnabled {
				digest := digestHeaderValue(ctx)
				if digest != expectedDigest {
					return nil, errors.DIGEST_MISMATCH.
						New("invalid digest header").WithMetadata(errors.DigestMetadata{
						ExpectedDigest: expectedDigest,
						GotDigest:      digest,
					})
				}
			}
		}
		return handler(ctx, req)
	}
}

func streamDigestHandler(
	getDigest func() (string, bool, error),
) grpc.StreamServerInterceptor {
	return func(
		srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		if strings.Contains(info.FullMethod, arkv1.ArkService_ServiceDesc.ServiceName) {
			expectedDigest, guardEnabled, err := getDigest()
			if err != nil {
				return errors.INTERNAL_ERROR.New("failed to verify version header, retry later")
			}
			if guardEnabled {
				digest := digestHeaderValue(ss.Context())
				if digest != expectedDigest {
					return errors.DIGEST_MISMATCH.
						New("invalid digest header").WithMetadata(errors.DigestMetadata{
						ExpectedDigest: expectedDigest,
						GotDigest:      digest,
					})
				}
			}
		}
		return handler(srv, ss)
	}
}

func digestHeaderValue(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(digestHeader)
	if len(vals) <= 0 {
		return ""
	}
	return vals[0]
}
