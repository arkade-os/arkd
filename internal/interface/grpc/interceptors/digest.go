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

// digestGuardExemptMethods lists the ArkService methods that bypass the digest
// guard. GetInfo is how a client (re)learns the current server digest, so it must
// stay reachable even with a stale or empty digest — otherwise a fresh client, or
// any client after a server-side config change (which rotates the digest), could
// never obtain a valid digest and would be permanently locked out.
var digestGuardExemptMethods = map[string]struct{}{
	arkv1.ArkService_GetInfo_FullMethodName: {},
}

func unaryDigestHandler(getDigest func() (string, bool, error)) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		if !skipDigestGuard(info.FullMethod) {
			expectedDigest, guardEnabled, err := getDigest()
			if err != nil {
				return nil, errors.INTERNAL_ERROR.New(
					"failed to verify digest header, retry later",
				)
			}
			// A present digest is always validated against the expected one;
			// an absent (empty) digest is rejected only when the header is
			// required. guardEnabled therefore governs only the missing-header
			// case, not whether a provided digest is checked.
			digest := digestHeaderValue(ctx)
			if digest != expectedDigest && (guardEnabled || digest != "") {
				return nil, errors.DIGEST_MISMATCH.
					New("invalid digest header").WithMetadata(errors.DigestMetadata{
					ExpectedDigest: expectedDigest,
					GotDigest:      digest,
				})
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
		if !skipDigestGuard(info.FullMethod) {
			expectedDigest, guardEnabled, err := getDigest()
			if err != nil {
				return errors.INTERNAL_ERROR.New("failed to verify digest header, retry later")
			}
			// A present digest is always validated against the expected one;
			// an absent (empty) digest is rejected only when the header is
			// required. guardEnabled therefore governs only the missing-header
			// case, not whether a provided digest is checked.
			digest := digestHeaderValue(ss.Context())
			if digest != expectedDigest && (guardEnabled || digest != "") {
				return errors.DIGEST_MISMATCH.
					New("invalid digest header").WithMetadata(errors.DigestMetadata{
					ExpectedDigest: expectedDigest,
					GotDigest:      digest,
				})
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

// skipDigestGuard reports whether fullMethod is exempt from the digest check:
// any non-ArkService method, plus the ArkService bootstrap/read methods in the
// exempt list (e.g. GetInfo, which a client must reach to learn the digest).
func skipDigestGuard(fullMethod string) bool {
	if !strings.Contains(fullMethod, arkv1.ArkService_ServiceDesc.ServiceName) {
		return true
	}
	_, exempt := digestGuardExemptMethods[fullMethod]
	return exempt
}
