package interceptors

import (
	"context"
	"sync/atomic"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const digestHeaderKey = "x-ark-digest"

// DigestService holds the current server digest. It is safe for concurrent use.
type DigestService struct {
	digest atomic.Value // stores string
}

// NewDigestService creates a new DigestService.
func NewDigestService() *DigestService {
	return &DigestService{}
}

// SetDigest stores the current digest value.
func (d *DigestService) SetDigest(digest string) {
	d.digest.Store(digest)
}

// checkDigest validates the client-supplied digest header against the stored
// digest. Returns nil when validation passes or isn't applicable.
func (d *DigestService) checkDigest(fullMethod string, md metadata.MD) error {
	// Skip GetInfo — clients call it to obtain the digest.
	if fullMethod == arkv1.ArkService_GetInfo_FullMethodName {
		return nil
	}

	// Only validate public service methods (ArkService / IndexerService).
	if !isPublicServiceMethod(fullMethod) {
		return nil
	}

	// If no digest has been stored yet, skip.
	stored, ok := d.digest.Load().(string)
	if !ok || stored == "" {
		return nil
	}

	// If the client didn't send the header, skip (opt-in).
	vals := md.Get(digestHeaderKey)
	if len(vals) == 0 {
		return nil
	}

	clientDigest := vals[0]
	if clientDigest == stored {
		return nil
	}

	return gRPCError{
		arkerrors.DIGEST_MISMATCH.
			New("digest mismatch: server parameters have changed, please call GetInfo again").
			WithMetadata(arkerrors.DigestMismatchMetadata{
				CurrentDigest: stored,
			}),
	}
}

func unaryDigestValidator(d *DigestService) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req any,
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		if err := d.checkDigest(info.FullMethod, md); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamDigestValidator(d *DigestService) grpc.StreamServerInterceptor {
	return func(
		srv any, stream grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		if err := d.checkDigest(info.FullMethod, md); err != nil {
			return err
		}
		return handler(srv, stream)
	}
}
