package interceptors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var sensitiveRequestFields = map[string]struct{}{
	"macaroon":      {},
	"password":      {},
	"secret":        {},
	"authorization": {},
	"seed":          {},
}

// metadataOfInterest is the allowlist of incoming gRPC metadata keys we log.
// gRPC lowercases all incoming metadata keys, so entries here must be lowercase.
var metadataOfInterest = map[string]struct{}{
	"x-build-version": {},
	"x-sdk-version":   {},
	"x-digest":        {},
}

func unaryLogger(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	logUnaryCall(info.FullMethod, req, ctx, time.Since(start), err)
	return resp, err
}

func streamLogger(
	srv any, stream grpc.ServerStream,
	info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	start := time.Now()
	err := handler(srv, stream)
	logStreamCall(info.FullMethod, stream.Context(), time.Since(start), err)
	return err
}

func logUnaryCall(method string, req any, ctx context.Context, dur time.Duration, err error) {
	str := fmt.Sprintf("method=%s duration=%dms", method, dur.Milliseconds())

	if log.IsLevelEnabled(log.DebugLevel) {
		if sanitizedReq, ok := sanitizeRequest(req); ok && sanitizedReq != "{}" {
			str += fmt.Sprintf(" request=%s", sanitizedReq)
		}
		if md, ok := sanitizeMetadata(ctx); ok {
			str += fmt.Sprintf(" metadata=%s", md)
		}
	}

	if err != nil {
		logStructuredError(err)
		log.WithError(err).Warn(str)
		return
	}

	log.Debug(str)
}

func logStreamCall(method string, ctx context.Context, dur time.Duration, err error) {
	str := fmt.Sprintf("method=%s duration=%dms", method, dur.Milliseconds())

	if log.IsLevelEnabled(log.DebugLevel) {
		if md, ok := sanitizeMetadata(ctx); ok {
			str += fmt.Sprintf(" metadata=%s", md)
		}
	}

	if err != nil {
		logStructuredError(err)
		log.WithError(err).Warn(str)
		return
	}

	log.Debug(str)
}

func logStructuredError(err error) {
	var structuredErr arkerrors.Error
	if errors.As(err, &structuredErr) {
		if structuredErr.Code() == arkerrors.INTERNAL_ERROR.Code {
			structuredErr.Log().Error(err)
		}
	}
}

func sanitizeMetadata(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md) == 0 {
		return "", false
	}

	selected := make(map[string]interface{})
	for key := range metadataOfInterest {
		vals := md.Get(key)
		if len(vals) == 0 {
			continue
		}
		if isSensitiveField(key) {
			selected[key] = "******"
			continue
		}
		if len(vals) == 1 {
			selected[key] = vals[0]
			continue
		}
		selected[key] = vals
	}

	if len(selected) == 0 {
		return "", false
	}

	formatted, err := json.Marshal(selected)
	if err != nil {
		return "", false
	}

	return string(formatted), true
}

func sanitizeRequest(req any) (string, bool) {
	if req == nil {
		return "", false
	}

	raw, err := json.Marshal(req)
	if err != nil {
		return "", false
	}

	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", false
	}

	sanitized := redactSensitiveFields(decoded)
	formatted, err := json.Marshal(sanitized)
	if err != nil {
		return "", false
	}

	return string(formatted), true
}

func redactSensitiveFields(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		redacted := make(map[string]interface{}, len(v))
		for key, item := range v {
			if isSensitiveField(key) {
				redacted[key] = "******"
				continue
			}
			redacted[key] = redactSensitiveFields(item)
		}
		return redacted
	case []interface{}:
		redacted := make([]interface{}, len(v))
		for i, item := range v {
			redacted[i] = redactSensitiveFields(item)
		}
		return redacted
	default:
		return v
	}
}

func isSensitiveField(name string) bool {
	normalized := normalizeFieldName(name)
	if _, ok := sensitiveRequestFields[normalized]; ok {
		return true
	}

	for sensitive := range sensitiveRequestFields {
		if strings.Contains(normalized, sensitive) {
			return true
		}
	}

	return false
}

func normalizeFieldName(name string) string {
	var builder strings.Builder
	builder.Grow(len(name))

	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}

	return strings.ToLower(builder.String())
}
