package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/trace"
)

type OTelHook struct {
}

func NewOTelHook() *OTelHook {
	return &OTelHook{}
}

func (h *OTelHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func mapLevel(l logrus.Level) log.Severity {
	switch l {
	case logrus.PanicLevel:
		return log.SeverityFatal
	case logrus.FatalLevel:
		return log.SeverityFatal
	case logrus.ErrorLevel:
		return log.SeverityError
	case logrus.WarnLevel:
		return log.SeverityWarn
	case logrus.InfoLevel:
		return log.SeverityInfo
	case logrus.DebugLevel:
		return log.SeverityDebug
	case logrus.TraceLevel:
		return log.SeverityTrace
	default:
		return log.SeverityInfo
	}
}

func (h *OTelHook) Fire(e *logrus.Entry) error {
	// extract trace context for correlation
	ctx := e.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// add trace_id and span_id to Logrus entry fields for Docker stdout logs
	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.IsValid() {
		e.Data["trace_id"] = spanCtx.TraceID().String()
		e.Data["span_id"] = spanCtx.SpanID().String()
	}

	// Create OTel log record
	rec := log.Record{}
	rec.SetTimestamp(e.Time)
	rec.SetSeverity(mapLevel(e.Level))
	rec.SetBody(log.StringValue(e.Message))

	rec.AddAttributes(
		log.String("log.kind", "app"),
		log.String("logger", "arkd.wallet"),
		log.String("level", e.Level.String()),
	)

	// include fields as attributes
	for k, v := range e.Data {
		rec.AddAttributes(log.String(k, toString(v)))
	}

	// observed ts (optional)
	rec.SetObservedTimestamp(time.Now())
	logger := global.GetLoggerProvider().Logger("arkd.wallet")
	logger.Emit(ctx, rec)

	if e.Level <= logrus.ErrorLevel {
		type flusher interface {
			ForceFlush(context.Context) error
		}
		if f, ok := global.GetLoggerProvider().(flusher); ok {
			// Bound the flush to avoid freezing the caller if the OTLP/Loki
			// endpoint is slow or unreachable.
			flushCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			//nolint:errcheck // ignoring flush error on purpose: logging it
			// from inside a log hook would risk infinite recursion.
			f.ForceFlush(flushCtx)
			cancel()
		}
	}

	return nil
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprintf("%v", v)
	}
}
