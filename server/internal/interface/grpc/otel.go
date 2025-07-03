package grpcservice

import (
	"context"
	"runtime/metrics"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	metricExport "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	traceExport "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

var arkRuntimeMetrics = []string{
	//CPU time in user Go code (not GC or idle). Compare with GC CPU to see if GC is dominating.
	"/cpu/classes/user:cpu-seconds",
	//CPU time spent in garbage collection. Helps detect if GC overhead is large.
	"/cpu/classes/gc/total:cpu-seconds",
	//Total number of completed GC cycles. A high rate may indicate excessive allocation or small heaps.
	"/gc/cycles/total:gc-cycles",
	//Heap memory used by live objects after the last GC cycle. Great for spotting leaks.
	"/gc/heap/live:bytes",
	//Current number of live goroutines. Rises if there's a goroutine leak or concurrency spikes.
	"/sched/goroutines:goroutines",
	//Total memory mapped by the Go runtime. Good for overall runtime footprint.
	"/memory/classes/total:bytes",
	//Approximate total time goroutines have spent blocked on locks. Spikes show contention.
	"/sync/mutex/wait/total:seconds",
	//Cumulative bytes allocated by Go on the heap since process start. Helps gauge allocation rate.
	"/gc/heap/allocs:bytes",
	//Cumulative bytes freed by the garbage collector. Compare with allocs to see net usage.
	"/gc/heap/frees:bytes",
}

func initOtelSDK(
	ctx context.Context, otelCollectorUrl string, pushInterval time.Duration,
) (func(context.Context) error, error) {
	otelCollectorUrl = strings.TrimSuffix(otelCollectorUrl, "/")
	traceExp, err := traceExport.New(
		ctx,
		traceExport.WithEndpoint(strings.TrimPrefix(otelCollectorUrl, "http://")),
		traceExport.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("arkd"),
	)
	tp := trace.NewTracerProvider(
		trace.WithBatcher(traceExp),
		trace.WithResource(res),
	)

	metricExp, err := metricExport.New(
		ctx,
		metricExport.WithEndpoint(strings.TrimPrefix(otelCollectorUrl, "http://")),
		metricExport.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	reader := sdkmetric.NewPeriodicReader(
		metricExp,
		sdkmetric.WithInterval(pushInterval),
	)

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)

	go collectGoRuntimeMetrics(context.Background())

	shutdown := func(ctx context.Context) error {
		err1 := tp.Shutdown(ctx)
		err2 := mp.Shutdown(ctx)
		if err1 != nil {
			return err1
		}
		return err2
	}

	log.Info("otel sdk initialized")

	return shutdown, nil
}

// collectGoRuntimeMetrics is the main function that sets up the OTEL callback
// to read runtime/metrics and publish them as OTel metrics.
func collectGoRuntimeMetrics(ctx context.Context) {
	m := otel.Meter("ark.runtime")
	inst, err := initArkRuntimeInstruments(m)
	if err != nil {
		return
	}

	samples := make([]metrics.Sample, 0, len(arkRuntimeMetrics))
	for _, n := range arkRuntimeMetrics {
		samples = append(samples, metrics.Sample{Name: n})
	}

	serviceUpGauge, err := m.Int64ObservableGauge(
		"ark_service_up",
		metric.WithDescription("1 if arkd service is up"),
	)
	if err != nil {
		log.WithError(err).Error("failed to create ark_service_up gauge")
	}

	instruments := collectInstruments(inst)
	if serviceUpGauge != nil {
		instruments = append(instruments, serviceUpGauge)
	}

	_, err = m.RegisterCallback(
		func(ctx context.Context, obs metric.Observer) error {
			metrics.Read(samples)
			mu.Lock()
			defer mu.Unlock()

			for _, sample := range samples {
				rName := sample.Name
				val := sample.Value
				mType := typeMap[rName]

				switch mType {
				case asCounter:
					switch val.Kind() {
					case metrics.KindUint64:
						obs.ObserveInt64(
							inst.counters[rName],
							int64(val.Uint64()),
							metric.WithAttributes(attribute.String("rt.name", rName)),
						)
					case metrics.KindFloat64:
						obs.ObserveInt64(
							inst.counters[rName],
							int64(val.Float64()),
							metric.WithAttributes(attribute.String("rt.name", rName)),
						)
					}

				case asGauge:
					switch val.Kind() {
					case metrics.KindUint64:
						obs.ObserveInt64(
							inst.gauges[rName],
							int64(val.Uint64()),
							metric.WithAttributes(attribute.String("rt.name", rName)),
						)
					case metrics.KindFloat64:
						obs.ObserveInt64(
							inst.gauges[rName],
							int64(val.Float64()),
							metric.WithAttributes(attribute.String("rt.name", rName)),
						)
					}
				}
			}

			if serviceUpGauge != nil {
				obs.ObserveInt64(serviceUpGauge, 1)
			}

			return nil
		},
		instruments...,
	)
	if err != nil {
		return
	}

	log.Info("otel started collecting runtime metrics")
}

type metricType int

const (
	asGauge metricType = iota
	asCounter
)

var typeMap = map[string]metricType{
	"/cpu/classes/user:cpu-seconds":     asCounter,
	"/cpu/classes/gc/total:cpu-seconds": asCounter,
	"/gc/cycles/total:gc-cycles":        asCounter,
	"/gc/heap/live:bytes":               asGauge,
	"/sched/goroutines:goroutines":      asGauge,
	"/memory/classes/total:bytes":       asGauge,
	"/sync/mutex/wait/total:seconds":    asCounter,
	"/gc/heap/allocs:bytes":             asCounter,
	"/gc/heap/frees:bytes":              asCounter,
}

var mu sync.Mutex

// arkMetricName converts e.g. "/cpu/classes/user:cpu-seconds" to "ark_cpu_classes_user_cpu-seconds"
func arkMetricName(name string) string {
	clean := strings.ReplaceAll(name, "/", "_")
	clean = strings.ReplaceAll(clean, ":", "_")
	for strings.HasPrefix(clean, "_") {
		clean = clean[1:]
	}
	return "ark_" + clean
}

type arkInstruments struct {
	counters map[string]metric.Int64ObservableCounter
	gauges   map[string]metric.Int64ObservableGauge
}

func initArkRuntimeInstruments(m metric.Meter) (*arkInstruments, error) {
	inst := &arkInstruments{
		counters: make(map[string]metric.Int64ObservableCounter),
		gauges:   make(map[string]metric.Int64ObservableGauge),
	}
	for _, rName := range arkRuntimeMetrics {
		mType := typeMap[rName]
		mName := arkMetricName(rName)

		switch mType {
		case asCounter:
			ctr, err := m.Int64ObservableCounter(
				mName,
				metric.WithDescription("runtime metric for "+rName),
			)
			if err != nil {
				return nil, err
			}
			inst.counters[rName] = ctr

		case asGauge:
			g, err := m.Int64ObservableGauge(
				mName,
				metric.WithDescription("runtime metric for "+rName),
			)
			if err != nil {
				return nil, err
			}
			inst.gauges[rName] = g
		}
	}
	return inst, nil
}

func collectInstruments(inst *arkInstruments) []metric.Observable {
	var list []metric.Observable
	for _, c := range inst.counters {
		list = append(list, c)
	}
	for _, g := range inst.gauges {
		list = append(list, g)
	}
	return list
}
