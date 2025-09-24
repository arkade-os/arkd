package telemetry

import (
	"context"
	"encoding/json"
	"time"

	"github.com/arkade-os/arkd/internal/core/application"
	otelLog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
)

type RoundReportLogExporter struct {
	cancel context.CancelFunc
	logger otelLog.Logger
}

func newRoundReportLogExporter(
	ctx context.Context,
	svc application.RoundReportService,
) (*RoundReportLogExporter, error) {
	lp := global.GetLoggerProvider()
	logger := lp.Logger("ark.round")

	runCtx, cancel := context.WithCancel(ctx)
	e := &RoundReportLogExporter{
		cancel: cancel,
		logger: logger,
	}

	ch := svc.Report()
	go func() {
		for {
			select {
			case <-runCtx.Done():
				return
			case rep, ok := <-ch:
				if !ok || rep == nil {
					return
				}
				e.emit(runCtx, rep)
			}
		}
	}()

	return e, nil
}

type roundStats struct {
	RoundID string                 `json:"round_id"`
	Stats   application.RoundStats `json:"round_stats"`
	Metrics struct {
		LatencySec           float64 `json:"latency_sec"`
		CPUSec               float64 `json:"cpu_sec"`
		CoreEq               float64 `json:"core_eq"`
		UtilizedPct          float64 `json:"utilized_pct"`
		MemAllocDeltaMB      float64 `json:"mem_alloc_delta_mb"`
		MemSysDeltaMB        float64 `json:"mem_sys_delta_mb"`
		MemTotalAllocDeltaMB float64 `json:"mem_total_alloc_delta_mb"`
		GCDelta              uint32  `json:"gc_delta"`
	} `json:"round_metrics"`
	Stages map[string]struct {
		LatencySec float64 `json:"latency_sec"`
	} `json:"stages"`
	Ops map[string]struct {
		LatencySec           float64 `json:"latency_sec"`
		CPUSec               float64 `json:"cpu_sec"`
		CoreEq               float64 `json:"core_eq"`
		UtilizedPct          float64 `json:"utilized_pct"`
		MemAllocDeltaMB      float64 `json:"mem_alloc_delta_mb"`
		MemSysDeltaMB        float64 `json:"mem_sys_delta_mb"`
		MemTotalAllocDeltaMB float64 `json:"mem_total_alloc_delta_mb"`
		GCDelta              uint32  `json:"gc_delta"`
	} `json:"ops"`
}

func (e *RoundReportLogExporter) emit(ctx context.Context, rep *application.RoundReport) {
	rs := roundStats{
		RoundID: rep.RoundID,
		Stats:   rep.Stats,
	}

	// Copy metrics with unit-aware field names
	rs.Metrics.LatencySec = rep.Metrics.Latency
	rs.Metrics.CPUSec = rep.Metrics.CPU
	rs.Metrics.CoreEq = rep.Metrics.CoreEq
	rs.Metrics.UtilizedPct = rep.Metrics.UtilizedPct
	rs.Metrics.MemAllocDeltaMB = rep.Metrics.MemAllocDelta
	rs.Metrics.MemSysDeltaMB = rep.Metrics.MemSysDelta
	rs.Metrics.MemTotalAllocDeltaMB = rep.Metrics.MemTotalAllocDelta
	rs.Metrics.GCDelta = rep.Metrics.GCDelta

	// Copy stages with unit-aware field names
	rs.Stages = make(map[string]struct {
		LatencySec float64 `json:"latency_sec"`
	})
	for stageName, stageMetric := range rep.Stages {
		rs.Stages[stageName] = struct {
			LatencySec float64 `json:"latency_sec"`
		}{
			LatencySec: stageMetric.Latency,
		}
	}

	// Copy ops with unit-aware field names
	rs.Ops = make(map[string]struct {
		LatencySec           float64 `json:"latency_sec"`
		CPUSec               float64 `json:"cpu_sec"`
		CoreEq               float64 `json:"core_eq"`
		UtilizedPct          float64 `json:"utilized_pct"`
		MemAllocDeltaMB      float64 `json:"mem_alloc_delta_mb"`
		MemSysDeltaMB        float64 `json:"mem_sys_delta_mb"`
		MemTotalAllocDeltaMB float64 `json:"mem_total_alloc_delta_mb"`
		GCDelta              uint32  `json:"gc_delta"`
	})
	for opName, opMetric := range rep.Ops {
		rs.Ops[opName] = struct {
			LatencySec           float64 `json:"latency_sec"`
			CPUSec               float64 `json:"cpu_sec"`
			CoreEq               float64 `json:"core_eq"`
			UtilizedPct          float64 `json:"utilized_pct"`
			MemAllocDeltaMB      float64 `json:"mem_alloc_delta_mb"`
			MemSysDeltaMB        float64 `json:"mem_sys_delta_mb"`
			MemTotalAllocDeltaMB float64 `json:"mem_total_alloc_delta_mb"`
			GCDelta              uint32  `json:"gc_delta"`
		}{
			LatencySec:           opMetric.Latency,
			CPUSec:               opMetric.CPU,
			CoreEq:               opMetric.CoreEq,
			UtilizedPct:          opMetric.UtilizedPct,
			MemAllocDeltaMB:      opMetric.MemAllocDelta,
			MemSysDeltaMB:        opMetric.MemSysDelta,
			MemTotalAllocDeltaMB: opMetric.MemTotalAllocDelta,
			GCDelta:              opMetric.GCDelta,
		}
	}

	raw, _ := json.Marshal(rs)

	var rec otelLog.Record
	rec.SetObservedTimestamp(time.Now())
	rec.SetSeverity(otelLog.SeverityInfo)
	rec.SetBody(otelLog.StringValue(string(raw)))
	rec.AddAttributes(
		otelLog.String("log.kind", "round_stats"),
		otelLog.String("round.id", rep.RoundID),
		otelLog.String("round.commitment_txid", rep.Stats.CommitmentTxID),
	)

	e.logger.Emit(ctx, rec)
}

func (e *RoundReportLogExporter) Close(ctx context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}
