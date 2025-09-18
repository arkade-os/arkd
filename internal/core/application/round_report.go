package application

import (
	"runtime"
	"runtime/metrics"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	ConfirmationStage         = "confirmation_stage"
	TreeNoncesCollectionStage = "tree_nonces_collection_stage"
	TreeSigsCollectionStage   = "tree_signaturea_collection_stage"
	ForfeitTxsCollectionStage = "forfeit_txs_collection_stage"

	BuildCommitmentTxOp          = "build_commitment_tx_op"
	GetNoncesOperatorOp          = "get_nonces_op"
	AggregateNoncesCoordinatorOp = "aggregate_nonces_op"
	SignCommitmentTxOp           = "sign_commitment_tx_op"
	SignTxOperatorOp             = "sign_tx_op"
	VerifyForfeitsSignaturesOp   = "verify_forfeits_signatures_op"
)

type RoundReportService interface {
	RoundStarted(roundID string)
	SetIntentsNum(numIntents int)
	RoundEnded(commitmentTxID string, totalInputs int, totalOutputs int, numTreeNodes int)
	StageStarted(stage string)
	StageEnded(stage string)
	OpStarted(op string)
	OpEnded(op string)
	Report() <-chan *RoundReport
	Close()
}

func NewRoundReportService() RoundReportService {
	log.Info("round report service running")
	return &roundReportSvc{
		numLogical:  runtime.NumCPU(),
		stageStarts: make(map[string]time.Time),
		opSamples:   make(map[string]sample),
		reportCh:    make(chan *RoundReport, 1),
	}
}

type roundReportSvc struct {
	mu         sync.Mutex
	numLogical int

	roundID     string
	roundSample sample
	stageStarts map[string]time.Time
	opSamples   map[string]sample
	rep         *RoundReport

	reportCh chan *RoundReport
	closed   bool
}

func (r *roundReportSvc) RoundStarted(roundID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.roundID = roundID
	r.roundSample = sample{t0: time.Now(), c0: procCPUTime(), m0: readMem()}
	r.stageStarts = make(map[string]time.Time)
	r.opSamples = make(map[string]sample)
	r.rep = &RoundReport{
		RoundID: roundID,
		Stages:  make(map[string]StageMetric),
		Ops:     make(map[string]OpMetric),
	}
}

func (r *roundReportSvc) SetIntentsNum(numIntents int) {
	r.mu.Lock()
	if r.rep != nil {
		r.rep.Stats.NumIntents = numIntents
	}
	r.mu.Unlock()
}

func (r *roundReportSvc) RoundEnded(
	commitmentTxID string,
	totalInputs, totalOutputs, numTreeNodes int,
) {
	r.mu.Lock()
	if r.rep == nil {
		r.mu.Unlock()
		return
	}
	s := r.roundSample
	rep := r.rep
	r.roundID = "" // mark inactive
	r.mu.Unlock()

	lat := time.Since(s.t0)
	cpu := procCPUTime() - s.c0
	core := safeRatio(cpu, lat)
	util := core / float64(r.numLogical) * 100
	m1 := readMem()

	rep.Stats.CommitmentTxID = commitmentTxID
	rep.Stats.TotalInputVtxos = totalInputs
	rep.Stats.TotalOutputVtxos = totalOutputs
	rep.Stats.NumTreeNodes = numTreeNodes

	rep.Metrics.Latency = lat.Seconds()
	rep.Metrics.CPU = cpu.Seconds()
	rep.Metrics.CoreEq = core
	rep.Metrics.UtilizedPct = util
	rep.Metrics.MemAllocDelta = float64(int64(m1.allocLive)-int64(s.m0.allocLive)) / (1024 * 1024)
	rep.Metrics.MemSysDelta = float64(int64(m1.sys)-int64(s.m0.sys)) / (1024 * 1024)
	rep.Metrics.MemTotalAllocDelta = float64(
		int64(m1.totalAlloc)-int64(s.m0.totalAlloc),
	) / (1024 * 1024)
	if m1.numGC >= s.m0.numGC {
		rep.Metrics.GCDelta = m1.numGC - s.m0.numGC
	}

	select {
	case r.reportCh <- rep:
	default:
	}

	log.Debugf("round stats: %+v", rep.Stats)
	log.Debugf("round metrics: %+v", rep.Metrics)
	log.Debugf("round stages: %+v", rep.Stages)
	log.Debugf("round ops: %+v", rep.Ops)
}

func (r *roundReportSvc) StageStarted(stage string) {
	r.mu.Lock()
	if r.rep != nil {
		r.stageStarts[stage] = time.Now()
	}
	r.mu.Unlock()
}

func (r *roundReportSvc) StageEnded(stage string) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rep == nil {
		return
	}
	if t0, ok := r.stageStarts[stage]; ok {
		r.rep.Stages[stage] = StageMetric{Latency: now.Sub(t0).Seconds()}
		delete(r.stageStarts, stage)
	}
}

func (r *roundReportSvc) OpStarted(op string) {
	r.mu.Lock()
	if r.rep != nil {
		r.opSamples[op] = sample{t0: time.Now(), c0: procCPUTime(), m0: readMem()}
	}
	r.mu.Unlock()
}

func (r *roundReportSvc) OpEnded(op string) {
	r.mu.Lock()
	s, ok := r.opSamples[op]
	rep := r.rep
	r.mu.Unlock()

	if !ok || rep == nil {
		return
	}

	lat := time.Since(s.t0)
	cpu := procCPUTime() - s.c0
	core := safeRatio(cpu, lat)
	util := core / float64(r.numLogical) * 100
	m1 := readMem()

	r.mu.Lock()
	if r.rep != nil {
		r.rep.Ops[op] = OpMetric{
			Latency:       lat.Seconds(),
			CPU:           cpu.Seconds(),
			CoreEq:        core,
			UtilizedPct:   util,
			MemAllocDelta: float64(int64(m1.allocLive)-int64(s.m0.allocLive)) / (1024 * 1024),
			MemSysDelta:   float64(int64(m1.sys)-int64(s.m0.sys)) / (1024 * 1024),
			MemTotalAllocDelta: float64(
				int64(m1.totalAlloc)-int64(s.m0.totalAlloc),
			) / (1024 * 1024),
			GCDelta: deltaGC(m1.numGC, s.m0.numGC),
		}
	}
	r.mu.Unlock()
}

func (r *roundReportSvc) Report() <-chan *RoundReport { return r.reportCh }

func (r *roundReportSvc) Close() {
	r.mu.Lock()
	if !r.closed {
		close(r.reportCh)
		r.closed = true
	}
	r.mu.Unlock()
}

type RoundReport struct {
	RoundID string                 `json:"round_id"`
	Stats   RoundStats             `json:"round_stats"`
	Metrics RoundMetrics           `json:"round_metrics"`
	Stages  map[string]StageMetric `json:"stages"`
	Ops     map[string]OpMetric    `json:"ops"`
}

type RoundStats struct {
	NumIntents       int    `json:"num_intents"`
	TotalInputVtxos  int    `json:"total_input_vtxos"`
	TotalOutputVtxos int    `json:"total_output_vtxos"`
	NumTreeNodes     int    `json:"num_tree_nodes"`
	CommitmentTxID   string `json:"commitment_txid"`
}

type RoundMetrics struct {
	Latency            float64 // seconds
	CPU                float64 // seconds
	CoreEq             float64 // equivalent CPU cores used (CPU time / wall-clock time)
	UtilizedPct        float64 // CPU utilization percentage across all logical cores
	MemAllocDelta      float64 // MB
	MemSysDelta        float64 // MB
	MemTotalAllocDelta float64 // MB
	GCDelta            uint32
}

// Example metrics calculation:
// If a process runs for 10 seconds but only uses CPU for 2 seconds:
// - Latency = 10.0 seconds (wall-clock time)
// - CPU = 2.0 seconds (actual CPU time consumed)
// - CoreEq = 0.2 (2.0 / 10.0 = equivalent to 0.2 cores running continuously)
// - UtilizedPct = 20% on single-core system (0.2 / 1 * 100)
//               = 5% on 4-core system (0.2 / 4 * 100)

type StageMetric struct{ Latency float64 } // seconds

type OpMetric struct {
	Latency            float64 // seconds
	CPU                float64 // seconds
	CoreEq             float64
	UtilizedPct        float64
	MemAllocDelta      float64 // MB
	MemSysDelta        float64 // MB
	MemTotalAllocDelta float64 // MB
	GCDelta            uint32
}

type roundMem struct {
	allocLive, sys, totalAlloc uint64
	numGC                      uint32
}

type sample struct {
	t0 time.Time
	c0 time.Duration
	m0 roundMem
}

func procCPUTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	u := time.Duration(ru.Utime.Sec)*time.Second + time.Duration(ru.Utime.Usec)*time.Microsecond
	s := time.Duration(ru.Stime.Sec)*time.Second + time.Duration(ru.Stime.Usec)*time.Microsecond
	return u + s
}

func safeRatio(cpu, latency time.Duration) float64 {
	if latency <= 0 {
		return 0
	}
	return float64(cpu) / float64(latency)
}

func readMem() roundMem {
	return roundMem{
		allocLive:  loadUint64("/gc/heap/live:bytes"),
		sys:        loadUint64("/memory/classes/total:bytes"),
		totalAlloc: loadUint64("/gc/heap/allocs:bytes"),
		numGC:      uint32(loadUint64("/gc/cycles/total:gc-cycles")),
	}
}

func loadUint64(name string) uint64 {
	s := []metrics.Sample{{Name: name}}
	metrics.Read(s)
	if len(s) == 0 {
		return 0
	}
	v := s[0].Value
	switch v.Kind() {
	case metrics.KindUint64:
		return v.Uint64()
	case metrics.KindFloat64:
		return uint64(v.Float64())
	default:
		return 0
	}
}

func deltaGC(a, b uint32) uint32 {
	if a >= b {
		return a - b
	}
	return 0
}

var closedRoundReportCh = func() chan *RoundReport {
	ch := make(chan *RoundReport)
	close(ch)
	return ch
}()

type roundReportUnimplemented struct{}

func (roundReportUnimplemented) RoundStarted(roundID string)  {}
func (roundReportUnimplemented) SetIntentsNum(numIntents int) {}

func (roundReportUnimplemented) RoundEnded(
	commitmentTxID string,
	totalInputs int,
	totalOutputs int,
	numTreeNodes int,
) {
}
func (roundReportUnimplemented) StageStarted(stage string) {}
func (roundReportUnimplemented) StageEnded(stage string)   {}
func (roundReportUnimplemented) OpStarted(op string)       {}
func (roundReportUnimplemented) OpEnded(op string)         {}
func (roundReportUnimplemented) Report() <-chan *RoundReport {
	return closedRoundReportCh
}
func (roundReportUnimplemented) Close() {}
