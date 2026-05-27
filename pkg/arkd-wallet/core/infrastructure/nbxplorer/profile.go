package nbxplorer

// THROWAWAY: NBXplorer-startup measurement. Plan:
//   /home/bob/.claude/plans/theres-likely-improvmeents-in-abstract-hummingbird.md
// Remove this file (and references in service.go / wallet service / arkd app
// service) once we've decided which optimizations to ship.

import (
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const profileLogPrefix = "[startup-profile]"

var (
	startupT0       = time.Now()
	globalProfiler  = newProfiler()
	groupIDPattern  = regexp.MustCompile(`/groups/[^/]+`)
	schemePattern   = regexp.MustCompile(`/derivations/[^/]+`)
	txidPattern     = regexp.MustCompile(`/transactions/[0-9a-fA-F]+`)
	scriptPattern   = regexp.MustCompile(`/scripts/[^/]+`)
	addressPattern  = regexp.MustCompile(`/addresses/[^/]+`)
	feesPattern     = regexp.MustCompile(`/fees/\d+`)
	summaryLoggedMu sync.Mutex
	summaryLogged   bool
)

type requestRecord struct {
	method   string
	pattern  string
	duration time.Duration
	status   int
}

type profiler struct {
	mu      sync.Mutex
	records []requestRecord
}

func newProfiler() *profiler {
	return &profiler{records: make([]requestRecord, 0, 64)}
}

func (p *profiler) record(r requestRecord) {
	p.mu.Lock()
	p.records = append(p.records, r)
	p.mu.Unlock()
}

func (p *profiler) snapshot() []requestRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]requestRecord, len(p.records))
	copy(out, p.records)
	return out
}

type profilingTransport struct {
	inner http.RoundTripper
}

func (t *profilingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.inner.RoundTrip(req)
	dur := time.Since(start)

	pattern := endpointPattern(req.URL.Path)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	globalProfiler.record(requestRecord{
		method:   req.Method,
		pattern:  pattern,
		duration: dur,
		status:   status,
	})
	log.Infof(
		"%s nbx-call t+%s %s %s status=%d duration=%s",
		profileLogPrefix, time.Since(startupT0), req.Method, pattern, status, dur,
	)
	return resp, err
}

func newProfilingHTTPClient() *http.Client {
	return &http.Client{
		Transport: &profilingTransport{inner: http.DefaultTransport},
	}
}

func endpointPattern(path string) string {
	p := schemePattern.ReplaceAllString(path, "/derivations/{scheme}")
	p = groupIDPattern.ReplaceAllString(p, "/groups/{id}")
	p = txidPattern.ReplaceAllString(p, "/transactions/{txid}")
	p = scriptPattern.ReplaceAllString(p, "/scripts/{script}")
	p = addressPattern.ReplaceAllString(p, "/addresses/{address}")
	p = feesPattern.ReplaceAllString(p, "/fees/{n}")
	return p
}

// PhaseMark emits a [startup-profile] phase line with the wall-clock offset
// since package load. Safe to call from any goroutine.
func PhaseMark(label string) {
	log.Infof("%s phase=%s t+%s", profileLogPrefix, label, time.Since(startupT0))
}

// LogSummary aggregates everything recorded so far and prints a per-endpoint
// summary plus a TOTAL row. Idempotent: subsequent calls are no-ops so we can
// safely call it from multiple ready paths.
func LogSummary() {
	summaryLoggedMu.Lock()
	if summaryLogged {
		summaryLoggedMu.Unlock()
		return
	}
	summaryLogged = true
	summaryLoggedMu.Unlock()

	records := globalProfiler.snapshot()
	type key struct {
		method, pattern string
	}
	buckets := make(map[key][]time.Duration)
	for _, r := range records {
		k := key{method: r.method, pattern: r.pattern}
		buckets[k] = append(buckets[k], r.duration)
	}

	keys := make([]key, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pattern != keys[j].pattern {
			return keys[i].pattern < keys[j].pattern
		}
		return keys[i].method < keys[j].method
	})

	log.Infof("%s summary t+%s (records=%d)",
		profileLogPrefix, time.Since(startupT0), len(records))
	log.Infof("%s   %-7s %-55s %6s %10s %10s %10s %10s",
		profileLogPrefix, "method", "pattern", "count", "total", "p50", "p95", "max")

	var totalCount int
	var totalDur time.Duration
	for _, k := range keys {
		durs := buckets[k]
		stats := summarize(durs)
		totalCount += len(durs)
		totalDur += stats.total
		log.Infof("%s   %-7s %-55s %6d %10s %10s %10s %10s",
			profileLogPrefix, k.method, truncate(k.pattern, 55),
			len(durs),
			stats.total, stats.p50, stats.p95, stats.max,
		)
	}
	log.Infof("%s   %-7s %-55s %6d %10s",
		profileLogPrefix, "TOTAL", "", totalCount, totalDur)
}

type durStats struct {
	total, p50, p95, max time.Duration
}

func summarize(durs []time.Duration) durStats {
	if len(durs) == 0 {
		return durStats{}
	}
	sorted := make([]time.Duration, len(durs))
	copy(sorted, durs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	idx := func(p float64) time.Duration {
		i := int(float64(len(sorted)-1) * p)
		return sorted[i]
	}
	return durStats{
		total: total,
		p50:   idx(0.50),
		p95:   idx(0.95),
		max:   sorted[len(sorted)-1],
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// init logs the very first marker so we anchor t=0 in the output.
func init() {
	log.Infof("%s phase=%s t+%s", profileLogPrefix, "package_load", time.Since(startupT0))
}
