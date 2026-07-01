// probe-vtxo-chain probes arkd's GetVtxoChain indexer endpoint against a set
// of outpoints sampled from a real projection DB, records per-call latency
// and chain length, and supports comparing results between two runs (e.g.
// master vs bob/dag-1) to quantify the DAG enhancement on real-world chains.
//
// Two modes:
//
//	probe (default): connect to the projection DB, pick or load a candidate
//	    outpoint set, time GetVtxoChain on each via gRPC, write JSON results.
//
//	compare (-compare): load two probe result files, match by outpoint,
//	    report per-outpoint and aggregate latency deltas plus speedup stats.
//
// Build once from bob/dag-1; the binary talks to arkd via gRPC and works
// against any arkd build.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/types"

	_ "github.com/lib/pq"
)

var (
	dsn = flag.String(
		"dsn",
		"postgresql://replay2826@127.0.0.1:5433/projection?sslmode=disable",
		"DSN for the projection postgres",
	)
	serverURL = flag.String(
		"server-url", "127.0.0.1:7070",
		"arkd gRPC address",
	)
	sampleSize = flag.Int(
		"sample-size", 50,
		"Number of candidate outpoints to probe (ignored if -outpoints-file already exists)",
	)
	topK = flag.Int(
		"top-k", 20,
		"How many of the longest chains to print in detail",
	)
	discoverDeep = flag.Bool(
		"discover-deep", false,
		"Run a recursive CTE on the projection to pre-select tips of long chains "+
			"(expensive once per dump). Cached via -outpoints-file.",
	)
	perProbeTimeout = flag.Duration(
		"per-probe-timeout", 90*time.Second,
		"Per-call timeout for GetVtxoChain. Real prod chains can be slow; "+
			"set generously enough that the deepest chain finishes.",
	)
	outpointsFile = flag.String(
		"outpoints-file", "",
		"JSON file with the outpoint set. If it exists, outpoints are loaded "+
			"from it (this is how the A/B keeps both runs probing identical "+
			"outpoints). If it doesn't exist, candidates are picked and written here.",
	)
	resultsFile = flag.String(
		"results-file", "",
		"Write probe results to this JSON file (for later -compare)",
	)
	label = flag.String(
		"label", "",
		"Label embedded in results-file (e.g. \"master\", \"dag-1\")",
	)

	compareMode = flag.Bool(
		"compare", false,
		"Compare two probe result files (set -baseline and -candidate)",
	)
	baselineFile = flag.String(
		"baseline", "",
		"Baseline probe results JSON (e.g. master)",
	)
	candidateFile = flag.String(
		"candidate", "",
		"Candidate probe results JSON (e.g. dag-1)",
	)
	csvOut = flag.String(
		"csv", "",
		"In -compare mode, write per-outpoint deltas to this CSV",
	)
)

type outpoint struct {
	Txid string `json:"txid"`
	VOut uint32 `json:"vout"`
}

type probeResult struct {
	Txid       string `json:"txid"`
	VOut       uint32 `json:"vout"`
	ChainLen   int    `json:"chain_len"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

func (p probeResult) key() string { return fmt.Sprintf("%s:%d", p.Txid, p.VOut) }

type results struct {
	Label   string        `json:"label"`
	RanAt   string        `json:"ran_at"`
	Server  string        `json:"server"`
	DSN     string        `json:"dsn"`
	Timeout time.Duration `json:"per_probe_timeout"`
	Probes  []probeResult `json:"probes"`
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	if *compareMode {
		return runCompare()
	}
	return runProbe()
}

func runProbe() error {
	ctx := context.Background()

	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		return fmt.Errorf("open projection: %w", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping projection: %w", err)
	}

	outpoints, err := loadOrPickOutpoints(ctx, db)
	if err != nil {
		return err
	}
	if len(outpoints) == 0 {
		return errors.New("no candidate outpoints")
	}
	fmt.Fprintf(os.Stderr, "probing %d outpoints (label=%q, server=%s)\n",
		len(outpoints), *label, *serverURL)

	idx, err := grpcindexer.NewClient(*serverURL)
	if err != nil {
		return fmt.Errorf("dial indexer: %w", err)
	}

	res := results{
		Label:   *label,
		RanAt:   time.Now().UTC().Format(time.RFC3339),
		Server:  *serverURL,
		DSN:     *dsn,
		Timeout: *perProbeTimeout,
		Probes:  make([]probeResult, 0, len(outpoints)),
	}

	overallStart := time.Now()
	for i, op := range outpoints {
		probeCtx, cancel := context.WithTimeout(ctx, *perProbeTimeout)
		start := time.Now()
		resp, err := idx.GetVtxoChain(probeCtx, types.Outpoint{
			Txid: op.Txid, VOut: op.VOut,
		})
		dur := time.Since(start)
		cancel()

		chainLen := 0
		if resp != nil {
			chainLen = len(resp.Chain)
		}
		errStr := ""
		status := "ok"
		if err != nil {
			errStr = err.Error()
			status = "err:" + truncErr(errStr)
		}

		res.Probes = append(res.Probes, probeResult{
			Txid:       op.Txid,
			VOut:       op.VOut,
			ChainLen:   chainLen,
			DurationMs: dur.Milliseconds(),
			Error:      errStr,
		})

		fmt.Fprintf(os.Stderr,
			"[%3d/%d] %s:%d  len=%d  time=%s  elapsed=%s  %s\n",
			i+1, len(outpoints), op.Txid, op.VOut, chainLen,
			dur.Truncate(time.Millisecond),
			time.Since(overallStart).Truncate(time.Millisecond),
			status,
		)
	}

	if *resultsFile != "" {
		if err := writeJSON(*resultsFile, &res); err != nil {
			return fmt.Errorf("write results: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote results to %s\n", *resultsFile)
	}

	printProbeSummary(res.Probes)
	return nil
}

func loadOrPickOutpoints(ctx context.Context, db *sql.DB) ([]outpoint, error) {
	if *outpointsFile != "" {
		if data, err := os.ReadFile(*outpointsFile); err == nil && len(data) > 0 {
			var ops []outpoint
			if err := json.Unmarshal(data, &ops); err != nil {
				return nil, fmt.Errorf("decode outpoints file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "loaded %d outpoints from %s\n",
				len(ops), *outpointsFile)
			return ops, nil
		}
	}

	var (
		ops []outpoint
		err error
	)
	if *discoverDeep {
		ops, err = discoverDeepChainTips(ctx, db, *sampleSize)
	} else {
		ops, err = sampleOutpoints(ctx, db, *sampleSize)
	}
	if err != nil {
		return nil, err
	}

	if *outpointsFile != "" {
		if err := writeJSON(*outpointsFile, ops); err != nil {
			return nil, fmt.Errorf("write outpoints: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d outpoints to %s\n",
			len(ops), *outpointsFile)
	}
	return ops, nil
}

func sampleOutpoints(ctx context.Context, db *sql.DB, n int) ([]outpoint, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT txid, vout FROM vtxo TABLESAMPLE BERNOULLI(1)
		WHERE ark_txid IS NOT NULL AND ark_txid <> ''
		LIMIT $1
	`, n)
	if err != nil {
		return nil, fmt.Errorf("sample query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ops []outpoint
	for rows.Next() {
		var op outpoint
		if err := rows.Scan(&op.Txid, &op.VOut); err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(ops) == 0 {
		// TABLESAMPLE can return fewer rows than requested; fall back to LIMIT.
		rows2, err := db.QueryContext(ctx, `
			SELECT txid, vout FROM vtxo
			WHERE ark_txid IS NOT NULL AND ark_txid <> ''
			LIMIT $1
		`, n)
		if err != nil {
			return nil, fmt.Errorf("fallback query: %w", err)
		}
		defer func() { _ = rows2.Close() }()
		for rows2.Next() {
			var op outpoint
			if err := rows2.Scan(&op.Txid, &op.VOut); err != nil {
				return nil, err
			}
			ops = append(ops, op)
		}
		if err := rows2.Err(); err != nil {
			return nil, err
		}
	}
	return ops, nil
}

func discoverDeepChainTips(ctx context.Context, db *sql.DB, n int) ([]outpoint, error) {
	fmt.Fprintln(os.Stderr, "discovering deep chains via recursive CTE...")
	start := time.Now()
	rows, err := db.QueryContext(ctx, `
		WITH RECURSIVE chain AS (
			SELECT txid, vout, ark_txid, 1 AS hops
			FROM vtxo
			WHERE ark_txid IS NOT NULL AND ark_txid <> ''
			UNION ALL
			SELECT c.txid, c.vout, c.ark_txid, parent.hops + 1
			FROM vtxo c
			JOIN chain parent ON c.txid = parent.ark_txid
			WHERE parent.ark_txid IS NOT NULL AND parent.ark_txid <> ''
		)
		SELECT txid, vout, MAX(hops) AS chain_len
		FROM chain
		GROUP BY txid, vout
		ORDER BY chain_len DESC
		LIMIT $1
	`, n)
	if err != nil {
		return nil, fmt.Errorf("recursive cte: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ops []outpoint
	for rows.Next() {
		var (
			op outpoint
			cl int
		)
		if err := rows.Scan(&op.Txid, &op.VOut, &cl); err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "found %d deep tips in %s\n",
		len(ops), time.Since(start))
	return ops, nil
}

func printProbeSummary(probes []probeResult) {
	durs := okDurations(probes)
	var ok, errs, empty, maxLen int
	var totalDur, maxDur time.Duration
	for _, p := range probes {
		if p.Error != "" {
			errs++
			continue
		}
		ok++
		d := time.Duration(p.DurationMs) * time.Millisecond
		totalDur += d
		if d > maxDur {
			maxDur = d
		}
		if p.ChainLen > maxLen {
			maxLen = p.ChainLen
		}
		if p.ChainLen == 0 {
			empty++
		}
	}
	var avg time.Duration
	if ok > 0 {
		avg = totalDur / time.Duration(ok)
	}

	fmt.Println()
	fmt.Println("=== Probe summary ===")
	fmt.Printf("  ok=%d  errors=%d  empty=%d\n", ok, errs, empty)
	fmt.Printf("  chain_len max=%d\n", maxLen)
	fmt.Printf("  latency avg=%s  p50=%s  p90=%s  p99=%s  max=%s\n",
		avg, dpercentile(durs, 0.50), dpercentile(durs, 0.90),
		dpercentile(durs, 0.99), maxDur)

	sorted := append([]probeResult(nil), probes...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ChainLen > sorted[j].ChainLen
	})
	n := *topK
	if n > len(sorted) {
		n = len(sorted)
	}
	fmt.Printf("\n=== Top %d chains by length ===\n", n)
	for i := 0; i < n; i++ {
		p := sorted[i]
		extra := ""
		if p.Error != "" {
			extra = "  err:" + truncErr(p.Error)
		}
		fmt.Printf("  %s:%d  len=%d  time=%dms%s\n",
			p.Txid, p.VOut, p.ChainLen, p.DurationMs, extra)
	}
}

func runCompare() error {
	if *baselineFile == "" || *candidateFile == "" {
		return errors.New("-compare requires -baseline and -candidate")
	}
	base, err := loadResults(*baselineFile)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	cand, err := loadResults(*candidateFile)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}

	baseByOp := make(map[string]probeResult, len(base.Probes))
	for _, p := range base.Probes {
		baseByOp[p.key()] = p
	}

	type pair struct {
		base, cand probeResult
		speedup    float64 // base.dur / cand.dur — >1 means candidate is faster
		deltaMs    int64
	}

	var (
		pairs                              []pair
		bothOk, candFaster, candSlower     int
		baseErrCount, candErrCount, missed int
		speedups                           []float64
		baseDurs, candDurs                 []time.Duration
		totalSpeedup                       float64
	)

	for _, p := range base.Probes {
		if p.Error != "" {
			baseErrCount++
		}
	}
	for _, c := range cand.Probes {
		if c.Error != "" {
			candErrCount++
		}
		b, ok := baseByOp[c.key()]
		if !ok {
			missed++
			continue
		}
		if b.Error != "" || c.Error != "" {
			continue
		}
		bothOk++
		// Guard against zero-ms candidate durations to avoid div-by-zero.
		candMs := math.Max(float64(c.DurationMs), 1.0)
		sp := float64(b.DurationMs) / candMs
		speedups = append(speedups, sp)
		totalSpeedup += sp
		switch {
		case sp > 1.0:
			candFaster++
		case sp < 1.0:
			candSlower++
		}
		pairs = append(pairs, pair{
			base:    b,
			cand:    c,
			speedup: sp,
			deltaMs: c.DurationMs - b.DurationMs,
		})
		baseDurs = append(baseDurs, time.Duration(b.DurationMs)*time.Millisecond)
		candDurs = append(candDurs, time.Duration(c.DurationMs)*time.Millisecond)
	}

	sort.Float64s(speedups)
	sort.Slice(baseDurs, func(i, j int) bool { return baseDurs[i] < baseDurs[j] })
	sort.Slice(candDurs, func(i, j int) bool { return candDurs[i] < candDurs[j] })

	fmt.Println()
	fmt.Printf("=== Comparison: baseline=%q vs candidate=%q ===\n",
		base.Label, cand.Label)
	fmt.Printf("  baseline:  ran_at=%s  probes=%d errors=%d\n",
		base.RanAt, len(base.Probes), baseErrCount)
	fmt.Printf("  candidate: ran_at=%s  probes=%d errors=%d\n",
		cand.RanAt, len(cand.Probes), candErrCount)
	fmt.Printf("  matched ok in both:    %d\n", bothOk)
	fmt.Printf("  outpoints in candidate but not baseline: %d\n", missed)
	fmt.Printf("\n  candidate faster: %d   candidate slower: %d\n",
		candFaster, candSlower)
	fmt.Printf("\n  latency p50:   baseline=%-10s   candidate=%-10s\n",
		dpercentile(baseDurs, 0.50), dpercentile(candDurs, 0.50))
	fmt.Printf("  latency p90:   baseline=%-10s   candidate=%-10s\n",
		dpercentile(baseDurs, 0.90), dpercentile(candDurs, 0.90))
	fmt.Printf("  latency p99:   baseline=%-10s   candidate=%-10s\n",
		dpercentile(baseDurs, 0.99), dpercentile(candDurs, 0.99))
	fmt.Printf("  latency max:   baseline=%-10s   candidate=%-10s\n",
		maxDur(baseDurs), maxDur(candDurs))

	mean := 0.0
	if bothOk > 0 {
		mean = totalSpeedup / float64(bothOk)
	}
	med := fpercentile(speedups, 0.50)
	fmt.Printf(
		"\n  speedup (baseline/candidate):  mean=%.2fx  median=%.2fx  p10=%.2fx  p90=%.2fx\n",
		mean,
		med,
		fpercentile(speedups, 0.10),
		fpercentile(speedups, 0.90),
	)

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].cand.ChainLen > pairs[j].cand.ChainLen
	})
	n := *topK
	if n > len(pairs) {
		n = len(pairs)
	}
	fmt.Printf("\n=== Top %d chains by length ===\n", n)
	fmt.Printf("  %-70s %5s   %10s   %10s   %8s\n",
		"outpoint", "len", "base", "cand", "speedup")
	for i := 0; i < n; i++ {
		p := pairs[i]
		fmt.Printf("  %-70s %5d   %8dms   %8dms   %7.2fx\n",
			p.cand.key(), p.cand.ChainLen,
			p.base.DurationMs, p.cand.DurationMs, p.speedup)
	}

	if *csvOut != "" {
		f, err := os.Create(*csvOut)
		if err != nil {
			return fmt.Errorf("write csv: %w", err)
		}
		if _, err := fmt.Fprintln(
			f,
			"txid,vout,chain_len,baseline_ms,candidate_ms,delta_ms,speedup",
		); err != nil {
			_ = f.Close()
			return fmt.Errorf("write csv header: %w", err)
		}
		for _, p := range pairs {
			if _, err := fmt.Fprintf(f, "%s,%d,%d,%d,%d,%d,%.4f\n",
				p.cand.Txid, p.cand.VOut, p.cand.ChainLen,
				p.base.DurationMs, p.cand.DurationMs,
				p.deltaMs, p.speedup); err != nil {
				_ = f.Close()
				return fmt.Errorf("write csv row: %w", err)
			}
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close csv: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote per-outpoint deltas to %s\n", *csvOut)
	}
	return nil
}

func okDurations(probes []probeResult) []time.Duration {
	out := make([]time.Duration, 0, len(probes))
	for _, p := range probes {
		if p.Error != "" {
			continue
		}
		out = append(out, time.Duration(p.DurationMs)*time.Millisecond)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func dpercentile(durs []time.Duration, p float64) time.Duration {
	if len(durs) == 0 {
		return 0
	}
	i := int(float64(len(durs)-1) * p)
	return durs[i]
}

func fpercentile(vs []float64, p float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	i := int(float64(len(vs)-1) * p)
	return vs[i]
}

func maxDur(durs []time.Duration) time.Duration {
	if len(durs) == 0 {
		return 0
	}
	return durs[len(durs)-1]
}

func loadResults(path string) (results, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return results{}, err
	}
	var r results
	if err := json.Unmarshal(data, &r); err != nil {
		return results{}, err
	}
	return r, nil
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func truncErr(s string) string {
	const max = 80
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
