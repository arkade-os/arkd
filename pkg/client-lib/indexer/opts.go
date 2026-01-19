package indexer

import (
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type RequestOption struct {
	page *PageRequest
}

func (o *RequestOption) WithPage(page *PageRequest) {
	o.page = page
}

func (o *RequestOption) GetPage() *PageRequest {
	return o.page
}

type GetVtxosRequestOption struct {
	RequestOption
	scripts         []string
	outpoints       []types.Outpoint
	spentOnly       bool
	spendableOnly   bool
	recoverableOnly bool
	pendingOnly     bool
	after           int64
	before          int64
}

func (o *GetVtxosRequestOption) WithScripts(scripts []string) error {
	if o.scripts != nil {
		return fmt.Errorf("scripts already set")
	}
	if o.outpoints != nil {
		return fmt.Errorf("outpoints already set")
	}
	o.scripts = scripts
	return nil
}

func (o *GetVtxosRequestOption) GetScripts() []string {
	return o.scripts
}

func (o *GetVtxosRequestOption) WithOutpoints(outpoints []types.Outpoint) error {
	if o.outpoints != nil {
		return fmt.Errorf("outpoints already set")
	}
	if o.scripts != nil {
		return fmt.Errorf("scripts already set")
	}
	o.outpoints = outpoints
	return nil
}

func (o *GetVtxosRequestOption) GetOutpoints() []string {
	outs := make([]string, 0, len(o.outpoints))
	for _, out := range o.outpoints {
		outs = append(outs, fmt.Sprintf("%s:%d", out.Txid, out.VOut))
	}
	return outs
}

func (o *GetVtxosRequestOption) WithSpentOnly() {
	o.spentOnly = true
}

func (o *GetVtxosRequestOption) GetSpentOnly() bool {
	return o.spentOnly
}

func (o *GetVtxosRequestOption) WithSpendableOnly() {
	o.spendableOnly = true
}

func (o *GetVtxosRequestOption) GetSpendableOnly() bool {
	return o.spendableOnly
}

func (o *GetVtxosRequestOption) WithRecoverableOnly() {
	o.recoverableOnly = true
}

func (o *GetVtxosRequestOption) GetRecoverableOnly() bool {
	return o.recoverableOnly
}

func (o *GetVtxosRequestOption) WithPendingOnly() {
	o.pendingOnly = true
}

func (o *GetVtxosRequestOption) GetPendingOnly() bool {
	return o.pendingOnly
}

func (o *GetVtxosRequestOption) WithTimeRange(before, after int64) error {
	if o.after > 0 || o.before > 0 {
		return fmt.Errorf("time range already set")
	}
	if before <= 0 && after <= 0 {
		return fmt.Errorf("missing time range")
	}
	if before > 0 && after > 0 && before <= after {
		return fmt.Errorf("before must be greater than after")
	}
	o.before = before
	o.after = after
	return nil
}

func (o *GetVtxosRequestOption) GetTimeRange() (after, before int64) {
	after = o.after
	before = o.before
	return
}

type GetTxHistoryRequestOption struct {
	RequestOption
	startTime time.Time
	endTime   time.Time
}

func (o *GetTxHistoryRequestOption) WithStartTime(startTime time.Time) {
	o.startTime = startTime
}

func (o *GetTxHistoryRequestOption) GetStartTime() time.Time {
	return o.startTime
}

func (o *GetTxHistoryRequestOption) WithEndTime(endTime time.Time) {
	o.endTime = endTime
}

func (o *GetTxHistoryRequestOption) GetEndTime() time.Time {
	return o.endTime
}
