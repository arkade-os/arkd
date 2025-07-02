package indexer

import (
	"fmt"
	"time"
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
	outpoints       []Outpoint
	spentOnly       bool
	spendableOnly   bool
	recoverableOnly bool
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

func (o *GetVtxosRequestOption) WithOutpoints(outpoints []Outpoint) error {
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
