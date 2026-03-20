package indexer

import (
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

// PageOption is a functional option for paginated requests.
type PageOption func(*pageOption) error

func WithPage(page *PageRequest) PageOption {
	return func(o *pageOption) error {
		o.Page = page
		return nil
	}
}

type pageOption struct {
	Page *PageRequest
}

func ApplyPageOptions(opts ...PageOption) (*pageOption, error) {
	o := &pageOption{}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// GetVtxosOption is a functional option for GetVtxos requests.
type GetVtxosOption func(*getVtxosOption) error

func WithScripts(scripts []string) GetVtxosOption {
	return func(o *getVtxosOption) error {
		if o.Scripts != nil {
			return fmt.Errorf("scripts already set")
		}
		if o.Outpoints != nil {
			return fmt.Errorf("outpoints already set")
		}
		o.Scripts = scripts
		return nil
	}
}

func WithOutpoints(outpoints []types.Outpoint) GetVtxosOption {
	return func(o *getVtxosOption) error {
		if o.Outpoints != nil {
			return fmt.Errorf("outpoints already set")
		}
		if o.Scripts != nil {
			return fmt.Errorf("scripts already set")
		}
		o.Outpoints = outpoints
		return nil
	}
}

func WithSpentOnly() GetVtxosOption {
	return func(o *getVtxosOption) error {
		o.SpentOnly = true
		return nil
	}
}

func WithSpendableOnly() GetVtxosOption {
	return func(o *getVtxosOption) error {
		o.SpendableOnly = true
		return nil
	}
}

func WithRecoverableOnly() GetVtxosOption {
	return func(o *getVtxosOption) error {
		o.RecoverableOnly = true
		return nil
	}
}

func WithPendingOnly() GetVtxosOption {
	return func(o *getVtxosOption) error {
		o.PendingOnly = true
		return nil
	}
}

func WithVtxosPage(page *PageRequest) GetVtxosOption {
	return func(o *getVtxosOption) error {
		o.Page = page
		return nil
	}
}

func WithTimeRange(before, after int64) GetVtxosOption {
	return func(o *getVtxosOption) error {
		if o.After > 0 || o.Before > 0 {
			return fmt.Errorf("time range already set")
		}
		if before < 0 || after < 0 {
			return fmt.Errorf("negative time bound")
		}
		if before == 0 && after == 0 {
			return fmt.Errorf("missing time range")
		}
		if before > 0 && after > 0 && before <= after {
			return fmt.Errorf("before must be greater than after")
		}
		o.Before = before
		o.After = after
		return nil
	}
}

type getVtxosOption struct {
	Page            *PageRequest
	Scripts         []string
	Outpoints       []types.Outpoint
	SpentOnly       bool
	SpendableOnly   bool
	RecoverableOnly bool
	PendingOnly     bool
	After           int64
	Before          int64
}

func (o *getVtxosOption) FormattedOutpoints() []string {
	outs := make([]string, 0, len(o.Outpoints))
	for _, out := range o.Outpoints {
		outs = append(outs, fmt.Sprintf("%s:%d", out.Txid, out.VOut))
	}
	return outs
}

func ApplyGetVtxosOptions(opts ...GetVtxosOption) (*getVtxosOption, error) {
	o := &getVtxosOption{}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// GetTxHistoryOption is a functional option for GetTxHistory requests.
type GetTxHistoryOption func(*getTxHistoryOption) error

func WithStartTime(startTime time.Time) GetTxHistoryOption {
	return func(o *getTxHistoryOption) error {
		o.StartTime = startTime
		return nil
	}
}

func WithEndTime(endTime time.Time) GetTxHistoryOption {
	return func(o *getTxHistoryOption) error {
		o.EndTime = endTime
		return nil
	}
}

type getTxHistoryOption struct {
	Page      *PageRequest
	StartTime time.Time
	EndTime   time.Time
}

func ApplyGetTxHistoryOptions(opts ...GetTxHistoryOption) (*getTxHistoryOption, error) {
	o := &getTxHistoryOption{}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}
