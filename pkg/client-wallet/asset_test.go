package wallet

import (
	"context"
	"testing"
)

func TestIssueAsset(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("reads vtxos under txLock", func(t *testing.T) {
			requireReadsUnderTxLock(t, func(ctx context.Context, w *wallet) error {
				_, err := w.IssueAsset(ctx, 1, nil, nil)
				return err
			})
		})
	})
}

func TestReissueAsset(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("reads control asset under txLock", func(t *testing.T) {
			requireReadsUnderTxLock(t, func(ctx context.Context, w *wallet) error {
				_, err := w.ReissueAsset(ctx, "asset", 1)
				return err
			})
		})
	})
}

func TestBurnAsset(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("reads vtxos under txLock", func(t *testing.T) {
			requireReadsUnderTxLock(t, func(ctx context.Context, w *wallet) error {
				_, err := w.BurnAsset(ctx, "asset", 1)
				return err
			})
		})
	})
}
