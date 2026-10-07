package domain_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestUtxoSpendIsConfirmed(t *testing.T) {
	fixtures := []struct {
		name        string
		spend       domain.UtxoSpend
		isConfirmed bool
	}{
		{
			name:        "unconfirmed",
			spend:       domain.UtxoSpend{Txid: "txid"},
			isConfirmed: false,
		},
		{
			name:        "confirmed by time",
			spend:       domain.UtxoSpend{Txid: "txid", ConfirmedAtTime: 1700000000},
			isConfirmed: true,
		},
		{
			name:        "confirmed by height",
			spend:       domain.UtxoSpend{Txid: "txid", ConfirmedAtHeight: 100},
			isConfirmed: true,
		},
		{
			name: "confirmed by both",
			spend: domain.UtxoSpend{
				Txid: "txid", ConfirmedAtTime: 1700000000, ConfirmedAtHeight: 100,
			},
			isConfirmed: true,
		},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			require.Equal(t, f.isConfirmed, f.spend.IsConfirmed())
		})
	}
}
