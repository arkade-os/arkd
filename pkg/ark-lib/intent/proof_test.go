package intent

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestGetOutpoints(t *testing.T) {
	t.Run("zero inputs", func(t *testing.T) {
		ptxWithZeroInputs := psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{},
			},
		}
		proof := Proof{Packet: ptxWithZeroInputs}
		outpoints := proof.GetOutpoints()
		require.Len(t, outpoints, 0)
	})

	t.Run("one input", func(t *testing.T) {
		ptxWithOneInput := psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{}}},
			},
		}
		proof := Proof{Packet: ptxWithOneInput}
		outpoints := proof.GetOutpoints()
		require.Len(t, outpoints, 0)
	})
}
