package application

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/require"
)

// VerifyVtxoTapscriptSigs returns a nil packet with every error it reports.
type nilPacketTxBuilder struct {
	ports.TxBuilder // unimplemented methods panic on call
}

func (b nilPacketTxBuilder) VerifyVtxoTapscriptSigs(
	tx string, mustIncludeSignerSig bool,
) (bool, *psbt.Packet, error) {
	return false, nil, fmt.Errorf("invalid control block")
}

func TestVerifyForfeitTxsSigsSurvivesNilPacket(t *testing.T) {
	s := &service{builder: nilPacketTxBuilder{}}

	require.NotPanics(t, func() {
		convictions := s.verifyForfeitTxsSigs("round-id", []string{"not-a-psbt"}, nil)
		// extraction failed, so there is no vtxo script to attribute a crime to
		require.Empty(t, convictions)
	})
}
