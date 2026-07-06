package db_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	bitcointxdecoder "github.com/arkade-os/arkd/internal/infrastructure/tx-decoder/bitcoin"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestOffchainTxSweptOutputsPersisted covers the finalized-offchain-tx
// projection when the tx is considered swept (batch swept or expired). The
// swept column no longer exists, so non-dust outputs must land in swept_vtxo
// or they read back as unswept despite Swept being set on the structs.
func TestOffchainTxSweptOutputsPersisted(t *testing.T) {
	svc, err := db.NewService(db.ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    "sqlite",
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  []interface{}{t.TempDir()},
		Settings:         validSettings(),
	}, bitcointxdecoder.NewService())
	require.NoError(t, err)
	require.NotNil(t, svc)
	defer svc.Close()

	ctx := context.Background()

	// Ark tx with one non-dust taproot output.
	prevoutHash, err := chainhash.NewHashFromStr(randomString(32))
	require.NoError(t, err)
	taprootScript := append([]byte{0x51, 0x20}, make([]byte, 32)...)
	// nolint
	rand.Read(taprootScript[2:])
	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *prevoutHash, Index: 0}},
		[]*wire.TxOut{{Value: 10000, PkScript: taprootScript}},
		3, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	arkTx, err := ptx.B64Encode()
	require.NoError(t, err)
	sweptArkTxid := ptx.UnsignedTx.TxID()

	checkpointTxid := randomString(32)
	checkpointTx := randomTx()

	// Expiry in the past marks the tx swept at projection time.
	events := []domain.Event{
		domain.OffchainTxRequested{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: sweptArkTxid, Type: domain.EventTypeOffchainTxRequested,
			},
			ArkTx:                 arkTx,
			UnsignedCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
			StartingTimestamp:     time.Now().Add(-2 * time.Hour).Unix(),
		},
		domain.OffchainTxAccepted{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: sweptArkTxid, Type: domain.EventTypeOffchainTxAccepted,
			},
			CommitmentTxids:     map[string]string{checkpointTxid: randomString(32)},
			RootCommitmentTxid:  randomString(32),
			FinalArkTx:          arkTx,
			SignedCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
			ExpiryTimestamp:     time.Now().Add(-time.Hour).Unix(),
			Depth:               1,
		},
		domain.OffchainTxFinalized{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: sweptArkTxid, Type: domain.EventTypeOffchainTxFinalized,
			},
			FinalCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
			Timestamp:          time.Now().Unix(),
		},
	}
	require.NoError(t, svc.Events().Save(ctx, domain.OffchainTxTopic, sweptArkTxid, events))

	outpoint := domain.Outpoint{Txid: sweptArkTxid, VOut: 0}
	require.Eventually(t, func() bool {
		vtxos, err := svc.Vtxos().GetVtxos(ctx, []domain.Outpoint{outpoint})
		return err == nil && len(vtxos) == 1 && vtxos[0].Swept
	}, 5*time.Second, 100*time.Millisecond,
		"non-dust output of a swept tx must read back as swept")
}
