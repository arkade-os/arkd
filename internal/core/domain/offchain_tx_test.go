package domain_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

var (
	signedPtx             = "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA=signed"
	finalPtx              = "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA=final"
	rootCommitmentTxid    = "0000000000000000000000000000000000000000000000000000000000000006"
	unsignedCheckpointTxs = map[string]string{
		txid: emptyPtx,
	}
	signedCheckpointTxs = map[string]string{
		txid: signedPtx,
	}
	finalCheckpointTxs = map[string]string{
		txid: finalPtx,
	}
	arkTx                         = signedPtx
	finalArkTx                    = finalPtx
	commitmentTxsByCheckpointTxid = map[string]string{txid: rootCommitmentTxid}
	expiryTimestamp               = time.Now().Add(1 * time.Hour).Unix()
)

func TestOffchainTx(t *testing.T) {
	testRequestOffchainTx(t)

	testAcceptOffchainTx(t)

	testFinalizeOffchainTx(t)

	testFailOffchainTx(t)
}

func testRequestOffchainTx(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			offchainTx := domain.NewOffchainTx()
			require.NotNil(t, offchainTx)
			require.Empty(t, offchainTx.Events())
			require.False(t, offchainTx.IsRequested())
			require.False(t, offchainTx.IsAccepted())
			require.False(t, offchainTx.IsFinalized())
			require.False(t, offchainTx.IsFailed())

			event, err := offchainTx.Request(txid, arkTx, unsignedCheckpointTxs)
			require.NoError(t, err)
			require.NotNil(t, event)
			require.Equal(t, domain.EventTypeOffchainTxRequested, event.GetType())
			require.True(t, offchainTx.IsRequested())
			require.False(t, offchainTx.IsAccepted())
			require.False(t, offchainTx.IsFinalized())
			require.False(t, offchainTx.IsFailed())
			require.Equal(t, txid, offchainTx.ArkTxid)
			require.Equal(t, arkTx, offchainTx.ArkTx)
			require.Equal(t, unsignedCheckpointTxs, offchainTx.CheckpointTxs)
			require.NotEmpty(t, offchainTx.StartingTimestamp)

			events := offchainTx.Events()
			require.Len(t, events, 1)
			require.Equal(t, event, events[0])
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				offchainTx            *domain.OffchainTx
				txid                  string
				arkTx                 string
				unsignedCheckpointTxs map[string]string
				expectedErr           string
			}{
				{
					offchainTx:            domain.NewOffchainTx(),
					arkTx:                 arkTx,
					unsignedCheckpointTxs: unsignedCheckpointTxs,
					expectedErr:           "missing ark txid",
				},
				{
					offchainTx:            domain.NewOffchainTx(),
					txid:                  txid,
					unsignedCheckpointTxs: unsignedCheckpointTxs,
					expectedErr:           "missing ark tx",
				},
				{
					offchainTx:  domain.NewOffchainTx(),
					txid:        txid,
					arkTx:       arkTx,
					expectedErr: "missing unsigned checkpoint txs",
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code:   int(domain.OffchainTxUndefinedStage),
							Failed: true,
						},
					},
					txid:                  txid,
					arkTx:                 arkTx,
					unsignedCheckpointTxs: unsignedCheckpointTxs,
					expectedErr:           "not in a valid stage to request offchain tx",
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code: int(domain.OffchainTxRequestedStage),
						},
					},
					txid:                  txid,
					arkTx:                 arkTx,
					unsignedCheckpointTxs: unsignedCheckpointTxs,
					expectedErr:           "not in a valid stage to request offchain tx",
				},
			}

			for _, f := range fixtures {
				event, err := f.offchainTx.Request(f.txid, f.arkTx, f.unsignedCheckpointTxs)
				require.EqualError(t, err, f.expectedErr)
				require.Nil(t, event)
			}
		})
	})
}

func testAcceptOffchainTx(t *testing.T) {
	t.Run("accept", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			offchainTx := domain.NewOffchainTx()
			event, err := offchainTx.Request(txid, arkTx, unsignedCheckpointTxs)
			require.NoError(t, err)
			require.NotNil(t, event)
			require.Empty(t, offchainTx.RootCommitmentTxId)

			event, err = offchainTx.Accept(
				finalArkTx,
				signedCheckpointTxs,
				commitmentTxsByCheckpointTxid,
				rootCommitmentTxid,
				expiryTimestamp,
			)
			require.NoError(t, err)
			require.NotNil(t, event)
			require.Equal(t, domain.EventTypeOffchainTxAccepted, event.GetType())
			require.False(t, offchainTx.IsRequested())
			require.True(t, offchainTx.IsAccepted())
			require.False(t, offchainTx.IsFinalized())
			require.False(t, offchainTx.IsFailed())
			require.Equal(t, finalArkTx, offchainTx.ArkTx)
			require.Equal(t, signedCheckpointTxs, offchainTx.CheckpointTxs)
			require.Equal(t, commitmentTxsByCheckpointTxid, offchainTx.CommitmentTxids)
			require.Equal(t, rootCommitmentTxid, offchainTx.RootCommitmentTxId)

			events := offchainTx.Events()
			require.Len(t, events, 2)
			require.Equal(t, event, events[1])
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				offchainTx          *domain.OffchainTx
				finalArkTx          string
				signedCheckpointTxs map[string]string
				commitmentTxids     map[string]string
				expiryTimestamp     int64
				expectedErr         string
			}{
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code: int(domain.OffchainTxRequestedStage),
						},
					},
					signedCheckpointTxs: signedCheckpointTxs,
					commitmentTxids:     commitmentTxsByCheckpointTxid,
					expectedErr:         "missing final ark tx",
					expiryTimestamp:     expiryTimestamp,
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code: int(domain.OffchainTxRequestedStage),
						},
					},
					finalArkTx:      finalArkTx,
					commitmentTxids: commitmentTxsByCheckpointTxid,
					expectedErr:     "missing signed checkpoint txs",
					expiryTimestamp: expiryTimestamp,
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code: int(domain.OffchainTxRequestedStage),
						},
						CheckpointTxs: signedCheckpointTxs,
					},
					finalArkTx:          finalArkTx,
					signedCheckpointTxs: signedCheckpointTxs,
					expectedErr:         "missing commitment txids",
					expiryTimestamp:     expiryTimestamp,
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code:   int(domain.OffchainTxRequestedStage),
							Failed: true,
						},
						CheckpointTxs: signedCheckpointTxs,
					},
					finalArkTx:          finalArkTx,
					signedCheckpointTxs: signedCheckpointTxs,
					commitmentTxids:     commitmentTxsByCheckpointTxid,
					expectedErr:         "not in a valid stage to accept offchain tx",
					expiryTimestamp:     expiryTimestamp,
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code: int(domain.OffchainTxRequestedStage),
						},
						CheckpointTxs: signedCheckpointTxs,
					},
					finalArkTx:          finalArkTx,
					signedCheckpointTxs: signedCheckpointTxs,
					commitmentTxids:     commitmentTxsByCheckpointTxid,
					expectedErr:         "missing expiry timestamp",
					expiryTimestamp:     0,
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code: int(domain.OffchainTxAcceptedStage),
						},
						CheckpointTxs: signedCheckpointTxs,
					},
					finalArkTx:          finalArkTx,
					signedCheckpointTxs: signedCheckpointTxs,
					commitmentTxids:     commitmentTxsByCheckpointTxid,
					expectedErr:         "not in a valid stage to accept offchain tx",
					expiryTimestamp:     expiryTimestamp,
				},
			}

			for _, f := range fixtures {
				event, err := f.offchainTx.Accept(
					f.finalArkTx, f.signedCheckpointTxs,
					f.commitmentTxids, rootCommitmentTxid, f.expiryTimestamp,
				)
				require.EqualError(t, err, f.expectedErr)
				require.Nil(t, event)
			}
		})
	})
}

func testFinalizeOffchainTx(t *testing.T) {
	t.Run("finalize", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			offchainTx := domain.NewOffchainTx()
			event, err := offchainTx.Request(txid, arkTx, unsignedCheckpointTxs)
			require.NoError(t, err)
			require.NotNil(t, event)

			event, err = offchainTx.Accept(
				finalArkTx, signedCheckpointTxs,
				commitmentTxsByCheckpointTxid, rootCommitmentTxid, expiryTimestamp,
			)
			require.NoError(t, err)
			require.NotNil(t, event)

			event, err = offchainTx.Finalize(finalCheckpointTxs)
			require.NoError(t, err)
			require.NotNil(t, event)
			require.Equal(t, domain.EventTypeOffchainTxFinalized, event.GetType())
			require.False(t, offchainTx.IsRequested())
			require.False(t, offchainTx.IsAccepted())
			require.True(t, offchainTx.IsFinalized())
			require.False(t, offchainTx.IsFailed())
			require.Equal(t, finalCheckpointTxs, offchainTx.CheckpointTxs)
			require.GreaterOrEqual(t, offchainTx.EndingTimestamp, offchainTx.StartingTimestamp)
			require.Equal(t, expiryTimestamp, offchainTx.ExpiryTimestamp)

			events := offchainTx.Events()
			require.Len(t, events, 3)
			require.Equal(t, event, events[2])
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				offchainTx         *domain.OffchainTx
				finalCheckpointTxs map[string]string
				expectedErr        string
			}{
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code: int(domain.OffchainTxAcceptedStage),
						},
					},
					expectedErr: "missing final checkpoint txs",
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code:   int(domain.OffchainTxAcceptedStage),
							Failed: true,
						},
						CheckpointTxs: finalCheckpointTxs,
					},
					finalCheckpointTxs: finalCheckpointTxs,
					expectedErr:        "not in a valid stage to finalize offchain tx",
				},
				{
					offchainTx: &domain.OffchainTx{
						Stage: domain.Stage{
							Code: int(domain.OffchainTxFinalizedStage),
						},
						CheckpointTxs: finalCheckpointTxs,
					},
					finalCheckpointTxs: finalCheckpointTxs,
					expectedErr:        "not in a valid stage to finalize offchain tx",
				},
			}

			for _, f := range fixtures {
				event, err := f.offchainTx.Finalize(f.finalCheckpointTxs)
				require.EqualError(t, err, f.expectedErr)
				require.Nil(t, event)
			}
		})
	})
}

func testFailOffchainTx(t *testing.T) {
	t.Run("fail", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			offchainTx := domain.NewOffchainTx()
			event, err := offchainTx.Request(txid, arkTx, unsignedCheckpointTxs)
			require.NoError(t, err)
			require.NotNil(t, event)
			require.Equal(t, domain.EventTypeOffchainTxRequested, event.GetType())

			event, err = offchainTx.Accept(
				finalArkTx, signedCheckpointTxs,
				commitmentTxsByCheckpointTxid, rootCommitmentTxid, expiryTimestamp,
			)
			require.NoError(t, err)
			require.NotNil(t, event)
			require.Equal(t, domain.EventTypeOffchainTxAccepted, event.GetType())

			reason := fmt.Errorf("some valid reason")
			event = offchainTx.Fail(reason)
			require.NotNil(t, event)
			require.False(t, offchainTx.IsRequested())
			require.False(t, offchainTx.IsAccepted())
			require.False(t, offchainTx.IsFinalized())
			require.True(t, offchainTx.IsFailed())
			require.Equal(t, reason.Error(), offchainTx.FailReason)
			require.Equal(t, domain.EventTypeOffchainTxFailed, event.GetType())

			events := offchainTx.Events()
			require.Len(t, events, 3)
			require.Equal(t, event, events[2])
		})
	})
}
