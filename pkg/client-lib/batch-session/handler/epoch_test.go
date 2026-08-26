package batchsessionhandler

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestSweepParamsFromBatchStarted is the point of carrying the epoch date over
// the wire: whichever scheme the server announces, the client must rebuild the
// same sweep root, or every node's aggregate key fails to reproduce and it
// rejects a perfectly good tree.
func TestSweepParamsFromBatchStarted(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("an epoch event yields the epoch root", func(t *testing.T) {
		h := &defaultHandler{}
		date := int64(1788134400)
		grace := uint32(7168)

		applyBatchStarted(h, clientlib.BatchStartedEvent{
			BatchExpiry:     int64(grace),
			BatchExpiryDate: date,
			UnrollGrace:     int64(grace),
		})

		got, _, err := h.sweepParams().Root(prv.PubKey())
		require.NoError(t, err)

		want, _, err := tree.BuildEpochSweepTapTreeRoot(
			prv.PubKey(), arklib.AbsoluteLocktime(date),
			arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: grace},
		)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("a legacy event yields the legacy root", func(t *testing.T) {
		h := &defaultHandler{}
		expiry := uint32(604672)

		applyBatchStarted(h, clientlib.BatchStartedEvent{BatchExpiry: int64(expiry)})

		require.False(t, h.sweepParams().IsEpoch())

		got, _, err := h.sweepParams().Root(prv.PubKey())
		require.NoError(t, err)

		want, _, err := tree.BuildLegacySweepTapTreeRoot(
			prv.PubKey(),
			arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: expiry},
		)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("the two roots differ", func(t *testing.T) {
		epoch := &defaultHandler{}
		applyBatchStarted(epoch, clientlib.BatchStartedEvent{
			BatchExpiry: 7168, BatchExpiryDate: 1788134400, UnrollGrace: 7168,
		})
		legacy := &defaultHandler{}
		applyBatchStarted(legacy, clientlib.BatchStartedEvent{BatchExpiry: 7168})

		a, _, err := epoch.sweepParams().Root(prv.PubKey())
		require.NoError(t, err)
		b, _, err := legacy.sweepParams().Root(prv.PubKey())
		require.NoError(t, err)
		require.NotEqual(t, a, b)
	})
}

// applyBatchStarted mirrors the field assignment OnBatchStarted performs once it
// has matched the intent id, without the client round trip that surrounds it.
func applyBatchStarted(h *defaultHandler, event clientlib.BatchStartedEvent) {
	if event.BatchExpiryDate > 0 {
		date := arklib.AbsoluteLocktime(event.BatchExpiryDate)
		h.batchExpiryDate = &date
		h.batchExpiry = getBatchExpiryLocktime(uint32(event.UnrollGrace))
		return
	}
	h.batchExpiryDate = nil
	h.batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
}
