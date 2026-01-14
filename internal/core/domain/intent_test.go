package domain_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

// x-only pubkey

var (
	pubkey  = "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967"
	proof   = "proof"
	message = "message"
	inputs  = []domain.Vtxo{
		{
			Outpoint: domain.Outpoint{
				Txid: "0000000000000000000000000000000000000000000000000000000000000000",
				VOut: 0,
			},
			PubKey: pubkey,
			Amount: 1000,
		},
	}
)

func TestIntent(t *testing.T) {
	t.Run("new_intent", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			intent, err := domain.NewIntent(proof, message, inputs)
			require.NoError(t, err)
			require.NotNil(t, intent)
			require.NotEmpty(t, intent.Id)
			require.Exactly(t, inputs, intent.Inputs)
			require.Empty(t, intent.Receivers)
		})
		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				inputs      []domain.Vtxo
				proof       string
				message     string
				expectedErr string
			}{
				{
					inputs:      inputs,
					proof:       "",
					message:     message,
					expectedErr: "missing proof",
				},
				{
					inputs:      inputs,
					proof:       proof,
					message:     "",
					expectedErr: "missing message",
				},
			}
			for _, f := range fixtures {
				t.Run(f.expectedErr, func(t *testing.T) {
					intent, err := domain.NewIntent(f.proof, f.message, f.inputs)
					require.Nil(t, intent)
					require.Error(t, err)
					require.Contains(t, err.Error(), f.expectedErr)
				})
			}
		})
	})

	t.Run("add_receivers", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			intent, err := domain.NewIntent(proof, message, inputs)
			require.NoError(t, err)
			require.NotNil(t, intent)

			err = intent.AddReceivers([]domain.Receiver{
				{
					PubKey: pubkey,
					Amount: 450,
				},
				{
					PubKey: pubkey,
					Amount: 550,
				},
			})
			require.NoError(t, err)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				receivers   []domain.Receiver
				expectedErr string
			}{
				{
					receivers:   nil,
					expectedErr: "missing outputs",
				},
			}

			intent, err := domain.NewIntent(proof, message, inputs)
			require.NoError(t, err)
			require.NotNil(t, intent)

			for _, f := range fixtures {
				err := intent.AddReceivers(f.receivers)
				require.EqualError(t, err, f.expectedErr)
			}
		})
	})
}
