package errors

import (
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
)

// generateErrorFixtures creates test fixtures with sample metadata for each error type
func generateErrorFixtures() []Error {
	return []Error{
		// INTERNAL_ERROR
		INTERNAL_ERROR.New("Internal server error occurred").
			WithMetadata(map[string]any{
				"component": "database",
				"operation": "query",
				"timestamp": 1640995200,
			}),

		// INVALID_ARK_PSBT
		INVALID_ARK_PSBT.New("Invalid ARK PSBT format").
			WithMetadata(PsbtMetadata{
				Tx: "0200000001a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890000000000ffffffff0100f902950000000017a9141234567890abcdef1234567890abcdef1234567887",
			}),

		// INVALID_CHECKPOINT_PSBT
		INVALID_CHECKPOINT_PSBT.New("Invalid checkpoint PSBT").
			WithMetadata(PsbtMetadata{
				Tx: "0200000001b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890000000000ffffffff0100f902950000000017a914234567890abcdef1234567890abcdef1234567887",
			}),

		// INVALID_PSBT_MISSING_INPUT
		INVALID_PSBT_MISSING_INPUT.New("PSBT missing required input").
			WithMetadata(PsbtInputMetadata{
				Txid: "c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890ab",
			}),

		// VTXO_ALREADY_REGISTERED
		VTXO_ALREADY_REGISTERED.New("VTXO already registered").
			WithMetadata(VtxoMetadata{
				VtxoOutpoint: "d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890abc:1",
			}),

		// INVALID_PSBT_INPUT
		INVALID_PSBT_INPUT.New("Invalid PSBT input format").
			WithMetadata(InputMetadata{
				Txid:       "e5f6789012345678901234567890abcdef1234567890abcdef1234567890abcd",
				InputIndex: 0,
			}),

		// VTXO_ALREADY_SPENT
		VTXO_ALREADY_SPENT.New("VTXO already spent").
			WithMetadata(VtxoMetadata{
				VtxoOutpoint: "f6789012345678901234567890abcdef1234567890abcdef1234567890abcde:2",
			}),

		// VTXO_ALREADY_UNROLLED
		VTXO_ALREADY_UNROLLED.New("VTXO already unrolled").
			WithMetadata(VtxoMetadata{
				VtxoOutpoint: "789012345678901234567890abcdef1234567890abcdef1234567890abcdef:3",
			}),

		// VTXO_ALREADY_SWEPT
		VTXO_ALREADY_SWEPT.New("VTXO already swept").
			WithMetadata(VtxoMetadata{
				VtxoOutpoint: "89012345678901234567890abcdef1234567890abcdef1234567890abcdef1:4",
			}),

		// OFFCHAIN_TX_SPENDING_NOTE
		OFFCHAIN_TX_SPENDING_NOTE.New("Offchain transaction spending note").
			WithMetadata(VtxoMetadata{
				VtxoOutpoint: "9012345678901234567890abcdef1234567890abcdef1234567890abcdef12:5",
			}),

		// INVALID_VTXO_SCRIPT
		INVALID_VTXO_SCRIPT.New("Invalid VTXO script").
			WithMetadata(InvalidVtxoScriptMetadata{
				Tapscripts: []string{
					"5120abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
					"5120fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
				},
			}),

		// FORFEIT_CLOSURE_LOCKED
		FORFEIT_CLOSURE_LOCKED.New("Forfeit closure is locked").
			WithMetadata(ForfeitClosureLockedMetadata{
				Locktime:        1640995200,
				CurrentLocktime: 1640995100,
				Type:            "timelock",
			}),

		// ARK_TX_INPUT_NOT_SIGNED
		ARK_TX_INPUT_NOT_SIGNED.New("ARK transaction input not signed").
			WithMetadata(InputMetadata{
				Txid:       "012345678901234567890abcdef1234567890abcdef1234567890abcdef123456",
				InputIndex: 1,
			}),

		// MALFORMED_ARK_TX
		MALFORMED_ARK_TX.New("Malformed ARK transaction").
			WithMetadata(PsbtMetadata{
				Tx: "020000000112345678901234567890abcdef1234567890abcdef1234567890abcdef1234560000000000ffffffff0100f902950000000017a914345678901234567890abcdef1234567890abcdef1234567887",
			}),

		// AMOUNT_TOO_HIGH
		AMOUNT_TOO_HIGH.New("Amount exceeds maximum allowed").
			WithMetadata(AmountTooHighMetadata{
				OutputIndex: 0,
				Amount:      1000000,
				MaxAmount:   500000,
			}),

		// AMOUNT_TOO_LOW
		AMOUNT_TOO_LOW.New("Amount below minimum required").
			WithMetadata(AmountTooLowMetadata{
				OutputIndex: 1,
				Amount:      100,
				MinAmount:   1000,
			}),

		// CHECKPOINT_MISMATCH
		CHECKPOINT_MISMATCH.New("Checkpoint transaction mismatch").
			WithMetadata(CheckpointMismatchMetadata{
				ExpectedTxid: "123456789012345678901234567890abcdef1234567890abcdef1234567890abcd",
			}),

		// ARK_TX_MISMATCH
		ARK_TX_MISMATCH.New("ARK transaction mismatch").
			WithMetadata(ArkTxMismatchMetadata{
				ExpectedTxid: "23456789012345678901234567890abcdef1234567890abcdef1234567890abcde",
				GotTxid:      "3456789012345678901234567890abcdef1234567890abcdef1234567890abcdef",
			}),

		// INVALID_SIGNATURE
		INVALID_SIGNATURE.New("Invalid signature provided").
			WithMetadata(InvalidSignatureMetadata{
				Tx: "0200000001456789012345678901234567890abcdef1234567890abcdef1234567890abcdef0000000000ffffffff0100f902950000000017a914456789012345678901234567890abcdef1234567890abcdef1234567887",
			}),

		// TX_NOT_FOUND
		TX_NOT_FOUND.New("Transaction not found").
			WithMetadata(TxNotFoundMetadata{
				Txid: "56789012345678901234567890abcdef1234567890abcdef1234567890abcdef12",
			}),

		// INVALID_INTENT_TIMERANGE
		INVALID_INTENT_TIMERANGE.New("Invalid intent time range").
			WithMetadata(IntentTimeRangeMetadata{
				ValidAt:  1640995200,
				ExpireAt: 1641081600,
				Now:      1641081700,
			}),

		// INVALID_INTENT_MESSAGE
		INVALID_INTENT_MESSAGE.New("Invalid intent message").
			WithMetadata(InvalidIntentMessageMetadata{
				Message: intent.BaseMessage{
					// This would need to be populated with actual intent message data
				},
			}),

		// INVALID_INTENT_PSBT
		INVALID_INTENT_PSBT.New("Invalid intent PSBT").
			WithMetadata(PsbtMetadata{
				Tx: "02000000016789012345678901234567890abcdef1234567890abcdef1234567890abcdef120000000000ffffffff0100f902950000000017a9146789012345678901234567890abcdef1234567890abcdef1234567887",
			}),

		// INVALID_INTENT_PROOF
		INVALID_INTENT_PROOF.New("Invalid intent proof").
			WithMetadata(InvalidIntentProofMetadata{
				Proof:   "invalid_proof_string_here",
				Message: "intent_message_hash",
			}),

		// INVALID_PKSCRIPT
		INVALID_PKSCRIPT.New("Invalid public key script").
			WithMetadata(InvalidPkScriptMetadata{
				Script: "76a914abcdef1234567890abcdef1234567890abcdef1288ac",
			}),

		// CONFIRMATION_SESSION_NOT_STARTED
		CONFIRMATION_SESSION_NOT_STARTED.New("Confirmation session not started").
			WithMetadata(any("session_id_12345")),

		// INVALID_FORFEIT_TXS
		INVALID_FORFEIT_TXS.New("Invalid forfeit transactions").
			WithMetadata(InvalidForfeitTxsMetadata{
				ForfeitTxs: []string{
					"789012345678901234567890abcdef1234567890abcdef1234567890abcdef123",
					"89012345678901234567890abcdef1234567890abcdef1234567890abcdef1234",
				},
			}),

		// INVALID_BOARDING_INPUT_SIG
		INVALID_BOARDING_INPUT_SIG.New("Invalid boarding input signature").
			WithMetadata(InvalidBoardingInputSigMetadata{
				SignedCommitmentTx: "02000000019012345678901234567890abcdef1234567890abcdef1234567890abcdef12340000000000ffffffff0100f902950000000017a9149012345678901234567890abcdef1234567890abcdef1234567887",
			}),
	}
}

func TestErrorGRPCStatus(t *testing.T) {
	fixtures := generateErrorFixtures()

	for _, err := range fixtures {
		require.NotNil(t, err)
		require.NotEmpty(t, err.Error())

		st := status.Convert(err)
		require.NotNil(t, st)

		details := st.Details()
		require.Len(t, details, 1)

		detail := details[0].(*arkv1.ErrorDetails)
		require.NotEmpty(t, detail.Name)
		require.NotEmpty(t, detail.Message)
		require.GreaterOrEqual(t, detail.Code, int32(0))
	}
}
