package batchsession

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2"
)

// RedeemNotesArgs configures a RedeemNotes call: the Notes to redeem and the
// ReceiverAddr that will receive the resulting vtxo. SignTx signs the intent
// proof, and Client/ServerInfo are used to talk to the server.
type RedeemNotesArgs struct {
	Client       clientlib.Client
	SignTx       clientlib.SignFn
	ServerInfo   clientlib.Info
	Notes        []string
	ReceiverAddr string
}

func (a RedeemNotesArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx function")
	}
	if len(a.Notes) <= 0 {
		return fmt.Errorf("missing notes to redeem")
	}
	if len(a.ReceiverAddr) <= 0 {
		return fmt.Errorf("missing receiver")
	}
	info := a.ServerInfo
	if len(info.Network) <= 0 ||
		len(info.ForfeitPubKey) <= 0 ||
		len(info.ForfeitAddress) <= 0 {
		return fmt.Errorf("missing server info")
	}
	buf, err := hex.DecodeString(info.ForfeitPubKey)
	if err != nil {
		return fmt.Errorf(
			"expected hex format for forfeit pubkey, got %s", info.ForfeitPubKey,
		)
	}
	if _, err := btcec.ParsePubKey(buf); err != nil {
		return fmt.Errorf("failed to parse forfeit pubkey: %w", err)
	}
	return nil
}

// RedeemNotes performs the full lifecycle of redeeming one or more notes into
// a fresh vtxo via a batch session: builds, signs, submits the register
// intent, handles batch events, and finalizes the commitment transaction via
// JoinBatch.
func RedeemNotes(
	ctx context.Context, args RedeemNotesArgs, opts ...Option,
) (*BatchTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	amount := uint64(0)
	for _, noteStr := range args.Notes {
		n, err := note.NewNoteFromString(noteStr)
		if err != nil {
			return nil, err
		}
		amount += uint64(n.Value)
	}

	return joinBatchWithRetry(ctx, JoinBatchArgs{
		BaseArgs: BaseArgs{
			Notes:  args.Notes,
			SignTx: args.SignTx,
			Outputs: []clientlib.Receiver{{
				To:     args.ReceiverAddr,
				Amount: amount,
			}},
		},
		Client:     args.Client,
		ServerInfo: args.ServerInfo,
	}, opts...)
}
