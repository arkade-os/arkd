package domain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type Outpoint struct {
	Txid string
	VOut uint32
}

func (k Outpoint) String() string {
	return fmt.Sprintf("%s:%d", k.Txid, k.VOut)
}

type Vtxo struct {
	Outpoint
	Amount             uint64
	PubKey             string
	CommitmentTxids    []string
	RootCommitmentTxid string
	SettledBy          string // commitment txid
	SpentBy            string // forfeit txid or checkpoint txid
	ArkTxid            string // the link to the ark txid that spent the vtxos
	Spent              bool
	Unrolled           bool
	Swept              bool
	Preconfirmed       bool
	ExpiresAt          int64
	CreatedAt          int64
}

func (v Vtxo) String() string {
	// nolint
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (v Vtxo) IsNote() bool {
	return len(v.CommitmentTxids) <= 0 && v.RootCommitmentTxid == ""
}

func (v Vtxo) RequiresForfeit() bool {
	return !v.Swept && !v.IsNote()
}

func (v Vtxo) IsSettled() bool {
	return v.SettledBy != ""
}

func (v Vtxo) TapKey() (*btcec.PublicKey, error) {
	pubkeyBytes, err := hex.DecodeString(v.PubKey)
	if err != nil {
		return nil, err
	}
	return schnorr.ParsePubKey(pubkeyBytes)
}
