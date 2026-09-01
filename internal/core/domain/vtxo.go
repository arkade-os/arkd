package domain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type Outpoint struct {
	Txid string
	VOut uint32
}

func (k *Outpoint) FromString(s string) error {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid outpoint string: %s", s)
	}
	txid := parts[0]
	txidBytes, err := hex.DecodeString(txid)
	if err != nil {
		return fmt.Errorf("invalid txid hex: %s", txid)
	}
	if len(txidBytes) != 32 {
		return fmt.Errorf("invalid txid length: expected 32 bytes, got %d", len(txidBytes))
	}
	vout, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid vout string: %s", parts[1])
	}
	k.Txid = hex.EncodeToString(txidBytes)
	k.VOut = uint32(vout)
	return nil
}

func (k Outpoint) String() string {
	return fmt.Sprintf("%s:%d", k.Txid, k.VOut)
}

type AssetDenomination = asset.Asset

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
	Depth              uint32   // chain depth: 0 for vtxos from batch, increments on each chain
	MarkerIDs          []string // marker IDs for DAG traversal optimization (supports multiple parent markers)
	Assets             []AssetDenomination
	Kind               VtxoKind // how the vtxo is held (offchain by default, onchain for on-chain Arkade UTXOs)
}

// VtxoKind distinguishes how a vtxo is held. Offchain (the default) is a batch
// leaf or an offchain-tx output. Onchain marks a vtxo held in an on-chain
// Arkade UTXO (issue #1159). It is an open enum so future on-chain sub-kinds can
// be added without another schema migration.
type VtxoKind uint8

const (
	VtxoKindOffchain VtxoKind = iota
	VtxoKindOnchain
)

func (v Vtxo) String() string {
	// nolint
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (v Vtxo) IsNote() bool {
	// An on-chain Arkade UTXO also has no commitment txids, so the kind check
	// keeps it from reading as a note.
	return v.Kind != VtxoKindOnchain &&
		len(v.CommitmentTxids) <= 0 && v.RootCommitmentTxid == ""
}

func (v Vtxo) RequiresForfeit() bool {
	return !v.Swept && !v.IsNote() && !v.Unrolled
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

func (v Vtxo) OutputScript() ([]byte, error) {
	pubkey, err := v.TapKey()
	if err != nil {
		return nil, err
	}
	return script.P2TRScript(pubkey)
}

func (v Vtxo) IsExpired() bool {
	// An on-chain Arkade UTXO has no batch expiry, so ExpiresAt is not
	// meaningful for it. Without this an on-chain vtxo (which carries a zero
	// ExpiresAt) would read as permanently expired and be treated as
	// unspendable by every caller.
	if v.Kind == VtxoKindOnchain {
		return false
	}
	return time.Now().After(time.Unix(v.ExpiresAt, 0))
}
