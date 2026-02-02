package domain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

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
	k.Txid = parts[0]
	vout, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid vout string: %s", parts[1])
	}
	k.VOut = uint32(vout)
	return nil
}

func (k Outpoint) String() string {
	return fmt.Sprintf("%s:%d", k.Txid, k.VOut)
}

type Asset struct {
	AssetID        string
	Metadata       map[string]string
	ControlAssetId string
	Immutable      bool
}

// I recall being told to add this but now the Asset struct has no Amount field,
// so when used in Vtxo, we can't tell how much of the asset is in the vtxo. not sure where
// to use this new struct.
type AssetWithAmount struct {
	AssetID string
	Amount  uint64
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
	Assets             []Asset
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

func (v Vtxo) OutputScript() ([]byte, error) {
	pubkey, err := v.TapKey()
	if err != nil {
		return nil, err
	}
	return script.P2TRScript(pubkey)
}
