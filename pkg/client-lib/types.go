package clientlib

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type StreamConnectionState string

const (
	StreamConnectionStateDisconnected StreamConnectionState = "DISCONNECTED"
	StreamConnectionStateReconnected  StreamConnectionState = "RECONNECTED"
	StreamConnectionStateReady        StreamConnectionState = "READY"
)

type FeeInfo struct {
	IntentFees arkfee.Config
	TxFeeRate  float64
}

type StreamConnectionEvent struct {
	State          StreamConnectionState
	At             time.Time
	DisconnectedAt time.Time
	Err            error
}

type DeprecatedSigner struct {
	PubKey     *btcec.PublicKey
	CutoffDate time.Time
}

type Address struct {
	// KeyID identifies which wallet key produced this address.
	// Single-key wallets populate it with their fixed key handle; HD wallets can
	// use the derivation path.
	KeyID      string
	Tapscripts []string
	Address    string

	vtxoScript script.VtxoScript
}

func (a *Address) RawScript() (script.VtxoScript, error) {
	if a.vtxoScript != nil {
		return a.vtxoScript, nil
	}

	vtxoScript, err := script.ParseVtxoScript(a.Tapscripts)
	if err != nil {
		return nil, err
	}
	a.vtxoScript = vtxoScript
	return vtxoScript, nil
}

func (a Address) Script() (string, error) {
	addr, err := arklib.DecodeAddressV0(a.Address)
	if err != nil {
		return "", err
	}
	outScript, err := script.P2TRScript(addr.VtxoTapKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(outScript), nil
}

func (a *Address) CollaborativeClosure() (script.Closure, error) {
	if a.vtxoScript != nil {
		return a.vtxoScript.ForfeitClosures()[0], nil
	}

	vtxoScript, err := script.ParseVtxoScript(a.Tapscripts)
	if err != nil {
		return nil, err
	}
	if len(vtxoScript.ForfeitClosures()) <= 0 {
		return nil, fmt.Errorf("address %s has no collaborative closures", a.Address)
	}
	a.vtxoScript = vtxoScript
	return vtxoScript.ForfeitClosures()[0], nil
}

func (a *Address) ExitClosure() (script.Closure, error) {
	if a.vtxoScript != nil {
		return a.vtxoScript.ExitClosures()[0], nil
	}

	vtxoScript, err := script.ParseVtxoScript(a.Tapscripts)
	if err != nil {
		return nil, err
	}
	if len(vtxoScript.ExitClosures()) <= 0 {
		return nil, fmt.Errorf("address %s has no exit closures", a.Address)
	}
	a.vtxoScript = vtxoScript
	return vtxoScript.ExitClosures()[0], nil
}

type Outpoint struct {
	Txid string
	VOut uint32
}

func (v Outpoint) String() string {
	return fmt.Sprintf("%s:%d", v.Txid, v.VOut)
}

type Vtxo struct {
	Outpoint
	Script          string
	Amount          uint64
	CommitmentTxids []string
	ExpiresAt       time.Time
	CreatedAt       time.Time
	Preconfirmed    bool
	Swept           bool
	Unrolled        bool
	Spent           bool
	SpentBy         string
	SettledBy       string
	ArkTxid         string
	Assets          []Asset
	Tapscripts      []string
	SigningClosure  script.Closure
}

type Asset struct {
	AssetId string
	Amount  uint64
}

func (v Vtxo) String() string {
	// nolint
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (v Vtxo) IsRecoverable() bool {
	expired := !v.ExpiresAt.IsZero() && !time.Now().Before(v.ExpiresAt)
	return (v.Swept || expired) && !v.Spent
}

func (v Vtxo) Address(server *btcec.PublicKey, net arklib.Network) (string, error) {
	buf, err := hex.DecodeString(v.Script)
	if err != nil {
		return "", err
	}
	pubkeyBytes := buf[2:]

	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return "", err
	}

	a := &arklib.Address{
		HRP:        net.Addr,
		Signer:     server,
		VtxoTapKey: pubkey,
	}

	return a.EncodeV0()
}

func (v Vtxo) ToArkFeeInput() arkfee.OffchainInput {
	vtxoType := arkfee.VtxoTypeVtxo
	if v.Swept {
		vtxoType = arkfee.VtxoTypeRecoverable
	}

	return arkfee.OffchainInput{
		Amount: v.Amount,
		Expiry: v.ExpiresAt,
		Birth:  v.CreatedAt,
		Type:   vtxoType,
		Weight: 0,
	}
}

func (v Vtxo) ParseClosure() ([]byte, *arklib.TaprootMerkleProof, error) {
	pkScript, leafProof, err := parseClosure(v.Outpoint, v.SigningClosure, v.Tapscripts)
	if err != nil {
		return nil, nil, fmt.Errorf("vtxo %w", err)
	}

	return pkScript, leafProof, nil
}

type UtxoEventType int

const (
	UtxosAdded UtxoEventType = iota
	UtxosConfirmed
	UtxosReplaced
	UtxosSpent
)

func (e UtxoEventType) String() string {
	return map[UtxoEventType]string{
		UtxosAdded:     "UTXOS_ADDED",
		UtxosConfirmed: "UTXOS_CONFIRMED",
		UtxosReplaced:  "UTXOS_REPLACED",
		UtxosSpent:     "UTXOS_SPENT",
	}[e]
}

type UtxoEvent struct {
	Type  UtxoEventType
	Utxos []Utxo
}

type VtxoEventType int

const (
	VtxosAdded VtxoEventType = iota
	VtxosSpent
	VtxosUpdated
)

func (e VtxoEventType) String() string {
	return map[VtxoEventType]string{
		VtxosAdded:   "VTXOS_ADDED",
		VtxosSpent:   "VTXOS_SPENT",
		VtxosUpdated: "VTXOS_UPDATED",
	}[e]
}

type VtxoEvent struct {
	Type  VtxoEventType
	Vtxos []Vtxo
}

const (
	TxSent     TxType = "SENT"
	TxReceived TxType = "RECEIVED"
)

type TxType string

type TransactionKey struct {
	BoardingTxid   string
	CommitmentTxid string
	ArkTxid        string
}

func (t TransactionKey) String() string {
	return fmt.Sprintf("%s%s%s", t.BoardingTxid, t.CommitmentTxid, t.ArkTxid)
}

type Transaction struct {
	TransactionKey
	Amount      uint64
	Type        TxType
	CreatedAt   time.Time
	Hex         string
	SettledBy   string
	AssetPacket asset.Packet
	// Assets is the per-asset breakdown for this transaction, expressed as
	// net amounts (gross inputs minus own change). Populated at construction
	// by any code path that has the source vtxos in hand — notably
	// funding.vtxosToTxs (for reconciled history) and the wallet-side
	// send/batch handlers (for just-signed sends). Nil for pure-BTC
	// transactions.
	Assets []Asset
}

func (t Transaction) String() string {
	buf, _ := json.MarshalIndent(t, "", "  ")
	return string(buf)
}

type TxEventType int

const (
	TxsAdded TxEventType = iota
	TxsSettled
	TxsConfirmed
	TxsReplaced
	TxsUpdated
)

func (e TxEventType) String() string {
	return map[TxEventType]string{
		TxsAdded:     "TXS_ADDED",
		TxsSettled:   "TXS_SETTLED",
		TxsConfirmed: "TXS_CONFIRMED",
		TxsReplaced:  "TXS_REPLACED",
		TxsUpdated:   "TXS_UPDATED",
	}[e]
}

type Utxo struct {
	Outpoint
	Amount         uint64
	Script         string
	Delay          arklib.RelativeLocktime
	RedeemableAt   time.Time
	CreatedAt      time.Time
	Spent          bool
	SpentBy        string
	Tx             string
	Assets         []Asset
	Tapscripts     []string
	SigningClosure script.Closure
}

func (u Utxo) IsConfirmed() bool {
	return !u.CreatedAt.IsZero()
}

func (u Utxo) Sequence() (uint32, error) {
	return arklib.BIP68Sequence(u.Delay)
}

func (u Utxo) ToArkFeeInput() arkfee.OnchainInput {
	return arkfee.OnchainInput{
		Amount: u.Amount,
	}
}

func (u Utxo) ParseClosure() ([]byte, *arklib.TaprootMerkleProof, error) {
	pkScript, leafProof, err := parseClosure(u.Outpoint, u.SigningClosure, u.Tapscripts)
	if err != nil {
		return nil, nil, fmt.Errorf("utxo %w", err)
	}

	return pkScript, leafProof, nil
}

type Receiver struct {
	To     string
	Amount uint64
	Assets []Asset
}

func (r Receiver) IsOnchain() bool {
	_, err := btcutil.DecodeAddress(r.To, nil)
	return err == nil
}

func (o Receiver) ToTxOut() (*wire.TxOut, bool, error) {
	var pkScript []byte
	isOnchain := false

	arkAddress, err := arklib.DecodeAddressV0(o.To)
	if err != nil {
		// Decode onchain address
		btcAddress, err := btcutil.DecodeAddress(o.To, nil)
		if err != nil {
			return nil, false, err
		}

		pkScript, err = txscript.PayToAddrScript(btcAddress)
		if err != nil {
			return nil, false, err
		}

		isOnchain = true
	} else {
		pkScript, err = script.P2TRScript(arkAddress.VtxoTapKey)
		if err != nil {
			return nil, false, err
		}
	}

	if len(pkScript) == 0 {
		return nil, false, fmt.Errorf("invalid address")
	}

	return &wire.TxOut{
		Value:    int64(o.Amount),
		PkScript: pkScript,
	}, isOnchain, nil
}

func (r Receiver) ToArkFeeOutput() arkfee.Output {
	txout, _, err := r.ToTxOut()
	if err != nil {
		return arkfee.Output{}
	}
	return arkfee.Output{
		Amount: r.Amount,
		Script: hex.EncodeToString(txout.PkScript),
	}
}

type OnchainOutput struct {
	Outpoint
	Script    string
	Amount    uint64
	CreatedAt time.Time
	Spent     bool
	SpentBy   string
}

type OnchainAddressEvent struct {
	Error          error
	SpentUtxos     []OnchainOutput
	NewUtxos       []OnchainOutput
	ConfirmedUtxos []OnchainOutput
	Replacements   map[string]string // replacedTxid -> replacementTxid
}

type SyncEvent struct {
	Synced bool
	Err    error
}

// ControlAsset represents the control asset configuration for issuing new assets.
// Use either NewControlAsset to create a new control asset, or ExistingControlAsset
type ControlAsset interface {
	isControlAsset()
}

// NewControlAsset creates a new control asset with the specified amount.
type NewControlAsset struct {
	Amount uint64
}

func (NewControlAsset) isControlAsset() {}

// ExistingControlAsset references an existing control asset by its ID.
type ExistingControlAsset struct {
	ID string
}

func (ExistingControlAsset) isControlAsset() {}

func parseClosure(
	outpoint Outpoint, closure script.Closure, tapscripts []string,
) ([]byte, *arklib.TaprootMerkleProof, error) {
	if closure == nil {
		return nil, nil, fmt.Errorf("%s has no signing closure", outpoint.String())
	}
	if len(tapscripts) <= 0 {
		return nil, nil, fmt.Errorf("%s has no tapscripts", outpoint.String())
	}

	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid tapscripts: %w", outpoint.String(), err)
	}
	forfeitScript, err := closure.Script()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%s has invalid signing closure: %w", outpoint.String(), err,
		)
	}

	taprootKey, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid taptree: %w", outpoint.String(), err)
	}

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%s has invalid signing script: %w", outpoint.String(), err,
		)
	}
	pkScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid tapkey: %w", outpoint.String(), err)
	}

	return pkScript, leafProof, nil
}
