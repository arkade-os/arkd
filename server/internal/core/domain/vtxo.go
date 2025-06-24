package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type VtxoKey struct {
	Txid string
	VOut uint32
}
type Outpoint VtxoKey

func (k VtxoKey) String() string {
	return fmt.Sprintf("%s:%d", k.Txid, k.VOut)
}

func (k VtxoKey) Hash() string {
	calcHash := func(buf []byte, hasher hash.Hash) []byte {
		_, _ = hasher.Write(buf)
		return hasher.Sum(nil)
	}

	hash160 := func(buf []byte) []byte {
		return calcHash(calcHash(buf, sha256.New()), sha256.New())
	}

	buf, _ := hex.DecodeString(k.Txid)
	buf = append(buf, byte(k.VOut))
	return hex.EncodeToString(hash160(buf))
}

type Vtxo struct {
	VtxoKey
	Amount             uint64
	PubKey             string
	CommitmentTxids    []string
	RootCommitmentTxid string
	SpentBy            string // round txid or redeem txid
	Spent              bool
	Redeemed           bool
	Swept              bool
	ExpireAt           int64
	RedeemTx           string // empty if in-round vtxo
	CreatedAt          int64
}

func (v Vtxo) IsPending() bool {
	return len(v.RedeemTx) > 0
}

func (v Vtxo) IsNote() bool {
	return len(v.CommitmentTxids) <= 0 && v.RootCommitmentTxid == ""
}

func (v Vtxo) RequiresForfeit() bool {
	return !v.Swept && !v.IsNote()
}

func (v Vtxo) TapKey() (*btcec.PublicKey, error) {
	pubkeyBytes, err := hex.DecodeString(v.PubKey)
	if err != nil {
		return nil, err
	}
	return schnorr.ParsePubKey(pubkeyBytes)
}
