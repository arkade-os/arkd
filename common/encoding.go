package common

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Address represents an Ark address with HRP, server public key, and VTXO Taproot public key
type Address struct {
	HRP        string
	VtxoScript []byte
	Server     *secp256k1.PublicKey
}

// Encode converts the address to its bech32m string representation
func (a *Address) Encode() (string, error) {
	if a.Server == nil {
		return "", fmt.Errorf("missing server public key")
	}
	if len(a.VtxoScript) <= 0 {
		return "", fmt.Errorf("missing vtxo script")
	}

	if !IsP2TRScript(a.VtxoScript) {
		return "", fmt.Errorf("invalid vtxo script, must be P2TR")
	}

	combinedKey := append(a.VtxoScript, schnorr.SerializePubKey(a.Server)...)
	grp, err := bech32.ConvertBits(combinedKey, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.EncodeM(a.HRP, grp)
}

// DecodeAddress parses a bech32m encoded address string and returns an Address object
func DecodeAddress(addr string) (*Address, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("missing address")
	}

	prefix, buf, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return nil, err
	}
	if prefix != Bitcoin.Addr && prefix != BitcoinTestNet.Addr && prefix != BitcoinRegTest.Addr {
		return nil, fmt.Errorf("unknown prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return nil, err
	}

	vtxoScript := grp[:34]
	if !IsP2TRScript(vtxoScript) {
		return nil, fmt.Errorf("failed to parse vtxo script, must be P2TR")
	}
	serverKey, err := schnorr.ParsePubKey(grp[34:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %s", err)
	}

	return &Address{
		HRP:        prefix,
		VtxoScript: vtxoScript,
		Server:     serverKey,
	}, nil
}
