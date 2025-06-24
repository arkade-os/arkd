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
	Server     *secp256k1.PublicKey
	VtxoTapKey *secp256k1.PublicKey
}

// Encode converts the address to its bech32m string representation
func (a *Address) Encode() (string, error) {
	if a.Server == nil {
		return "", fmt.Errorf("missing server public key")
	}
	if a.VtxoTapKey == nil {
		return "", fmt.Errorf("missing vtxo tap public key")
	}

	combinedKey := append(
		schnorr.SerializePubKey(a.Server), schnorr.SerializePubKey(a.VtxoTapKey)...,
	)
	grp, err := bech32.ConvertBits(combinedKey, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.EncodeM(a.HRP, grp)
}

// DecodeAddress parses a bech32m encoded address string and returns an Address object
func DecodeAddress(addr string) (*Address, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("address is empty")
	}

	prefix, buf, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return nil, err
	}
	if prefix != Bitcoin.Addr && prefix != BitcoinTestNet.Addr && prefix != BitcoinRegTest.Addr {
		return nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return nil, err
	}

	serverKey, err := schnorr.ParsePubKey(grp[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %s", err)
	}

	vtxoKey, err := schnorr.ParsePubKey(grp[32:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %s", err)
	}

	return &Address{
		HRP:        prefix,
		Server:     serverKey,
		VtxoTapKey: vtxoKey,
	}, nil
}
