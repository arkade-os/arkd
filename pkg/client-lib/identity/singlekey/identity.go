package singlekeyidentity

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	identitystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	ErrNotInitialized = fmt.Errorf("identity not initialized")
	ErrIsLocked       = fmt.Errorf("identity is locked")
)

type service struct {
	store      identitystore.IdentityStore
	privateKey *btcec.PrivateKey
	data       *identitystore.IdentityData
}

func NewIdentity(store identitystore.IdentityStore) (identity.Identity, error) {
	data, err := store.Get()
	if err != nil {
		return nil, err
	}
	return &service{
		store: store,
		data:  data,
	}, nil
}

func (s *service) GetType() string {
	return identity.SingleKeyIdentity
}

func (s *service) Create(
	_ context.Context, _ chaincfg.Params, password, seed string,
) (string, error) {
	var privateKey *btcec.PrivateKey
	if len(seed) <= 0 {
		prvkey, err := utils.GenerateRandomPrivateKey()
		if err != nil {
			return "", err
		}
		privateKey = prvkey
	} else {
		prvkeyBytes, err := hex.DecodeString(seed)
		if err != nil {
			return "", err
		}

		privateKey, _ = btcec.PrivKeyFromBytes(prvkeyBytes)
	}

	pwd := []byte(password)
	passwordHash := utils.HashPassword(pwd)
	pubkey := privateKey.PubKey()
	buf := privateKey.Serialize()
	encryptedPrivateKey, err := utils.EncryptAES256(buf, pwd)
	if err != nil {
		return "", err
	}

	data := identitystore.IdentityData{
		EncryptedPrvkey: encryptedPrivateKey,
		PasswordHash:    passwordHash,
		PubKey:          pubkey,
	}
	if err := s.store.Add(data); err != nil {
		return "", err
	}

	s.data = &data

	return hex.EncodeToString(privateKey.Serialize()), nil
}

func (s *service) Lock(context.Context) error {
	if s.data == nil {
		return ErrNotInitialized
	}

	if s.privateKey == nil {
		return nil
	}

	s.privateKey = nil
	return nil
}

func (s *service) Unlock(
	_ context.Context, password string,
) (bool, error) {
	if s.data == nil {
		return false, ErrNotInitialized
	}

	if s.privateKey != nil {
		return true, nil
	}

	pwd := []byte(password)
	currentPassHash := utils.HashPassword(pwd)

	if !bytes.Equal(s.data.PasswordHash, currentPassHash) {
		return false, fmt.Errorf("invalid password")
	}

	privateKeyBytes, err := utils.DecryptAES256(s.data.EncryptedPrvkey, pwd)
	if err != nil {
		return false, err
	}

	s.privateKey, _ = btcec.PrivKeyFromBytes(privateKeyBytes)
	return false, nil
}

func (s *service) IsLocked() bool {
	return s.privateKey == nil
}

func (s *service) Dump(ctx context.Context) (string, error) {
	if s.data == nil {
		return "", ErrNotInitialized
	}

	if s.IsLocked() {
		return "", ErrIsLocked
	}

	return hex.EncodeToString(s.privateKey.Serialize()), nil
}

func (s *service) NewKey(ctx context.Context) (*identity.KeyRef, error) {
	if s.data == nil {
		return nil, ErrNotInitialized
	}
	return &identity.KeyRef{
		Id:     "m",
		PubKey: s.data.PubKey,
	}, nil
}

func (s *service) ClaimKey(_ context.Context, _ string) error {
	if s.data == nil {
		return ErrNotInitialized
	}
	return nil
}

func (s *service) GetKey(ctx context.Context, _ string) (*identity.KeyRef, error) {
	if s.data == nil {
		return nil, ErrNotInitialized
	}
	return &identity.KeyRef{
		Id:     "m",
		PubKey: s.data.PubKey,
	}, nil
}

func (s *service) NextKeyId(ctx context.Context, _ string) (string, error) {
	return "m", nil
}

func (s *service) GetKeyIndex(ctx context.Context, _ string) (uint32, error) {
	return 0, nil
}

func (s *service) ListKeys(ctx context.Context) ([]identity.KeyRef, error) {
	key, err := s.GetKey(ctx, "")
	if err != nil {
		return nil, err
	}
	return []identity.KeyRef{*key}, nil
}
func (s *service) SignTransaction(
	ctx context.Context, tx string, _ map[string]string,
) (string, error) {
	if s.data == nil {
		return "", ErrNotInitialized
	}

	if s.IsLocked() {
		return "", ErrIsLocked
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for i := range updater.Upsbt.Inputs {
		in := updater.Upsbt.Inputs[i]
		outpoint := updater.Upsbt.UnsignedTx.TxIn[i].PreviousOutPoint
		switch {
		case in.WitnessUtxo != nil:
			prevouts[outpoint] = in.WitnessUtxo
		case in.NonWitnessUtxo != nil && int(outpoint.Index) < len(in.NonWitnessUtxo.TxOut):
			prevouts[outpoint] = in.NonWitnessUtxo.TxOut[outpoint.Index]
		default:
			return "", fmt.Errorf(
				"input %d: missing prevout (WitnessUtxo or NonWitnessUtxo) for %s:%d",
				i, outpoint.Hash, outpoint.Index,
			)
		}
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txsighashes := txscript.NewTxSigHashes(updater.Upsbt.UnsignedTx, prevoutFetcher)

	onchainPkScript, err := script.P2TRScript(
		txscript.ComputeTaprootKeyNoScript(s.data.PubKey),
	)
	if err != nil {
		return "", err
	}

	for i, input := range ptx.Inputs {
		if len(input.TaprootLeafScript) > 0 {
			if err := s.signTapscriptSpend(updater, input, i, txsighashes, prevoutFetcher); err != nil {
				return "", err
			}
			continue
		}

		if input.WitnessUtxo != nil {
			// onchain P2TR
			if bytes.Equal(input.WitnessUtxo.PkScript, onchainPkScript) {
				updater.Upsbt.Inputs[i].TaprootInternalKey = schnorr.SerializePubKey(
					txscript.ComputeTaprootKeyNoScript(s.data.PubKey),
				)
				input = updater.Upsbt.Inputs[i]
			}
		}

		// taproot key path spend
		if len(input.TaprootInternalKey) > 0 {
			if err := s.signTaprootKeySpend(updater, input, i, txsighashes, prevoutFetcher); err != nil {
				return "", err
			}
			continue
		}

	}

	return ptx.B64Encode()
}

func (s *service) signTapscriptSpend(
	updater *psbt.Updater,
	input psbt.PInput,
	inputIndex int,
	txsighashes *txscript.TxSigHashes,
	prevoutFetcher *txscript.MultiPrevOutFetcher,
) error {
	myPubkey := schnorr.SerializePubKey(s.data.PubKey)

	for _, leaf := range input.TaprootLeafScript {
		closure, err := script.DecodeClosure(leaf.Script)
		if err != nil {
			// skip unknown leaf
			continue
		}

		sign := false

		switch c := closure.(type) {
		case *script.CSVMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *script.MultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *script.CLTVMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *script.ConditionMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		}

		if sign {
			hash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()

			preimage, err := txscript.CalcTapscriptSignaturehash(
				txsighashes,
				input.SighashType,
				updater.Upsbt.UnsignedTx,
				inputIndex,
				prevoutFetcher,
				txscript.NewBaseTapLeaf(leaf.Script),
			)
			if err != nil {
				return err
			}

			sig, err := schnorr.Sign(s.privateKey, preimage)
			if err != nil {
				return err
			}

			if len(updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig) == 0 {
				updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig = make(
					[]*psbt.TaprootScriptSpendSig,
					0,
				)
			}

			updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig = append(
				updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig,
				&psbt.TaprootScriptSpendSig{
					XOnlyPubKey: myPubkey,
					LeafHash:    hash.CloneBytes(),
					Signature:   sig.Serialize(),
					SigHash:     input.SighashType,
				},
			)
		}
	}

	return nil
}

func (s *service) signTaprootKeySpend(
	updater *psbt.Updater,
	input psbt.PInput,
	inputIndex int,
	txsighashes *txscript.TxSigHashes,
	prevoutFetcher *txscript.MultiPrevOutFetcher,
) error {
	if len(input.TaprootKeySpendSig) > 0 {
		// already signed, skip
		return nil
	}

	xOnlyPubkey := schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(s.data.PubKey))
	if !bytes.Equal(xOnlyPubkey, input.TaprootInternalKey) {
		// not the identity's key, skip
		return nil
	}

	preimage, err := txscript.CalcTaprootSignatureHash(
		txsighashes,
		input.SighashType,
		updater.Upsbt.UnsignedTx,
		inputIndex,
		prevoutFetcher,
	)

	if err != nil {
		return err
	}

	sig, err := schnorr.Sign(txscript.TweakTaprootPrivKey(*s.privateKey, nil), preimage)
	if err != nil {
		return err
	}

	updater.Upsbt.Inputs[inputIndex].TaprootKeySpendSig = sig.Serialize()

	return nil
}

func (s *service) NewVtxoTreeSigner(ctx context.Context) (tree.SignerSession, error) {
	if s.data == nil {
		return nil, ErrNotInitialized
	}
	if s.IsLocked() {
		return nil, ErrIsLocked
	}

	key, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return tree.NewTreeSignerSession(key), nil
}

func (s *service) SignMessage(
	ctx context.Context, message []byte,
) (string, error) {
	if s.data == nil {
		return "", ErrNotInitialized
	}
	if s.IsLocked() {
		return "", ErrIsLocked
	}

	sig, err := schnorr.Sign(s.privateKey, message)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sig.Serialize()), nil
}
