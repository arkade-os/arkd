package tree

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	ErrMissingVtxoTree = errors.New("missing vtxo tree")
)

type Musig2Nonce struct {
	PubNonce [66]byte
}

// TreeNonces is a map of txid to public nonces only
// it implements json.Marshaler and json.Unmarshaler
type TreeNonces map[string]*Musig2Nonce // txid -> public nonces only

func (n TreeNonces) MarshalJSON() ([]byte, error) {
	mapObject := make(map[string]string)
	for txid, nonce := range n {
		mapObject[txid] = hex.EncodeToString(nonce.PubNonce[:])
	}

	return json.Marshal(mapObject)
}

func (n *TreeNonces) UnmarshalJSON(data []byte) error {
	mapObject := make(map[string]string)
	if err := json.Unmarshal(data, &mapObject); err != nil {
		return err
	}

	*n = make(TreeNonces)

	for txid, nonce := range mapObject {
		nonceBytes, err := hex.DecodeString(nonce)
		if err != nil {
			return err
		}

		if len(nonceBytes) != 66 {
			return fmt.Errorf("expected nonce to be 66 bytes, got %d", len(nonceBytes))
		}

		(*n)[txid] = &Musig2Nonce{
			PubNonce: [66]byte(nonceBytes),
		}
	}

	return nil
}

// TreePartialSigs is a map of txid to partial signature
// it implements json.Marshaler and json.Unmarshaler
type TreePartialSigs map[string]*musig2.PartialSignature // txid -> partial signature

func (s TreePartialSigs) MarshalJSON() ([]byte, error) {
	mapObject := make(map[string]string)
	for txid, sig := range s {
		var sigBytes bytes.Buffer
		if err := sig.Encode(&sigBytes); err != nil {
			return nil, err
		}

		mapObject[txid] = hex.EncodeToString(sigBytes.Bytes())
	}

	return json.Marshal(mapObject)
}

func (s *TreePartialSigs) UnmarshalJSON(data []byte) error {
	mapObject := make(map[string]string)
	if err := json.Unmarshal(data, &mapObject); err != nil {
		return err
	}

	for txid, sig := range mapObject {
		sigBytes, err := hex.DecodeString(sig)
		if err != nil {
			return err
		}

		sig := &musig2.PartialSignature{}
		if err := sig.Decode(bytes.NewReader(sigBytes)); err != nil {
			return err
		}

		(*s)[txid] = sig
	}
	return nil
}

type SignerSession interface {
	Init(batchOutSweepClosure []byte, batchOutAmount int64, vtxoTree *TxTree) error
	GetPublicKey() string
	GetNonces() (TreeNonces, error) // generate tree nonces for this session
	SetAggregatedNonces(TreeNonces) // set the aggregated nonces
	Sign() (TreePartialSigs, error) // sign the tree
}

type CoordinatorSession interface {
	AddNonce(*btcec.PublicKey, TreeNonces)
	AddSignatures(*btcec.PublicKey, TreePartialSigs)
	AggregateNonces() (TreeNonces, error)
	// SignTree combines the signatures and add them to the tree's psbts
	SignTree() (*TxTree, error)
}

// AggregateKeys is a wrapper around musig2.AggregateKeys using the given tweak
func AggregateKeys(pubkeys []*btcec.PublicKey, tweak []byte) (*musig2.AggregateKey, error) {
	if len(pubkeys) == 0 {
		return nil, errors.New("no pubkeys")
	}

	for _, pubkey := range pubkeys {
		if pubkey == nil {
			return nil, errors.New("nil pubkey")
		}
	}

	// if there is only one pubkey, fallback to classic P2TR
	if len(pubkeys) == 1 {
		res := &musig2.AggregateKey{
			PreTweakedKey: pubkeys[0],
		}

		if len(tweak) > 0 {
			finalKey := txscript.ComputeTaprootOutputKey(pubkeys[0], tweak)
			res.FinalKey = finalKey
		} else {
			res.FinalKey = pubkeys[0]
		}

		return res, nil
	}

	opts := make([]musig2.KeyAggOption, 0)
	if len(tweak) > 0 {
		opts = append(opts, musig2.WithTaprootKeyTweak(tweak))
	}

	key, _, _, err := musig2.AggregateKeys(pubkeys, true, opts...)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// ValidateTreeSigs validates the signatures on the given vtxo tree.
//
// It validates that each input in the tree has a valid signature, and that the
// signature was generated using the aggregated public key of all cosigners.
//
// The function returns an error if any of the signatures are invalid, or if there
// are any issues with the aggregated public key.
func ValidateTreeSigs(
	batchOutSweepClosure []byte, batchOutAmount int64, vtxoTree *TxTree,
) error {
	prevoutFetcherFactory, err := prevOutFetcherFactory(
		batchOutSweepClosure, batchOutAmount, vtxoTree,
	)
	if err != nil {
		return err
	}

	txs := treeToIndexedTxs(vtxoTree, make(map[string]*psbt.Packet))

	_, err = workPoolMap(txs, func(partialTx *psbt.Packet) (any, error) {
		sig := partialTx.Inputs[0].TaprootKeySpendSig
		if len(sig) == 0 {
			return nil, errors.New("unsigned tree input")
		}

		schnorrSig, err := schnorr.ParseSignature(sig)
		if err != nil {
			return nil, fmt.Errorf("failed to parse signature: %w", err)
		}

		prevoutFetcher, err := prevoutFetcherFactory(partialTx)
		if err != nil {
			return nil, fmt.Errorf("failed to get prevout fetcher: %w", err)
		}

		message, err := txscript.CalcTaprootSignatureHash(
			txscript.NewTxSigHashes(partialTx.UnsignedTx, prevoutFetcher),
			txscript.SigHashDefault, partialTx.UnsignedTx, 0, prevoutFetcher,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate sighash: %w", err)
		}

		keys, err := txutils.GetCosignerKeys(partialTx.Inputs[0])
		if err != nil {
			return nil, fmt.Errorf("failed to get cosigner keys: %w", err)
		}

		if len(keys) == 0 {
			return nil, fmt.Errorf("no keys for txid %s", partialTx.UnsignedTx.TxID())
		}

		aggregateKey, err := AggregateKeys(keys, batchOutSweepClosure)
		if err != nil {
			return nil, fmt.Errorf("failed to aggregate keys: %w", err)
		}

		if !schnorrSig.Verify(message, aggregateKey.FinalKey) {
			return nil, fmt.Errorf("invalid signature for txid %s", partialTx.UnsignedTx.TxID())
		}

		return nil, nil
	})
	return err
}

func NewTreeSignerSession(signer *btcec.PrivateKey) SignerSession {
	return &treeSignerSession{secretKey: signer}
}

type treeSignerSession struct {
	secretKey             *btcec.PrivateKey
	txs                   map[string]*psbt.Packet
	myNonces              map[string]*musig2.Nonces
	aggregateNonces       TreeNonces
	scriptRoot            []byte
	prevoutFetcherFactory func(*psbt.Packet) (txscript.PrevOutputFetcher, error)
}

func (t *treeSignerSession) Init(
	batchOutSweepClosure []byte, batchOutAmount int64, vtxoTree *TxTree,
) error {
	prevOutFetcherFactory, err := prevOutFetcherFactory(
		batchOutSweepClosure, batchOutAmount, vtxoTree,
	)
	if err != nil {
		return err
	}

	t.scriptRoot = batchOutSweepClosure
	t.prevoutFetcherFactory = prevOutFetcherFactory
	t.txs = treeToIndexedTxs(vtxoTree, make(map[string]*psbt.Packet))
	return nil
}

func (t *treeSignerSession) GetPublicKey() string {
	return hex.EncodeToString(t.secretKey.PubKey().SerializeCompressed())
}

// GetNonces returns only the public musig2 nonces for each transaction
// where the signer's key is in the list of cosigners
func (t *treeSignerSession) GetNonces() (TreeNonces, error) {
	if t.myNonces == nil {
		if err := t.generateNonces(); err != nil {
			return nil, err
		}
	}

	publicNonces := make(TreeNonces)
	for txid, nonces := range t.myNonces {
		publicNonces[txid] = &Musig2Nonce{nonces.PubNonce}
	}

	return publicNonces, nil
}

func (t *treeSignerSession) SetAggregatedNonces(nonces TreeNonces) {
	t.aggregateNonces = nonces
}

// Sign generates the musig2 partial signatures for each transaction of the tree that includes the
// signer as in the cosigners list.
func (t *treeSignerSession) Sign() (TreePartialSigs, error) {
	if t.txs == nil {
		return nil, errors.New("vtxo tree not initialized")
	}

	if t.aggregateNonces == nil {
		return nil, errors.New("nonces not set")
	}

	musigParamsMap := make(map[string]musigParams)
	serializedSignerPubKey := schnorr.SerializePubKey(t.secretKey.PubKey())

	for txid, tx := range t.txs {
		mustSign, cosigners, err := getCosignersPublicKeys(serializedSignerPubKey, tx)
		if err != nil {
			return nil, err
		}

		// if the signer's key is not in the list of keys, skip signing
		if !mustSign {
			continue
		}

		prevoutFetcher, err := t.prevoutFetcherFactory(tx)
		if err != nil {
			return nil, err
		}

		combinedNonce, ok := t.aggregateNonces[txid]
		if !ok {
			return nil, fmt.Errorf("missing combined nonce for txid %s", txid)
		}

		secretNonce, ok := t.myNonces[txid]
		if !ok {
			return nil, fmt.Errorf("missing secret nonce for txid %s", txid)
		}

		musigParamsMap[txid] = musigParams{
			tx:             tx,
			prevoutFetcher: prevoutFetcher,
			combinedNonce:  combinedNonce.PubNonce,
			secretNonce:    secretNonce.SecNonce,
			cosigners:      cosigners,
		}
	}

	return workPoolMap(musigParamsMap, sign(t.secretKey, t.scriptRoot))
}

// generateNonces generates musig2 private and public nonces for each transaction of the tree.
func (t *treeSignerSession) generateNonces() error {
	if len(t.txs) == 0 {
		return ErrMissingVtxoTree
	}

	myNonces, err := workPoolMap(t.txs, generateNonces(t.secretKey.PubKey()))
	if err != nil {
		return err
	}

	t.myNonces = myNonces
	return nil
}

type treeCoordinatorSession struct {
	scriptRoot            []byte
	nonces                map[string]TreeNonces      // xonly pubkey -> nonces
	sigs                  map[string]TreePartialSigs // xonly pubkey -> sigs
	prevoutFetcherFactory func(*psbt.Packet) (txscript.PrevOutputFetcher, error)
	vtxoTree              *TxTree
	txs                   map[string]*psbt.Packet
}

func NewTreeCoordinatorSession(
	batchOutSweepClosure []byte, batchOutAmount int64, vtxoTree *TxTree,
) (CoordinatorSession, error) {
	prevoutFetcherFactory, err := prevOutFetcherFactory(
		batchOutSweepClosure, batchOutAmount, vtxoTree,
	)
	if err != nil {
		return nil, err
	}

	return &treeCoordinatorSession{
		scriptRoot:            batchOutSweepClosure,
		nonces:                make(map[string]TreeNonces),
		sigs:                  make(map[string]TreePartialSigs),
		prevoutFetcherFactory: prevoutFetcherFactory,
		vtxoTree:              vtxoTree,
		txs:                   treeToIndexedTxs(vtxoTree, make(map[string]*psbt.Packet)),
	}, nil
}

func (t *treeCoordinatorSession) AddNonce(pubkey *btcec.PublicKey, nonce TreeNonces) {
	t.nonces[hex.EncodeToString(schnorr.SerializePubKey(pubkey))] = nonce
}

func (t *treeCoordinatorSession) AddSignatures(pubkey *btcec.PublicKey, sig TreePartialSigs) {
	t.sigs[hex.EncodeToString(schnorr.SerializePubKey(pubkey))] = sig
}

// AggregateNonces aggregates the musig2 nonces for each transaction in the tree
// it returns an error if any of the nonces are not set
func (t *treeCoordinatorSession) AggregateNonces() (TreeNonces, error) {
	return workPoolMap(t.txs, combineNonces(t.nonces))
}

// SignTree combines the signatures and add them to the tree's psbts
// it returns the vtxo tree with the signed transactions set as TaprootKeySpendSig
func (t *treeCoordinatorSession) SignTree() (*TxTree, error) {
	combineSigsItems := make(map[string]combineSigsParams)

	for txid, tx := range t.txs {
		prevoutFetcher, err := t.prevoutFetcherFactory(tx)
		if err != nil {
			return nil, err
		}

		combineSigsItems[txid] = combineSigsParams{tx: tx, prevoutFetcher: prevoutFetcher}
	}

	combinedSigs, err := workPoolMap(combineSigsItems, combineSigs(t.scriptRoot, t.sigs))
	if err != nil {
		return nil, err
	}

	if err := t.vtxoTree.Apply(func(g *TxTree) (bool, error) {
		sig, ok := combinedSigs[g.Root.UnsignedTx.TxID()]
		if !ok {
			return true, nil
		}

		g.Root.Inputs[0].TaprootKeySpendSig = sig.Serialize()
		return true, nil
	}); err != nil {
		return nil, err
	}

	return t.vtxoTree, nil
}

func prevOutFetcherFactory(
	batchOutSweepClosure []byte, batchOutAmount int64, vtxoTree *TxTree,
) (func(*psbt.Packet) (txscript.PrevOutputFetcher, error), error) {
	return func(ptx *psbt.Packet) (txscript.PrevOutputFetcher, error) {
		parentOutpoint := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
		parentTxID := parentOutpoint.Hash.String()
		// root tx case
		if vtxoTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String() == parentTxID {
			keys, err := txutils.GetCosignerKeys(ptx.Inputs[0])
			if err != nil {
				return nil, err
			}

			if len(keys) == 0 {
				return nil, fmt.Errorf("no keys for txid %s", ptx.UnsignedTx.TxID())
			}

			aggregateKey, err := AggregateKeys(keys, batchOutSweepClosure)
			if err != nil {
				return nil, err
			}

			pkscript, err := script.P2TRScript(aggregateKey.FinalKey)
			if err != nil {
				return nil, err
			}

			return &treePrevOutFetcher{
				prevout: &wire.TxOut{
					Value:    batchOutAmount,
					PkScript: pkscript,
				},
			}, nil
		}

		parent := vtxoTree.Find(parentTxID)

		if parent == nil {
			return nil, errors.New("parent tx not found " + parentTxID)
		}

		return &treePrevOutFetcher{
			prevout: parent.Root.UnsignedTx.TxOut[parentOutpoint.Index],
		}, nil
	}, nil
}

type treePrevOutFetcher struct {
	prevout *wire.TxOut
}

func (f *treePrevOutFetcher) FetchPrevOutput(wire.OutPoint) *wire.TxOut {
	return f.prevout
}

// workPool is a generic worker pool that processes items concurrently
func workPool[T any](items []T, workers int, processItem func(item T) error) error {
	errChan := make(chan error, 1)
	workChan := make(chan T)

	var wg sync.WaitGroup
	wg.Add(workers)

	// launch workers
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for item := range workChan {
				if err := processItem(item); err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
			}
		}()
	}

	// distribute tasks
	go func() {
		for _, item := range items {
			select {
			case err := <-errChan:
				close(workChan)
				errChan <- err
				return
			default:
				workChan <- item
			}
		}
		close(workChan)
	}()

	// wait for all workers to finish
	wg.Wait()

	select {
	case err := <-errChan:
		return err
	default:
		return nil
	}
}

// workPoolMap is a specialized version of workPool for processing maps jobs in parallel
func workPoolMap[T any, R comparable](
	kvMap map[string]T, processItem func(item T) (R, error),
) (map[string]R, error) {
	locker := sync.Mutex{}
	results := make(map[string]R)

	type workItem struct {
		key  string
		item T
	}

	items := make([]workItem, 0, len(kvMap))
	for key, item := range kvMap {
		items = append(items, workItem{key: key, item: item})
	}

	if err := workPool(items, runtime.NumCPU(), func(item workItem) error {
		result, err := processItem(item.item)
		if err != nil {
			return err
		}

		zero := new(R)
		if result != *zero {
			locker.Lock()
			results[item.key] = result
			locker.Unlock()
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return results, nil
}

// getCosignersPublicKeys checks if the given signer public key is present in the cosigner keys for
// the transaction's first input.
// It returns a boolean indicating the presence of the key, the list of cosigner public keys, and
// an error if one occurs while fetching cosigner keys.
func getCosignersPublicKeys(
	signerPubkey []byte, tx *psbt.Packet,
) (bool, []*btcec.PublicKey, error) {
	keys, err := txutils.GetCosignerKeys(tx.Inputs[0])
	if err != nil {
		return false, nil, err
	}

	for _, key := range keys {
		if bytes.Equal(schnorr.SerializePubKey(key), signerPubkey) {
			return true, keys, nil
		}
	}
	return false, nil, nil
}

func treeToIndexedTxs(txTree *TxTree, res map[string]*psbt.Packet) map[string]*psbt.Packet {
	res[txTree.Root.UnsignedTx.TxID()] = txTree.Root

	for _, child := range txTree.Children {
		res = treeToIndexedTxs(child, res)
	}

	return res
}

func combineNonces(allNonces map[string]TreeNonces) func(tx *psbt.Packet) (*Musig2Nonce, error) {
	return func(tx *psbt.Packet) (*Musig2Nonce, error) {
		keys, err := txutils.GetCosignerKeys(tx.Inputs[0])
		if err != nil {
			return nil, fmt.Errorf("failed to get cosigner keys: %w", err)
		}

		if len(keys) == 0 {
			return nil, fmt.Errorf("no keys for txid %s", tx.UnsignedTx.TxID())
		}

		nonces := make([][66]byte, 0, len(keys))

		for _, key := range keys {
			keyStr := hex.EncodeToString(schnorr.SerializePubKey(key))
			nonceMap, ok := allNonces[keyStr]
			if !ok {
				return nil, fmt.Errorf(
					"nonces not set for cosigner key %x",
					key.SerializeCompressed(),
				)
			}

			nonce := nonceMap[tx.UnsignedTx.TxID()]
			if nonce == nil {
				return nil, fmt.Errorf(
					"missing nonce for cosigner key %x",
					key.SerializeCompressed(),
				)
			}

			nonces = append(nonces, nonce.PubNonce)
		}

		if len(nonces) == 0 {
			return nil, fmt.Errorf("missing nonces for txid %s", tx.UnsignedTx.TxID())
		}

		if len(nonces) != len(keys) {
			return nil, fmt.Errorf(
				"wrong number of nonces for txid %s, expected %d got %d",
				tx.UnsignedTx.TxID(),
				len(keys),
				len(nonces),
			)
		}

		aggregatedNonce, err := musig2.AggregateNonces(nonces)
		if err != nil {
			return nil, fmt.Errorf("failed to aggregate nonces: %w", err)
		}

		return &Musig2Nonce{aggregatedNonce}, nil
	}
}

func generateNonces(
	signerPubKey *btcec.PublicKey,
) func(*psbt.Packet) (*musig2.Nonces, error) {
	serializedSignerPubKey := schnorr.SerializePubKey(signerPubKey)

	return func(ptx *psbt.Packet) (*musig2.Nonces, error) {
		mustGenerateNonce, _, err := getCosignersPublicKeys(serializedSignerPubKey, ptx)
		if err != nil {
			return nil, err
		}

		// if the signer's key is not in the list of keys, skip generating nonces
		if !mustGenerateNonce {
			return nil, nil
		}

		// generate musig2 nonces
		nonce, err := musig2.GenNonces(
			musig2.WithPublicKey(signerPubKey),
		)
		if err != nil {
			return nil, err
		}

		return nonce, nil
	}
}

type musigParams struct {
	tx             *psbt.Packet
	combinedNonce  [66]byte
	secretNonce    [97]byte
	prevoutFetcher txscript.PrevOutputFetcher
	cosigners      []*btcec.PublicKey
}

func sign(
	signer *btcec.PrivateKey, batchOutSweepClosure []byte,
) func(musigParams) (*musig2.PartialSignature, error) {
	return func(params musigParams) (*musig2.PartialSignature, error) {
		message, err := txscript.CalcTaprootSignatureHash(
			txscript.NewTxSigHashes(params.tx.UnsignedTx, params.prevoutFetcher),
			txscript.SigHashDefault, params.tx.UnsignedTx, 0, params.prevoutFetcher,
		)
		if err != nil {
			return nil, err
		}

		return musig2.Sign(
			params.secretNonce, signer, params.combinedNonce, params.cosigners, [32]byte(message),
			musig2.WithSortedKeys(), musig2.WithTaprootSignTweak(batchOutSweepClosure),
			musig2.WithFastSign(),
		)
	}
}

type combineSigsParams struct {
	tx             *psbt.Packet
	prevoutFetcher txscript.PrevOutputFetcher
}

// combineSigs combines the partial signatures from all cosigners
// and returns the combined schnorr signature.
//
// The function also takes the prevout fetcher, which is used to fetch
// the prevout for the given txid.
//
// The function returns an error if the partial signatures are not
// set for any of the cosigners, or if the combined nonce is not set.
//
// The function returns an error if the combined nonce is not set, or
// if the signatures are invalid.
//
// The function returns an error if the number of signatures is not
// equal to the number of cosigners.
//
// The function returns an error if the aggregated key is not set.
//
// The function returns an error if the combined signature is invalid.
func combineSigs(
	batchOutSweepClosure []byte, allSigs map[string]TreePartialSigs,
) func(combineSigsParams) (*schnorr.Signature, error) {
	return func(params combineSigsParams) (*schnorr.Signature, error) {
		keys, err := txutils.GetCosignerKeys(params.tx.Inputs[0])
		if err != nil {
			return nil, err
		}

		if len(keys) == 0 {
			return nil, fmt.Errorf("no keys for txid %s", params.tx.UnsignedTx.TxID())
		}

		var combinedNonce *btcec.PublicKey
		sigs := make([]*musig2.PartialSignature, 0, len(keys))

		for _, key := range keys {
			keySigs, ok := allSigs[hex.EncodeToString(schnorr.SerializePubKey(key))]
			if !ok {
				return nil, fmt.Errorf(
					"sigs not set for cosigner key %x", key.SerializeCompressed(),
				)
			}

			s := keySigs[params.tx.UnsignedTx.TxID()]
			if s == nil {
				return nil, fmt.Errorf(
					"missing signature for cosigner key %x", key.SerializeCompressed(),
				)
			}

			if s.R != nil {
				combinedNonce = s.R
			}
			sigs = append(sigs, s)
		}

		if combinedNonce == nil {
			return nil, fmt.Errorf(
				"missing combined nonce for txid %s",
				params.tx.UnsignedTx.TxID(),
			)
		}

		message, err := txscript.CalcTaprootSignatureHash(
			txscript.NewTxSigHashes(params.tx.UnsignedTx, params.prevoutFetcher),
			txscript.SigHashDefault, params.tx.UnsignedTx, 0, params.prevoutFetcher,
		)
		if err != nil {
			return nil, err
		}

		if len(sigs) == 0 {
			return nil, fmt.Errorf("missing signatures for txid %s", params.tx.UnsignedTx.TxID())
		}

		if len(sigs) != len(keys) {
			return nil, fmt.Errorf(
				"wrong number of signatures for txid %s, expected %d got %d",
				params.tx.UnsignedTx.TxID(), len(keys), len(sigs),
			)
		}

		combineOpts := make([]musig2.CombineOption, 0)
		if batchOutSweepClosure != nil {
			combineOpts = append(
				combineOpts, musig2.WithTaprootTweakedCombine(
					[32]byte(message), keys, batchOutSweepClosure, true,
				),
			)
		}

		combinedSig := musig2.CombineSigs(
			combinedNonce, sigs,
			combineOpts...,
		)

		aggregatedKey, err := AggregateKeys(keys, batchOutSweepClosure)
		if err != nil {
			return nil, err
		}

		if !combinedSig.Verify(message, aggregatedKey.FinalKey) {
			return nil, fmt.Errorf(
				"invalid signature for cosigner key %x, txid %s",
				keys[0].SerializeCompressed(), params.tx.UnsignedTx.TxID(),
			)
		}

		return combinedSig, nil
	}
}
