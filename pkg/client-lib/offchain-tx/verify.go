package offchaintx

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func VerifySignedCheckpointTxs(
	originalCheckpoints, signedCheckpoints []string, signers map[string]*btcec.PublicKey,
) error {
	// index by txid
	indexedOriginalCheckpoints := make(map[string]*psbt.Packet)
	indexedSignedCheckpoints := make(map[string]*psbt.Packet)

	for _, cp := range originalCheckpoints {
		originalPtx, err := psbt.NewFromRawBytes(strings.NewReader(cp), true)
		if err != nil {
			return err
		}
		indexedOriginalCheckpoints[originalPtx.UnsignedTx.TxID()] = originalPtx
	}

	for _, cp := range signedCheckpoints {
		signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(cp), true)
		if err != nil {
			return err
		}
		indexedSignedCheckpoints[signedPtx.UnsignedTx.TxID()] = signedPtx
	}

	for txid, originalPtx := range indexedOriginalCheckpoints {
		signedPtx, ok := indexedSignedCheckpoints[txid]
		if !ok {
			return fmt.Errorf("signed checkpoint %s not found", txid)
		}
		if err := verifyOffchainTx(originalPtx, signedPtx, signers); err != nil {
			return err
		}
	}

	return nil
}

func VerifySignedTx(original, signed string, signers map[string]*btcec.PublicKey) error {
	originalPtx, err := psbt.NewFromRawBytes(strings.NewReader(original), true)
	if err != nil {
		return err
	}

	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	if err != nil {
		return err
	}

	return verifyOffchainTx(originalPtx, signedPtx, signers)
}
