package application

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
)

type bitcoindRPCClient struct {
	chainClient *chain.BitcoindClient
}

// TODO support submitpackage, need btcwallet update ?
func (b *bitcoindRPCClient) broadcast(txs ...string) error {
	if len(txs) == 1 {
		var tx wire.MsgTx

		err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txs[0])))
		if err != nil {
			return err
		}

		_, err = b.chainClient.SendRawTransaction(&tx, true)
		if err != nil {
			if errors.Is(err, chain.ErrNonBIP68Final) {
				return ErrNonFinalBIP68
			}
			return err
		}

		return nil
	}

	return fmt.Errorf("package relay not supported")
}

func (b *bitcoindRPCClient) getTxStatus(txid string) (isConfirmed bool, height, blocktime int64, err error) {
	txhash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return false, 0, 0, err
	}

	tx, err := b.chainClient.GetRawTransactionVerbose(txhash)
	if err != nil {
		if strings.Contains(err.Error(), "No such mempool or blockchain transaction") {
			return false, 0, 0, nil
		}
		return false, 0, 0, err
	}

	blockHash, err := chainhash.NewHashFromStr(tx.BlockHash)
	if err != nil {
		return false, 0, 0, err
	}

	blockHeight, err := b.chainClient.GetBlockHeight(blockHash)
	if err != nil {
		return false, 0, 0, err
	}

	return tx.Confirmations > 0, int64(blockHeight), tx.Blocktime, nil
}

func (b *bitcoindRPCClient) getTx(txid string) (*wire.MsgTx, error) {
	txhash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return nil, err
	}

	tx, err := b.chainClient.GetRawTransaction(txhash)
	if err != nil {
		return nil, err
	}

	return tx.MsgTx(), nil
}
