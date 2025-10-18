package walletclient

import (
	"context"
	"fmt"
	"log"

	"github.com/arkade-os/go-sdk/types"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type explorerClient struct {
	client  arkwalletv1.WalletServiceClient
	conn    *grpc.ClientConn
	baseUrl string
}

func NewExplorerClient(addr string) (*explorerClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to explorer: %w", err)
	}
	return &explorerClient{
		client:  arkwalletv1.NewWalletServiceClient(conn),
		conn:    conn,
		baseUrl: addr,
	}, nil
}

func (e *explorerClient) GetTxHex(txid string) (string, error) {
	ctx := context.Background()
	resp, err := e.client.GetTransaction(ctx, &arkwalletv1.GetTransactionRequest{Txid: txid})
	if err != nil {
		return "", err
	}
	return resp.GetTxHex(), nil
}

func (e *explorerClient) Broadcast(txs ...string) (string, error) {
	ctx := context.Background()
	resp, err := e.client.BroadcastTransaction(
		ctx,
		&arkwalletv1.BroadcastTransactionRequest{Txs: txs},
	)
	if err != nil {
		return "", err
	}
	return resp.GetTxid(), nil
}

func (e *explorerClient) GetTransactions(addr string) ([]tx, error) {
	ctx := context.Background()
	resp, err := e.client.GetTransactions(ctx, &arkwalletv1.GetTransactionsRequest{Address: addr})
	if err != nil {
		return nil, err
	}

	txs := make([]tx, len(resp.Transactions))
	for i, protoTx := range resp.Transactions {
		txs[i] = tx{
			Txid: protoTx.Txid,
			Vin:  convertExplorerTxInputs(protoTx.Vin),
			Vout: convertExplorerTxOutputs(protoTx.Vout),
			Status: struct {
				Confirmed bool  `json:"confirmed"`
				Blocktime int64 `json:"block_time"`
			}{
				Confirmed: protoTx.Status.Confirmed,
				Blocktime: protoTx.Status.BlockTime,
			},
		}
	}
	return txs, nil
}

func (e *explorerClient) GetTxOutspends(tx string) ([]spentStatus, error) {
	ctx := context.Background()
	resp, err := e.client.GetTxOutspends(ctx, &arkwalletv1.GetTxOutspendsRequest{Txid: tx})
	if err != nil {
		return nil, err
	}

	outspends := make([]spentStatus, len(resp.Outspends))
	for i, protoOutspend := range resp.Outspends {
		outspends[i] = spentStatus{
			Spent:   protoOutspend.Spent,
			SpentBy: protoOutspend.SpentBy,
		}
	}
	return outspends, nil
}

func (e *explorerClient) GetUtxos(addr string) ([]Utxo, error) {
	ctx := context.Background()
	resp, err := e.client.GetUtxos(ctx, &arkwalletv1.GetUtxosRequest{Address: addr})
	if err != nil {
		return nil, err
	}

	utxos := make([]Utxo, len(resp.Utxos))
	for i, protoUtxo := range resp.Utxos {
		utxos[i] = Utxo{
			Txid:   protoUtxo.Txid,
			Vout:   protoUtxo.Vout,
			Amount: protoUtxo.Value,
			Asset:  protoUtxo.Asset,
			Status: struct {
				Confirmed bool  `json:"confirmed"`
				BlockTime int64 `json:"block_time"`
			}{
				Confirmed: protoUtxo.Status.Confirmed,
				BlockTime: protoUtxo.Status.BlockTime,
			},
			Script: protoUtxo.Script,
		}
	}
	return utxos, nil
}

func (e *explorerClient) GetTxBlockTime(
	txid string,
) (confirmed bool, blocktime int64, err error) {
	ctx := context.Background()
	resp, err := e.client.IsTransactionConfirmed(
		ctx,
		&arkwalletv1.IsTransactionConfirmedRequest{Txid: txid},
	)
	if err != nil {
		return false, 0, err
	}
	return resp.GetConfirmed(), resp.GetBlocktime(), nil
}

func (e *explorerClient) BaseUrl() string {
	return e.baseUrl
}

func (e *explorerClient) GetFeeRate() (float64, error) {
	ctx := context.Background()
	resp, err := e.client.FeeRate(ctx, &arkwalletv1.FeeRateRequest{})
	if err != nil {
		return 0, err
	}
	return float64(resp.GetSatPerKvbyte()) / 1000, nil
}

func (e *explorerClient) GetAddressesEvents() <-chan types.OnchainAddressEvent {
	// This method is deprecated - use WatchScripts with NotificationStream instead
	ch := make(chan types.OnchainAddressEvent)
	close(ch)
	return ch
}

func (e *explorerClient) SubscribeForAddresses(addresses []string) error {
	ctx := context.Background()
	_, err := e.client.WatchScripts(ctx, &arkwalletv1.WatchScriptsRequest{
		Addresses: addresses,
	})
	return err
}

func (e *explorerClient) UnsubscribeForAddresses(addresses []string) error {
	ctx := context.Background()
	_, err := e.client.UnwatchScripts(ctx, &arkwalletv1.UnwatchScriptsRequest{
		Addresses: addresses,
	})
	return err
}

func (e *explorerClient) Stop() {
	if e.conn != nil {
		if err := e.conn.Close(); err != nil {
			log.Printf("error closing explorer client connection: %v", err)
		}
	}
}
func convertExplorerTxInputs(protoInputs []*arkwalletv1.ExplorerTxInput) []struct {
	Txid    string `json:"txid"`
	Vout    uint32 `json:"vout"`
	Prevout struct {
		Address string `json:"scriptpubkey_address"`
		Amount  uint64 `json:"value"`
	} `json:"prevout"`
} {
	inputs := make([]struct {
		Txid    string `json:"txid"`
		Vout    uint32 `json:"vout"`
		Prevout struct {
			Address string `json:"scriptpubkey_address"`
			Amount  uint64 `json:"value"`
		} `json:"prevout"`
	}, len(protoInputs))

	for i, input := range protoInputs {
		inputs[i] = struct {
			Txid    string `json:"txid"`
			Vout    uint32 `json:"vout"`
			Prevout struct {
				Address string `json:"scriptpubkey_address"`
				Amount  uint64 `json:"value"`
			} `json:"prevout"`
		}{
			Txid: input.Txid,
			Vout: input.Vout,
			Prevout: struct {
				Address string `json:"scriptpubkey_address"`
				Amount  uint64 `json:"value"`
			}{
				Address: input.Prevout.Address,
				Amount:  input.Prevout.Value,
			},
		}
	}
	return inputs
}

func convertExplorerTxOutputs(protoOutputs []*arkwalletv1.ExplorerTxOutput) []struct {
	Script  string `json:"scriptpubkey"`
	Address string `json:"scriptpubkey_address"`
	Amount  uint64 `json:"value"`
} {
	outputs := make([]struct {
		Script  string `json:"scriptpubkey"`
		Address string `json:"scriptpubkey_address"`
		Amount  uint64 `json:"value"`
	}, len(protoOutputs))

	for i, output := range protoOutputs {
		outputs[i] = struct {
			Script  string `json:"scriptpubkey"`
			Address string `json:"scriptpubkey_address"`
			Amount  uint64 `json:"value"`
		}{
			Script:  output.Script,
			Address: output.Address,
			Amount:  output.Value,
		}
	}
	return outputs
}
