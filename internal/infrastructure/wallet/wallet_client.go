package walletclient

import (
	"context"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	"github.com/arkade-os/arkd/internal/core/ports"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type walletDaemonClient struct {
	client arkwalletv1.WalletServiceClient
	conn   *grpc.ClientConn
}

// New creates a ports.WalletService backed by a gRPC client.
func New(addr string) (ports.WalletService, *arklib.Network, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to wallet: %w", err)
	}
	client := arkwalletv1.NewWalletServiceClient(conn)

	svc := &walletDaemonClient{client: client, conn: conn}
	network, err := svc.GetNetwork(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to wallet: %s", err)
	}
	return svc, network, nil
}

func (w *walletDaemonClient) GenSeed(ctx context.Context) (string, error) {
	resp, err := w.client.GenSeed(ctx, &arkwalletv1.GenSeedRequest{})
	if err != nil {
		return "", err
	}
	return resp.Seed, nil
}

func (w *walletDaemonClient) Create(ctx context.Context, seed, password string) error {
	_, err := w.client.Create(ctx, &arkwalletv1.CreateRequest{Seed: seed, Password: password})
	return err
}

func (w *walletDaemonClient) Restore(ctx context.Context, seed, password string) error {
	_, err := w.client.Restore(ctx, &arkwalletv1.RestoreRequest{Seed: seed, Password: password})
	return err
}

func (w *walletDaemonClient) Unlock(ctx context.Context, password string) error {
	_, err := w.client.Unlock(ctx, &arkwalletv1.UnlockRequest{Password: password})
	return err
}

func (w *walletDaemonClient) Lock(ctx context.Context) error {
	_, err := w.client.Lock(ctx, &arkwalletv1.LockRequest{})
	return err
}

func (w *walletDaemonClient) Status(ctx context.Context) (ports.WalletStatus, error) {
	resp, err := w.client.Status(ctx, &arkwalletv1.StatusRequest{})
	if err != nil {
		return nil, err
	}
	return &walletStatus{resp}, nil
}

func (w *walletDaemonClient) GetTransaction(ctx context.Context, txid string) (string, error) {
	resp, err := w.client.GetTransaction(ctx, &arkwalletv1.GetTransactionRequest{Txid: txid})
	if err != nil {
		return "", err
	}
	return resp.GetTxHex(), nil
}

func (w *walletDaemonClient) WatchScripts(ctx context.Context, scripts []string) error {
	_, err := w.client.WatchScripts(ctx, &arkwalletv1.WatchScriptsRequest{Scripts: scripts})
	return err
}

func (w *walletDaemonClient) UnwatchScripts(ctx context.Context, scripts []string) error {
	_, err := w.client.UnwatchScripts(ctx, &arkwalletv1.UnwatchScriptsRequest{Scripts: scripts})
	return err
}

func (w *walletDaemonClient) SignMessage(ctx context.Context, message []byte) ([]byte, error) {
	resp, err := w.client.SignMessage(ctx, &arkwalletv1.SignMessageRequest{Message: message})
	if err != nil {
		return nil, err
	}
	return resp.GetSignature(), nil
}

func (w *walletDaemonClient) GetNotificationChannel(
	ctx context.Context,
) <-chan map[string][]ports.VtxoWithValue {
	ch := make(chan map[string][]ports.VtxoWithValue)
	stream, err := w.client.NotificationStream(ctx, &arkwalletv1.NotificationStreamRequest{})
	if err != nil {
		close(ch)
		return ch
	}
	go func() {
		defer close(ch)
		for {
			resp, err := stream.Recv()
			if err != nil {
				if strings.Contains(err.Error(), "EOF") {
					log.Fatal("connection closed by wallet")
				}
				if status.Code(err) == codes.Canceled {
					return
				}
				log.WithError(err).Warnf("failed to receive notification")
				return
			}
			m := make(map[string][]ports.VtxoWithValue)
			for _, entry := range resp.Entries {
				vtxos := make([]ports.VtxoWithValue, 0, len(entry.Vtxos))
				for _, v := range entry.Vtxos {
					vtxos = append(vtxos, ports.VtxoWithValue{
						Outpoint: domain.Outpoint{
							Txid: v.Txid,
							VOut: v.Vout,
						},
						Value: v.Value,
					})
				}
				m[entry.Script] = vtxos
			}
			ch <- m
		}
	}()
	return ch
}

func (w *walletDaemonClient) IsTransactionConfirmed(
	ctx context.Context, txid string,
) (bool, int64, int64, error) {
	resp, err := w.client.IsTransactionConfirmed(
		ctx, &arkwalletv1.IsTransactionConfirmedRequest{Txid: txid},
	)
	if err != nil {
		return false, 0, 0, err
	}
	return resp.Confirmed, resp.Blocknumber, resp.Blocktime, nil
}

func (w *walletDaemonClient) GetReadyUpdate(ctx context.Context) (<-chan struct{}, error) {
	ch := make(chan struct{})
	stream, err := w.client.GetReadyUpdate(ctx, &arkwalletv1.GetReadyUpdateRequest{})
	if err != nil {
		return nil, err
	}
	go func() {
		defer close(ch)
		for {
			resp, err := stream.Recv()
			if err != nil {
				if strings.Contains(err.Error(), "EOF") {
					log.Fatal("connection closed by wallet")
				}
				if status.Code(err) == codes.Canceled {
					return
				}
				log.WithError(err).Warnf("failed to receive wallet ready update")
				return
			}

			if resp.GetReady() {
				ch <- struct{}{}
				return
			}
		}
	}()
	return ch, nil
}

func (w *walletDaemonClient) GetPubkey(ctx context.Context) (*btcec.PublicKey, error) {
	resp, err := w.client.GetPubkey(ctx, &arkwalletv1.GetPubkeyRequest{})
	if err != nil {
		return nil, err
	}
	pubkey, err := btcec.ParsePubKey(resp.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pubkey: %w", err)
	}
	return pubkey, nil
}

func (w *walletDaemonClient) GetNetwork(ctx context.Context) (*arklib.Network, error) {
	resp, err := w.client.GetNetwork(ctx, &arkwalletv1.GetNetworkRequest{})
	if err != nil {
		return nil, err
	}
	var network arklib.Network
	switch resp.GetNetwork() {
	case arklib.BitcoinTestNet.Name:
		network = arklib.BitcoinTestNet
	case arklib.BitcoinTestNet4.Name:
		network = arklib.BitcoinTestNet4
	case arklib.BitcoinSigNet.Name:
		network = arklib.BitcoinSigNet
	case arklib.BitcoinMutinyNet.Name:
		network = arklib.BitcoinMutinyNet
	case arklib.BitcoinRegTest.Name:
		network = arklib.BitcoinRegTest
	case arklib.Bitcoin.Name:
		fallthrough
	default:
		network = arklib.Bitcoin
	}
	return &network, nil
}

func (w *walletDaemonClient) GetForfeitAddress(ctx context.Context) (string, error) {
	resp, err := w.client.GetForfeitAddress(ctx, &arkwalletv1.GetForfeitAddressRequest{})
	if err != nil {
		return "", err
	}
	return resp.GetAddress(), nil
}

func (w *walletDaemonClient) DeriveConnectorAddress(ctx context.Context) (string, error) {
	resp, err := w.client.DeriveConnectorAddress(ctx, &arkwalletv1.DeriveConnectorAddressRequest{})
	if err != nil {
		return "", err
	}
	return resp.GetAddress(), nil
}

func (w *walletDaemonClient) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	resp, err := w.client.DeriveAddresses(
		ctx, &arkwalletv1.DeriveAddressesRequest{Num: int32(num)},
	)
	if err != nil {
		return nil, err
	}
	return resp.GetAddresses(), nil
}

func (w *walletDaemonClient) SignTransaction(
	ctx context.Context, partialTx string, extractRawTx bool,
) (string, error) {
	resp, err := w.client.SignTransaction(
		ctx, &arkwalletv1.SignTransactionRequest{PartialTx: partialTx, ExtractRawTx: extractRawTx},
	)
	if err != nil {
		return "", err
	}
	return resp.GetSignedTx(), nil
}

func (w *walletDaemonClient) SignTransactionTapscript(
	ctx context.Context, partialTx string, inputIndexes []int,
) (string, error) {
	indexes := make([]int32, len(inputIndexes))
	for i, v := range inputIndexes {
		indexes[i] = int32(v)
	}
	resp, err := w.client.SignTransactionTapscript(
		ctx, &arkwalletv1.SignTransactionTapscriptRequest{
			PartialTx: partialTx, InputIndexes: indexes,
		},
	)
	if err != nil {
		return "", err
	}
	return resp.GetSignedTx(), nil
}

func (w *walletDaemonClient) SelectUtxos(
	ctx context.Context, asset string, amount uint64, confirmedOnly bool,
) ([]ports.TxInput, uint64, error) {
	resp, err := w.client.SelectUtxos(ctx, &arkwalletv1.SelectUtxosRequest{
		Asset:         asset,
		Amount:        amount,
		ConfirmedOnly: confirmedOnly,
	})
	if err != nil {
		return nil, 0, err
	}
	inputs := make([]ports.TxInput, len(resp.Utxos))
	for i, utxo := range resp.Utxos {
		inputs[i] = &txInput{
			txId:   utxo.GetTxid(),
			index:  utxo.GetIndex(),
			script: utxo.GetScript(),
			value:  utxo.GetValue(),
		}
	}
	return inputs, resp.GetTotalAmount(), nil
}

func (w *walletDaemonClient) BroadcastTransaction(
	ctx context.Context, txs ...string,
) (string, error) {
	resp, err := w.client.BroadcastTransaction(
		ctx, &arkwalletv1.BroadcastTransactionRequest{Txs: txs},
	)
	if err != nil {
		return "", err
	}
	return resp.GetTxid(), nil
}

func (w *walletDaemonClient) EstimateFees(ctx context.Context, psbt string) (uint64, error) {
	resp, err := w.client.EstimateFees(ctx, &arkwalletv1.EstimateFeesRequest{Psbt: psbt})
	if err != nil {
		return 0, err
	}
	return resp.GetFee(), nil
}

func (w *walletDaemonClient) FeeRate(ctx context.Context) (uint64, error) {
	resp, err := w.client.FeeRate(ctx, &arkwalletv1.FeeRateRequest{})
	if err != nil {
		return 0, err
	}
	return resp.GetSatPerKvbyte(), nil
}

func (w *walletDaemonClient) ListConnectorUtxos(
	ctx context.Context, connectorAddress string,
) ([]ports.TxInput, error) {
	resp, err := w.client.ListConnectorUtxos(
		ctx, &arkwalletv1.ListConnectorUtxosRequest{ConnectorAddress: connectorAddress},
	)
	if err != nil {
		return nil, err
	}
	inputs := make([]ports.TxInput, len(resp.Utxos))
	for i, utxo := range resp.Utxos {
		inputs[i] = &txInput{
			txId:   utxo.GetTxid(),
			index:  utxo.GetIndex(),
			script: utxo.GetScript(),
			value:  utxo.GetValue(),
		}
	}
	return inputs, nil
}

func (w *walletDaemonClient) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	resp, err := w.client.MainAccountBalance(ctx, &arkwalletv1.MainAccountBalanceRequest{})
	if err != nil {
		return 0, 0, err
	}
	return resp.GetConfirmed(), resp.GetUnconfirmed(), nil
}

func (w *walletDaemonClient) ConnectorsAccountBalance(
	ctx context.Context,
) (uint64, uint64, error) {
	resp, err := w.client.ConnectorsAccountBalance(
		ctx, &arkwalletv1.ConnectorsAccountBalanceRequest{},
	)
	if err != nil {
		return 0, 0, err
	}
	return resp.GetConfirmed(), resp.GetUnconfirmed(), nil
}

func (w *walletDaemonClient) LockConnectorUtxos(
	ctx context.Context, utxos []domain.Outpoint,
) error {
	protoUtxos := make([]*arkwalletv1.TxOutpoint, len(utxos))
	for i, u := range utxos {
		protoUtxos[i] = &arkwalletv1.TxOutpoint{
			Txid:  u.Txid,
			Index: u.VOut,
		}
	}
	_, err := w.client.LockConnectorUtxos(
		ctx, &arkwalletv1.LockConnectorUtxosRequest{Utxos: protoUtxos},
	)
	return err
}

func (w *walletDaemonClient) GetDustAmount(ctx context.Context) (uint64, error) {
	resp, err := w.client.GetDustAmount(ctx, &arkwalletv1.GetDustAmountRequest{})
	if err != nil {
		return 0, err
	}
	return resp.GetDustAmount(), nil
}

func (w *walletDaemonClient) VerifyMessageSignature(
	ctx context.Context, message, signature []byte,
) (bool, error) {
	resp, err := w.client.VerifyMessageSignature(
		ctx,
		&arkwalletv1.VerifyMessageSignatureRequest{Message: message, Signature: signature},
	)
	if err != nil {
		return false, err
	}
	return resp.GetValid(), nil
}

func (w *walletDaemonClient) GetCurrentBlockTime(
	ctx context.Context,
) (*ports.BlockTimestamp, error) {
	resp, err := w.client.GetCurrentBlockTime(ctx, &arkwalletv1.GetCurrentBlockTimeRequest{})
	if err != nil {
		return nil, err
	}
	if resp.Timestamp == nil {
		return nil, fmt.Errorf("missing timestamp in response")
	}
	return &ports.BlockTimestamp{
		Height: resp.GetTimestamp().GetHeight(), Time: resp.GetTimestamp().GetTime(),
	}, nil
}

func (w *walletDaemonClient) Withdraw(
	ctx context.Context, address string, amount uint64,
) (string, error) {
	resp, err := w.client.Withdraw(ctx, &arkwalletv1.WithdrawRequest{
		Address: address, Amount: amount},
	)
	if err != nil {
		return "", err
	}
	return resp.GetTxid(), nil
}

func (w *walletDaemonClient) GetOutpointStatus(
	ctx context.Context,
	outpoint domain.Outpoint,
) (spent bool, err error) {
	resp, err := w.client.GetOutpointStatus(ctx, &arkwalletv1.GetOutpointStatusRequest{
		Txid: outpoint.Txid,
		Vout: outpoint.VOut,
	})
	if err != nil {
		return false, err
	}
	return resp.GetSpent(), nil
}
