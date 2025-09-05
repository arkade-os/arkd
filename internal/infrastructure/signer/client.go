package signerclient

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	"github.com/arkade-os/arkd/internal/core/ports"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type signerClient struct {
	client signerv1.SignerServiceClient
	conn   *grpc.ClientConn
}

// New creates a ports.WalletService backed by a gRPC client.
func New(addr string) (ports.SignerService, error) {
	// TODO: support TLS.
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to signer: %w", err)
	}

	client := signerv1.NewSignerServiceClient(conn)
	if _, err := client.GetStatus(context.Background(), &signerv1.GetStatusRequest{}); err != nil {
		return nil, fmt.Errorf("failed to connect to signer: %s", err)
	}
	return &signerClient{client: client, conn: conn}, nil
}

func (c *signerClient) IsReady(ctx context.Context) (bool, error) {
	resp, err := c.client.GetStatus(ctx, &signerv1.GetStatusRequest{})
	if err != nil {
		return false, err
	}
	return resp.GetReady(), nil
}

func (c *signerClient) GetPubkey(ctx context.Context) (*btcec.PublicKey, error) {
	resp, err := c.client.GetPubkey(ctx, &signerv1.GetPubkeyRequest{})
	if err != nil {
		return nil, err
	}
	buf, err := hex.DecodeString(resp.GetPubkey())
	if err != nil {
		return nil, fmt.Errorf("failed to decode signer pubkey form hex: %s", err)
	}
	pubkey, err := btcec.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ec signer pubkey: %s", err)
	}
	return pubkey, nil
}

func (c *signerClient) SignTransaction(
	ctx context.Context, partialTx string, extractRawTx bool,
) (string, error) {
	resp, err := c.client.SignTransaction(ctx, &signerv1.SignTransactionRequest{
		PartialTx:    partialTx,
		ExtractRawTx: extractRawTx,
	})
	if err != nil {
		return "", err
	}
	return resp.GetSignedTx(), nil
}

func (c *signerClient) SignTransactionTapscript(
	ctx context.Context, partialTx string, inputIndexes []int,
) (string, error) {
	inIndexes := make([]int32, 0, len(inputIndexes))
	for _, v := range inputIndexes {
		inIndexes = append(inIndexes, int32(v))
	}
	resp, err := c.client.SignTransactionTapscript(ctx, &signerv1.SignTransactionTapscriptRequest{
		PartialTx: partialTx, InputIndexes: inIndexes,
	})
	if err != nil {
		return "", err
	}
	return resp.GetSignedTx(), nil
}
