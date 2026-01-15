package handlers

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/metadata"
)

type mockIndexerService struct {
	mock.Mock
}

func (m *mockIndexerService) GetAssetGroup(
	ctx context.Context,
	assetId string,
) (*application.AssetGroupResp, error) {
	args := m.Called(ctx, assetId)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*application.AssetGroupResp), args.Error(1)
}

func (m *mockIndexerService) GetCommitmentTxInfo(
	ctx context.Context,
	txid string,
) (*application.CommitmentTxInfo, error) {
	return nil, nil
}

func (m *mockIndexerService) GetVtxoTree(
	ctx context.Context,
	batchOutpoint application.Outpoint,
	page *application.Page,
) (*application.TreeTxResp, error) {
	return nil, nil
}

func (m *mockIndexerService) GetVtxoTreeLeaves(
	ctx context.Context,
	batchOutpoint application.Outpoint,
	page *application.Page,
) (*application.VtxoTreeLeavesResp, error) {
	return nil, nil
}

func (m *mockIndexerService) GetForfeitTxs(
	ctx context.Context,
	txid string,
	page *application.Page,
) (*application.ForfeitTxsResp, error) {
	return nil, nil
}

func (m *mockIndexerService) GetConnectors(
	ctx context.Context,
	txid string,
	page *application.Page,
) (*application.TreeTxResp, error) {
	return nil, nil
}

func (m *mockIndexerService) GetVtxos(
	ctx context.Context,
	pubkeys []string,
	spendableOnly, spentOnly, recoverableOnly, includeAnchors bool,
	page *application.Page,
) (*application.GetVtxosResp, error) {
	return nil, nil
}

func (m *mockIndexerService) GetVtxosByOutpoint(
	ctx context.Context,
	outpoints []application.Outpoint,
	page *application.Page,
) (*application.GetVtxosResp, error) {
	return nil, nil
}

func (m *mockIndexerService) GetVtxoChain(
	ctx context.Context,
	outpoint application.Outpoint,
	page *application.Page,
) (*application.VtxoChainResp, error) {
	return nil, nil
}

func (m *mockIndexerService) GetVirtualTxs(
	ctx context.Context,
	txids []string,
	page *application.Page,
) (*application.VirtualTxsResp, error) {
	return nil, nil
}

func (m *mockIndexerService) GetBatchSweepTxs(
	ctx context.Context,
	batchOutpoint application.Outpoint,
) ([]string, error) {
	return nil, nil
}

type mockStream struct {
	mock.Mock
}

func (m *mockStream) Send(resp *arkv1.GetSubscriptionResponse) error {
	args := m.Called(resp)
	return args.Error(0)
}

func (m *mockStream) Context() context.Context {
	return context.Background()
}

func (m *mockStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockStream) SendHeader(metadata.MD) error { return nil }
func (m *mockStream) SetTrailer(metadata.MD)       {}
func (m *mockStream) SendMsg(m_ interface{}) error { return nil }
func (m *mockStream) RecvMsg(m_ interface{}) error { return nil }

func TestSubscribeForTeleportHash(t *testing.T) {
	mockSvc := new(mockIndexerService)
	eventsCh := make(chan application.TransactionEvent)
	svc := NewIndexerService(mockSvc, eventsCh, time.Minute, 5)

	// Create AssetGroup Group with Teleport Output
	teleportHashBytes, err := hex.DecodeString("deadbeef")
	assert.NoError(t, err)

	var commitment [32]byte
	copy(commitment[:], teleportHashBytes)

	assetGroup := extension.AssetPacket{
		Assets: []extension.AssetGroup{
			{
				Outputs: []extension.AssetOutput{
					{
						Type:       extension.AssetTypeTeleport,
						Commitment: commitment,
					},
				},
			},
		},
		Version: extension.AssetVersion,
	}

	opretTxOut, _ := assetGroup.EncodeAssetPacket()

	// Create PSBT
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&opretTxOut)

	ptx, _ := psbt.NewFromUnsignedTx(tx)

	// Encode PSBT to Base64 (ignoring error for test)
	b64Ptx, _ := ptx.B64Encode()

	// 1. Subscribe
	ctx := context.Background()
	subRes, err := svc.SubscribeForTeleportHash(ctx, &arkv1.SubscribeForTeleportHashRequest{
		TeleportHashes: []string{hex.EncodeToString(commitment[:])},
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, subRes.SubscriptionId)

	// 2. Mock Stream
	stream := new(mockStream)
	stream.On("Send", mock.Anything).Run(func(args mock.Arguments) {
		resp := args.Get(0).(*arkv1.GetSubscriptionResponse)
		if resp.GetEvent() != nil {
			t.Log("Received event", resp.GetEvent())
			assert.Equal(t, "txid", resp.GetEvent().Txid)
			assert.Len(t, resp.GetEvent().TeleportEvents, 1)
			assert.Equal(
				t,
				hex.EncodeToString(commitment[:]),
				resp.GetEvent().TeleportEvents[0].TeleportHash,
			)
			assert.Equal(t, uint32(0), resp.GetEvent().TeleportEvents[0].OutputVout)
		}
	}).Return(nil)

	// 3. Start GetSubscription loop
	go func() {
		err := svc.GetSubscription(&arkv1.GetSubscriptionRequest{
			SubscriptionId: subRes.SubscriptionId,
		}, stream)
		assert.NoError(t, err)
	}()

	// 4. Send Event
	time.Sleep(100 * time.Millisecond) // wait for sub to be active

	eventsCh <- application.TransactionEvent{
		TxData: application.TxData{
			Tx:   b64Ptx, // Not strictly needed by indexer logic anymore but good for completeness
			Txid: "txid",
		},
		Type:           application.CommitmentTxType,
		SpentVtxos:     []domain.Vtxo{},
		SpendableVtxos: []domain.Vtxo{},
		TeleportAssets: []application.TeleportAsset{
			{
				TeleportHash: hex.EncodeToString(commitment[:]),
				AnchorOutpoint: domain.Outpoint{
					Txid: "txid",
					VOut: 0,
				},
				OutputVout: 0,
			},
		},
	}

	time.Sleep(200 * time.Millisecond) // wait for processing
}
