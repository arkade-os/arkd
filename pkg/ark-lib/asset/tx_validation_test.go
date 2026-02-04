package asset_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type txFixture struct {
	Name string `json:"name"`
	Tx string `json:"tx"`
	Prevouts map[int][]struct{
		AssetID string `json:"assetId"`
		Amount uint64 `json:"amount"`
	} `json:"prevouts"`
	ControlAssets map[string]string `json:"controlAssets,omitempty"`
	ExistingAssets []string `json:"existingAssets,omitempty"`
}

type txValidationFixtures struct {
	Valid []txFixture `json:"valid"`
	Invalid []struct {
		txFixture
		ExpectedError string `json:"expectedError"`
	} `json:"invalid"`
}


func TestTxValidation(t *testing.T) {
	ctx := t.Context()
	var fixtures txValidationFixtures
	buf, err := os.ReadFile("testdata/tx_validation_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(buf, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, v := range fixtures.Valid {
			t.Run(v.Name, func(t *testing.T) {
				tx, assetPrevouts, assetSrc := parseTxFixture(t, v)
				err := asset.ValidateAssetTransaction(ctx, tx, assetPrevouts, assetSrc)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, v := range fixtures.Invalid {
			t.Run(v.Name, func(t *testing.T) {
				tx, assetPrevouts, assetSrc := parseTxFixture(t, v.txFixture)
				err := asset.ValidateAssetTransaction(ctx, tx, assetPrevouts, assetSrc)
				require.Error(t, err)
				require.ErrorContains(t, err, v.ExpectedError)
			})
		}
	})
}

func parseTxFixture(t *testing.T, fixture txFixture) (
	*wire.MsgTx, map[int][]asset.Asset, asset.AssetSource,
) {
	var tx wire.MsgTx
	err := tx.Deserialize(hex.NewDecoder(strings.NewReader(fixture.Tx)))
	require.NoError(t, err)
	assetPrevouts := make(map[int][]asset.Asset)
	for inputIndex, prevouts := range fixture.Prevouts {
		assetTxs := make([]asset.Asset, 0)
		for _, prevout := range prevouts {
			assetTxs = append(assetTxs, asset.Asset{AssetID: prevout.AssetID, Amount: prevout.Amount})
		}
		assetPrevouts[inputIndex] = assetTxs
	}
	controlAssets := make(map[string]string)
	for assetID, controlAssetID := range fixture.ControlAssets {
		controlAssets[assetID] = controlAssetID
	}

	return &tx, assetPrevouts, &assetSrc{controlAssets, fixture.ExistingAssets}
}

type assetSrc struct {
	controlAssets map[string]string
	existingAssets []string
}
func (s *assetSrc) AssetExists(_ context.Context, assetID string) bool {
	return slices.Contains(s.existingAssets, assetID)
}

func (s *assetSrc) GetControlAsset(_ context.Context, assetID string) (string, error) {
	controlAssetID, ok := s.controlAssets[assetID]
	if !ok {
		return "", fmt.Errorf("control asset not found for asset %s", assetID)
	}
	return controlAssetID, nil
}