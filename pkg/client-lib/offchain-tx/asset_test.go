package offchaintx

import (
	"context"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

func TestIssueAsset(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*IssueAssetArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *IssueAssetArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *IssueAssetArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
			{
				name:      "missing server info",
				mutate:    func(a *IssueAssetArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
			{
				name:      "missing signer pubkey",
				mutate:    func(a *IssueAssetArgs) { a.ServerParams.SignerPubKey = nil },
				errSubstr: "missing signer pubkey",
			},
			{
				name:      "missing change addr",
				mutate:    func(a *IssueAssetArgs) { a.ChangeAddr = "" },
				errSubstr: "missing change address",
			},
			{
				name:      "zero amount",
				mutate:    func(a *IssueAssetArgs) { a.Amount = 0 },
				errSubstr: "amount must be > 0",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestIssueAssetArgs()
				tc.mutate(&args)

				_, err := IssueAsset(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

func TestBuildAndSignIssuanceTx(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*BuildAndSignIssuanceTxArgs)
			errSubstr string
		}{
			{
				name:      "missing sign tx",
				mutate:    func(a *BuildAndSignIssuanceTxArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
			{
				name:      "missing server info",
				mutate:    func(a *BuildAndSignIssuanceTxArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
			{
				name:      "missing signer pubkey",
				mutate:    func(a *BuildAndSignIssuanceTxArgs) { a.ServerParams.SignerPubKey = nil },
				errSubstr: "missing signer pubkey",
			},
			{
				name:      "missing change addr",
				mutate:    func(a *BuildAndSignIssuanceTxArgs) { a.ChangeAddr = "" },
				errSubstr: "missing change address",
			},
			{
				name:      "zero amount",
				mutate:    func(a *BuildAndSignIssuanceTxArgs) { a.Amount = 0 },
				errSubstr: "amount must be > 0",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestIssueAssetBuildArgs()
				tc.mutate(&args)

				_, err := BuildAndSignIssuanceTx(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

func TestReissueAsset(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*ReissueAssetArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *ReissueAssetArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *ReissueAssetArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
			{
				name:      "missing server info",
				mutate:    func(a *ReissueAssetArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
			{
				name:      "missing signer pubkey",
				mutate:    func(a *ReissueAssetArgs) { a.ServerParams.SignerPubKey = nil },
				errSubstr: "missing signer pubkey",
			},
			{
				name:      "missing change addr",
				mutate:    func(a *ReissueAssetArgs) { a.ChangeAddr = "" },
				errSubstr: "missing change address",
			},
			{
				name:      "missing asset id",
				mutate:    func(a *ReissueAssetArgs) { a.Asset.AssetId = "" },
				errSubstr: "missing asset id",
			},
			{
				name:      "missing control asset id",
				mutate:    func(a *ReissueAssetArgs) { a.ControlAsset.AssetId = "" },
				errSubstr: "missing control asset id",
			},
			{
				name:      "missing asset amount",
				mutate:    func(a *ReissueAssetArgs) { a.Asset.Amount = 0 },
				errSubstr: "missing asset amount",
			},
			{
				name:      "missing control asset amount",
				mutate:    func(a *ReissueAssetArgs) { a.ControlAsset.Amount = 0 },
				errSubstr: "missing control asset amount",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestReissueAssetArgs()
				tc.mutate(&args)

				_, err := ReissueAsset(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

func TestBuildAndSignReissuanceTx(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*BuildAndSignReissuanceTxArgs)
			errSubstr string
		}{
			{
				name:      "missing sign tx",
				mutate:    func(a *BuildAndSignReissuanceTxArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
			{
				name:      "missing server info",
				mutate:    func(a *BuildAndSignReissuanceTxArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
			{
				name:      "missing signer pubkey",
				mutate:    func(a *BuildAndSignReissuanceTxArgs) { a.ServerParams.SignerPubKey = nil },
				errSubstr: "missing signer pubkey",
			},
			{
				name:      "missing change addr",
				mutate:    func(a *BuildAndSignReissuanceTxArgs) { a.ChangeAddr = "" },
				errSubstr: "missing change address",
			},
			{
				name:      "missing asset id",
				mutate:    func(a *BuildAndSignReissuanceTxArgs) { a.Asset.AssetId = "" },
				errSubstr: "missing asset id",
			},
			{
				name:      "missing control asset id",
				mutate:    func(a *BuildAndSignReissuanceTxArgs) { a.ControlAsset.AssetId = "" },
				errSubstr: "missing control asset id",
			},
			{
				name:      "missing asset amount",
				mutate:    func(a *BuildAndSignReissuanceTxArgs) { a.Asset.Amount = 0 },
				errSubstr: "missing asset amount",
			},
			{
				name:      "missing control asset amount",
				mutate:    func(a *BuildAndSignReissuanceTxArgs) { a.ControlAsset.Amount = 0 },
				errSubstr: "missing control asset amount",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestReissueAssetBuildArgs()
				tc.mutate(&args)

				_, err := BuildAndSignReissuanceTx(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

func TestBurnAsset(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*BurnAssetArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *BurnAssetArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *BurnAssetArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
			{
				name:      "missing server info",
				mutate:    func(a *BurnAssetArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
			{
				name:      "missing signer pubkey",
				mutate:    func(a *BurnAssetArgs) { a.ServerParams.SignerPubKey = nil },
				errSubstr: "missing signer pubkey",
			},
			{
				name:      "missing change addr",
				mutate:    func(a *BurnAssetArgs) { a.ChangeAddr = "" },
				errSubstr: "missing change address",
			},
			{
				name:      "missing asset id",
				mutate:    func(a *BurnAssetArgs) { a.Asset = clientlib.Asset{Amount: a.Asset.Amount} },
				errSubstr: "missing asset id",
			},
			{
				name:      "zero amount",
				mutate:    func(a *BurnAssetArgs) { a.Asset = clientlib.Asset{AssetId: a.Asset.AssetId} },
				errSubstr: "amount must be > 0",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestBurnAssetArgs()
				tc.mutate(&args)

				_, err := BurnAsset(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

func TestBuildAndSignBurnTx(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*BuildAndSignBurnTxArgs)
			errSubstr string
		}{
			{
				name:      "missing sign tx",
				mutate:    func(a *BuildAndSignBurnTxArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
			{
				name:      "missing server info",
				mutate:    func(a *BuildAndSignBurnTxArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
			{
				name:      "missing signer pubkey",
				mutate:    func(a *BuildAndSignBurnTxArgs) { a.ServerParams.SignerPubKey = nil },
				errSubstr: "missing signer pubkey",
			},
			{
				name:      "missing change addr",
				mutate:    func(a *BuildAndSignBurnTxArgs) { a.ChangeAddr = "" },
				errSubstr: "missing change address",
			},
			{
				name:      "missing asset id",
				mutate:    func(a *BuildAndSignBurnTxArgs) { a.Asset = clientlib.Asset{Amount: a.Asset.Amount} },
				errSubstr: "missing asset id",
			},
			{
				name:      "zero amount",
				mutate:    func(a *BuildAndSignBurnTxArgs) { a.Asset = clientlib.Asset{AssetId: a.Asset.AssetId} },
				errSubstr: "amount must be > 0",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestBurnAssetBuildArgs()
				tc.mutate(&args)

				_, err := BuildAndSignBurnTx(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

// newTestIssueAssetArgs returns a valid baseline IssueAssetArgs. Tests in this
// file mutate a single field to exercise the corresponding validation error.
func newTestIssueAssetArgs() IssueAssetArgs {
	b := newTestIssueAssetBuildArgs()
	return IssueAssetArgs{
		Client:       mockClient{},
		ServerParams: b.ServerParams,
		SignTx:       b.SignTx,
		Vtxos:        b.Vtxos,
		ChangeAddr:   b.ChangeAddr,
		Amount:       b.Amount,
		ControlAsset: b.ControlAsset,
		Metadata:     b.Metadata,
	}
}

// newTestIssueAssetBuildArgs returns a valid baseline IssueAssetBuildArgs.
// Tests mutate a single field to exercise validation errors from the
// BuildAndSignIssuanceTx primitive.
func newTestIssueAssetBuildArgs() BuildAndSignIssuanceTxArgs {
	return BuildAndSignIssuanceTxArgs{
		BaseArgs: BaseArgs{
			ServerParams: clientlib.ServerParams{Dust: 1000, SignerPubKey: testSignerPubKey},
			SignTx:       mockSignTx,
			ChangeAddr:   "tark1qexample",
		},
		Amount:       100,
		ControlAsset: clientlib.NewControlAsset{Amount: 1},
	}
}

// newTestReissueAssetArgs returns a valid baseline ReissueAssetArgs.
func newTestReissueAssetArgs() ReissueAssetArgs {
	b := newTestReissueAssetBuildArgs()
	return ReissueAssetArgs{
		Client:       mockClient{},
		ServerParams: b.ServerParams,
		SignTx:       b.SignTx,
		Vtxos:        b.Vtxos,
		ChangeAddr:   b.ChangeAddr,
		Asset:        b.Asset,
		ControlAsset: b.ControlAsset,
	}
}

// newTestReissueAssetBuildArgs returns a valid baseline
// ReissueAssetBuildArgs. Tests mutate one field to exercise the primitive's
// validation errors.
func newTestReissueAssetBuildArgs() BuildAndSignReissuanceTxArgs {
	return BuildAndSignReissuanceTxArgs{
		BaseArgs: BaseArgs{
			ServerParams: clientlib.ServerParams{Dust: 1000, SignerPubKey: testSignerPubKey},
			SignTx:       mockSignTx,
			ChangeAddr:   "tark1qexample",
		},
		Asset: clientlib.Asset{
			AssetId: "fakeassetid",
			Amount:  100,
		},
		ControlAsset: clientlib.Asset{
			AssetId: "fakecontrolassetid",
			Amount:  2,
		},
	}
}

// newTestBurnAssetArgs returns a valid baseline BurnAssetArgs.
func newTestBurnAssetArgs() BurnAssetArgs {
	b := newTestBurnAssetBuildArgs()
	return BurnAssetArgs{
		Client:       mockClient{},
		ServerParams: b.ServerParams,
		SignTx:       b.SignTx,
		Vtxos:        b.Vtxos,
		ChangeAddr:   b.ChangeAddr,
		Asset:        b.Asset,
	}
}

// newTestBurnAssetBuildArgs returns a valid baseline BurnAssetBuildArgs.
// Tests mutate one field to exercise the primitive's validation errors.
func newTestBurnAssetBuildArgs() BuildAndSignBurnTxArgs {
	return BuildAndSignBurnTxArgs{
		BaseArgs: BaseArgs{
			ServerParams: clientlib.ServerParams{Dust: 1000, SignerPubKey: testSignerPubKey},
			SignTx:       mockSignTx,
			ChangeAddr:   "tark1qexample",
		},
		Asset: clientlib.Asset{
			AssetId: "fakeassetid",
			Amount:  100,
		},
	}
}
