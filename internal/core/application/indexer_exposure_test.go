package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	testTxids = []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	testVtxoTxid  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testVtxoVout  = uint32(0)
	differentTxid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestHashOutpoints(t *testing.T) {
	opA := Outpoint{Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VOut: 0}
	opB := Outpoint{Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VOut: 1}

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name      string
			outpoints []Outpoint
		}{
			{
				name:      "single outpoint produces consistent hash",
				outpoints: []Outpoint{opA},
			},
			{
				name:      "multiple outpoints produces consistent hash",
				outpoints: []Outpoint{opA, opB},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				input := slices.Clone(tc.outpoints)
				h1, err := hashOutpoints(input)
				require.NoError(t, err)
				// Make sure input list of outpoints is not modified by hashOutpoints
				require.Equal(t, tc.outpoints[0], input[0])

				slices.Reverse(input)
				h2, err := hashOutpoints(input)
				require.NoError(t, err)
				require.Equal(t, h1, h2)
				require.NotEmpty(t, h1)
			})
		}
	})
}

func TestAuthToken(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	indexer := newTestIndexer(t, privkey, exposurePublic, nil, nil, nil)

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name      string
			outpoints []Outpoint
		}{
			{
				name:      "single outpoint round-trip",
				outpoints: []Outpoint{{Txid: testTxids[0], VOut: 0}},
			},
			{
				name: "multiple outpoints round-trip",
				outpoints: []Outpoint{
					{Txid: testTxids[0], VOut: 0},
					{Txid: testVtxoTxid, VOut: testVtxoVout},
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				token, err := indexer.createAuthToken(tc.outpoints)
				require.NoError(t, err)
				require.NotEmpty(t, token)

				hash, err := indexer.validateAuthToken(token)
				require.NoError(t, err)

				expectedHash, err := hashOutpoints(append([]Outpoint{}, tc.outpoints...))
				require.NoError(t, err)
				require.Equal(t, hex.EncodeToString(expectedHash), hash)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			makeToken   func() string
			errContains string
		}{
			{
				name:        "empty token",
				makeToken:   func() string { return "" },
				errContains: "missing auth",
			},
			{
				name:        "bad base64",
				makeToken:   func() string { return "not-valid-base64!!!" },
				errContains: "invalid auth token format",
			},
			{
				name: "wrong length",
				makeToken: func() string {
					return base64.StdEncoding.EncodeToString([]byte("tooshort"))
				},
				errContains: "invalid auth token length",
			},
			{
				name: "expired token",
				makeToken: func() string {
					return buildExpiredToken(t, privkey, []Outpoint{{Txid: testTxids[0], VOut: 0}})
				},
				errContains: "auth token expired",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := indexer.validateAuthToken(tc.makeToken())
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
			})
		}

		t.Run("wrong signer pubkey", func(t *testing.T) {
			key1, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			key2, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			signer := newTestIndexer(t, key1, exposurePublic, nil, nil, nil)
			// token signed with key1; validator expects key2 — deliberate mismatch
			validator := &indexerService{
				authPrvkey:   key2,
				authTokenTTL: defaultAuthTokenTTL,
				tokenCache:   newTokenCache(defaultAuthTokenTTL),
			}

			token, err := signer.createAuthToken([]Outpoint{{Txid: testTxids[0], VOut: 0}})
			require.NoError(t, err)

			_, err = validator.validateAuthToken(token)
			require.Error(t, err)
			require.Contains(t, err.Error(), "verif")
		})
	})
}

func TestGetVirtualTxs(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name       string
			exposure   exposure
			makeToken  func(*testing.T, *indexerService) string
			setupMocks func(*mockedRoundRepo, *mockedVtxoRepo)
			wantTxs    int
		}{
			{
				// public + no token: valid=false → stripArkdSignatures is called.
				// Return empty list to avoid PSBT parse error on fake tx data.
				name:      "public, no token",
				exposure:  exposurePublic,
				makeToken: func(_ *testing.T, indexer *indexerService) string { return "" },
				setupMocks: func(rounds *mockedRoundRepo, _ *mockedVtxoRepo) {
					rounds.On("GetTxsWithTxids", mock.Anything, testTxids).
						Return([]string{}, nil)
				},
				wantTxs: 0,
			},
			{
				// public + bad token: exposurePublic branch has no body — authToken is
				// never read regardless of value, valid=false → stripArkdSignatures called.
				// Return empty list to avoid PSBT parse error.
				name:      "public, bad token is ignored",
				exposure:  exposurePublic,
				makeToken: func(_ *testing.T, indexer *indexerService) string { return "badtoken" },
				setupMocks: func(rounds *mockedRoundRepo, _ *mockedVtxoRepo) {
					rounds.On("GetTxsWithTxids", mock.Anything, testTxids).
						Return([]string{}, nil)
				},
				wantTxs: 0,
			},
			{
				// withheld + no token: proceeds without auth, valid=false → stripArkdSignatures.
				// Return empty list to avoid PSBT parse error on fake tx data.
				name:      "withheld, no token",
				exposure:  exposureWithheld,
				makeToken: func(_ *testing.T, indexer *indexerService) string { return "" },
				setupMocks: func(rounds *mockedRoundRepo, _ *mockedVtxoRepo) {
					rounds.On("GetTxsWithTxids", mock.Anything, testTxids).
						Return([]string{}, nil)
				},
				wantTxs: 0,
			},
			{
				// withheld + valid token: cache hit → valid=true → signatures not stripped.
				// Returns the txs from the repo as-is (empty list here).
				name:     "withheld, valid token",
				exposure: exposureWithheld,
				makeToken: func(t *testing.T, i *indexerService) string {
					token, err := i.createAuthToken([]Outpoint{{Txid: testTxids[0], VOut: 0}})
					require.NoError(t, err)
					return token
				},
				setupMocks: func(rounds *mockedRoundRepo, _ *mockedVtxoRepo) {
					rounds.On("GetTxsWithTxids", mock.Anything, testTxids).
						Return([]string{}, nil)
				},
				wantTxs: 0,
			},
			{
				// private + valid token: cache hit → valid=true → signatures not stripped.
				// Fake tx strings are returned as-is since stripping is skipped.
				name:     "private, valid token",
				exposure: exposurePrivate,
				makeToken: func(t *testing.T, i *indexerService) string {
					token, err := i.createAuthToken([]Outpoint{{Txid: testTxids[0], VOut: 0}})
					require.NoError(t, err)
					return token
				},
				setupMocks: func(rounds *mockedRoundRepo, _ *mockedVtxoRepo) {
					rounds.On("GetTxsWithTxids", mock.Anything, testTxids).
						Return(testTxids, nil)
				},
				wantTxs: 1,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				rounds := &mockedRoundRepo{}
				vtxos := &mockedVtxoRepo{}
				tc.setupMocks(rounds, vtxos)

				indexer := newTestIndexer(t, privkey, tc.exposure, rounds, vtxos, nil)
				token := tc.makeToken(t, indexer)

				resp, err := indexer.GetVirtualTxs(t.Context(), token, testTxids, nil)
				require.NoError(t, err)
				require.Len(t, resp.Txs, tc.wantTxs)

				rounds.AssertExpectations(t)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			exposure    exposure
			makeToken   func(*testing.T, *indexerService) string
			errContains string
		}{
			{
				name:        "private, no token",
				exposure:    exposurePrivate,
				makeToken:   func(*testing.T, *indexerService) string { return "" },
				errContains: "missing auth",
			},
			{
				name:     "private, bad token format",
				exposure: exposurePrivate,
				makeToken: func(*testing.T, *indexerService) string {
					return "invalidtoken!!!"
				},
				errContains: "invalid auth token format",
			},
			{
				name:     "private, expired token",
				exposure: exposurePrivate,
				makeToken: func(*testing.T, *indexerService) string {
					return buildExpiredToken(t, privkey, []Outpoint{{
						Txid: testTxids[0],
						VOut: 0,
					}})
				},
				errContains: "auth token expired",
			},

			{
				// private + token for different txid: cache hit, but txid not in whitelist.
				name:     "private, valid token but for different txid",
				exposure: exposurePrivate,
				makeToken: func(t *testing.T, i *indexerService) string {
					token, err := i.createAuthToken([]Outpoint{{Txid: differentTxid, VOut: 0}})
					require.NoError(t, err)
					return token
				},
				errContains: "auth token is not for txid",
			},
			{
				name:     "withheld, bad token format",
				exposure: exposureWithheld,
				makeToken: func(*testing.T, *indexerService) string {
					return "invalidtoken!!!"
				},
				errContains: "invalid auth token format",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				indexer := newTestIndexer(t, privkey, tc.exposure, nil, nil, nil)
				token := tc.makeToken(t, indexer)

				_, err := indexer.GetVirtualTxs(t.Context(), token, testTxids, nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
			})
		}
	})
}

func TestGetVirtualTxsByIntent(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		vtxoKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		const vtxoAmount = int64(21000)
		validIntent, vtxoTaprootKey := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, vtxoAmount)
		validVtxo := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
			Amount:             uint64(vtxoAmount),
			PubKey:             hex.EncodeToString(schnorr.SerializePubKey(vtxoTaprootKey)),
			RootCommitmentTxid: testTxids[0],
		}

		tests := []struct {
			name       string
			exposure   exposure
			intent     Intent
			setupMocks func(*mockedRoundRepo, *mockedVtxoRepo, *mockedWallet)
			wantTxs    int
		}{
			{
				// public: extractOutpointsFromIntent runs, validateIntent is skipped
				name:     "public, vtxo validation skipped",
				exposure: exposurePublic,
				intent:   validIntent,
				setupMocks: func(rounds *mockedRoundRepo, _ *mockedVtxoRepo, _ *mockedWallet) {
					rounds.On("GetTxsWithTxids", mock.Anything, []string{testVtxoTxid}).
						Return([]string{"fakeTxData"}, nil)
				},
				wantTxs: 1,
			},
			{
				name:     "private, valid intent",
				exposure: exposurePrivate,
				intent:   validIntent,
				setupMocks: func(rounds *mockedRoundRepo, vtxos *mockedVtxoRepo, _ *mockedWallet) {
					vtxos.On("GetVtxos", mock.Anything,
						[]domain.Outpoint{{Txid: testVtxoTxid, VOut: testVtxoVout}}).
						Return([]domain.Vtxo{validVtxo}, nil)
					rounds.On("GetTxsWithTxids", mock.Anything, []string{testVtxoTxid}).
						Return([]string{"fakeTxData"}, nil)
				},
				wantTxs: 1,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				rounds := &mockedRoundRepo{}
				vtxos := &mockedVtxoRepo{}
				wallet := &mockedWallet{}
				tc.setupMocks(rounds, vtxos, wallet)

				indexer := newTestIndexer(t, privkey, tc.exposure, rounds, vtxos, wallet)

				resp, err := indexer.GetVirtualTxsByIntent(t.Context(), tc.intent, nil)
				require.NoError(t, err)
				require.Len(t, resp.Txs, tc.wantTxs)

				rounds.AssertExpectations(t)
				vtxos.AssertExpectations(t)
				wallet.AssertExpectations(t)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		vtxoKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		const vtxoAmount = int64(21000)
		// validVtxo uses a matching taprootKey so that amount-check tests reach the
		// right error before any script comparison.
		_, vtxoTaprootKey := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, vtxoAmount)
		validVtxo := domain.Vtxo{
			Outpoint: domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
			Amount:   uint64(vtxoAmount),
			PubKey:   hex.EncodeToString(schnorr.SerializePubKey(vtxoTaprootKey)),
		}

		tests := []struct {
			name        string
			exposure    exposure
			makeIntent  func() Intent
			setupMocks  func(*mockedVtxoRepo, *mockedWallet)
			errContains string
		}{
			{
				name:        "empty proof",
				exposure:    exposurePrivate,
				makeIntent:  func() Intent { return Intent{} },
				setupMocks:  func(*mockedVtxoRepo, *mockedWallet) {},
				errContains: "missing intent proof tx",
			},
			{
				name:        "invalid PSBT",
				exposure:    exposurePrivate,
				makeIntent:  func() Intent { return Intent{Proof: "notavalidpsbt"} },
				setupMocks:  func(*mockedVtxoRepo, *mockedWallet) {},
				errContains: "failed to parse intent proof tx",
			},
			{
				name:     "private, unknown vtxo — wallet also fails",
				exposure: exposurePrivate,
				makeIntent: func() Intent {
					intent, _ := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, vtxoAmount)
					return intent
				},
				setupMocks: func(vtxos *mockedVtxoRepo, wallet *mockedWallet) {
					vtxos.On("GetVtxos", mock.Anything, mock.Anything).
						Return([]domain.Vtxo{}, nil)
					wallet.On("GetTransaction", mock.Anything, testVtxoTxid).
						Return("", fmt.Errorf("tx not found"))
				},
				errContains: "failed to get boarding tx",
			},
			{
				name:     "private, amount mismatch",
				exposure: exposurePrivate,
				makeIntent: func() Intent {
					// intent claims 99999 but vtxo has 21000
					intent, _ := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, 99999)
					return intent
				},
				setupMocks: func(vtxos *mockedVtxoRepo, _ *mockedWallet) {
					vtxos.On("GetVtxos", mock.Anything, mock.Anything).
						Return([]domain.Vtxo{validVtxo}, nil)
				},
				errContains: "got prevout value",
			},
			{
				name:     "private, script mismatch",
				exposure: exposurePrivate,
				makeIntent: func() Intent {
					intent, _ := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, vtxoAmount)
					return intent
				},
				setupMocks: func(vtxos *mockedVtxoRepo, _ *mockedWallet) {
					wrongKey, _ := btcec.NewPrivateKey()
					// vtxo has a different pubkey → P2TR script won't match the intent's pkScript
					vtxos.On("GetVtxos", mock.Anything, mock.Anything).
						Return([]domain.Vtxo{{
							Outpoint: domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
							Amount:   uint64(vtxoAmount),
							PubKey:   hex.EncodeToString(schnorr.SerializePubKey(wrongKey.PubKey())),
						}}, nil)
				},
				errContains: "got witness utxo script",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				vtxos := &mockedVtxoRepo{}
				wallet := &mockedWallet{}
				tc.setupMocks(vtxos, wallet)

				indexer := newTestIndexer(t, privkey, tc.exposure, nil, vtxos, wallet)

				_, err := indexer.GetVirtualTxsByIntent(t.Context(), tc.makeIntent(), nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)

				vtxos.AssertExpectations(t)
				wallet.AssertExpectations(t)
			})
		}
	})
}

func TestGetVtxoChain(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	testOutpoint := Outpoint{Txid: testTxids[0], VOut: 0}
	otherOutpoint := Outpoint{Txid: differentTxid, VOut: 0}

	t.Run("valid", func(t *testing.T) {
		t.Run("private, token covers tree tx outpoints", func(t *testing.T) {
			// Build a 2-node PSBT tree: root_tx → vtxo_tx (leaf).
			// buildVtxoChain collects allOutpoints = [vtxoOutpoint, vtxoOutpoint (dup),
			// rootTxid:0, vtxoTxid:0] so the auth token covers both the vtxo and the tree tx.
			rootTxid, vtxoTxid, flatTree := buildTestTreeTxs(t)

			commitmentTxid := differentTxid
			vtxoOutpoint := Outpoint{Txid: vtxoTxid, VOut: 0}
			vtxoData := domain.Vtxo{
				Outpoint:           vtxoOutpoint,
				Preconfirmed:       false,
				RootCommitmentTxid: commitmentTxid,
			}

			rounds := &mockedRoundRepo{}
			vtxos := &mockedVtxoRepo{}
			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{vtxoOutpoint}).
				Return([]domain.Vtxo{vtxoData}, nil)
			rounds.On("GetRoundVtxoTree", mock.Anything, commitmentTxid).
				Return(flatTree, nil)

			indexer := newTestIndexer(t, privkey, exposurePrivate, rounds, vtxos, nil)

			// Build chain first to collect allOutpoints.
			// allOutpoints includes vtxoOutpoint and the tree tx outpoints.
			_, allOutpoints, err := indexer.buildVtxoChain(t.Context(), vtxoOutpoint)
			require.NoError(t, err)

			// Verify allOutpoints covers both the vtxo and the root tree tx.
			outpointSet := make(map[string]struct{}, len(allOutpoints))
			for _, op := range allOutpoints {
				outpointSet[op.String()] = struct{}{}
			}
			require.Contains(t, outpointSet, vtxoOutpoint.String())
			require.Contains(t, outpointSet, Outpoint{Txid: rootTxid, VOut: 0}.String())

			// Create auth token for the whole chain.
			token, err := indexer.createAuthToken(allOutpoints)
			require.NoError(t, err)

			// GetVtxoChain with the token — auth check passes and chain is returned.
			resp, err := indexer.GetVtxoChain(t.Context(), token, vtxoOutpoint, nil)
			require.NoError(t, err)
			require.NotEmpty(t, resp.Chain)

			// Chain must contain a tree tx and the commitment tx.
			chainByType := make(map[ChainTxType]bool)
			for _, tx := range resp.Chain {
				chainByType[tx.Type] = true
			}
			require.True(t, chainByType[IndexerChainedTxTypeTree])
			require.True(t, chainByType[IndexerChainedTxTypeCommitment])

			rounds.AssertExpectations(t)
			vtxos.AssertExpectations(t)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			exposure    exposure
			makeToken   func(*testing.T, *indexerService) string
			outpoint    Outpoint
			errContains string
		}{
			{
				name:        "private, no token",
				exposure:    exposurePrivate,
				makeToken:   func(*testing.T, *indexerService) string { return "" },
				outpoint:    testOutpoint,
				errContains: "missing auth",
			},
			{
				name:        "private, bad base64",
				exposure:    exposurePrivate,
				makeToken:   func(*testing.T, *indexerService) string { return "not-base64!!!" },
				outpoint:    testOutpoint,
				errContains: "invalid auth token format",
			},
			{
				// private + token for different outpoint: token validates OK but cache lookup
				// misses (known key-mismatch bug between createAuthToken and validateAuthToken),
				// so GetVtxoChain returns "auth token not found" before reaching outpoint check.
				name:     "private, token for different outpoint",
				exposure: exposurePrivate,
				makeToken: func(t *testing.T, i *indexerService) string {
					token, err := i.createAuthToken([]Outpoint{otherOutpoint})
					require.NoError(t, err)
					return token
				},
				outpoint:    testOutpoint,
				errContains: "auth token is not for outpoint",
			},
			{
				name:        "withheld, invalid non-empty token",
				exposure:    exposureWithheld,
				makeToken:   func(*testing.T, *indexerService) string { return "invalidtoken!!!" },
				outpoint:    testOutpoint,
				errContains: "invalid auth token format",
			},
			{
				// withheld + token for different outpoint: cache hit, but outpoint not in whitelist.
				name:     "withheld, token for different outpoint",
				exposure: exposureWithheld,
				makeToken: func(t *testing.T, i *indexerService) string {
					token, err := i.createAuthToken([]Outpoint{otherOutpoint})
					require.NoError(t, err)
					return token
				},
				outpoint:    testOutpoint,
				errContains: "auth token is not for outpoint",
			},
			{
				name:     "private, expired token",
				exposure: exposurePrivate,
				makeToken: func(_ *testing.T, i *indexerService) string {
					return buildExpiredToken(t, privkey, []Outpoint{testOutpoint})
				},
				outpoint:    testOutpoint,
				errContains: "auth token expired",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				indexer := newTestIndexer(t, privkey, tc.exposure, nil, nil, nil)
				token := tc.makeToken(t, indexer)

				_, err := indexer.GetVtxoChain(t.Context(), token, tc.outpoint, nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
			})
		}
	})
}

func TestGetVtxoChainByIntent(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Run("private, token covers all tree tx txids for GetVirtualTxs", func(t *testing.T) {
			// Build a 2-node PSBT tree (root → leaf). The leaf is the vtxo the intent
			// proves ownership of. GetVtxoChainByIntent should produce a token whose
			// txid whitelist includes both the leaf txid and the root tree tx txid,
			// so GetVirtualTxs can be called for the whole chain without errors.
			rootTxid, leafTxid, flatTree := buildTestTreeTxs(t)

			vtxoKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			const vtxoAmount = int64(21000)
			commitmentTxid := differentTxid

			vtxoIntent, vtxoTaprootKey := buildTestIntent(t, leafTxid, 0, vtxoKey, vtxoAmount)
			vtxoData := domain.Vtxo{
				Outpoint:           domain.Outpoint{Txid: leafTxid, VOut: 0},
				Amount:             uint64(vtxoAmount),
				PubKey:             hex.EncodeToString(schnorr.SerializePubKey(vtxoTaprootKey)),
				RootCommitmentTxid: commitmentTxid,
				Preconfirmed:       false,
			}

			rounds := &mockedRoundRepo{}
			vtxos := &mockedVtxoRepo{}

			// GetVtxos is called twice: validateIntent + buildVtxoChain.
			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: leafTxid, VOut: 0}}).
				Return([]domain.Vtxo{vtxoData}, nil)
			rounds.On("GetRoundVtxoTree", mock.Anything, commitmentTxid).
				Return(flatTree, nil)
			// GetVirtualTxs fetches the txs for the leaf and root txids.
			rounds.On("GetTxsWithTxids", mock.Anything, mock.Anything).
				Return([]string{"fakeTx1", "fakeTx2"}, nil)

			indexer := newTestIndexer(t, privkey, exposurePrivate, rounds, vtxos, nil)

			// GetVtxoChainByIntent validates the intent, builds the chain, and
			// returns a token covering all outpoints in the chain.
			chainResp, err := indexer.GetVtxoChainByIntent(t.Context(), vtxoIntent, nil)
			require.NoError(t, err)
			require.NotEmpty(t, chainResp.Chain)
			require.NotEmpty(t, chainResp.AuthToken)

			// The token's txid whitelist must include the leaf and the root tree tx.
			// Verify by calling GetVirtualTxs for both txids — should succeed without error.
			virtualResp, err := indexer.GetVirtualTxs(
				t.Context(), chainResp.AuthToken, []string{leafTxid, rootTxid}, nil,
			)
			require.NoError(t, err)
			require.Len(t, virtualResp.Txs, 2)

			rounds.AssertExpectations(t)
			vtxos.AssertExpectations(t)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		vtxoKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		const vtxoAmount = int64(21000)

		tests := []struct {
			name        string
			exposure    exposure
			makeIntent  func() Intent
			setupMocks  func(*mockedVtxoRepo, *mockedWallet)
			errContains string
		}{
			{
				name:        "empty proof",
				exposure:    exposurePrivate,
				makeIntent:  func() Intent { return Intent{} },
				setupMocks:  func(*mockedVtxoRepo, *mockedWallet) {},
				errContains: "missing intent proof tx",
			},
			{
				name:        "invalid PSBT",
				exposure:    exposurePrivate,
				makeIntent:  func() Intent { return Intent{Proof: "notavalidpsbt"} },
				setupMocks:  func(*mockedVtxoRepo, *mockedWallet) {},
				errContains: "failed to parse intent proof tx",
			},
			{
				name:     "private, unknown vtxo",
				exposure: exposurePrivate,
				makeIntent: func() Intent {
					intent, _ := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, vtxoAmount)
					return intent
				},
				setupMocks: func(vtxos *mockedVtxoRepo, wallet *mockedWallet) {
					vtxos.On("GetVtxos", mock.Anything, mock.Anything).
						Return([]domain.Vtxo{}, nil)
					wallet.On("GetTransaction", mock.Anything, testVtxoTxid).
						Return("", fmt.Errorf("tx not found"))
				},
				errContains: "failed to get boarding tx",
			},
			{
				// GetVtxoChainByIntent requires exactly one outpoint; build a 3-input PSBT
				// (toSpend dummy + two vtxo inputs) to trigger the guard.
				name:       "more than one outpoint in intent",
				exposure:   exposurePrivate,
				setupMocks: func(*mockedVtxoRepo, *mockedWallet) {},
				makeIntent: func() Intent {
					vtxoHash1, _ := chainhash.NewHashFromStr(testVtxoTxid)
					vtxoHash2, _ := chainhash.NewHashFromStr(differentTxid)
					ptx, err := psbt.New(
						[]*wire.OutPoint{
							{Hash: chainhash.Hash{0x01}, Index: 0},
							{Hash: *vtxoHash1, Index: 0},
							{Hash: *vtxoHash2, Index: 0},
						},
						[]*wire.TxOut{{Value: 1000, PkScript: []byte{txscript.OP_TRUE}}},
						2, 0,
						[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
					)
					require.NoError(t, err)
					b64, err := ptx.B64Encode()
					require.NoError(t, err)
					return Intent{Proof: b64}
				},
				errContains: "only one outpoint expected in intent proof",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				vtxos := &mockedVtxoRepo{}
				wallet := &mockedWallet{}
				tc.setupMocks(vtxos, wallet)

				indexer := newTestIndexer(t, privkey, tc.exposure, nil, vtxos, wallet)

				_, err := indexer.GetVtxoChainByIntent(t.Context(), tc.makeIntent(), nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)

				vtxos.AssertExpectations(t)
				wallet.AssertExpectations(t)
			})
		}
	})
}

func TestStripSignerSignatures(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	otherKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	otherXOnly := schnorr.SerializePubKey(otherKey.PubKey())

	// buildOffchainTx creates a base64 PSBT with TaprootScriptSpendSigs mocking a virtual tx
	buildOffchainTx := func(t *testing.T, sigs []*psbt.TaprootScriptSpendSig) string {
		t.Helper()
		ptx, err := psbt.New(
			[]*wire.OutPoint{{Hash: chainhash.Hash{0x01}, Index: 0}},
			[]*wire.TxOut{{Value: 1000, PkScript: []byte{txscript.OP_TRUE}}},
			2, 0, []uint32{wire.MaxTxInSequenceNum},
		)
		require.NoError(t, err)
		ptx.Inputs[0].TaprootScriptSpendSig = sigs
		var buf bytes.Buffer
		require.NoError(t, ptx.Serialize(&buf))
		return base64.StdEncoding.EncodeToString(buf.Bytes())
	}

	// buildTreeTx creates a base64 PSBT with TaprootKeySpendSig mocking a tree tx
	buildTreeTx := func(t *testing.T, keySig []byte) string {
		t.Helper()
		ptx, err := psbt.New(
			[]*wire.OutPoint{{Hash: chainhash.Hash{0x01}, Index: 0}},
			[]*wire.TxOut{{Value: 1000, PkScript: []byte{txscript.OP_TRUE}}},
			2, 0, []uint32{wire.MaxTxInSequenceNum},
		)
		require.NoError(t, err)
		ptx.Inputs[0].TaprootKeySpendSig = keySig
		var buf bytes.Buffer
		require.NoError(t, ptx.Serialize(&buf))
		return base64.StdEncoding.EncodeToString(buf.Bytes())
	}

	// sigsFrom decodes a base64 PSBT and returns the TaprootScriptSpendSigs on input 0.
	sigsFrom := func(t *testing.T, b64 string) []*psbt.TaprootScriptSpendSig {
		t.Helper()
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
		require.NoError(t, err)
		return ptx.Inputs[0].TaprootScriptSpendSig
	}

	// keySigFrom decodes a base64 PSBT and returns the TaprootKeySpendSig on input 0.
	keySigFrom := func(t *testing.T, b64 string) []byte {
		t.Helper()
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
		require.NoError(t, err)
		return ptx.Inputs[0].TaprootKeySpendSig
	}

	indexer := &indexerService{signerPubkey: signerKey.PubKey()}

	t.Run("valid", func(t *testing.T) {
		t.Run("empty slice is a no-op", func(t *testing.T) {
			txs := []string{}
			require.NoError(t, indexer.stripSignerSignatures(txs))
			require.Empty(t, txs)
		})

		t.Run("no sigs passes through unchanged", func(t *testing.T) {
			b64 := buildOffchainTx(t, nil)
			txs := []string{b64}
			require.NoError(t, indexer.stripSignerSignatures(txs))
			require.Empty(t, sigsFrom(t, txs[0]))
		})

		t.Run("strips sigs from tree tx", func(t *testing.T) {
			txs := []string{buildTreeTx(t, make([]byte, 64))}
			require.NoError(t, indexer.stripSignerSignatures(txs))
			require.Empty(t, keySigFrom(t, txs[0]))
		})

		t.Run("strips signer sig and keeps other party sig", func(t *testing.T) {
			signerSig := &psbt.TaprootScriptSpendSig{
				XOnlyPubKey: schnorr.SerializePubKey(signerKey.PubKey()),
				LeafHash:    make([]byte, 32),
				Signature:   make([]byte, 64),
			}
			otherSig := &psbt.TaprootScriptSpendSig{
				XOnlyPubKey: otherXOnly,
				LeafHash:    make([]byte, 32),
				Signature:   make([]byte, 64),
			}
			txs := []string{buildOffchainTx(t, []*psbt.TaprootScriptSpendSig{signerSig, otherSig})}
			require.NoError(t, indexer.stripSignerSignatures(txs))
			sigs := sigsFrom(t, txs[0])
			require.Len(t, sigs, 1)
			require.Equal(t, otherXOnly, sigs[0].XOnlyPubKey)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("invalid tx format", func(t *testing.T) {
			txs := []string{"not-a-valid-psbt"}
			err := indexer.stripSignerSignatures(txs)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to deserialize virtual tx")
		})
	})
}

func TestListTokens(t *testing.T) {
	outpoints1 := []Outpoint{{Txid: testTxids[0], VOut: 0}}
	outpoints2 := []Outpoint{{Txid: testVtxoTxid, VOut: testVtxoVout}}

	t.Run("valid", func(t *testing.T) {
		t.Run("returns tokens created via createAuthToken", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
			ctx := t.Context()

			token1, err := indexer.createAuthToken(outpoints1)
			require.NoError(t, err)
			_, err = indexer.createAuthToken(outpoints2)
			require.NoError(t, err)

			entries, err := indexer.ListTokens(ctx, "", "", "", "")
			require.NoError(t, err)
			require.Len(t, entries, 2)

			// Verify filtering by the token string resolves to the right hash.
			entries, err = indexer.ListTokens(ctx, token1, "", "", "")
			require.NoError(t, err)
			require.Len(t, entries, 1)

			// That entry's outpoints should match outpoints1.
			require.Len(t, entries[0].Outpoints, 1)
			require.Equal(t, outpoints1[0].String(), entries[0].Outpoints[0])
		})

		t.Run("filters by outpoint", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
			ctx := t.Context()

			_, err = indexer.createAuthToken(outpoints1)
			require.NoError(t, err)
			_, err = indexer.createAuthToken(outpoints2)
			require.NoError(t, err)

			entries, err := indexer.ListTokens(ctx, "", "", testVtxoTxid+":0", "")
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})

		t.Run("filters by txid", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
			ctx := t.Context()

			_, err = indexer.createAuthToken(outpoints1)
			require.NoError(t, err)
			_, err = indexer.createAuthToken(outpoints2)
			require.NoError(t, err)

			entries, err := indexer.ListTokens(ctx, "", "", "", testTxids[0])
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("rejects invalid outpoint format", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)

			_, err = indexer.ListTokens(t.Context(), "", "", "garbage", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid outpoint")
		})

		t.Run("nil privkey errors on token filter", func(t *testing.T) {
			publicIndexer := &indexerService{
				authPrvkey:   nil,
				authTokenTTL: defaultAuthTokenTTL,
				tokenCache:   newTokenCache(defaultAuthTokenTTL),
			}
			t.Cleanup(publicIndexer.tokenCache.close)

			_, err := publicIndexer.ListTokens(t.Context(), "sometoken", "", "", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), "public exposure")
		})
	})
}

func TestRevokeTokens(t *testing.T) {
	outpoints1 := []Outpoint{{Txid: testTxids[0], VOut: 0}}
	outpoints2 := []Outpoint{{Txid: testVtxoTxid, VOut: testVtxoVout}}
	outpoints3 := []Outpoint{{Txid: differentTxid, VOut: 0}}

	t.Run("valid", func(t *testing.T) {
		t.Run("by hash removes token", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
			ctx := t.Context()

			_, err = indexer.createAuthToken(outpoints3)
			require.NoError(t, err)

			entries, err := indexer.ListTokens(ctx, "", "", "", differentTxid)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			hash := entries[0].Hash

			count, err := indexer.RevokeTokens(ctx, "", hash, "", "")
			require.NoError(t, err)
			require.Equal(t, 1, count)

			// Verify it's gone.
			entries, err = indexer.ListTokens(ctx, "", hash, "", "")
			require.NoError(t, err)
			require.Empty(t, entries)
		})

		t.Run("by txid", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
			ctx := t.Context()

			_, err = indexer.createAuthToken(outpoints1)
			require.NoError(t, err)
			_, err = indexer.createAuthToken(outpoints2)
			require.NoError(t, err)

			count, err := indexer.RevokeTokens(ctx, "", "", "", testTxids[0])
			require.NoError(t, err)
			require.Equal(t, 1, count)

			after, err := indexer.ListTokens(ctx, "", "", "", "")
			require.NoError(t, err)
			require.Len(t, after, 1)
		})

		t.Run("by token string", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
			ctx := t.Context()

			_, err = indexer.createAuthToken(outpoints1)
			require.NoError(t, err)
			token2, err := indexer.createAuthToken(outpoints2)
			require.NoError(t, err)

			count, err := indexer.RevokeTokens(ctx, token2, "", "", "")
			require.NoError(t, err)
			require.Equal(t, 1, count)

			entries, err := indexer.ListTokens(ctx, "", "", "", "")
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("rejects invalid outpoint format", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)

			_, err = indexer.RevokeTokens(t.Context(), "", "", "bad", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid outpoint")
		})

		t.Run("rejects empty filters", func(t *testing.T) {
			privkey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)

			_, err = indexer.RevokeTokens(t.Context(), "", "", "", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), "at least one filter")
		})

		t.Run("nil privkey errors on token filter", func(t *testing.T) {
			publicIndexer := &indexerService{
				authPrvkey:   nil,
				authTokenTTL: defaultAuthTokenTTL,
				tokenCache:   newTokenCache(defaultAuthTokenTTL),
			}
			t.Cleanup(publicIndexer.tokenCache.close)

			_, err := publicIndexer.RevokeTokens(t.Context(), "sometoken", "", "", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), "public exposure")
		})
	})
}

// newTestIndexer builds a minimal indexerService for unit tests.
// Pass nil for repos/wallet that the test does not need — calling an
// unconfigured mock method will panic, surfacing unexpected calls immediately.
func newTestIndexer(
	t *testing.T, privkey *btcec.PrivateKey, exposure exposure,
	rounds *mockedRoundRepo, vtxos *mockedVtxoRepo, wallet *mockedWallet,
) *indexerService {
	t.Helper()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	repo := &mockedRepoManager{}
	if rounds != nil {
		repo.On("Rounds").Return(rounds)
	}
	if vtxos != nil {
		repo.On("Vtxos").Return(vtxos)
	}

	cache := newTokenCache(defaultAuthTokenTTL)
	t.Cleanup(cache.close)

	svc := &indexerService{
		repoManager:  repo,
		authPrvkey:   privkey,
		signerPubkey: signerKey.PubKey(),
		txExposure:   exposure,
		authTokenTTL: defaultAuthTokenTTL,
		tokenCache:   cache,
	}
	if wallet != nil {
		svc.wallet = wallet
	}
	return svc
}

// buildTestTreeTxs creates a minimal 2-node tx tree: root_tx → leaf_tx.
// root_tx spends a fixed dummy input; leaf_tx spends root_tx output 0.
// Returns the txids and the FlatTxTree ready for mocking.
func buildTestTreeTxs(t *testing.T) (rootTxid, leafTxid string, flatTree arktree.FlatTxTree) {
	t.Helper()

	// Root PSBT: spends a fixed dummy input.
	rootPtx, err := psbt.New(
		[]*wire.OutPoint{{Hash: chainhash.Hash{0x01}, Index: 0}},
		[]*wire.TxOut{{Value: 1000, PkScript: []byte{txscript.OP_TRUE}}},
		2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	rootTxid = rootPtx.UnsignedTx.TxID()
	rootB64, err := rootPtx.B64Encode()
	require.NoError(t, err)

	// Leaf PSBT: spends root output 0.
	rootHash, err := chainhash.NewHashFromStr(rootTxid)
	require.NoError(t, err)
	leafPtx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *rootHash, Index: 0}},
		[]*wire.TxOut{{Value: 1000, PkScript: []byte{txscript.OP_TRUE}}},
		2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	leafTxid = leafPtx.UnsignedTx.TxID()
	leafB64, err := leafPtx.B64Encode()
	require.NoError(t, err)

	flatTree = arktree.FlatTxTree{
		{Txid: rootTxid, Tx: rootB64, Children: map[uint32]string{0: leafTxid}},
		{Txid: leafTxid, Tx: leafB64, Children: nil},
	}
	return
}

// buildTestIntent creates a valid signed intent proof that passes intent.Verify.
// It builds a MultisigClosure with vtxoKey, derives the taproot output key from
// that closure, signs input 1, and returns the intent plus the taproot key (so
// callers can set up vtxo mocks with the correct PubKey).
func buildTestIntent(
	t *testing.T, vtxoTxid string, vtxoVout uint32, vtxoKey *btcec.PrivateKey, amount int64,
) (Intent, *btcec.PublicKey) {
	t.Helper()

	// Build a single-key closure for the vtxo spending leaf.
	closure := &arkscript.MultisigClosure{
		PubKeys: []*btcec.PublicKey{vtxoKey.PubKey()},
		Type:    arkscript.MultisigTypeChecksig,
	}
	closureScript, err := closure.Script()
	require.NoError(t, err)

	// Taproot output key: unspendable internal key tweaked with the single leaf.
	unspendable := arkscript.UnspendableKey()
	leaf := txscript.NewBaseTapLeaf(closureScript)
	leafHash := leaf.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(unspendable, leafHash[:])

	pkScript, err := arkscript.P2TRScript(taprootKey)
	require.NoError(t, err)

	// Build the GetData message.
	intentMessage := intent.GetDataMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeGetData},
	}
	message, err := intentMessage.Encode()
	require.NoError(t, err)

	// Build the intent proof PSBT.
	vtxoHash, err := chainhash.NewHashFromStr(vtxoTxid)
	require.NoError(t, err)
	inputs := []intent.Input{{
		OutPoint:    &wire.OutPoint{Hash: *vtxoHash, Index: vtxoVout},
		WitnessUtxo: &wire.TxOut{Value: amount, PkScript: pkScript},
	}}
	outputs := []*wire.TxOut{{Value: amount, PkScript: pkScript}}
	proof, err := intent.New(message, inputs, outputs)
	require.NoError(t, err)

	// Control block for a single-leaf tree: [LeafVersion | outputKeyParity][internalKey_32].
	isOdd := taprootKey.SerializeCompressed()[0] == 0x03
	parityBit := byte(0)
	if isOdd {
		parityBit = 0x01
	}
	controlBlock := make([]byte, 33)
	controlBlock[0] = byte(txscript.BaseLeafVersion) | parityBit
	copy(controlBlock[1:], schnorr.SerializePubKey(unspendable))
	proof.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBlock,
		Script:       closureScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	// Sign input 1 (the vtxo input) with vtxoKey to prove ownership.
	prevoutFetcher, err := txutils.GetPrevOutputFetcher(&proof.Packet)
	require.NoError(t, err)
	txSigHashes := txscript.NewTxSigHashes(proof.UnsignedTx, prevoutFetcher)
	sighash, err := txscript.CalcTapscriptSignaturehash(
		txSigHashes, txscript.SigHashDefault, proof.UnsignedTx, 1, prevoutFetcher, leaf,
	)
	require.NoError(t, err)
	sig, err := schnorr.Sign(vtxoKey, sighash)
	require.NoError(t, err)
	proof.Inputs[1].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
		XOnlyPubKey: schnorr.SerializePubKey(vtxoKey.PubKey()),
		Signature:   sig.Serialize(),
		LeafHash:    leafHash[:],
	}}

	b64, err := proof.B64Encode()
	require.NoError(t, err)

	return Intent{Proof: b64, Message: message}, taprootKey
}

// buildExpiredToken constructs a signed auth token with a timestamp one hour
// in the past, bypassing indexerService entirely. Used to test expiry rejection.
func buildExpiredToken(t *testing.T, privkey *btcec.PrivateKey, outpoints []Outpoint) string {
	t.Helper()

	// copy to avoid mutating caller's slice
	hash, err := hashOutpoints(append([]Outpoint{}, outpoints...))
	require.NoError(t, err)

	msg := make([]byte, 40)
	copy(msg[:32], hash)
	binary.BigEndian.PutUint64(msg[32:], uint64(time.Now().Add(-time.Hour).Unix()))

	sig, err := schnorr.Sign(privkey, chainhash.HashB(msg))
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(append(msg, sig.Serialize()...))
}

type mockedRoundRepo struct {
	mock.Mock
	domain.RoundRepository // unimplemented methods panic on call
}

func (m *mockedRoundRepo) GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error) {
	args := m.Called(ctx, txids)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) GetRoundVtxoTree(ctx context.Context, txid string) (arktree.FlatTxTree, error) {
	args := m.Called(ctx, txid)
	if v := args.Get(0); v != nil {
		return v.(arktree.FlatTxTree), args.Error(1)
	}
	return nil, args.Error(1)
}

type mockedVtxoRepo struct {
	mock.Mock
	domain.VtxoRepository // unimplemented methods panic on call
}

func (m *mockedVtxoRepo) GetVtxos(ctx context.Context, outpoints []domain.Outpoint) ([]domain.Vtxo, error) {
	args := m.Called(ctx, outpoints)
	if v := args.Get(0); v != nil {
		return v.([]domain.Vtxo), args.Error(1)
	}
	return nil, args.Error(1)
}

type mockedRepoManager struct {
	mock.Mock
	ports.RepoManager // unimplemented methods panic on call
}

func (m *mockedRepoManager) Rounds() domain.RoundRepository {
	if v := m.Called().Get(0); v != nil {
		return v.(domain.RoundRepository)
	}
	return nil
}

func (m *mockedRepoManager) Vtxos() domain.VtxoRepository {
	if v := m.Called().Get(0); v != nil {
		return v.(domain.VtxoRepository)
	}
	return nil
}

type mockedWallet struct {
	mock.Mock
	ports.WalletService // unimplemented methods panic on call
}

func (m *mockedWallet) GetTransaction(ctx context.Context, txid string) (string, error) {
	args := m.Called(ctx, txid)
	return args.String(0), args.Error(1)
}
