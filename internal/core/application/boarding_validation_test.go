package application

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// processBoardingInputs memoizes the funding tx per txid, and used to memoize
// the whole validation with it: a second input spending the same funding tx
// skipped every check. These cases go through the loop that had the bug.
func TestProcessBoardingInputs(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signer := signerKey.PubKey()

	ownerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	owner := ownerKey.PubKey()

	now := time.Now()
	// Confirmed an hour ago at height 100. CSV seconds must be a multiple of 512
	// (BIP68), so 7168s (~2h) is still locked while 1536s (~25m) has matured.
	confirmedAt := &ports.BlockTimestamp{Height: 100, Time: now.Add(-time.Hour).Unix()}

	secondsLong := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}
	secondsShort := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1536}
	// Confirmed at 100, these mature at 244 and 120.
	blocksLong := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
	blocksShort := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 20}

	secondsSettings := ports.Settings{SignerPubkey: signer}
	secondsSettings.BoardingExitDelay = secondsShort
	secondsSettings.UnilateralExitDelay = secondsShort
	secondsSettings.UtxoMinAmount = 1_000
	secondsSettings.UtxoMaxAmount = 1_000_000

	blocksSettings := secondsSettings
	blocksSettings.BoardingExitDelay = blocksShort
	blocksSettings.UnilateralExitDelay = blocksShort
	blocksSettings.VtxoTreeExpiry = blocksShort // makes AllowCSVBlockType() true

	// newFundingTx builds one funding tx paying an output per exit delay, and the
	// boarding inputs spending each of them.
	newFundingTx := func(
		t *testing.T, delays ...arklib.RelativeLocktime,
	) (string, string, []boardingIntentInput) {
		t.Helper()

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
		tapscripts := make([][]string, 0, len(delays))
		for _, delay := range delays {
			vtxoScript := script.NewDefaultVtxoScript(owner, signer, delay)
			encoded, err := vtxoScript.Encode()
			require.NoError(t, err)
			tapKey, _, err := vtxoScript.TapTree()
			require.NoError(t, err)
			pkScript, err := script.P2TRScript(tapKey)
			require.NoError(t, err)

			tx.AddTxOut(&wire.TxOut{Value: 100_000, PkScript: pkScript})
			tapscripts = append(tapscripts, encoded)
		}

		var buf bytes.Buffer
		require.NoError(t, tx.Serialize(&buf))
		txid := tx.TxID()

		inputs := make([]boardingIntentInput, 0, len(delays))
		for vout, out := range tx.TxOut {
			in := boardingInput(uint32(vout), tapscripts[vout])
			in.Txid = txid
			in.witnessUtxo = out
			inputs = append(inputs, in)
		}
		return hex.EncodeToString(buf.Bytes()), txid, inputs
	}

	newService := func(
		txHex, txid string, tip *ports.BlockTimestamp, tipErr error,
	) (*service, *mockedWallet) {
		wallet := &mockedWallet{}
		wallet.On("GetTransaction", mock.Anything, txid).Return(txHex, nil)
		wallet.On("IsTransactionConfirmed", mock.Anything, txid).Return(true, confirmedAt, nil)
		if tip != nil || tipErr != nil {
			wallet.On("GetCurrentBlockTime", mock.Anything).Return(tip, tipErr)
		}

		scanner := &mockedScanner{}
		scanner.On("WatchScripts", mock.Anything, mock.Anything).Return(nil)
		scanner.On("UnwatchScripts", mock.Anything, mock.Anything).Return(nil)

		return &service{wallet: wallet, scanner: scanner}, wallet
	}

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name     string
			settings ports.Settings
			delays   []arklib.RelativeLocktime
			tip      *ports.BlockTimestamp
			// tipCalls pins that the chain tip is fetched only for block-typed
			// delays, and at most once per request.
			tipCalls int
		}{
			{
				name:     "inputs sharing a funding tx with seconds delays",
				settings: secondsSettings,
				delays:   []arklib.RelativeLocktime{secondsLong, secondsLong},
				tipCalls: 0,
			},
			{
				name:     "inputs sharing a funding tx with block delays",
				settings: blocksSettings,
				delays:   []arklib.RelativeLocktime{blocksLong, blocksLong},
				tip:      &ports.BlockTimestamp{Height: 110},
				tipCalls: 1,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				txHex, txid, inputs := newFundingTx(t, tt.delays...)
				svc, wallet := newService(txHex, txid, tt.tip, nil)

				boardingInputs, err := svc.processBoardingInputs(
					t.Context(), "intent", inputs, tt.settings,
				)
				require.NoError(t, err)
				require.Len(t, boardingInputs, len(inputs))

				// The funding tx is fetched once, however many inputs spend it.
				wallet.AssertNumberOfCalls(t, "GetTransaction", 1)
				wallet.AssertNumberOfCalls(t, "IsTransactionConfirmed", 1)
				wallet.AssertNumberOfCalls(t, "GetCurrentBlockTime", tt.tipCalls)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			settings    ports.Settings
			delays      []arklib.RelativeLocktime
			tip         *ports.BlockTimestamp
			tipErr      error
			errCode     uint16
			errContains string
		}{
			{
				name:        "second input sharing a funding tx has a matured exit path in seconds",
				settings:    secondsSettings,
				delays:      []arklib.RelativeLocktime{secondsLong, secondsShort},
				errCode:     errors.INVALID_PSBT_INPUT.Code,
				errContains: "expired",
			},
			{
				// Tip 130 is past the short delay's 120 and short of the long one's 244.
				name:        "second input sharing a funding tx has a matured exit path in blocks",
				settings:    blocksSettings,
				delays:      []arklib.RelativeLocktime{blocksLong, blocksShort},
				tip:         &ports.BlockTimestamp{Height: 130},
				errCode:     errors.INVALID_PSBT_INPUT.Code,
				errContains: "expired",
			},
			{
				// A wallet failure is not the input's fault.
				name:        "chain tip lookup fails for a block delay",
				settings:    blocksSettings,
				delays:      []arklib.RelativeLocktime{blocksLong},
				tipErr:      fmt.Errorf("wallet unavailable"),
				errCode:     errors.INTERNAL_ERROR.Code,
				errContains: "failed to get chain tip",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				txHex, txid, inputs := newFundingTx(t, tt.delays...)
				svc, _ := newService(txHex, txid, tt.tip, tt.tipErr)

				boardingInputs, err := svc.processBoardingInputs(
					t.Context(), "intent", inputs, tt.settings,
				)
				require.ErrorContains(t, err, tt.errContains)
				require.Equal(t, tt.errCode, err.Code())
				require.Nil(t, boardingInputs)
			})
		}
	})
}

// Two boarding inputs can share one funding tx while carrying different
// tapscripts, exit delays and amounts, so every check in validateBoardingInput
// has to be per-output.
func TestValidateBoardingInput(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signer := signerKey.PubKey()

	ownerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	owner := ownerKey.PubKey()

	now := time.Now()
	// Confirmed an hour ago at height 100. CSV seconds must be a multiple of 512
	// (BIP68), so 7168s (~2h) is still locked while 1536s (~25m) has matured.
	blockTimestamp := &ports.BlockTimestamp{Height: 100, Time: now.Add(-time.Hour).Unix()}

	// tipAt is used for block-typed test cases and returns a chain tip.
	tipAt := func(height uint32) func() (*ports.BlockTimestamp, error) {
		return func() (*ports.BlockTimestamp, error) {
			return &ports.BlockTimestamp{Height: height, Time: now.Unix()}, nil
		}
	}
	// noTip is used for second-typed test cases and returns an error to ensure it's never called,
	// leading to test failure otherwise.
	noTip := func() (*ports.BlockTimestamp, error) {
		return nil, fmt.Errorf("chain tip fetched for a seconds-typed exit delay")
	}

	encodeScript := func(delay arklib.RelativeLocktime) []string {
		tapscripts, err := script.NewDefaultVtxoScript(owner, signer, delay).Encode()
		require.NoError(t, err)
		return tapscripts
	}

	longDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}
	shortDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1536}
	// Confirmed at 100, it matures at 244.
	blockDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}

	longTapscripts := encodeScript(longDelay)
	shortTapscripts := encodeScript(shortDelay)
	blockTapscripts := encodeScript(blockDelay)

	fundingWithAmounts := func(amounts ...int64) fundingTx {
		tx := wire.MsgTx{}
		for _, amount := range amounts {
			tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: amount})
		}
		return fundingTx{tx: tx, blockTimestamp: blockTimestamp}
	}
	// One funding tx with two outputs, spent by two different boarding inputs.
	funding := fundingWithAmounts(100_000, 100_000)

	settings := ports.Settings{SignerPubkey: signer}
	settings.BoardingExitDelay = shortDelay
	settings.UnilateralExitDelay = shortDelay
	settings.UtxoMinAmount = 1_000
	settings.UtxoMaxAmount = 1_000_000

	blockSettings := settings
	blockSettings.BoardingExitDelay = blockDelay
	blockSettings.UnilateralExitDelay = blockDelay
	blockSettings.VtxoTreeExpiry = blockDelay // makes AllowCSVBlockType() true

	marginSettings := settings
	marginSettings.UnrolledVtxoMinExpiryMargin = 4 * time.Hour

	blockMarginSettings := blockSettings
	// The regtest margin. At arklib.SECONDS_PER_BLOCK it is 10 blocks.
	blockMarginSettings.UnrolledVtxoMinExpiryMargin = 10 * time.Second

	withLocktime := func(
		in boardingIntentInput, locktime arklib.RelativeLocktime, disabled bool,
	) boardingIntentInput {
		in.locktime = &locktime
		in.locktimeDisabled = disabled
		return in
	}
	asUnrolled := func(in boardingIntentInput) boardingIntentInput {
		in.isUnrolledVtxo = true
		return in
	}
	seconds := func(v uint32) arklib.RelativeLocktime {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: v}
	}
	blocks := func(v uint32) arklib.RelativeLocktime {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: v}
	}

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name     string
			funding  fundingTx
			getTip   func() (*ports.BlockTimestamp, error)
			input    boardingIntentInput
			settings ports.Settings
		}{
			{
				name:     "exit delay in seconds not expired, locktime disabled",
				funding:  funding,
				getTip:   noTip,
				input:    boardingInput(0, longTapscripts),
				settings: settings,
			},
			{
				// The locktime limit is time since confirmation + exit delay:
				// 3600 + 7168 = 10768s.
				name:     "exit delay in seconds not expired, locktime within limit",
				funding:  funding,
				getTip:   noTip,
				input:    withLocktime(boardingInput(0, longTapscripts), seconds(10752), false),
				settings: settings,
			},
			{
				// 11264s is beyond the 10768s limit, but a disabled locktime is not checked.
				name:     "exit delay in seconds not expired, locktime beyond limit but disabled",
				funding:  funding,
				getTip:   noTip,
				input:    withLocktime(boardingInput(0, longTapscripts), seconds(11264), true),
				settings: settings,
			},
			{
				// The locktime limit is blocks since confirmation + exit delay:
				// (200 - 100) + 144 = 244 blocks.
				name:     "exit delay in blocks not expired, locktime within limit",
				funding:  funding,
				getTip:   tipAt(200),
				input:    withLocktime(boardingInput(0, blockTapscripts), blocks(244), false),
				settings: blockSettings,
			},
			{
				// Expires at 244, margin is 10 blocks: 200+1+10 < 244.
				name:     "unrolled vtxo, exit delay in blocks not expiring within margin",
				funding:  funding,
				getTip:   tipAt(200),
				input:    asUnrolled(boardingInput(0, blockTapscripts)),
				settings: blockMarginSettings,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validateBoardingInput(tt.funding, tt.getTip, tt.input, now, tt.settings)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			funding     fundingTx
			getTip      func() (*ports.BlockTimestamp, error)
			input       boardingIntentInput
			settings    ports.Settings
			errContains string
		}{
			{
				name:        "exit delay in seconds expired",
				funding:     funding,
				getTip:      noTip,
				input:       boardingInput(1, shortTapscripts),
				settings:    settings,
				errContains: "expired",
			},
			{
				name:        "amount below min utxo amount",
				funding:     fundingWithAmounts(100_000, 10),
				getTip:      noTip,
				input:       boardingInput(1, longTapscripts),
				settings:    settings,
				errContains: "lower than min utxo amount",
			},
			{
				name:        "amount above max utxo amount",
				funding:     fundingWithAmounts(100_000, 9_000_000),
				getTip:      noTip,
				input:       boardingInput(1, longTapscripts),
				settings:    settings,
				errContains: "higher than max utxo amount",
			},
			{
				name:        "vout out of range",
				funding:     funding,
				getTip:      noTip,
				input:       boardingInput(5, longTapscripts),
				settings:    settings,
				errContains: "invalid vout index",
			},
			{
				// 496s beyond the 10768s limit.
				name:        "exit delay in seconds not expired, locktime beyond limit",
				funding:     funding,
				getTip:      noTip,
				input:       withLocktime(boardingInput(0, longTapscripts), seconds(11264), false),
				settings:    settings,
				errContains: "can be used for intent registration",
			},
			{
				// 156 blocks beyond the 244 blocks limit.
				name:        "exit delay in blocks not expired, locktime beyond limit",
				funding:     funding,
				getTip:      tipAt(200),
				input:       withLocktime(boardingInput(0, blockTapscripts), blocks(400), false),
				settings:    blockSettings,
				errContains: "in 156 blocks",
			},
			{
				// Expires in ~1h, margin is 4h.
				name:        "unrolled vtxo, exit delay in seconds expiring within margin",
				funding:     funding,
				getTip:      noTip,
				input:       asUnrolled(boardingInput(0, longTapscripts)),
				settings:    marginSettings,
				errContains: "expires too soon",
			},
			{
				// Expires at 244, margin is 10 blocks: 233+1+10 == 244.
				name:        "unrolled vtxo, exit delay in blocks expiring within margin",
				funding:     funding,
				getTip:      tipAt(233),
				input:       asUnrolled(boardingInput(0, blockTapscripts)),
				settings:    blockMarginSettings,
				errContains: "expires too soon",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validateBoardingInput(tt.funding, tt.getTip, tt.input, now, tt.settings)
				require.ErrorContains(t, err, tt.errContains)
			})
		}
	})
}

// Block-typed relative locktimes must be evaluated in blocks. Routing them
// through RelativeLocktime.Seconds() converts at SECONDS_PER_BLOCK = 1, which
// would mature a 144-block exit 144 seconds after confirmation.
func TestIsExitDelayExpired(t *testing.T) {
	// Whole seconds, so a delay can expire exactly on a boundary.
	now := time.Unix(time.Now().Unix(), 0)
	// Confirmed an hour ago at height 100.
	conf := &ports.BlockTimestamp{Height: 100, Time: now.Add(-time.Hour).Unix()}
	tip := func(height uint32) *ports.BlockTimestamp {
		return &ports.BlockTimestamp{Height: height, Time: now.Unix()}
	}
	seconds := func(v uint32) arklib.RelativeLocktime {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: v}
	}
	blocks := func(v uint32) arklib.RelativeLocktime {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: v}
	}

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name     string
			conf     *ports.BlockTimestamp
			tip      *ports.BlockTimestamp
			delay    arklib.RelativeLocktime
			margin   time.Duration
			expected bool
		}{
			// A delay in blocks expires when the next block reaches
			// confirmation height + delay: 100 + 144 = 244.
			{
				name:     "delay in blocks, next block before expiry",
				conf:     conf,
				tip:      tip(242),
				delay:    blocks(144),
				expected: false,
			},
			{
				name:     "delay in blocks, next block is the expiry",
				conf:     conf,
				tip:      tip(243),
				delay:    blocks(144),
				expected: true,
			},
			{
				name:     "delay in blocks, tip past expiry",
				conf:     conf,
				tip:      tip(244),
				delay:    blocks(144),
				expected: true,
			},
			// The margin is converted at 1 block per second: 240+1+2 < 244.
			{
				name:     "delay in blocks, not expiring within margin",
				conf:     conf,
				tip:      tip(240),
				delay:    blocks(144),
				margin:   2 * time.Second,
				expected: false,
			},
			// 240+1+3 == 244.
			{
				name:     "delay in blocks, expiring within margin",
				conf:     conf,
				tip:      tip(240),
				delay:    blocks(144),
				margin:   3 * time.Second,
				expected: true,
			},
			// A delay in seconds expires at confirmation time + delay.
			{
				name:     "delay in seconds, expired",
				conf:     conf,
				delay:    seconds(1536),
				expected: true,
			},
			{
				name:     "delay in seconds, not expired",
				conf:     conf,
				delay:    seconds(7168),
				expected: false,
			},
			// 7168s from an hour ago leaves ~59m.
			{
				name:     "delay in seconds, not expiring within margin",
				conf:     conf,
				delay:    seconds(7168),
				margin:   30 * time.Minute,
				expected: false,
			},
			{
				name:     "delay in seconds, expiring within margin",
				conf:     conf,
				delay:    seconds(7168),
				margin:   2 * time.Hour,
				expected: true,
			},
			// The exit path is spendable onchain as soon as chain time reaches
			// confirmation + delay, so the boundary counts as expired.
			{
				name:     "delay in seconds, expiring exactly now",
				conf:     &ports.BlockTimestamp{Time: now.Add(-3584 * time.Second).Unix()},
				delay:    seconds(3584),
				expected: true,
			},
			{
				name:     "delay in seconds, expiring exactly at now plus margin",
				conf:     &ports.BlockTimestamp{Time: now.Add(-3000 * time.Second).Unix()},
				delay:    seconds(3584),
				margin:   584 * time.Second,
				expected: true,
			},
			{
				name:     "delay in seconds, expiring one second after now plus margin",
				conf:     &ports.BlockTimestamp{Time: now.Add(-3000 * time.Second).Unix()},
				delay:    seconds(3584),
				margin:   583 * time.Second,
				expected: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := isExitDelayExpired(tt.conf, tt.tip, tt.delay, tt.margin, now)
				require.NoError(t, err)
				require.Equal(t, tt.expected, got)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			conf        *ports.BlockTimestamp
			tip         *ports.BlockTimestamp
			delay       arklib.RelativeLocktime
			errContains string
		}{
			{
				name:        "delay in blocks, missing chain tip",
				conf:        conf,
				delay:       blocks(144),
				errContains: "chain tip",
			},
			{
				name:        "delay in blocks, missing confirmation height",
				conf:        &ports.BlockTimestamp{Height: 0},
				tip:         tip(200),
				delay:       blocks(144),
				errContains: "confirmation height",
			},
			{
				name:        "delay in seconds, missing confirmation",
				delay:       seconds(1536),
				errContains: "confirmation timestamp",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := isExitDelayExpired(tt.conf, tt.tip, tt.delay, 0, now)
				require.ErrorContains(t, err, tt.errContains)
			})
		}
	})
}

// Seconds() converts a block count at SECONDS_PER_BLOCK = 1, so reading both
// sides through it measures blocks against a clock.
func TestLocktimeTillExitDelay(t *testing.T) {
	now := time.Now()
	conf := &ports.BlockTimestamp{Height: 100, Time: now.Add(-time.Hour).Unix()}
	tip := &ports.BlockTimestamp{Height: 106}

	blocks := func(v uint32) arklib.RelativeLocktime {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: v}
	}
	seconds := func(v uint32) arklib.RelativeLocktime {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: v}
	}

	// Tip 106 plus a 144-block exit is height 250, which is 150 blocks after the
	// confirmation at 100.
	t.Run("both block-typed, counted in blocks", func(t *testing.T) {
		for _, tc := range []struct {
			locktime  uint32
			remaining int64
		}{
			{1000, 850},
			{151, 1},
			{150, 0},
			{100, 0}, // already elapsed, never negative
		} {
			got, err := locktimeTillExitDelay(conf, tip, blocks(tc.locktime), blocks(144), now)
			require.NoError(t, err)
			require.Equalf(t, tc.remaining, got, "locktime=%d blocks", tc.locktime)
		}
	})

	// Confirmed 3600s ago with a 7168s exit delay puts the window at 10768s.
	t.Run("both seconds-typed, counted on the clock", func(t *testing.T) {
		got, err := locktimeTillExitDelay(conf, tip, seconds(11264), seconds(7168), now)
		require.NoError(t, err)
		require.Equal(t, int64(496), got)

		got, err = locktimeTillExitDelay(conf, tip, seconds(10752), seconds(7168), now)
		require.NoError(t, err)
		require.Zero(t, got)
	})

	t.Run("mixed types keep the wall-clock reading", func(t *testing.T) {
		got, err := locktimeTillExitDelay(conf, tip, blocks(1000), seconds(7168), now)
		require.NoError(t, err)
		require.Zero(t, got, "1000 read as seconds is inside the 10768s window")

		got, err = locktimeTillExitDelay(conf, tip, seconds(11264), blocks(144), now)
		require.NoError(t, err)
		require.Equal(t, int64(11264-(144+3600)), got)
	})

	t.Run("block-typed needs a tip and a real confirmation height", func(t *testing.T) {
		_, err := locktimeTillExitDelay(conf, nil, blocks(1000), blocks(144), now)
		require.ErrorContains(t, err, "chain tip")

		_, err = locktimeTillExitDelay(
			&ports.BlockTimestamp{Height: 0}, tip, blocks(1000), blocks(144), now,
		)
		require.ErrorContains(t, err, "confirmation height")
	})

	t.Run("the clock path needs a confirmation timestamp", func(t *testing.T) {
		_, err := locktimeTillExitDelay(nil, tip, seconds(1024), seconds(7168), now)
		require.ErrorContains(t, err, "confirmation timestamp")
	})
}

// boardingInput builds a boarding input for the given output index, with the
// locktime check disabled so tests exercise one rule at a time.
func boardingInput(vout uint32, tapscripts []string) boardingIntentInput {
	in := boardingIntentInput{locktimeDisabled: true}
	in.VOut = vout
	in.Txid = "0000000000000000000000000000000000000000000000000000000000000001"
	in.Tapscripts = tapscripts
	return in
}
