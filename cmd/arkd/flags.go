package main

import (
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/config"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/urfave/cli/v2"
)

const (
	urlFlagName                       = "url"
	datadirFlagName                   = "datadir"
	macaroonFlagName                  = "macaroon"
	passwordFlagName                  = "password"
	mnemonicFlagName                  = "mnemonic"
	gapLimitFlagName                  = "addr-gap-limit"
	amountFlagName                    = "amount"
	withdrawAllFlagName               = "all"
	quantityFlagName                  = "quantity"
	addressFlagName                   = "address"
	intentIdsFlagName                 = "ids"
	roundIdFlagName                   = "id"
	beforeDateFlagName                = "before-date"
	afterDateFlagName                 = "after-date"
	scheduledSessionStartDateFlagName = "start-date"
	scheduledSessionEndDateFlagName   = "end-date"
	sessionDurationFlagName           = "session-duration"
	scheduledSessionPeriodFlagName    = "period"
	roundMinParticipantsFlagName      = "round-min-participants"
	roundMaxParticipantsFlagName      = "round-max-participants"
	signerKeyFlagName                 = "signer-prvkey"
	signerUrlFlagName                 = "signer-url"
	tokenFlagName                     = "token"
	convictionIdsFlagName             = "ids"
	convictionFromFlagName            = "from"
	convictionToFlagName              = "to"
	convictionIdFlagName              = "id"
	scriptFlagName                    = "script"
	banDurationFlagName               = "duration"
	banReasonFlagName                 = "reason"
	completedFlagName                 = "completed"
	failedFlagName                    = "failed"
	withDetailsFlagName               = "with-details"
	sweepConnectorsFlagName           = "with-connectors"
	sweepCommitmentTxidsFlagName      = "commitment-txids"
	onchainInputFlagName              = "onchain-input"
	offchainInputFlagName             = "offchain-input"
	onchainOutputFlagName             = "onchain-output"
	offchainOutputFlagName            = "offchain-output"
	clearFlagName                     = "clear"

	unrolledVtxoMinExpiryMarginFlagName   = "unrolled-vtxo-min-expiry-margin"
	banThresholdFlagName                  = "ban-threshold"
	unilateralExitDelayFlagName           = "unilateral-exit-delay"
	publicUnilateralExitDelayFlagName     = "public-unilateral-exit-delay"
	checkpointExitDelayFlagName           = "checkpoint-exit-delay"
	boardingExitDelayFlagName             = "boarding-exit-delay"
	vtxoTreeExpiryFlagName                = "vtxo-tree-expiry"
	vtxoMinAmountFlagName                 = "vtxo-min-amount"
	vtxoMaxAmountFlagName                 = "vtxo-max-amount"
	utxoMinAmountFlagName                 = "utxo-min-amount"
	utxoMaxAmountFlagName                 = "utxo-max-amount"
	settlementMinExpiryGapFlagName        = "settlement-min-expiry-gap"
	vtxoNoCsvValidationCutoffDateFlagName = "vtxo-no-csv-validation-cutoff-date"
	maxTxWeightFlagName                   = "max-tx-weight"
	maxOpReturnOutsFlagName               = "max-op-return-outputs"
	assetTxMaxWeightRatioFlagName         = "asset-tx-max-weight-ratio"
	notePrefixFlagName                    = "note-uri-prefix"
	buildVersionHeaderFlagName            = "build-version-header"
	buildVersionHeaderRequiredFlagName    = "build-version-header-required"

	dateFormat         = time.DateOnly
	dateWithTimeFormat = time.DateTime
)

var (
	urlFlag = &cli.StringFlag{
		Name:  urlFlagName,
		Usage: "the url where to reach ark server",
		Value: fmt.Sprintf("http://127.0.0.1:%d", config.DefaultAdminPort),
	}
	datadirFlag = &cli.StringFlag{
		Name:  datadirFlagName,
		Usage: "arkd datadir from where to source TLS cert and macaroon if needed",
		Value: arklib.AppDataDir("arkd", false),
	}
	macaroonFlag = &cli.StringFlag{
		Name:  macaroonFlagName,
		Usage: "macaroon in hex format used for authenticated requests",
	}
	passwordFlag = &cli.StringFlag{
		Name:     passwordFlagName,
		Usage:    "wallet password",
		Required: true,
	}
	mnemonicFlag = &cli.StringFlag{
		Name:  mnemonicFlagName,
		Usage: "mnemonic from which restore the wallet",
	}
	gapLimitFlag = &cli.Uint64Flag{
		Name:  gapLimitFlagName,
		Usage: "address gap limit for wallet restoration",
		Value: 100,
	}
	amountFlag = &cli.UintFlag{
		Name:     amountFlagName,
		Usage:    "amount of the note in satoshis",
		Required: true,
	}
	quantityFlag = &cli.UintFlag{
		Name:  quantityFlagName,
		Usage: "quantity of notes to create",
		Value: 1,
	}
	intentIdsFlag = func(required bool) *cli.StringSliceFlag {
		return &cli.StringSliceFlag{
			Name:     intentIdsFlagName,
			Usage:    "ids of the intents to delete",
			Required: required,
		}
	}
	withdrawAllFlag = &cli.BoolFlag{
		Name:  withdrawAllFlagName,
		Usage: "withdraw all available balance including connectors account funds",
		Value: false,
	}
	withdrawAmountFlag = &cli.Float64Flag{
		Name:  amountFlagName,
		Usage: "amount to withdraw in BTC",
	}
	withdrawAddressFlag = &cli.StringFlag{
		Name:     addressFlagName,
		Usage:    "address to withdraw to",
		Required: true,
	}
	roundIdFlag = &cli.StringFlag{
		Name:     roundIdFlagName,
		Usage:    "id of the round to get info",
		Required: true,
	}
	beforeDateFlag = &cli.StringFlag{
		Name: beforeDateFlagName,
		Usage: fmt.Sprintf(
			"get ids of rounds before the give date, must be in %s format", dateFormat,
		),
	}
	afterDateFlag = &cli.StringFlag{
		Name: afterDateFlagName,
		Usage: fmt.Sprintf(
			"get ids of rounds after the give date, must be in %s format", dateFormat,
		),
	}
	scheduledSessionStartDateFlag = &cli.StringFlag{
		Name: scheduledSessionStartDateFlagName,
		Usage: fmt.Sprintf(
			"the starting date of the very first scheduled session, must be in %s format (GMT)",
			dateWithTimeFormat,
		),
	}
	scheduledSessionEndDateFlag = &cli.StringFlag{
		Name: scheduledSessionEndDateFlagName,
		Usage: fmt.Sprintf(
			"the ending date of the very first scheduled session, must be in %s format (GMT)",
			dateWithTimeFormat,
		),
	}
	sessionDurationFlag = &cli.IntFlag{
		Name:  sessionDurationFlagName,
		Usage: "the duration of the scheduled sessions in seconds",
	}
	scheduledSessionPeriodFlag = &cli.IntFlag{
		Name:  scheduledSessionPeriodFlagName,
		Usage: "the interval between a scheduled session and the next one",
	}
	roundMinParticipantsFlag = &cli.IntFlag{
		Name:  roundMinParticipantsFlagName,
		Usage: "the min number of participants per round",
	}
	roundMaxParticipantsFlag = &cli.IntFlag{
		Name:  roundMaxParticipantsFlagName,
		Usage: "the max number of participants per round",
	}
	signerKeyFlag = &cli.StringFlag{
		Name:  signerKeyFlagName,
		Usage: "the private key to be loaded to arkd wallet and used as signer",
	}
	signerUrlFlag = &cli.StringFlag{
		Name:  signerUrlFlagName,
		Usage: "the url of the signer to connect to",
	}
	tokenFlag = &cli.StringFlag{
		Name:  tokenFlagName,
		Usage: "the macaroon to be revoked",
	}
	convictionIdsFlag = &cli.StringSliceFlag{
		Name:     convictionIdsFlagName,
		Usage:    "conviction IDs to retrieve",
		Required: false,
	}
	convictionFromFlag = &cli.Int64Flag{
		Name:  convictionFromFlagName,
		Usage: "start timestamp for conviction range (Unix timestamp). If not set, defaults to 24 hours ago",
	}
	convictionToFlag = &cli.Int64Flag{
		Name:  convictionToFlagName,
		Usage: "end timestamp for conviction range (Unix timestamp). If not set, defaults to now",
	}
	convictionIdFlag = &cli.StringFlag{
		Name:     convictionIdFlagName,
		Usage:    "conviction ID to pardon",
		Required: true,
	}
	scriptFlag = &cli.StringFlag{
		Name:     scriptFlagName,
		Usage:    "script to query or ban",
		Required: true,
	}
	banDurationFlag = &cli.Int64Flag{
		Name:  banDurationFlagName,
		Usage: "ban duration in seconds (0 for permanent ban)",
		Value: 0,
	}
	banReasonFlag = &cli.StringFlag{
		Name:     banReasonFlagName,
		Usage:    "reason for banning the script",
		Required: true,
	}
	completedFlag = &cli.BoolFlag{
		Name:  completedFlagName,
		Usage: "include completed rounds in the results",
		Value: true,
	}
	failedFlag = &cli.BoolFlag{
		Name:  failedFlagName,
		Usage: "include failed rounds in the results",
		Value: false,
	}
	withDetailsFlag = &cli.BoolFlag{
		Name:  withDetailsFlagName,
		Usage: "return detailed information for each round (like round-info command)",
		Value: false,
	}
	sweepConnectorsFlag = &cli.BoolFlag{
		Name:  sweepConnectorsFlagName,
		Usage: "include all spendable connector UTXOs in the sweep",
		Value: false,
	}
	sweepCommitmentTxidsFlag = &cli.StringSliceFlag{
		Name:  sweepCommitmentTxidsFlagName,
		Usage: "commitment transaction IDs to sweep",
	}
	liquidityAfterFlag = &cli.StringFlag{
		Name: afterDateFlagName,
		Usage: fmt.Sprintf(
			"get expiring liquidity after a specific date in format %s. "+
				"If not provided, defaults to now", dateWithTimeFormat,
		),
		Value: "",
	}
	liquidityBeforeFlag = &cli.StringFlag{
		Name: beforeDateFlagName,
		Usage: fmt.Sprintf(
			"get expiring liquidity before a specific date in format %s. "+
				"If not provided, no upper bound is applied", dateWithTimeFormat,
		),
		Value: "",
	}
	onchainInputFlag = &cli.StringFlag{
		Name:  onchainInputFlagName,
		Usage: "update the intent fee program for boarding inputs",
		Value: "",
	}
	offchainInputFlag = &cli.StringFlag{
		Name:  offchainInputFlagName,
		Usage: "update the intent fee program for forfeited vtxos",
		Value: "",
	}
	onchainOutputFlag = &cli.StringFlag{
		Name:  onchainOutputFlagName,
		Usage: "update the intent fee program for collaborative exit outputs",
		Value: "",
	}
	offchainOutputFlag = &cli.StringFlag{
		Name:  offchainOutputFlagName,
		Usage: "update the intent fee program for new vtxo leaves",
		Value: "",
	}
	clearFlag = &cli.BoolFlag{
		Name:  clearFlagName,
		Usage: "clear all intent fee programs",
		Value: false,
	}
	unrolledVtxoMinExpiryMarginFlag = &cli.IntFlag{
		Name:  unrolledVtxoMinExpiryMarginFlagName,
		Usage: "the min expiry margin for unrolled vtxos in seconds",
	}
	banThresholdFlag = &cli.IntFlag{
		Name:  banThresholdFlagName,
		Usage: "the number of offenses before a script gets banned",
	}
	unilateralExitDelayFlag = &cli.IntFlag{
		Name:  unilateralExitDelayFlagName,
		Usage: "the unilateral exit delay as a relative locktime (seconds if >= 512, blocks otherwise)",
	}
	publicUnilateralExitDelayFlag = &cli.IntFlag{
		Name:  publicUnilateralExitDelayFlagName,
		Usage: "the public unilateral exit delay as a relative locktime (seconds if >= 512, blocks otherwise)",
	}
	checkpointExitDelayFlag = &cli.IntFlag{
		Name:  checkpointExitDelayFlagName,
		Usage: "the checkpoint exit delay as a relative locktime (seconds if >= 512, blocks otherwise)",
	}
	boardingExitDelayFlag = &cli.IntFlag{
		Name:  boardingExitDelayFlagName,
		Usage: "the boarding exit delay as a relative locktime (seconds if >= 512, blocks otherwise)",
	}
	vtxoTreeExpiryFlag = &cli.IntFlag{
		Name:  vtxoTreeExpiryFlagName,
		Usage: "the vtxo tree expiry as a relative locktime (seconds if >= 512, blocks otherwise)",
	}
	vtxoMinAmountFlag = &cli.IntFlag{
		Name:  vtxoMinAmountFlagName,
		Usage: "the min amount in satoshis for a vtxo (-1 to disable)",
	}
	vtxoMaxAmountFlag = &cli.IntFlag{
		Name:  vtxoMaxAmountFlagName,
		Usage: "the max amount in satoshis for a vtxo (-1 to disable)",
	}
	utxoMinAmountFlag = &cli.IntFlag{
		Name:  utxoMinAmountFlagName,
		Usage: "the min amount in satoshis for a boarding/exit utxo (-1 to disable)",
	}
	utxoMaxAmountFlag = &cli.IntFlag{
		Name:  utxoMaxAmountFlagName,
		Usage: "the max amount in satoshis for a boarding/exit utxo (-1 to disable)",
	}
	settlementMinExpiryGapFlag = &cli.IntFlag{
		Name:  settlementMinExpiryGapFlagName,
		Usage: "the min expiry gap in seconds required to settle a vtxo",
	}
	vtxoNoCsvValidationCutoffDateFlag = &cli.IntFlag{
		Name:  vtxoNoCsvValidationCutoffDateFlagName,
		Usage: "the cutoff date (Unix timestamp) before which vtxos skip CSV validation",
	}
	maxTxWeightFlag = &cli.IntFlag{
		Name:  maxTxWeightFlagName,
		Usage: "the max allowed weight for a transaction",
	}
	maxOpReturnOutsFlag = &cli.IntFlag{
		Name:  maxOpReturnOutsFlagName,
		Usage: "the max number of OP_RETURN outputs allowed in a transaction",
	}
	assetTxMaxWeightRatioFlag = &cli.Float64Flag{
		Name:  assetTxMaxWeightRatioFlagName,
		Usage: "the max ratio of asset tx weight over the total tx weight, in range (0, 1)",
	}
	notePrefixFlag = &cli.StringFlag{
		Name:  notePrefixFlagName,
		Usage: "the URI prefix used to encode notes",
	}
	buildVersionHeaderFlag = &cli.StringFlag{
		Name:  buildVersionHeaderFlagName,
		Usage: "the min client build version accepted by the server",
	}
	buildVersionHeaderRequiredFlag = &cli.StringFlag{
		Name: buildVersionHeaderRequiredFlagName,
		Usage: "whether clients are required to send a valid build version header " +
			"(true or false); omit to leave unchanged",
	}
)
