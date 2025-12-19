package main

import (
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/config"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/urfave/cli/v2"
)

const (
	urlFlagName                                       = "url"
	datadirFlagName                                   = "datadir"
	macaroonFlagName                                  = "macaroon"
	passwordFlagName                                  = "password"
	mnemonicFlagName                                  = "mnemonic"
	gapLimitFlagName                                  = "addr-gap-limit"
	amountFlagName                                    = "amount"
	withdrawAllFlagName                               = "all"
	quantityFlagName                                  = "quantity"
	addressFlagName                                   = "address"
	intentIdsFlagName                                 = "ids"
	roundIdFlagName                                   = "id"
	beforeDateFlagName                                = "before-date"
	afterDateFlagName                                 = "after-date"
	scheduledSessionStartDateFlagName                 = "start-date"
	scheduledSessionEndDateFlagName                   = "end-date"
	scheduledSessionDurationFlagName                  = "duration"
	scheduledSessionPeriodFlagName                    = "period"
	scheduledSessionRoundMinParticipantsCountFlagName = "round-min-participants"
	scheduledSessionRoundMaxParticipantsCountFlagName = "round-max-participants"
	signerKeyFlagName                                 = "signer-prvkey"
	signerUrlFlagName                                 = "signer-url"
	tokenFlagName                                     = "token"
	convictionIdsFlagName                             = "ids"
	convictionFromFlagName                            = "from"
	convictionToFlagName                              = "to"
	convictionIdFlagName                              = "id"
	scriptFlagName                                    = "script"
	banDurationFlagName                               = "duration"
	banReasonFlagName                                 = "reason"
	completedFlagName                                 = "completed"
	failedFlagName                                    = "failed"
	withDetailsFlagName                               = "with-details"
	sweepConnectorsFlagName                           = "with-connectors"
	sweepCommitmentTxidsFlagName                      = "commitment-txids"
	liquidityAfterFlagName                            = "after-date"
	liquidityBeforeFlagName                           = "before-date"

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
	scheduledSessionDurationFlag = &cli.IntFlag{
		Name:  scheduledSessionDurationFlagName,
		Usage: "the duration of the scheduled sessions in seconds",
	}
	scheduledSessionPeriodFlag = &cli.IntFlag{
		Name:  scheduledSessionPeriodFlagName,
		Usage: "the interval between a scheduled session and the next one",
	}
	scheduledSessionRoundMinParticipantsCountFlag = &cli.IntFlag{
		Name:  scheduledSessionRoundMinParticipantsCountFlagName,
		Usage: "the min number of participants per round during a scheduled session",
	}
	scheduledSessionRoundMaxParticipantsCountFlag = &cli.IntFlag{
		Name:  scheduledSessionRoundMaxParticipantsCountFlagName,
		Usage: "the max number of participants per round during a scheduled session",
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
		Name: liquidityAfterFlagName,
		Usage: fmt.Sprintf(
			"get expiring liquidity after a specific date in format %s. "+
				"If not provided, defaults to now", dateWithTimeFormat,
		),
		Value: "",
	}
	liquidityBeforeFlag = &cli.StringFlag{
		Name: liquidityBeforeFlagName,
		Usage: fmt.Sprintf(
			"get expiring liquidity before a specific date in format %s. "+
				"If not provided, no upper bound is applied", dateWithTimeFormat,
		),
		Value: "",
	}
)
