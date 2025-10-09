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

	dateFormat                 = time.DateOnly
	scheduledSessionDateFormat = time.DateTime
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
	withdrawAmountFlag = &cli.Float64Flag{
		Name:     amountFlagName,
		Usage:    "amount to withdraw in BTC",
		Required: true,
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
			scheduledSessionDateFormat,
		),
	}
	scheduledSessionEndDateFlag = &cli.StringFlag{
		Name: scheduledSessionEndDateFlagName,
		Usage: fmt.Sprintf(
			"the ending date of the very first scheduled session, must be in %s format (GMT)",
			scheduledSessionDateFormat,
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
)
