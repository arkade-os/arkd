package main

import (
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/config"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/urfave/cli/v2"
)

const (
	urlFlagName                     = "url"
	datadirFlagName                 = "datadir"
	passwordFlagName                = "password"
	dbPathFlagName                  = "datadir"
	mnemonicFlagName                = "mnemonic"
	gapLimitFlagName                = "addr-gap-limit"
	amountFlagName                  = "amount"
	quantityFlagName                = "quantity"
	addressFlagName                 = "address"
	intentIdsFlagName               = "ids"
	roundIdFlagName                 = "id"
	beforeDateFlagName              = "before-date"
	afterDateFlagName               = "after-date"
	marketHourStartDateFlagName     = "start-date"
	marketHourEndDateFlagName       = "end-date"
	marketHourRoundIntervalFlagName = "round-interval"
	marketHourPeriodFlagName        = "period"

	dateFormat           = time.DateOnly
	marketHourDateFormat = time.DateTime
)

var (
	urlFlag = &cli.StringFlag{
		Name:  urlFlagName,
		Usage: "the url where to reach ark server",
		Value: fmt.Sprintf("http://localhost:%d", config.DefaultPort),
	}
	datadirFlag = &cli.StringFlag{
		Name:  datadirFlagName,
		Usage: "arkd datadir from where to source TLS cert and macaroon if needed",
		Value: arklib.AppDataDir("arkd", false),
	}
	dbPathFlag = &cli.StringFlag{
		Name:     dbPathFlagName,
		Usage:    "path to the wallet database",
		Required: true,
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
	marketHourStartDateFlag = &cli.StringFlag{
		Name: marketHourStartDateFlagName,
		Usage: fmt.Sprintf(
			"the market hour starting date, must be in %s format",
			marketHourDateFormat,
		),
	}
	marketHourEndDateFlag = &cli.StringFlag{
		Name: marketHourEndDateFlagName,
		Usage: fmt.Sprintf(
			"the market hour ending date, must be in %s format",
			marketHourDateFormat,
		),
	}
	marketHourRoundIntervalFlag = &cli.IntFlag{
		Name:  marketHourRoundIntervalFlagName,
		Usage: "the market hour round interval in seconds",
	}
	marketHourPeriodFlag = &cli.IntFlag{
		Name:  marketHourPeriodFlagName,
		Usage: "the market hour period in minutes, ie the interval between a market hour and the next one",
	}
)
