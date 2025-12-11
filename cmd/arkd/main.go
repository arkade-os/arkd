package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Version will be set during build time
var Version string

const (
	macaroonDir  = "macaroons"
	macaroonFile = "operator.macaroon"
	tlsDir       = "tls"
	tlsCertFile  = "cert.pem"
)

func main() {
	app := cli.NewApp()
	app.Version = Version
	app.Name = "arkd"
	app.Usage = "run or manage the Ark Server"
	app.UsageText = "Run the Ark Server with:\n\tarkd\nManage the Ark Server with:\n\tarkd [global options] command [command options]"
	app.Commands = append(
		app.Commands,
		startCmdWrapper,
		versionCmd,
		walletCmd,
		signerCmd,
		genkeyCmd,
		noteCmd,
		intentsCmd,
		scheduledSweepCmd,
		roundInfoCmd,
		roundsInTimeRangeCmd,
		scheduledSessionCmd,
		revokeAuthCmd,
		convictionsCmd,
	)

	app.DefaultCommand = startCmd.Use
	app.Flags = append(app.Flags, urlFlag, datadirFlag, macaroonFlag)

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
