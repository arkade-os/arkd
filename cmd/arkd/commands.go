package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/urfave/cli/v2"
)

const ONE_BTC = float64(1_00_000_000)

// commands
var (
	walletCmd = &cli.Command{
		Name:  "wallet",
		Usage: "Manage the Ark Server wallet",
		Subcommands: cli.Commands{
			walletStatusCmd,
			walletCreateOrRestoreCmd,
			walletUnlockCmd,
			walletAddressCmd,
			walletBalanceCmd,
			walletWithdrawCmd,
		},
	}
	signerCmd = &cli.Command{
		Name:  "signer",
		Usage: "Manage the Ark Signer",
		Subcommands: cli.Commands{
			signerLoadCmd,
		},
	}
	genkeyCmd = &cli.Command{
		Name:   "genkey",
		Usage:  "Generate a new private key",
		Action: genkeyAction,
	}
	versionCmd = &cli.Command{
		Name:   "version",
		Usage:  "Display version information",
		Action: versionAction,
	}
	walletStatusCmd = &cli.Command{
		Name:   "status",
		Usage:  "Get info about the status of the wallet",
		Action: walletStatusAction,
	}
	walletCreateOrRestoreCmd = &cli.Command{
		Name:   "create",
		Usage:  "Create or restore the wallet",
		Action: walletCreateOrRestoreAction,
		Flags:  []cli.Flag{passwordFlag, mnemonicFlag, gapLimitFlag},
	}
	walletUnlockCmd = &cli.Command{
		Name:   "unlock",
		Usage:  "Unlock the wallet",
		Action: walletUnlockAction,
		Flags:  []cli.Flag{passwordFlag},
	}
	walletAddressCmd = &cli.Command{
		Name:   "address",
		Usage:  "Generate a receiving address",
		Action: walletAddressAction,
	}
	walletBalanceCmd = &cli.Command{
		Name:   "balance",
		Usage:  "Get the wallet balance",
		Action: walletBalanceAction,
	}
	walletWithdrawCmd = &cli.Command{
		Name:   "withdraw",
		Usage:  "Withdraw funds from the wallet",
		Action: walletWithdrawAction,
		Flags:  []cli.Flag{withdrawAmountFlag, withdrawAddressFlag, withdrawAllFlag},
	}
	signerLoadCmd = &cli.Command{
		Name:   "load",
		Usage:  "Load the ark signer address or private key",
		Action: signerLoadAction,
		Flags:  []cli.Flag{signerKeyFlag, signerUrlFlag},
	}
	noteCmd = &cli.Command{
		Name:   "note",
		Usage:  "Create a credit note",
		Action: createNoteAction,
		Flags:  []cli.Flag{amountFlag, quantityFlag},
	}
	intentsCmd = &cli.Command{
		Name:        "intents",
		Usage:       "List or manage the queue of registered intents",
		Subcommands: cli.Commands{deleteIntentsCmd, clearIntentsCmd},
		Action:      listIntentsAction,
	}
	deleteIntentsCmd = &cli.Command{
		Name:   "delete",
		Usage:  "Delete registered intents from the queue",
		Flags:  []cli.Flag{intentIdsFlag(true)},
		Action: deleteIntentsAction,
	}
	clearIntentsCmd = &cli.Command{
		Name:   "clear",
		Usage:  "Remove all registered intents from the queue",
		Action: clearIntentsAction,
	}
	scheduledSweepCmd = &cli.Command{
		Name:   "scheduled-sweeps",
		Usage:  "List all scheduled batches sweepings",
		Action: scheduledSweepAction,
	}
	roundInfoCmd = &cli.Command{
		Name:   "round-info",
		Usage:  "Get round info",
		Flags:  []cli.Flag{roundIdFlag},
		Action: roundInfoAction,
	}
	roundsInTimeRangeCmd = &cli.Command{
		Name:  "rounds",
		Usage: "Get ids of rounds in the given time range",
		Flags: []cli.Flag{
			beforeDateFlag,
			afterDateFlag,
			completedFlag,
			failedFlag,
			withDetailsFlag,
		},
		Action: roundsInTimeRangeAction,
	}
	scheduledSessionCmd = &cli.Command{
		Name:  "scheduled-session",
		Usage: "Get or update the scheduled session configuration",
		Subcommands: cli.Commands{
			updateScheduledSessionCmd,
			clearScheduledSessionCmd,
		},
		Action: getScheduledSessionAction,
	}
	updateScheduledSessionCmd = &cli.Command{
		Name:  "update",
		Usage: "Update the scheduled session configuration",
		Flags: []cli.Flag{
			scheduledSessionStartDateFlag, scheduledSessionEndDateFlag,
			scheduledSessionDurationFlag, scheduledSessionPeriodFlag,
			scheduledSessionRoundMinParticipantsCountFlag, scheduledSessionRoundMaxParticipantsCountFlag,
		},
		Action: updateScheduledSessionAction,
	}
	clearScheduledSessionCmd = &cli.Command{
		Name:   "clear",
		Usage:  "Clear the scheduled session configuration",
		Action: clearScheduledSessionAction,
	}
	revokeAuthCmd = &cli.Command{
		Name:   "revoke-auth",
		Usage:  "Revoke auth token",
		Flags:  []cli.Flag{tokenFlag},
		Action: revokeTokenAction,
	}
	convictionsCmd = &cli.Command{
		Name:   "convictions",
		Usage:  "Get convictions by IDs",
		Flags:  []cli.Flag{convictionIdsFlag},
		Action: getConvictionsAction,
		Subcommands: cli.Commands{
			getConvictionsInRangeCmd,
			getConvictionsByRoundCmd,
			getActiveScriptConvictionsCmd,
			pardonConvictionCmd,
			addConvictionCmd,
		},
	}
	getConvictionsInRangeCmd = &cli.Command{
		Name:   "range",
		Usage:  "Get convictions in time range",
		Flags:  []cli.Flag{convictionFromFlag, convictionToFlag},
		Action: getConvictionsInRangeAction,
	}
	getConvictionsByRoundCmd = &cli.Command{
		Name:   "by-round",
		Usage:  "Get convictions by round ID",
		Flags:  []cli.Flag{roundIdFlag},
		Action: getConvictionsByRoundAction,
	}
	getActiveScriptConvictionsCmd = &cli.Command{
		Name:   "active",
		Usage:  "Get active script convictions",
		Flags:  []cli.Flag{scriptFlag},
		Action: getActiveScriptConvictionsAction,
	}
	pardonConvictionCmd = &cli.Command{
		Name:   "pardon",
		Usage:  "Pardon a conviction",
		Flags:  []cli.Flag{convictionIdFlag},
		Action: pardonConvictionAction,
	}
	addConvictionCmd = &cli.Command{
		Name:   "add",
		Usage:  "Add a conviction",
		Flags:  []cli.Flag{scriptFlag, banDurationFlag, banReasonFlag},
		Action: banScriptAction,
	}
)

var timeout = time.Minute

func walletStatusAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	_, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/status", baseURL)
	status, err := getStatus(url, tlsConfig)
	if err != nil {
		return err
	}

	fmt.Println(status)
	return nil
}

func walletCreateOrRestoreAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	_, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	password := ctx.String(passwordFlagName)
	mnemonic := ctx.String(mnemonicFlagName)
	gapLimit := ctx.Uint64(gapLimitFlagName)

	if len(mnemonic) > 0 {
		url := fmt.Sprintf("%s/v1/admin/wallet/restore", baseURL)
		body := fmt.Sprintf(
			`{"seed": "%s", "password": "%s", "gap_limit": %d}`,
			mnemonic, password, gapLimit,
		)
		if _, err := post[struct{}](url, body, "", "", tlsConfig); err != nil {
			return err
		}

		fmt.Println("wallet restored")
		return nil
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/seed", baseURL)
	seed, err := get[string](url, "seed", "", tlsConfig)
	if err != nil {
		return err
	}

	url = fmt.Sprintf("%s/v1/admin/wallet/create", baseURL)
	body := fmt.Sprintf(
		`{"seed": "%s", "password": "%s"}`, seed, password,
	)
	if _, err := post[struct{}](url, body, "", "", tlsConfig); err != nil {
		return err
	}

	fmt.Println(seed)
	return nil
}

func walletUnlockAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	_, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	password := ctx.String(passwordFlagName)
	url := fmt.Sprintf("%s/v1/admin/wallet/unlock", baseURL)
	body := fmt.Sprintf(`{"password": "%s"}`, password)

	if _, err := post[struct{}](url, body, "", "", tlsConfig); err != nil {
		return err
	}

	fmt.Println("wallet unlocked")
	return nil
}

func walletAddressAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/address", baseURL)
	addr, err := get[string](url, "address", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	fmt.Println(addr)
	return nil
}

func walletBalanceAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/balance", baseURL)
	balance, err := getBalance(url, macaroon, tlsConfig)
	if err != nil {
		return err
	}

	fmt.Println(balance)
	return nil
}

func walletWithdrawAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	amount := ctx.Float64(amountFlagName)
	address := ctx.String(addressFlagName)
	all := ctx.Bool(withdrawAllFlagName)

	if !all && amount == 0 {
		return fmt.Errorf("amount must be provided")
	}

	// ask for confirmation
	if all {
		fmt.Println(
			"WARNING: this will withdraw all available balance including connectors account funds",
		)
		fmt.Println("WARNING: it may make connectors utxos unspendable, making forfeit txs invalid")
		fmt.Println("WARNING: are you sure you want to proceed? (y/n)")
		var confirm string
		if _, err := fmt.Scanln(&confirm); err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if confirm != "y" {
			return fmt.Errorf("operation cancelled")
		}
	}

	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/withdraw", baseURL)
	amountInSats := uint64(amount * ONE_BTC)
	body := fmt.Sprintf(`{"address": "%s", "amount": %d, "all": %t}`, address, amountInSats, all)

	txid, err := post[string](url, body, "txid", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	fmt.Println("transaction successfully broadcasted:")
	fmt.Println(txid)
	return nil
}

func signerLoadAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	signerKey := ctx.String(signerKeyFlagName)
	signerUrl := ctx.String(signerUrlFlagName)
	if signerKey == "" && signerUrl == "" {
		return fmt.Errorf("either private key or url must be provided")
	}
	if signerKey != "" && signerUrl != "" {
		return fmt.Errorf("private key and url are mutually esclusive, only one must be provided")
	}
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/signer", baseURL)
	body := fmt.Sprintf(`{"signerUrl": "%s"}`, signerUrl)
	if signerKey != "" {
		body = fmt.Sprintf(`{"signerPrivateKey": "%s"}`, signerKey)
	}

	if _, err := post[struct{}](url, body, "", macaroon, tlsConfig); err != nil {
		return err
	}

	fmt.Println("signer loaded")
	return nil
}

func genkeyAction(ctx *cli.Context) error {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(key.Serialize()))
	return nil
}

func versionAction(ctx *cli.Context) error {
	fmt.Printf("Arkd version: %s\n", Version)
	return nil
}

func createNoteAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	amount := ctx.Uint(amountFlagName)
	quantity := ctx.Uint(quantityFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/note", baseURL)
	body := fmt.Sprintf(`{"amount": %d, "quantity": %d}`, amount, quantity)

	notes, err := post[[]string](url, body, "notes", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	for _, note := range notes {
		fmt.Println(note)
	}

	return nil
}

func listIntentsAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	u, err := url.Parse(fmt.Sprintf("%s/v1/admin/intents", baseURL))
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	requestIds := ctx.StringSlice(intentIdsFlagName)
	if len(requestIds) > 0 {
		q := u.Query()
		q.Set("intent_ids", strings.Join(requestIds, ","))
		u.RawQuery = q.Encode()
	}
	response, err := get[[]map[string]any](u.String(), "intents", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	respJson, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode response: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func deleteIntentsAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	intentIds := ctx.StringSlice(intentIdsFlagName)
	intentIdsJSON, err := json.Marshal(intentIds)
	if err != nil {
		return fmt.Errorf("failed to marshal intent ids: %s", err)
	}

	url := fmt.Sprintf("%s/v1/admin/intents/delete", baseURL)
	body := fmt.Sprintf(`{"intent_ids": %s}`, intentIdsJSON)

	if _, err := post[struct{}](url, body, "", macaroon, tlsConfig); err != nil {
		return err
	}

	fmt.Printf("Successfully deleted intents: %s\n", intentIds)
	return nil
}

func clearIntentsAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/intents/delete", baseURL)
	body := `{"intent_ids": []}`

	if _, err := post[struct{}](url, body, "", macaroon, tlsConfig); err != nil {
		return err
	}

	fmt.Println("Successfully deleted all intents")
	return nil
}

func scheduledSweepAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/sweeps", baseURL)

	resp, err := get[[]map[string]any](url, "sweeps", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode response: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func roundInfoAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	roundId := ctx.String(roundIdFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/round/%s", baseURL, roundId)

	resp, err := getRoundInfo(url, macaroon, tlsConfig)
	if err != nil {
		return err
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode response: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func roundsInTimeRangeAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	beforeDate := ctx.String(beforeDateFlagName)
	afterDate := ctx.String(afterDateFlagName)
	completed := ctx.Bool(completedFlagName)
	failed := ctx.Bool(failedFlagName)
	withDetails := ctx.Bool(withDetailsFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/rounds", baseURL)

	// Default to today's time range if no flags are provided
	if afterDate == "" && beforeDate == "" {
		now := time.Now()
		startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		endOfDay := startOfDay.Add(24 * time.Hour)

		url = fmt.Sprintf(
			"%s?after=%d&before=%d&with_completed=%t&with_failed=%t",
			url,
			startOfDay.Unix(),
			endOfDay.Unix(),
			completed,
			failed,
		)
	} else {
		queryParams := make([]string, 0)

		if afterDate != "" {
			afterTs, err := time.Parse(dateFormat, afterDate)
			if err != nil {
				return fmt.Errorf("invalid --after-date format, must be %s", dateFormat)
			}
			queryParams = append(queryParams, fmt.Sprintf("after=%d", afterTs.Unix()))
		}
		if beforeDate != "" {
			beforeTs, err := time.Parse(dateFormat, beforeDate)
			if err != nil {
				return fmt.Errorf("invalid --before-date format, must be %s", dateFormat)
			}
			queryParams = append(queryParams, fmt.Sprintf("before=%d", beforeTs.Unix()))
		}

		// Add the filtering parameters
		queryParams = append(queryParams, fmt.Sprintf("with_completed=%t", completed))
		queryParams = append(queryParams, fmt.Sprintf("with_failed=%t", failed))

		if len(queryParams) > 0 {
			url = fmt.Sprintf("%s?%s", url, strings.Join(queryParams, "&"))
		}
	}

	roundIds, err := get[[]string](url, "rounds", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	if withDetails {
		roundDetails := make([]*roundInfo, 0, len(roundIds))
		for _, roundId := range roundIds {
			detailUrl := fmt.Sprintf("%s/v1/admin/round/%s", baseURL, roundId)
			detail, err := getRoundInfo(detailUrl, macaroon, tlsConfig)
			if err != nil {
				return fmt.Errorf("failed to get details for round %s: %w", roundId, err)
			}
			roundDetails = append(roundDetails, detail)
		}

		respJson, err := json.MarshalIndent(roundDetails, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to json encode round details: %s", err)
		}
		fmt.Println(string(respJson))
		return nil
	}

	// Default behavior: return just the round IDs
	respJson, err := json.MarshalIndent(roundIds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode round ids: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func getScheduledSessionAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/scheduledSession", baseURL)

	resp, err := get[map[string]string](url, "config", macaroon, tlsConfig)
	if err != nil {
		return err
	}
	if len(resp) == 0 {
		fmt.Println("{}")
		return nil
	}

	if resp["startTime"] != "" {
		startTime, err := strconv.Atoi(resp["startTime"])
		if err != nil {
			return fmt.Errorf("failed to parse scheduled session start time: %s", err)
		}
		startDate := time.Unix(int64(startTime), 0)
		resp["startTime"] = startDate.Format(time.RFC3339)
	}
	if resp["endTime"] != "" {
		endTime, err := strconv.Atoi(resp["endTime"])
		if err != nil {
			return fmt.Errorf("failed to parse scheduled session end time: %s", err)
		}
		endDate := time.Unix(int64(endTime), 0)
		resp["endTime"] = endDate.Format(time.RFC3339)
	}
	if resp["period"] != "" {
		resp["period"] += " minutes"
	}
	if resp["duration"] != "" {
		resp["duration"] += " seconds"
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode round ids: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func updateScheduledSessionAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	startDate := ctx.String(scheduledSessionStartDateFlagName)
	endDate := ctx.String(scheduledSessionEndDateFlagName)
	duration := ctx.Uint(scheduledSessionDurationFlagName)
	period := ctx.Uint(scheduledSessionPeriodFlagName)
	roundMinParticipantsCount := ctx.Uint(scheduledSessionRoundMinParticipantsCountFlagName)
	roundMaxParticipantsCount := ctx.Uint(scheduledSessionRoundMaxParticipantsCountFlagName)

	if ctx.IsSet(scheduledSessionStartDateFlagName) != ctx.IsSet(scheduledSessionEndDateFlagName) {
		return fmt.Errorf("--start-date and --end-date must be set together")
	}

	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/scheduledSession", baseURL)
	config := map[string]string{}
	if startDate != "" {
		startTime, err := time.Parse(scheduledSessionDateFormat, startDate)
		if err != nil {
			return fmt.Errorf("invalid --start-date format, must be %s", scheduledSessionDateFormat)
		}
		endTime, err := time.Parse(scheduledSessionDateFormat, endDate)
		if err != nil {
			return fmt.Errorf("invalid --end-date format, must be %s", scheduledSessionDateFormat)
		}
		config["startTime"] = strconv.Itoa(int(startTime.Unix()))
		config["endTime"] = strconv.Itoa(int(endTime.Unix()))
	}
	if duration > 0 {
		config["duration"] = strconv.Itoa(int(duration))
	}
	if period > 0 {
		config["period"] = strconv.Itoa(int(period))
	}
	if roundMinParticipantsCount > 0 {
		config["roundMinParticipantsCount"] = strconv.Itoa(int(roundMinParticipantsCount))
	}
	if roundMaxParticipantsCount > 0 {
		config["roundMaxParticipantsCount"] = strconv.Itoa(int(roundMaxParticipantsCount))
	}
	bodyMap := map[string]map[string]string{"config": config}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return fmt.Errorf("failed to encode request body: %s", err)
	}
	if _, err := post[any](url, string(body), "", macaroon, tlsConfig); err != nil {
		return err
	}

	fmt.Println("Successfully updated scheduled session config")
	return nil
}

func clearScheduledSessionAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/scheduledSession/clear", baseURL)
	if _, err := post[any](url, "", "", macaroon, tlsConfig); err != nil {
		return err
	}

	fmt.Println("Successfully cleared scheduled session config")
	return nil
}

func revokeTokenAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	token := ctx.String(tokenFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/auth/revoke", baseURL)
	body := fmt.Sprintf(`{"token": "%s"}`, token)

	newToken, err := post[string](url, body, "token", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	resp := map[string]string{"newToken": newToken}
	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode response: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func getConvictionsAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	convictionIds := ctx.StringSlice(convictionIdsFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf(
		"%s/v1/admin/convictions/%s",
		baseURL,
		url.PathEscape(strings.Join(convictionIds, ",")),
	)
	resp, err := get[[]map[string]any](url, "convictions", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode response: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func getConvictionsInRangeAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	// Default to last 24 hours if flags are not set
	now := time.Now()
	from := ctx.Int64(convictionFromFlagName)
	to := ctx.Int64(convictionToFlagName)

	if !ctx.IsSet(convictionFromFlagName) {
		from = now.Add(-24 * time.Hour).Unix()
	}
	if !ctx.IsSet(convictionToFlagName) {
		to = now.Unix()
	}

	url := fmt.Sprintf("%s/v1/admin/convictionsInRange?from=%d&to=%d", baseURL, from, to)
	resp, err := get[[]map[string]any](url, "convictions", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode response: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func getConvictionsByRoundAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	roundId := ctx.String(roundIdFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/convictionsByRound/%s", baseURL, url.PathEscape(roundId))
	resp, err := get[[]map[string]any](url, "convictions", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode response: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func getActiveScriptConvictionsAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	script := ctx.String(scriptFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/convictionsByScript/%s", baseURL, url.PathEscape(script))
	resp, err := get[[]map[string]any](url, "convictions", macaroon, tlsConfig)
	if err != nil {
		return err
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode response: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func pardonConvictionAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	convictionId := ctx.String(convictionIdFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/convictions/%s/pardon", baseURL, url.PathEscape(convictionId))

	if _, err := post[struct{}](url, "", "", macaroon, tlsConfig); err != nil {
		return err
	}

	fmt.Printf("Successfully pardoned conviction: %s\n", convictionId)
	return nil
}

func banScriptAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	script := ctx.String(scriptFlagName)
	banDuration := ctx.Int64(banDurationFlagName)
	banReason := ctx.String(banReasonFlagName)
	macaroon, tlsConfig, err := getCredentials(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/conviction/ban", baseURL)
	body := fmt.Sprintf(
		`{"script": "%s", "ban_duration": %d, "reason": "%s"}`,
		script,
		banDuration,
		banReason,
	)

	if _, err := post[struct{}](url, body, "", macaroon, tlsConfig); err != nil {
		return err
	}

	fmt.Printf("Successfully banned script: %s\n", script)
	return nil
}
