package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

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
		Flags:  []cli.Flag{withdrawAmountFlag, withdrawAddressFlag},
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
		Name:   "rounds",
		Usage:  "Get ids of rounds in the given time range",
		Flags:  []cli.Flag{beforeDateFlag, afterDateFlag},
		Action: roundsInTimeRangeAction,
	}
	marketHourCmd = &cli.Command{
		Name:        "market-hour",
		Usage:       "Get or update the market hour configuration",
		Subcommands: cli.Commands{updateMarketHourCmd},
		Action:      getMarketHourAction,
	}
	updateMarketHourCmd = &cli.Command{
		Name:  "update",
		Usage: "Update the market hour configuration",
		Flags: []cli.Flag{
			marketHourStartDateFlag, marketHourEndDateFlag,
			marketHourRoundIntervalFlag, marketHourPeriodFlag,
		},
		Action: updateMarketHourAction,
	}
)

var timeout = time.Minute

func walletStatusAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	_, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/status", baseURL)
	status, err := getStatus(url, tlsCertPath)
	if err != nil {
		return err
	}

	fmt.Println(status)
	return nil
}

func walletCreateOrRestoreAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	_, tlsCertPath, err := getCredentialPaths(ctx)
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
		if _, err := post[struct{}](url, body, "", "", tlsCertPath); err != nil {
			return err
		}

		fmt.Println("wallet restored")
		return nil
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/seed", baseURL)
	seed, err := get[string](url, "seed", "", tlsCertPath)
	if err != nil {
		return err
	}

	url = fmt.Sprintf("%s/v1/admin/wallet/create", baseURL)
	body := fmt.Sprintf(
		`{"seed": "%s", "password": "%s"}`, seed, password,
	)
	if _, err := post[struct{}](url, body, "", "", tlsCertPath); err != nil {
		return err
	}

	fmt.Println(seed)
	return nil
}

func walletUnlockAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	_, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	password := ctx.String(passwordFlagName)
	url := fmt.Sprintf("%s/v1/admin/wallet/unlock", baseURL)
	body := fmt.Sprintf(`{"password": "%s"}`, password)

	if _, err := post[struct{}](url, body, "", "", tlsCertPath); err != nil {
		return err
	}

	fmt.Println("wallet unlocked")
	return nil
}

func walletAddressAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/address", baseURL)
	addr, err := get[string](url, "address", macaroon, tlsCertPath)
	if err != nil {
		return err
	}

	fmt.Println(addr)
	return nil
}

func walletBalanceAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/balance", baseURL)
	balance, err := getBalance(url, macaroon, tlsCertPath)
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
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/withdraw", baseURL)
	amountInSats := uint64(amount * ONE_BTC)
	body := fmt.Sprintf(`{"address": "%s", "amount": %d}`, address, amountInSats)

	txid, err := post[string](url, body, "txid", macaroon, tlsCertPath)
	if err != nil {
		return err
	}

	fmt.Println("transaction successfully broadcasted:")
	fmt.Println(txid)
	return nil
}

func createNoteAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	amount := ctx.Uint(amountFlagName)
	quantity := ctx.Uint(quantityFlagName)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/note", baseURL)
	body := fmt.Sprintf(`{"amount": %d, "quantity": %d}`, amount, quantity)

	notes, err := post[[]string](url, body, "notes", macaroon, tlsCertPath)
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
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
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
	response, err := get[[]map[string]any](u.String(), "intents", macaroon, tlsCertPath)
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
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
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

	if _, err := post[struct{}](url, body, "", macaroon, tlsCertPath); err != nil {
		return err
	}

	fmt.Printf("Successfully deleted intents: %s\n", intentIds)
	return nil
}

func clearIntentsAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/intents/delete", baseURL)
	body := `{"intent_ids": []}`

	if _, err := post[struct{}](url, body, "", macaroon, tlsCertPath); err != nil {
		return err
	}

	fmt.Println("Successfully deleted all intents")
	return nil
}

func scheduledSweepAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/sweeps", baseURL)

	resp, err := get[[]map[string]any](url, "sweeps", macaroon, tlsCertPath)
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
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/round/%s", baseURL, roundId)

	resp, err := getRoundInfo(url, macaroon, tlsCertPath)
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
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/rounds", baseURL)
	if afterDate != "" {
		afterTs, err := time.Parse(dateFormat, afterDate)
		if err != nil {
			return fmt.Errorf("invalid --after-date format, must be %s", dateFormat)
		}
		url = fmt.Sprintf("%s?after=%d", url, afterTs.Unix())
	}
	if beforeDate != "" {
		beforeTs, err := time.Parse(dateFormat, beforeDate)
		if err != nil {
			return fmt.Errorf("invalid --before-date format, must be %s", dateFormat)
		}
		if afterDate != "" {
			url = fmt.Sprintf("%s&before=%d", url, beforeTs.Unix())
		} else {
			url = fmt.Sprintf("%s?before=%d", url, beforeTs.Unix())
		}
	}

	roundIds, err := get[map[string]string](url, "rounds", macaroon, tlsCertPath)
	if err != nil {
		return err
	}

	respJson, err := json.MarshalIndent(roundIds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode round ids: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func getMarketHourAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/marketHour", baseURL)

	resp, err := get[map[string]string](url, "config", macaroon, tlsCertPath)
	if err != nil {
		return err
	}

	if resp["startTime"] != "" {
		startTime, err := strconv.Atoi(resp["startTime"])
		if err != nil {
			return fmt.Errorf("failed to parse market hour start time: %s", err)
		}
		startDate := time.Unix(int64(startTime), 0)
		resp["startTime"] = startDate.Format(time.RFC3339)
	}
	if resp["endTime"] != "" {
		endTime, err := strconv.Atoi(resp["endTime"])
		if err != nil {
			return fmt.Errorf("failed to parse market hour end time: %s", err)
		}
		endDate := time.Unix(int64(endTime), 0)
		resp["endTime"] = endDate.Format(time.RFC3339)
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode round ids: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}

func updateMarketHourAction(ctx *cli.Context) error {
	baseURL := ctx.String(urlFlagName)
	startDate := ctx.String(marketHourStartDateFlagName)
	endDate := ctx.String(marketHourEndDateFlagName)
	roundInterval := ctx.Uint(marketHourRoundIntervalFlagName)
	period := ctx.Uint(marketHourPeriodFlagName)

	if ctx.IsSet(marketHourStartDateFlagName) != ctx.IsSet(marketHourEndDateFlagName) {
		return fmt.Errorf("--start-date and --end-date must be set together")
	}

	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/marketHour", baseURL)
	bodyMap := map[string]string{}
	if startDate != "" {
		startTime, err := time.Parse(marketHourDateFormat, startDate)
		if err != nil {
			return fmt.Errorf("invalid --start-date format, must be %s", marketHourDateFormat)
		}
		endTime, err := time.Parse(marketHourDateFormat, endDate)
		if err != nil {
			return fmt.Errorf("invalid --end-date format, must be %s", marketHourDateFormat)
		}
		bodyMap["startTime"] = strconv.Itoa(int(startTime.Unix()))
		bodyMap["endTime"] = strconv.Itoa(int(endTime.Unix()))
	}
	if roundInterval > 0 {
		bodyMap["roundInterval"] = strconv.Itoa(int(roundInterval))
	}
	if period > 0 {
		bodyMap["period"] = strconv.Itoa(int(period))
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return fmt.Errorf("failed to encode request body: %s", err)
	}
	resp, err := post[map[string]string](url, string(body), "", macaroon, tlsCertPath)
	if err != nil {
		return err
	}

	if resp["startTime"] != "" {
		startTime, err := strconv.Atoi(resp["startTime"])
		if err != nil {
			return fmt.Errorf("failed to parse market hour start time: %s", err)
		}
		startDate := time.Unix(int64(startTime), 0)
		resp["startTime"] = startDate.Format(time.RFC3339)
	}
	if resp["endTime"] != "" {
		endTime, err := strconv.Atoi(resp["endTime"])
		if err != nil {
			return fmt.Errorf("failed to parse market hour end time: %s", err)
		}
		endDate := time.Unix(int64(endTime), 0)
		resp["endTime"] = endDate.Format(time.RFC3339)
	}

	respJson, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to json encode round ids: %s", err)
	}
	fmt.Println(string(respJson))
	return nil
}
