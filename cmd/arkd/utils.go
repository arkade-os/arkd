package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
	"gopkg.in/macaroon.v2"
)

type accountBalance struct {
	Available string `json:"available"`
	Locked    string `json:"locked"`
}

func (b accountBalance) String() string {
	return fmt.Sprintf("   available: %s\n   locked: %s", b.Available, b.Locked)
}

type balance struct {
	MainAccount       accountBalance `json:"mainAccount"`
	ConnectorsAccount accountBalance `json:"connectorsAccount"`
}

func (b balance) String() string {
	return fmt.Sprintf(
		"main account\n%s\nconnectors account\n%s",
		b.MainAccount, b.ConnectorsAccount,
	)
}

func getBalance(url, macaroon, tlsCert string) (*balance, error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	if len(macaroon) > 0 {
		req.Header.Add("X-Macaroon", macaroon)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// nolint
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s", buf)
		return nil, err
	}

	result := &balance{}
	if err := json.Unmarshal(buf, result); err != nil {
		return nil, err
	}
	return result, nil
}

type status struct {
	Initialized bool `json:"initialized"`
	Unlocked    bool `json:"unlocked"`
	Synced      bool `json:"synced"`
}

func (s status) String() string {
	return fmt.Sprintf(
		"initialized: %t\nunlocked: %t\nsynced: %t",
		s.Initialized, s.Unlocked, s.Synced,
	)
}

func getStatus(url, tlsCert string) (*status, error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// nolint
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to get status: %s", string(buf))
		return nil, err
	}

	result := &status{}
	if err := json.Unmarshal(buf, result); err != nil {
		return nil, err
	}
	return result, nil
}

type roundInfo struct {
	Id               string   `json:"roundId"`
	CommitmentTxid   string   `json:"commitmentTxid"`
	ForfeitedAmount  string   `json:"forfeitedAmount"`
	TotalVtxosAmount string   `json:"totalVtxosAmount"`
	TotalExitAmount  string   `json:"totalExitAmount"`
	TotalFeeAmount   string   `json:"totalFeeAmount"`
	InputVtxos       []string `json:"inputsVtxos"`
	OutputVtxos      []string `json:"outputsVtxos"`
	ExitAddresses    []string `json:"exitAddresses"`
	StartedAt        string   `json:"startedAt"`
	EndedAt          string   `json:"endedAt"`
}

func getRoundInfo(url, macaroon, tlsCert string) (*roundInfo, error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	if len(macaroon) > 0 {
		req.Header.Add("X-Macaroon", macaroon)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// nolint
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s", buf)
		return nil, err
	}

	result := &roundInfo{}
	if err := json.Unmarshal(buf, result); err != nil {
		return nil, err
	}
	return result, nil
}

func getCredentialPaths(ctx *cli.Context) (macaroon string, tlsCertPath string, err error) {
	datadir := ctx.String(datadirFlagName)

	macaroonPath := filepath.Join(datadir, macaroonDir, macaroonFile)
	if _, err := os.Stat(macaroonPath); err == nil {
		macaroon, err = getMacaroon(macaroonPath)
		if err != nil {
			return "", "", fmt.Errorf("failed to read macaroon: %w", err)
		}
	}

	tlsCertPath = filepath.Join(datadir, tlsDir, tlsCertFile)
	if strings.Contains(ctx.String(urlFlagName), "http://") {
		tlsCertPath = ""
	}

	return macaroon, tlsCertPath, nil
}

func post[T any](url, body, key, macaroon, tlsCert string) (result T, err error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json")
	if len(macaroon) > 0 {
		req.Header.Add("X-Macaroon", macaroon)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	// nolint
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to post: %s", string(buf))
		return
	}
	if key == "" {
		return
	}
	res := make(map[string]T)
	if err = json.Unmarshal(buf, &res); err != nil {
		return
	}

	result = res[key]
	return
}

func get[T any](url, key, macaroon, tlsCert string) (result T, err error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json")
	if len(macaroon) > 0 {
		req.Header.Add("X-Macaroon", macaroon)
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	// nolint
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to get: %s", string(buf))
		return
	}

	res := make(map[string]T)
	if err = json.Unmarshal(buf, &res); err != nil {
		return
	}

	result = res[key]
	return
}

func getMacaroon(path string) (string, error) {
	macBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read macaroon %s: %s", path, err)
	}
	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return "", fmt.Errorf("failed to parse macaroon %s: %s", path, err)
	}

	return hex.EncodeToString(macBytes), nil
}

func getTLSConfig(path string) (*tls.Config, error) {
	if len(path) <= 0 {
		return nil, nil
	}
	var buf []byte
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(buf); !ok {
		return nil, fmt.Errorf("failed to parse tls cert")
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caCertPool,
	}, nil
}
