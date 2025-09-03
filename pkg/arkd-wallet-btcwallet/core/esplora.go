package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/wire"
)

type esploraClient struct {
	url string
}

type esploraTx struct {
	Status struct {
		Confirmed   bool  `json:"confirmed"`
		BlockTime   int64 `json:"block_time"`
		BlockNumber int64 `json:"block_height"`
	} `json:"status"`
}

func (f *esploraClient) broadcast(txs ...string) error {
	if len(txs) == 1 {
		endpoint, err := url.JoinPath(f.url, "tx")
		if err != nil {
			return err
		}

		resp, err := http.Post(endpoint, "text/plain", strings.NewReader(txs[0]))
		if err != nil {
			return err
		}

		// nolint:all
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			content, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			if strings.Contains(strings.ToLower(string(content)), "non-bip68-final") {
				return ErrNonFinalBIP68
			}

			return fmt.Errorf("failed to broadcast transaction: %s (%s, %s)", txs[0], resp.Status, content)
		}

		return nil
	}

	endpoint, err := url.JoinPath(f.url, "txs", "package")
	if err != nil {
		return err
	}

	body := bytes.NewBuffer(nil)
	if err := json.NewEncoder(body).Encode(txs); err != nil {
		return err
	}

	resp, err := http.Post(endpoint, "application/json", body)
	if err != nil {
		return err
	}

	// nolint:all
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to broadcast package: %s", resp.Status)
	}

	return nil
}

func (f *esploraClient) getTx(txid string) (*wire.MsgTx, error) {
	endpoint, err := url.JoinPath(f.url, "tx", txid, "raw")
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return nil, err
	}
	// nolint:all
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("tx endpoint HTTP error: " + resp.Status)
	}

	var tx wire.MsgTx

	if err := tx.Deserialize(resp.Body); err != nil {
		return nil, err
	}

	return &tx, nil
}

func (f *esploraClient) getTxStatus(txid string) (isConfirmed bool, blocknumber, blocktime int64, err error) {
	endpoint, err := url.JoinPath(f.url, "tx", txid)
	if err != nil {
		return false, 0, 0, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return false, 0, 0, err
	}

	// nolint:all
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, 0, err
	}

	var response esploraTx

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false, 0, 0, err
	}

	return response.Status.Confirmed, response.Status.BlockNumber, response.Status.BlockTime, nil
}

// GetFeeMap returns a map of sat/vbyte fees for different confirmation targets
// it implements the chainfee.WebAPIFeeSource interface
func (f *esploraClient) GetFeeMap() (map[uint32]uint32, error) {
	endpoint, err := url.JoinPath(f.url, "fee-estimates")
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return nil, err
	}
	// nolint:all
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("fee-estimates endpoint HTTP error: " + resp.Status)
	}

	response := make(map[string]float64)

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	if len(response) == 0 {
		response = map[string]float64{"1": 2.0}
	}

	mapResponse := make(map[uint32]uint32)
	for k, v := range response {
		key, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}

		mapResponse[uint32(key)] = uint32(v * 1000)
	}

	return mapResponse, nil
}

// /tx/:txid/outspends
func (f *esploraClient) IsSpent(outpoint wire.OutPoint) (spent bool, err error) {
	endpoint, err := url.JoinPath(f.url, "tx", outpoint.Hash.String(), "outspends")
	if err != nil {
		return false, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return false, err
	}

	// nolint:all
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("outspends endpoint HTTP error: " + resp.Status)
	}

	type spentStatusResponse struct {
		Spent bool `json:"spent"`
	}

	response := make([]spentStatusResponse, 0)

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false, err
	}

	if len(response) < int(outpoint.Index) {
		return false, errors.New("outpoint index out of range")
	}

	return response[outpoint.Index].Spent, nil
}
