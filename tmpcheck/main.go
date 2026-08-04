// Verifies that the WitnessUtxo of the vtxo input of every forfeit PSBT matches
// the real prevout, fetched from the arkade.computer indexer.
//
// The vtxo input is not always input 0: arkd accepts either input order (see
// vtxoFirst in internal/infrastructure/tx-builder/covenantless/builder.go). The
// vtxo is spent via script path so it carries a TaprootLeafScript; the connector
// is a key-path spend and carries none.
//
// Usage: go run ./tmpcheck <query.json>
//
// ponytail: throwaway one-off checker, delete after use.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

const baseURL = "https://arkade.computer/v1/indexer"

const batchSize = 50

type row struct {
	RoundID     string `json:"round_id"`
	Txid        string `json:"txid"`
	ForfeitPsbt string `json:"forfeit_psbt"`
}

// prevout is what the indexer says the vtxo output really is.
type prevout struct {
	value    int64
	pkScript string
}

func getJSON(url string, out any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// fetchVtxos resolves outpoints ("txid:vout") via the vtxos endpoint.
func fetchVtxos(outpoints []string) (map[string]prevout, error) {
	var body struct {
		Vtxos []struct {
			Outpoint struct {
				Txid string `json:"txid"`
				Vout uint32 `json:"vout"`
			} `json:"outpoint"`
			Amount string `json:"amount"`
			Script string `json:"script"`
		} `json:"vtxos"`
	}
	if err := getJSON(baseURL+"/vtxos?outpoints="+strings.Join(outpoints, "&outpoints="), &body); err != nil {
		return nil, err
	}
	out := make(map[string]prevout, len(body.Vtxos))
	for _, v := range body.Vtxos {
		amount, err := strconv.ParseInt(v.Amount, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad amount %q: %w", v.Amount, err)
		}
		out[fmt.Sprintf("%s:%d", v.Outpoint.Txid, v.Outpoint.Vout)] = prevout{amount, v.Script}
	}
	return out, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./tmpcheck <query.json>")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var rows []row
	if err := json.NewDecoder(f).Decode(&rows); err != nil {
		panic(err)
	}

	// vtxo outpoint -> the WitnessUtxo(s) forfeit txs claim for it
	type claim struct {
		row      row
		index    int
		value    int64
		pkScript string
	}
	claims := make(map[string][]claim)
	order := make([]string, 0, len(rows))
	bad := 0
	vtxoFirst := 0

	for _, r := range rows {
		p, err := psbt.NewFromRawBytes(strings.NewReader(r.ForfeitPsbt), true)
		if err != nil {
			fmt.Printf("DECODE_ERR %s %s: %v\n", r.RoundID, r.Txid, err)
			bad++
			continue
		}

		// the vtxo input is the script-path one
		idx := -1
		for i, in := range p.Inputs {
			if len(in.TaprootLeafScript) > 0 {
				if idx >= 0 {
					idx = -2
					break
				}
				idx = i
			}
		}
		if idx < 0 {
			fmt.Printf("AMBIGUOUS %s %s: %d inputs, cannot single out the vtxo input\n",
				r.RoundID, r.Txid, len(p.Inputs))
			bad++
			continue
		}
		if idx == 0 {
			vtxoFirst++
		}
		if p.Inputs[idx].WitnessUtxo == nil {
			fmt.Printf("NO_WITNESS_UTXO %s %s: input %d\n", r.RoundID, r.Txid, idx)
			bad++
			continue
		}

		op := p.UnsignedTx.TxIn[idx].PreviousOutPoint.String()
		if _, seen := claims[op]; !seen {
			order = append(order, op)
		}
		claims[op] = append(claims[op], claim{
			row:      r,
			index:    idx,
			value:    p.Inputs[idx].WitnessUtxo.Value,
			pkScript: hex.EncodeToString(p.Inputs[idx].WitnessUtxo.PkScript),
		})
	}
	fmt.Printf("vtxo input position: %d at index 0, %d at another index\n",
		vtxoFirst, len(rows)-vtxoFirst-bad)

	checked := 0
	for i := 0; i < len(order); i += batchSize {
		batch := order[i:min(i+batchSize, len(order))]

		prevouts, err := fetchVtxos(batch)
		if err != nil {
			fmt.Printf("FETCH_ERR vtxos %v: %v\n", batch, err)
			bad++
			continue
		}

		for _, op := range batch {
			want, ok := prevouts[op]
			if !ok {
				fmt.Printf("NOT_FOUND vtxo %s (forfeit %s)\n", op, claims[op][0].row.Txid)
				bad++
				continue
			}
			for _, c := range claims[op] {
				checked++
				if c.value != want.value {
					fmt.Printf("MISMATCH amount %s %s input%d=%s: psbt=%d chain=%d\n",
						c.row.RoundID, c.row.Txid, c.index, op, c.value, want.value)
					bad++
				}
				if !strings.EqualFold(c.pkScript, want.pkScript) {
					fmt.Printf("MISMATCH script %s %s input%d=%s: psbt=%s chain=%s\n",
						c.row.RoundID, c.row.Txid, c.index, op, c.pkScript, want.pkScript)
					bad++
				}
			}
		}
		fmt.Fprintf(os.Stderr, "\r%d/%d outpoints", min(i+batchSize, len(order)), len(order))
	}

	fmt.Printf("\nverified %d forfeit txs over %d distinct vtxos, %d problems\n",
		checked, len(order), bad)
}
