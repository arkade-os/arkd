package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

func (s *service) listenToScannerNotifications(ctx context.Context) {
	ch := s.scanner.GetNotificationChannel(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case notifications := <-ch:
				for _, notification := range notifications {
					for _, outpoint := range notification {
						go func() {
							defer func() {
								if r := recover(); r != nil {
									log.WithError(fmt.Errorf("panic: %v", r)).Error("panic while processing notification")
								}
							}()
							if err := s.onNotification(ctx, outpoint.Outpoint); err != nil {
								log.WithError(err).Error("error while processing notification")
							}
						}()
					}
				}
			}
		}
	}()
}

func (s *service) onNotification(ctx context.Context, outpoint domain.Outpoint) error {
	// check if the outpoint is a vtxo
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{outpoint})
	if err != nil {
		log.WithError(err).Warn("failed to retrieve vtxos, skipping...")
		return err
	}

	if len(vtxos) > 0 {
		vtxo := vtxos[0]

		// if the vtxo is spent by an ark tx, we need to subscribe to the children scripts
		if len(vtxo.ArkTxid) > 0 {
			go func() {
				offchainTx, err := s.repoManager.OffchainTxs().GetOffchainTx(ctx, vtxo.ArkTxid)
				if err != nil {
					log.WithError(err).Warn("failed to get offchain tx, skipping...")
					return
				}

				arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(offchainTx.ArkTx), true)
				if err != nil {
					log.WithError(err).Warn("failed to parse ark tx, skipping...")
					return
				}

				scripts := make([]string, 0)
				for _, out := range arkPtx.UnsignedTx.TxOut {
					if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
						continue
					}
					if script.IsSubDustScript(out.PkScript) {
						continue
					}
					scripts = append(scripts, hex.EncodeToString(out.PkScript))
				}

				if err := s.wallet.WatchScripts(ctx, scripts); err != nil {
					log.WithError(err).Warn("failed to watch scripts, skipping...")
					return
				}
			}()
		}

		// the vtxo is onchain, we need to update DB and sweeper state
		if err := s.onVtxoOnchain(ctx, vtxo); err != nil {
			return err
		}

		return nil
	}

	// if no vtxo found, it's a batch outpoint, we want to subscribe to the children scripts

	// we don't want to subscribe several times for the same batch outpoint
	// handling the treeTxid:0 is enough
	if outpoint.VOut > 0 {
		return nil
	}

	txs, err := s.repoManager.Rounds().GetChildrenTxs(ctx, outpoint.Txid)
	if err != nil {
		return err
	}
	if len(txs) == 0 {
		return fmt.Errorf("no children txs found for batch outpoint %s", outpoint.String())
	}

	scripts := make([]string, 0)
	for _, tx := range txs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		if err != nil {
			return fmt.Errorf("failed to parse tx: %s", err)
		}
		for _, out := range ptx.UnsignedTx.TxOut {
			if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
				continue
			}
			scripts = append(scripts, hex.EncodeToString(out.PkScript))
		}
	}

	if err := s.wallet.WatchScripts(ctx, scripts); err != nil {
		return fmt.Errorf("failed to watch scripts: %s", err)
	}

	return nil
}

func (s *service) onVtxoOnchain(ctx context.Context, vtxo domain.Vtxo) error {
	if vtxo.Preconfirmed {
		go func() {
			txs, err := s.repoManager.Rounds().GetTxsWithTxids(ctx, []string{vtxo.Txid})
			if err != nil {
				log.WithError(err).Warn("failed to get txs, skipping...")
				return
			}
			if len(txs) == 0 {
				log.Warn("tx not found, skipping...")
				return
			}

			ptx, err := psbt.NewFromRawBytes(strings.NewReader(txs[0]), true)
			if err != nil {
				log.WithError(err).Warn("failed to parse tx, skipping...")
				return
			}

			// remove sweeper task for the associated checkpoint outputs
			for _, in := range ptx.UnsignedTx.TxIn {
				taskId := in.PreviousOutPoint.Hash.String()
				s.sweeper.removeTask(taskId)
				log.Debugf("sweeper: unscheduled task for tx %s", taskId)
			}
		}()
	}

	if !vtxo.Unrolled {
		go func() {
			if err := s.repoManager.Vtxos().UnrollVtxos(
				ctx, []domain.Outpoint{vtxo.Outpoint},
			); err != nil {
				log.WithError(err).Warnf(
					"failed to mark vtxo %s as unrolled", vtxo.Outpoint.String(),
				)
			}

			log.Debugf("vtxo %s unrolled", vtxo.Outpoint.String())
		}()
	}

	if vtxo.Spent {
		log.Infof("fraud detected on vtxo %s", vtxo.Outpoint.String())
		go func() {
			if err := s.reactToFraud(ctx, vtxo); err != nil {
				log.WithError(err).Warnf(
					"failed to react to fraud for vtxo %s", vtxo.Outpoint.String(),
				)
			}
		}()
	}

	return nil
}
