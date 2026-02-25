package application

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/shopspring/decimal"
	log "github.com/sirupsen/logrus"
)

func (s *service) sendBatchAlert(
	ctx context.Context, round *domain.Round, commitmentTx *psbt.Packet,
) {
	batchStats := s.getBatchStats(ctx, round, commitmentTx)
	s.publishAlert(ports.BatchFinalized, batchStats)
}

func (s *service) publishAlert(topic ports.Topic, message ports.BatchFinalizedAlert) {
	if s.alerts == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.alerts.Publish(ctx, topic, message); err != nil {
		log.WithError(err).WithField("topic", topic).Warn("failed to publish alert")
	}
}

func (s *service) getBatchStats(
	ctx context.Context, round *domain.Round, ptx *psbt.Packet,
) (a ports.BatchFinalizedAlert) {
	createdAt := "N/A"
	endedAt := "N/A"
	duration := "N/A"
	if round.StartingTimestamp > 0 {
		createdAt = time.Unix(round.StartingTimestamp, 0).Format(time.RFC3339)
	}
	if round.EndingTimestamp > 0 {
		endedAt = time.Unix(round.EndingTimestamp, 0).Format(time.RFC3339)
	}
	if createdAt != "N/A" && endedAt != "N/A" {
		duration = time.Unix(round.EndingTimestamp, 0).Sub(
			time.Unix(round.StartingTimestamp, 0),
		).String()
	}
	totalIn := uint64(0)
	for _, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			continue
		}

		inputValue := uint64(input.WitnessUtxo.Value)
		totalIn += inputValue

		if len(input.TaprootLeafScript) > 0 {
			a.BoardingInputCount++
			a.BoardingInputAmount += inputValue
		} else {
			a.LiquidityProviderInputAmount += inputValue
		}
	}

	totalOut := uint64(0)
	for _, output := range ptx.UnsignedTx.TxOut {
		totalOut += uint64(output.Value)
	}
	if totalIn > totalOut {
		a.OnchainFees = totalIn - totalOut
	}

	a.CollectedFees = calculateCollectedFees(round, a.BoardingInputAmount)
	for _, intent := range round.Intents {
		a.ForfeitCount += len(intent.Inputs)
		a.ForfeitAmount += intent.TotalInputAmount()
		for _, receiver := range intent.Receivers {
			if receiver.IsOnchain() {
				a.ExitAmount += receiver.Amount
				a.ExitCount++
			} else {
				a.LeafCount++
				a.LeafAmount += receiver.Amount
			}
		}
	}

	a.ConnectorsCount = a.ForfeitCount
	a.ConnectorsAmount = uint64(a.ForfeitCount * 330)

	confirmedBalance, unconfirmedBalance, _ := s.wallet.MainAccountBalance(ctx)
	liquidityCost := "N/A"
	outAmount := a.LeafAmount + a.ExitAmount + a.ConnectorsAmount + a.OnchainFees
	if confirmedBalance > 0 || unconfirmedBalance > 0 {
		totLiquidity := decimal.NewFromInt(int64(confirmedBalance + unconfirmedBalance))
		totBatchAmount := decimal.NewFromInt(
			int64(a.LeafAmount + a.ExitAmount - a.BoardingInputAmount),
		)
		cost := totBatchAmount.Div(totLiquidity).Mul(decimal.NewFromInt(100)).StringFixed(2)
		liquidityCost = fmt.Sprintf("%s%%", cost)
		if cost != "0.00" {
			liquidityCost = fmt.Sprintf("-%s", liquidityCost)
		}

		a.LiquidityProviderConfirmedBalance = confirmedBalance
		a.LiquidityProviderUnconfirmedBalance = unconfirmedBalance
	}
	a.LiquidityProvided = outAmount - a.BoardingInputAmount
	a.LiquidityCost = liquidityCost
	a.Id = round.Id
	a.CommitmentTxid = round.CommitmentTxid
	a.Duration = duration
	a.IntentsCount = len(round.Intents)
	return
}

func calculateCollectedFees(round *domain.Round, boardingInputAmount uint64) uint64 {
	collectedFees := uint64(0)
	for _, intent := range round.Intents {
		collectedFees += intent.TotalInputAmount() + boardingInputAmount - intent.TotalOutputAmount()
	}
	return collectedFees
}

func calculateBoardingInputAmount(ptx *psbt.Packet) uint64 {
	boardingInputAmount := uint64(0)
	for _, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			continue
		}
		if len(input.TaprootLeafScript) > 0 {
			boardingInputAmount += uint64(input.WitnessUtxo.Value)
		}
	}
	return boardingInputAmount
}
