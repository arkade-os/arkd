package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

type withOutputScript interface {
	OutputScript() ([]byte, error)
}

func (s *service) checkIfBanned(ctx context.Context, script withOutputScript) error {
	// if ban threshold is less than 1, we disable banning
	if s.banThreshold <= 0 {
		return nil
	}
	scriptBytes, err := script.OutputScript()
	if err != nil {
		return err
	}
	conviction, err := s.repoManager.Convictions().
		GetActiveScriptConvictions(ctx, hex.EncodeToString(scriptBytes))
	if err != nil {
		return err
	}
	if int64(len(conviction)) >= s.banThreshold {
		convictionsStr := make([]string, 0)
		for _, conviction := range conviction {
			convictionsStr = append(convictionsStr, conviction.String())
		}
		return fmt.Errorf(
			"script %s is banned by %d convictions: %s",
			script,
			len(conviction),
			strings.Join(convictionsStr, ", "),
		)
	}

	return nil
}

func (s *service) banCosignerInputs(
	ctx context.Context,
	toBan map[string]domain.Crime,
	registeredIntents []ports.TimedIntent,
) {
	convictions := make([]domain.Conviction, 0)

	for cosignerPublicKey, crime := range toBan {
		for _, intent := range registeredIntents {
			if !slices.Contains(intent.CosignersPublicKeys, cosignerPublicKey) {
				// intent is not associated with the cosigner, skip
				continue
			}

			// get unique scripts from intent
			uniqueScripts := make(map[string]struct{})
			for _, boardingInput := range intent.BoardingInputs {
				pkscript, err := boardingInput.OutputScript()
				if err != nil {
					log.WithError(err).Warnf(
						"banning: failed to get output script for boarding input %s",
						boardingInput.String(),
					)
					continue
				}

				uniqueScripts[hex.EncodeToString(pkscript)] = struct{}{}
			}
			for _, input := range intent.Inputs {
				pkscript, err := input.OutputScript()
				if err != nil {
					log.WithError(err).Warnf(
						"banning: failed to get output script for input %s",
						input.Outpoint.String(),
					)
					continue
				}
				uniqueScripts[hex.EncodeToString(pkscript)] = struct{}{}
			}

			for script := range uniqueScripts {
				convictions = append(
					convictions,
					domain.NewScriptConviction(script, crime, &s.banDuration),
				)
			}
		}
	}

	if len(convictions) > 0 {
		if err := s.repoManager.Convictions().Add(ctx, convictions...); err != nil {
			log.WithError(err).Warn("failed to ban")
		}
		log.Debugf("banned %d script for %s", len(convictions), s.banDuration)
	}
}

func (s *service) banNoncesCollectionTimeout(
	ctx context.Context,
	roundId string,
	signingSession *ports.MusigSigningSession,
	registeredIntents []ports.TimedIntent,
) {
	toBan := make(map[string]domain.Crime)

	for cosignerPublicKey := range signingSession.Cosigners {
		if _, ok := signingSession.Nonces[cosignerPublicKey]; !ok {
			// cosigner didn't submit their nonce, ban their inputs
			toBan[cosignerPublicKey] = domain.Crime{
				Type:    domain.CrimeTypeMusig2NonceSubmission,
				RoundID: roundId,
				Reason:  fmt.Sprintf("missing musig2 nonce for cosigner %s", cosignerPublicKey),
			}
		}
	}

	s.banCosignerInputs(ctx, toBan, registeredIntents)
}

func (s *service) banSignaturesCollectionTimeout(
	ctx context.Context,
	roundId string,
	signingSession *ports.MusigSigningSession,
	registeredIntents []ports.TimedIntent,
) {
	toBan := make(map[string]domain.Crime)

	for cosignerPublicKey := range signingSession.Cosigners {
		if _, ok := signingSession.Signatures[cosignerPublicKey]; !ok {
			// cosigner didn't submit their signature, ban their inputs
			toBan[cosignerPublicKey] = domain.Crime{
				Type:    domain.CrimeTypeMusig2SignatureSubmission,
				RoundID: roundId,
				Reason:  fmt.Sprintf("missing musig2 signature for cosigner %s", cosignerPublicKey),
			}
		}
	}

	s.banCosignerInputs(ctx, toBan, registeredIntents)
}

func (s *service) banForfeitCollectionTimeout(
	ctx context.Context,
	roundId string,
) {
	unsignedVtxoKeys := s.cache.ForfeitTxs().GetUnsignedInputs()
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, unsignedVtxoKeys)
	if err != nil {
		log.WithError(err).Warn("failed to get vtxos")
		return
	}

	uniqueScripts := make(map[string]struct{})
	for _, vtxo := range vtxos {
		outputScript, err := vtxo.OutputScript()
		if err != nil {
			log.WithError(err).
				Warnf("failed to compute output script for vtxo %s", vtxo.Outpoint)
			continue
		}
		uniqueScripts[hex.EncodeToString(outputScript)] = struct{}{}
	}

	convictions := make([]domain.Conviction, 0)
	for script := range uniqueScripts {
		convictions = append(convictions, domain.NewScriptConviction(script, domain.Crime{
			Type:    domain.CrimeTypeForfeitSubmission,
			RoundID: roundId,
			Reason:  "missing forfeit signature",
		}, &s.banDuration))
	}

	if err := s.repoManager.Convictions().Add(ctx, convictions...); err != nil {
		log.WithError(err).Warn("failed to ban vtxos")
	}
}

func (s *service) banDoubleSpendAttempt(
	ctx context.Context,
	vtxo domain.Vtxo,
) {
	outputScript, err := vtxo.OutputScript()
	if err != nil {
		log.WithError(err).Warnf("failed to get output script for vtxo %s", vtxo.Outpoint)
		return
	}

	convictions := make([]domain.Conviction, 0)
	convictions = append(convictions, domain.NewScriptConviction(
		hex.EncodeToString(outputScript),
		domain.Crime{
			Type:   domain.CrimeTypeDoubleSpend,
			Reason: "double spend attempt",
		}, &s.banDuration))

	if err := s.repoManager.Convictions().Add(ctx, convictions...); err != nil {
		log.WithError(err).Warn("failed to ban double spend attempt")
	}
}
