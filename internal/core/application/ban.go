package application

import (
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

type withOutputScript interface {
	OutputScript() ([]byte, error)
}

func (s *service) getScriptConviction(script withOutputScript) (domain.Conviction, error) {
	scriptBytes, err := script.OutputScript()
	if err != nil {
		return nil, err
	}
	return s.repoManager.Convictions().GetActiveScriptConviction(hex.EncodeToString(scriptBytes))
}

func (s *service) banCosignerInputs(
	roundId string,
	toBan map[string]domain.Crime,
	registeredIntents []ports.TimedIntent,
) {
	// ban the vtxo associated with the signing session that didn't submit their nonces
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
		if err := s.repoManager.Convictions().Add(convictions...); err != nil {
			log.WithError(err).Warn("failed to ban")
		}
		log.Debugf("banned %d script for %s", len(convictions), s.banDuration)
	}
}

func (s *service) banNoncesCollectionTimeout(
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

	s.banCosignerInputs(roundId, toBan, registeredIntents)
}

func (s *service) banSignaturesCollectionTimeout(
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

	s.banCosignerInputs(roundId, toBan, registeredIntents)
}
