package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type withOutputScript interface {
	OutputScript() ([]byte, error)
}

// banCandidate is an input of a request and what its ban script is read from.
type banCandidate struct {
	outpoint domain.Outpoint
	script   withOutputScript
}

// scriptBan is a banned script with the inputs of the request it covers and the
// convictions that ban it.
type scriptBan struct {
	script      string
	outpoints   []string
	convictions []string
}

// checkIfBanned returns every banned script of a request, in the order the
// scripts first appear, so the first outpoint of the first ban is the first
// banned input. A script is banned once it carries at least banThreshold active
// convictions, or as soon as it carries a manual one. It reads all scripts in
// one query, and each script once however many inputs resolve to it.
func (s *service) checkIfBanned(
	ctx context.Context, banThreshold uint64, candidates []banCandidate,
) ([]scriptBan, error) {
	// If ban threshold is 0, we disable banning
	if banThreshold == 0 {
		return nil, nil
	}

	scripts := make([]string, 0, len(candidates))
	outpointsByScript := make(map[string][]string, len(candidates))
	for _, candidate := range candidates {
		scriptBytes, err := candidate.script.OutputScript()
		if err != nil {
			return nil, fmt.Errorf("failed to get output script: %w", err)
		}
		hexScript := hex.EncodeToString(scriptBytes)
		if _, seen := outpointsByScript[hexScript]; !seen {
			scripts = append(scripts, hexScript)
		}
		outpointsByScript[hexScript] = append(
			outpointsByScript[hexScript], candidate.outpoint.String(),
		)
	}

	allConvictions, err := s.repoManager.Convictions().GetActiveScriptsConvictions(ctx, scripts)
	if err != nil {
		return nil, err
	}
	banned := make([]scriptBan, 0)
	for _, script := range scripts {
		convictions := allConvictions[script]
		if !hasManualBan(convictions) && uint64(len(convictions)) < banThreshold {
			continue
		}

		formattedConvictions := make([]string, 0, len(convictions))
		for _, conviction := range convictions {
			formattedConvictions = append(formattedConvictions, conviction.String())
		}
		banned = append(banned, scriptBan{
			script:      script,
			outpoints:   outpointsByScript[script],
			convictions: formattedConvictions,
		})
	}
	if len(banned) == 0 {
		return nil, nil
	}

	return banned, nil
}

func (s *service) banCosignerInputs(
	ctx context.Context,
	banDuration *time.Duration, toBan map[string]domain.Crime, intents []ports.TimedIntent,
) {
	convictions := make([]domain.Conviction, 0)

	for cosignerPublicKey, crime := range toBan {
		for _, intent := range intents {
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
					domain.NewScriptConviction(script, crime, banDuration),
				)
			}
		}
	}

	if len(convictions) > 0 {
		if err := s.repoManager.Convictions().Add(ctx, convictions...); err != nil {
			log.WithError(err).Warn("failed to ban")
		}
		log.Debugf("banned %d scripts for %s", len(convictions), banDuration)
	}
}

func (s *service) banNoncesCollectionTimeout(
	ctx context.Context, roundId string, banDuration *time.Duration,
	signingSession *ports.MusigSigningSession, registeredIntents []ports.TimedIntent,
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

	s.banCosignerInputs(ctx, banDuration, toBan, registeredIntents)
}

func (s *service) banSignaturesCollectionTimeout(
	ctx context.Context, roundId string, banDuration *time.Duration,
	signingSession *ports.MusigSigningSession, registeredIntents []ports.TimedIntent,
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

	s.banCosignerInputs(ctx, banDuration, toBan, registeredIntents)
}

func (s *service) banForfeitCollectionTimeout(
	ctx context.Context, roundId string, banDuration *time.Duration,
	unsignedVtxoKeys []domain.Outpoint,
) {
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
		}, banDuration))
	}

	if err := s.repoManager.Convictions().Add(ctx, convictions...); err != nil {
		log.WithError(err).Warn("failed to ban vtxos")
	}
}

// hasManualBan reports whether an operator banned the script through the
// BanScript admin RPC. banThreshold asks for an offence to repeat before a
// script is punished for it, which an operator ban has no reason to wait for,
// so one is enough on its own.
func hasManualBan(convictions []domain.ScriptConviction) bool {
	for _, conviction := range convictions {
		if conviction.GetCrime().Type == domain.CrimeTypeManualBan {
			return true
		}
	}
	return false
}

func vtxoBannedError(bans []scriptBan) errors.Error {
	scripts := make([]string, 0, len(bans))
	outpoints := make([]string, 0, len(bans))
	reasons := make([]string, 0, len(bans))
	for _, ban := range bans {
		scripts = append(scripts, ban.script)
		outpoints = append(outpoints, ban.outpoints...)
		reasons = append(reasons, fmt.Sprintf(
			"script %s is banned by %d convictions: %s",
			ban.script, len(ban.convictions), strings.Join(ban.convictions, ", "),
		))
	}
	return errors.VTXO_BANNED.New("%s", strings.Join(reasons, "; ")).
		WithMetadata(errors.VtxoBannedMetadata{VtxoOutpoints: outpoints, Scripts: scripts})
}
