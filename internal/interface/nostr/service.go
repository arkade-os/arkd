package nostr

import (
	"github.com/arkade-os/arkd/internal/config"
	log "github.com/sirupsen/logrus"
)

// Service runs the optional Nostr transport: it uses the server's Identity to
// communicate with clients over the configured Nostr relays.
//
// NOTE: relay connectivity and message handling are still a work in progress.
// For now Start/Stop only manage lifecycle so the server can boot with the
// transport enabled.
type Service struct {
	identity *Identity
	relays   []string
	cfg      *config.Config
}

// NewService builds the Nostr transport service.
func NewService(identity *Identity, relays []string, cfg *config.Config) *Service {
	return &Service{
		identity: identity,
		relays:   relays,
		cfg:      cfg,
	}
}

// Start brings up the Nostr transport.
func (s *Service) Start() error {
	log.Infof(
		"nostr transport: starting (pubkey=%s, relays=%v)",
		s.identity.PubKeyHex(), s.relays,
	)
	return nil
}

// Stop tears down the Nostr transport.
func (s *Service) Stop() {
	log.Info("nostr transport: stopping")
}
