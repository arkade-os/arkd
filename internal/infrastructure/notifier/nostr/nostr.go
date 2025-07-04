package nostr_notifier

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/sirupsen/logrus"
)

type nostrNotifier struct{}

func New() ports.Notifier {
	return &nostrNotifier{}
}

// Notify expects nprofile as recipient, it encrypts the message using NIP-04
func (n *nostrNotifier) Notify(ctx context.Context, to any, message string) error {
	recipientProfile, ok := to.(string)
	if !ok {
		return fmt.Errorf("recipient must be a string (NIP-19 encoded nostr profile)")
	}

	prefix, result, err := nip19.Decode(recipientProfile)
	if err != nil {
		return fmt.Errorf("failed to decode NIP-19 string: %w", err)
	}

	if prefix != "nprofile" {
		return fmt.Errorf("invalid NIP-19 prefix: %s", prefix)
	}

	recipient, ok := result.(nostr.ProfilePointer)
	if !ok {
		return fmt.Errorf("invalid NIP-19 result: %v", result)
	}

	// validate public key
	if !nostr.IsValidPublicKey(recipient.PublicKey) {
		return fmt.Errorf("invalid nostr public key: %s", recipient.PublicKey)
	}

	// validate relays
	if len(recipient.Relays) == 0 {
		return fmt.Errorf("invalid nostr profile: at least one relay is required")
	}

	for _, relay := range recipient.Relays {
		if !nostr.IsValidRelayURL(relay) {
			return fmt.Errorf("invalid relay URL: %s", relay)
		}
	}

	// Generate ephemeral keypair for this notification
	ephemeralSec := nostr.GeneratePrivateKey()
	ephemeralPub, err := nostr.GetPublicKey(ephemeralSec)
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// encrypt message
	sharedSecret, err := nip04.ComputeSharedSecret(recipient.PublicKey, ephemeralSec)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encryptedMsg, err := nip04.Encrypt(message, sharedSecret)
	if err != nil {
		return fmt.Errorf(
			"failed to encrypt message for recipient %s: %w", recipient.PublicKey, err,
		)
	}

	// create NIP-04 event
	ev := &nostr.Event{
		PubKey:    ephemeralPub,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      nostr.KindEncryptedDirectMessage,
		Tags:      nostr.Tags{{"p", recipient.PublicKey}},
		Content:   encryptedMsg,
	}

	// sign event
	err = ev.Sign(ephemeralSec)
	if err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}

	// Connect to relays and publish
	var wg sync.WaitGroup
	atLeastOneSuccess := atomic.Bool{}

	for _, url := range recipient.Relays {
		wg.Add(1)
		go func(relayURL string) {
			defer wg.Done()

			relay, err := nostr.RelayConnect(ctx, relayURL)
			if err != nil {
				logrus.WithError(err).Warnf("failed to connect to relay %s", relayURL)
				return
			}
			// nolint:all
			defer relay.Close()

			err = relay.Publish(ctx, *ev)
			if err != nil {
				logrus.WithError(err).Warnf("failed to publish to relay %s", relayURL)
				return
			}

			atLeastOneSuccess.Store(true)
		}(url)
	}

	wg.Wait()

	if !atLeastOneSuccess.Load() {
		return fmt.Errorf("failed to publish to any relay")
	}

	return nil
}
