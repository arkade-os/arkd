package application

// THROWAWAY: arkd-side startup measurement. Plan:
//   /home/bob/.claude/plans/theres-likely-improvmeents-in-abstract-hummingbird.md
// Remove this file (and references) once we've decided which optimizations to
// ship.

import (
	"time"

	log "github.com/sirupsen/logrus"
)

const startupProfileLogPrefix = "[startup-profile]"

var startupProfileT0 = time.Now()

func startupProfilePhase(label string) {
	log.Infof("%s arkd phase=%s t+%s", startupProfileLogPrefix, label, time.Since(startupProfileT0))
}
