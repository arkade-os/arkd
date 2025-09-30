package domain

import "time"

type ConvictionRepository interface {
	Get(id string) (Conviction, error)
	GetAll(from, to time.Time) ([]Conviction, error)
	GetByRoundID(roundID string) ([]Conviction, error)
	// GetActiveScriptConviction returns all not-expired convictions associated with a given script
	GetActiveScriptConvictions(script string) ([]ScriptConviction, error)
	Add(...Conviction) error
	Pardon(id string) error
	Close()
}
