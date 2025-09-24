package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type CrimeType uint8

const (
	CrimeTypeUnknown CrimeType = iota
	CrimeTypeMusig2NonceSubmission
	CrimeTypeMusig2SignatureSubmission
	CrimeTypeMusig2InvalidSignature
	CrimeTypeForfeitSubmission
	CrimeTypeForfeitInvalidSignature
	CrimeTypeBoardingInputSubmission
	CrimeTypeManualBan
)

func (c CrimeType) String() string {
	return []string{
		"Unknown",
		"Musig2NonceSubmission",
		"Musig2SignatureSubmission",
		"Musig2InvalidSignature",
		"ForfeitSubmission",
		"ForfeitInvalidSignature",
		"BoardingInputSubmission",
		"ManualBan",
	}[c]
}

type Crime struct {
	Type    CrimeType
	RoundID string
	Reason  string
}

type ConvictionType uint8

const (
	ConvictionTypeScript ConvictionType = iota
)

type Conviction interface {
	GetType() ConvictionType
	GetID() string
	GetCreatedAt() time.Time
	GetExpiresAt() *time.Time
	GetCrime() Crime
	String() string
	IsPardoned() bool
}

type BaseConviction struct {
	ID        string
	Type      ConvictionType
	CreatedAt time.Time
	ExpiresAt *time.Time
	Crime     Crime
	Pardoned  bool
}

func (b BaseConviction) GetID() string {
	return b.ID
}

func (b BaseConviction) GetCreatedAt() time.Time {
	return b.CreatedAt
}

func (b BaseConviction) GetExpiresAt() *time.Time {
	return b.ExpiresAt
}

func (b BaseConviction) GetCrime() Crime {
	return b.Crime
}

func (b BaseConviction) GetType() ConvictionType {
	return b.Type
}

func (b BaseConviction) IsPardoned() bool {
	return b.Pardoned
}

// ScriptConviction bans all vtxos with the given script
type ScriptConviction struct {
	BaseConviction
	Script string
}

func (s ScriptConviction) String() string {
	if s.ExpiresAt == nil {
		return fmt.Sprintf(
			"VtxoScript %x banned forever, type: %s, reason: %s",
			s.Script,
			s.Crime.Type,
			s.Crime.Reason,
		)
	}
	return fmt.Sprintf(
		"VtxoScript %x banned until %s, type: %s, reason: %s",
		s.Script,
		s.ExpiresAt.Format(time.RFC3339),
		s.Crime.Type,
		s.Crime.Reason,
	)
}

func newBaseConviction(crime Crime, banDuration *time.Duration) BaseConviction {
	id := uuid.New().String()
	createdAt := time.Now()
	var expiresAt *time.Time
	if banDuration != nil {
		expireTimestamp := createdAt.Add(*banDuration)
		expiresAt = &expireTimestamp
	}
	return BaseConviction{
		ID:        id,
		Type:      ConvictionTypeScript,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
		Crime:     crime,
		Pardoned:  false,
	}
}

func NewScriptConviction(script string, crime Crime, banDuration *time.Duration) Conviction {
	return ScriptConviction{
		BaseConviction: newBaseConviction(crime, banDuration),
		Script:         script,
	}
}
