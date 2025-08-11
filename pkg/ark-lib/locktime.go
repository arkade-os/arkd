package arklib

import (
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	SEQUENCE_LOCKTIME_MASK         = 0x0000ffff
	SEQUENCE_LOCKTIME_TYPE_FLAG    = 1 << 22
	SEQUENCE_LOCKTIME_GRANULARITY  = 9
	SECONDS_MOD                    = 1 << SEQUENCE_LOCKTIME_GRANULARITY
	SECONDS_MAX                    = SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY
	SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31

	SECONDS_PER_BLOCK = 10 * 60 // 10 minutes

	// before this value, nLocktime is interpreted as blockheight
	nLocktimeMinSeconds = 500_000_000
)

// RelativeLocktimeType represents a BIP68 relative locktime
// it is passed as argument to CheckSequenceVerify opcode
type RelativeLocktimeType uint

const (
	LocktimeTypeSecond RelativeLocktimeType = iota
	LocktimeTypeBlock
)

// AbsoluteLocktime represents an nLocktime value
// it is used as argument to a CheckLocktimeVerify opcode
type AbsoluteLocktime uint32

func (l AbsoluteLocktime) IsSeconds() bool {
	return l >= nLocktimeMinSeconds
}

// RelativeLocktime represents a BIP68 relative timelock value
type RelativeLocktime struct {
	Type  RelativeLocktimeType
	Value uint32
}

func (l RelativeLocktime) Seconds() int64 {
	if l.Type == LocktimeTypeBlock {
		return int64(l.Value) * SECONDS_PER_BLOCK
	}
	return int64(l.Value)
}

func (l RelativeLocktime) Compare(other RelativeLocktime) int {
	val := l.Seconds()
	otherVal := other.Seconds()

	if val == otherVal {
		return 0
	}
	if val < otherVal {
		return -1
	}
	return 1
}

// LessThan returns true if this locktime is less than the other locktime
func (l RelativeLocktime) LessThan(other RelativeLocktime) bool {
	return l.Compare(other) < 0
}

func BIP68Sequence(locktime RelativeLocktime) (uint32, error) {
	value := locktime.Value
	isSeconds := locktime.Type == LocktimeTypeSecond
	if isSeconds {
		if value > SECONDS_MAX {
			return 0, fmt.Errorf("seconds too large, max is %d", SECONDS_MAX)
		}
		if value%SECONDS_MOD != 0 {
			return 0, fmt.Errorf("seconds must be a multiple of %d", SECONDS_MOD)
		}
	}

	return blockchain.LockTimeToSequence(isSeconds, value), nil
}

func BIP68DecodeSequenceFromBytes(sequence []byte) (*RelativeLocktime, error) {
	scriptNumber, err := txscript.MakeScriptNum(sequence, true, len(sequence))
	if err != nil {
		return nil, err
	}

	if scriptNumber >= txscript.OP_1 && scriptNumber <= txscript.OP_16 {
		scriptNumber = scriptNumber - (txscript.OP_1 - 1)
	}

	asNumber := int64(scriptNumber)

	if asNumber&SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
		return nil, fmt.Errorf("sequence is disabled")
	}
	if asNumber&SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
		seconds := asNumber & SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY
		return &RelativeLocktime{Type: LocktimeTypeSecond, Value: uint32(seconds)}, nil
	}

	return &RelativeLocktime{Type: LocktimeTypeBlock, Value: uint32(asNumber)}, nil
}

func BIP68DecodeSequence(sequenceNum uint32) (*RelativeLocktime, bool) {
	relativeLock := int64(sequenceNum & wire.SequenceLockTimeMask)

	switch {
	case sequenceNum&wire.SequenceLockTimeDisabled == wire.SequenceLockTimeDisabled:
		return nil, true
	case sequenceNum&wire.SequenceLockTimeIsSeconds == wire.SequenceLockTimeIsSeconds:
		timeLockSeconds := (relativeLock << wire.SequenceLockTimeGranularity) - 1
		return &RelativeLocktime{
			Type:  LocktimeTypeSecond,
			Value: uint32(timeLockSeconds),
		}, false
	default:
		return &RelativeLocktime{
			Type:  LocktimeTypeBlock,
			Value: uint32(relativeLock),
		}, false
	}
}
