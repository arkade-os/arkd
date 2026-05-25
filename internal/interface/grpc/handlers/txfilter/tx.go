package txfilter

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire"
)

type Tx struct {
	Extension map[int64]string `json:"extension,omitempty"`
}

func NewTx(rawTx *wire.MsgTx) (Tx, error) {
	if rawTx == nil {
		return Tx{}, nil
	}

	ext, err := extension.NewExtensionFromTx(rawTx)
	if err != nil {
		if errors.Is(err, extension.ErrExtensionNotFound) {
			return Tx{}, nil
		}
		return Tx{}, fmt.Errorf("parse extension failed: %w", err)
	}

	extMap := make(map[int64]string, len(ext))
	for _, p := range ext {
		data, err := p.Serialize()
		if err != nil {
			return Tx{}, fmt.Errorf("serialize packet: %w", err)
		}
		extMap[int64(p.Type())] = hex.EncodeToString(data)
	}

	return Tx{Extension: extMap}, nil
}