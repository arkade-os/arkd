package txutils

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/btcsuite/btcd/txscript"
)

// TapTree is a wrapper around a list of tapscripts
// it is used to encode and decode the taproot tree
// in a way that is compatible with the PSBT_OUT_TAP_TREE field / BIP-371
type TapTree []string

func (t TapTree) Encode() ([]byte, error) {
	var tapscriptsBytes bytes.Buffer

	// write number of leaves as compact size uint
	if err := writeCompactSizeUint(&tapscriptsBytes, uint64(len(t))); err != nil {
		return nil, err
	}

	for _, tapscript := range t {
		scriptBytes, err := hex.DecodeString(tapscript)
		if err != nil {
			return nil, err
		}

		// write depth (always 1)
		// TODO: allow multiple depth
		if err := tapscriptsBytes.WriteByte(1); err != nil {
			return nil, err
		}

		if err := tapscriptsBytes.WriteByte(byte(txscript.BaseLeafVersion)); err != nil {
			return nil, err
		}

		// write script
		if err := writeCompactSizeUint(&tapscriptsBytes, uint64(len(scriptBytes))); err != nil {
			return nil, err
		}
		if _, err := tapscriptsBytes.Write(scriptBytes); err != nil {
			return nil, err
		}
	}

	return tapscriptsBytes.Bytes(), nil
}

func DecodeTapTree(data []byte) (TapTree, error) {
	var leaves []string

	buf := bytes.NewReader(data)

	// len of tapscripts
	count, err := readCompactSizeUint(buf)
	if err != nil {
		return nil, err
	}

	for i := uint64(0); i < count; i++ {
		// depth : ignore
		if _, err := buf.ReadByte(); err != nil {
			return nil, err
		}

		// leaf version : ignore, we assume base tapscript
		if _, err := buf.ReadByte(); err != nil {
			return nil, err
		}

		// script length
		scriptLen, err := readCompactSizeUint(buf)
		if err != nil {
			return nil, err
		}

		// script bytes
		scriptBytes := make([]byte, scriptLen)
		if _, err := buf.Read(scriptBytes); err != nil {
			return nil, err
		}

		leaves = append(leaves, hex.EncodeToString(scriptBytes))
	}

	return TapTree(leaves), nil
}

// writeCompactSizeUint writes a compact size uint to the writer
func writeCompactSizeUint(w *bytes.Buffer, val uint64) error {
	if val < 253 {
		return w.WriteByte(byte(val))
	}
	if val < 0x10000 {
		if err := w.WriteByte(253); err != nil {
			return err
		}
		return binary.Write(w, binary.LittleEndian, uint16(val))
	}
	if val < 0x100000000 {
		if err := w.WriteByte(254); err != nil {
			return err
		}
		return binary.Write(w, binary.LittleEndian, uint32(val))
	}
	if err := w.WriteByte(255); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, val)
}

// readCompactSizeUint reads a compact size uint from the reader
func readCompactSizeUint(r *bytes.Reader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	switch firstByte {
	case 253:
		var val uint16
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case 254:
		var val uint32
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case 255:
		var val uint64
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return val, nil
	default:
		return uint64(firstByte), nil
	}
}
