package asset

import (
	"bytes"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var (
	arkLeafTag   = []byte("ArkadeAssetLeaf")
	arkBranchTag = []byte("ArkadeAssetBranch")
)

type metadataLeafVersion byte

const (
	arkLeafVersion metadataLeafVersion = 0x00
)

// GenerateMetadataListHash computes the Merkle root of the
// asset's metadata entries.
func GenerateMetadataListHash(md []Metadata) ([]byte, error) {
	if len(md) == 0 {
		return nil, nil
	}
	hashes, err := sortAndHashMetadataLeaves(md)
	if err != nil {
		return nil, err
	}
	levels := buildMerkleTree(hashes)
	root := levels[len(levels)-1][0]
	return root[:], nil
}

// "ArkadeAssetLeaf" provides domain separation from Taproot's "TapLeaf" and
func (md Metadata) Hash() [32]byte {
	var buf bytes.Buffer
	buf.WriteByte(byte(arkLeafVersion))
	// nolint: errcheck — bytes.Buffer.Write never returns an error
	_ = serializeVarSlice(&buf, md.Key)
	_ = serializeVarSlice(&buf, md.Value)
	return [32]byte(*chainhash.TaggedHash(arkLeafTag, buf.Bytes()))
}

// "ArkadeAssetBranch" computes the branch hash for the two given leaves.
func computeBranchHash(a, b [32]byte) [32]byte {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	return [32]byte(*chainhash.TaggedHash(arkBranchTag, a[:], b[:]))
}

// buildMerkleTree constructs a Merkle tree from pre-sorted
// leaves and returns every level.
func buildMerkleTree(leaves [][32]byte) [][][32]byte {
	if len(leaves) == 0 {
		return nil
	}
	levels := [][][32]byte{leaves}
	current := leaves

	// reduce the leaves by combining pairs into branches
	for len(current) > 1 {
		var next [][32]byte
		for i := 0; i+1 < len(current); i += 2 {
			next = append(next, computeBranchHash(current[i], current[i+1]))
		}
		if len(current)%2 == 1 {
			next = append(next, current[len(current)-1])
		}
		levels = append(levels, next)
		current = next
	}
	return levels
}

// sortAndHashMetadataLeaves sorts entries by key and returns their hashes in the same order.
func sortAndHashMetadataLeaves(md []Metadata) ([][32]byte, error) {
	for _, m := range md {
		if err := m.validate(); err != nil {
			return nil, err
		}
	}

	// precompute key || value bytes to avoid per-compare allocations
	keyAndValue := make([][]byte, len(md))
	for i := range md {
		buf := make([]byte, len(md[i].Key)+len(md[i].Value))
		copy(buf, md[i].Key)
		copy(buf[len(md[i].Key):], md[i].Value)
		keyAndValue[i] = buf
	}
	sort.SliceStable(md, func(i, j int) bool {
		return bytes.Compare(keyAndValue[i], keyAndValue[j]) < 0
	})
	
	sorted := make([]Metadata, len(md))
	copy(sorted, md)

	hashes := make([][32]byte, len(sorted))
	for pos, orig := range sorted {
		hashes[pos] = orig.Hash()
	}
	return hashes, nil
}


