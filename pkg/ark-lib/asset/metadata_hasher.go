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
	leaves, err := sortedLeaves(md)
	if err != nil {
		return nil, err
	}
	levels := buildMerkleTree(leaves)
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

// sortedLeaves sorts entries by key and returns their leaf hashes in the same order.
func sortedLeaves(md []Metadata) ([][32]byte, error) {
	sorted := make([]Metadata, len(md))
	copy(sorted, md)
	for _, m := range sorted {
		if err := m.validate(); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		keyValueI := append(sorted[i].Key, sorted[i].Value...)
		keyValueJ := append(sorted[j].Key, sorted[j].Value...)
		return bytes.Compare(keyValueI, keyValueJ) < 0
	})
	leaves := make([][32]byte, len(sorted))
	for i, m := range sorted {
		leaves[i] = m.Hash()
	}
	return leaves, nil
}


