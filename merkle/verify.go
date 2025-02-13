package merkle

import (
	"bytes"
	"crypto/sha256"
)

const (
	left = iota
	right
)

type Proof struct {
	Hashes [][]byte
	Order  []byte
}

// VerifyProof verifies a Merkle proof for a given value,
// reconstructing the root hash and comparing it to the given root hash
func VerifyProof(value []byte, proof *Proof, rootHash []byte) bool {
	hash := sha256.Sum256(value)

	for i := 0; i < len(proof.Hashes); i++ {
		if proof.Order[i] == left {
			hash = sha256.Sum256(append(proof.Hashes[i], hash[:]...))
		} else {
			hash = sha256.Sum256(append(hash[:], proof.Hashes[i]...))
		}
	}

	return bytes.Equal(hash[:], rootHash[:])
}
