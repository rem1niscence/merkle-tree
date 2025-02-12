package merkle

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestNewMerkleTree(t *testing.T) {
	tests := []struct {
		name    string
		input   [][]byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty merkle should return error",
			input:   [][]byte{},
			want:    nil,
			wantErr: true,
		},
		{
			name:  "single item merkle (odd)",
			input: [][]byte{[]byte("a")},
			want: func() []byte {
				v := sha256.Sum256([]byte("a"))
				root := sha256.Sum256(append(v[:], v[:]...))
				return root[:]
			}(),
			wantErr: false,
		},
		{
			name:  "two item merkle (even)",
			input: [][]byte{[]byte("a"), []byte("b")},
			want: func() []byte {
				a := sha256.Sum256([]byte("a"))
				b := sha256.Sum256([]byte("b"))
				root := sha256.Sum256(append(a[:], b[:]...))
				return root[:]
			}(),
			wantErr: false,
		},
		{
			name:  "three item merkle (odd)",
			input: [][]byte{[]byte("a"), []byte("b"), []byte("c")},
			want: func() []byte {
				a := sha256.Sum256([]byte("a"))
				b := sha256.Sum256([]byte("b"))
				c := sha256.Sum256([]byte("c"))
				ab := sha256.Sum256(append(a[:], b[:]...))
				cc := sha256.Sum256(append(c[:], c[:]...))
				root := sha256.Sum256(append(ab[:], cc[:]...))
				return root[:]
			}(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewMerkleTree(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMerkleTree() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got == nil && tt.wantErr {
				return
			}

			if !bytes.Equal(got.Root.Hash[:], tt.want) {
				t.Errorf("NewMerkleTree() = %x, want %x", got.Root.Hash, tt.want)
			}
		})
	}
}

func TestMerkleProof(t *testing.T) {
	// Sample data
	data := [][]byte{
		[]byte("a"), []byte("b"), []byte("c"), []byte("d"),
		[]byte("e"), []byte("f"), []byte("g"), []byte("h"),
	}

	// Create the Merkle tree
	tree, err := NewMerkleTree(data)
	if err != nil {
		t.Fatalf("failed to create Merkle tree: %v", err)
	}

	// Select a value to generate a proof for
	targetValue := data[3] // "d"

	// Generate the Merkle proof
	proof, err := tree.MerkleProof(targetValue)
	if err != nil {
		t.Fatalf("failed to generate Merkle proof: %v", err)
	}

	// Get the root hash
	rootHash := tree.Root.Hash[:]

	// Verify the proof
	if !VerifyProof(targetValue, proof, rootHash) {
		t.Errorf("Merkle proof verification failed for value: %s", targetValue)
	}

	// Corrupt the proof by changing a hash
	proof.Hashes[0][0] ^= 0xFF
	if VerifyProof(targetValue, proof, rootHash) {
		t.Errorf("Merkle proof verification should fail for modified proof")
	}
}

func BenchmarkNewMerkleTree(b *testing.B) {
	data := [][]byte{[]byte("a"), []byte("c"), []byte("d"), []byte("e"), []byte("f")}
	for b.Loop() {
		NewMerkleTree(data)
	}
}
