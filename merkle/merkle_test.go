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

func BenchmarkNewMerkleTree(b *testing.B) {
	data := [][]byte{[]byte("a"), []byte("c"), []byte("d"), []byte("e"), []byte("f")}
	for b.Loop() {
		NewMerkleTree(data)
	}
}
