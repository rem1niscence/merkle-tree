package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

var ErrEmptyData = errors.New("no data provided")
var ErrNodeNotFound = errors.New("node not found")

type Node struct {
	Hash   [32]byte
	Left   *Node
	Right  *Node
	Parent *Node
}

type MerkleTree struct {
	Root *Node
}

func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	root, err := buildMerkleTree(data)
	if err != nil {
		return nil, err
	}

	return &MerkleTree{
		Root: root,
	}, nil
}

func (m *MerkleTree) MerkleProof(value []byte) ([][]byte, error) {
	hash := sha256.Sum256(value)
	node := m.findNode(hash[:], m.Root)
	if node == nil {
		return nil, fmt.Errorf("proof cannot be generated: %w", ErrNodeNotFound)
	}

	return [][]byte{}, nil
}

// findNode traverses the merkle tree using Depth-First-Search and returns a node
// with the given hash, or nil if not found
func (m *MerkleTree) findNode(hash []byte, node *Node) *Node {
	if bytes.Equal(node.Hash[:], hash) {
		return node
	}

	if node.Left != nil {
		leftNode := m.findNode(hash, node.Left)
		if leftNode != nil {
			return leftNode
		}
	}
	if node.Right != nil {
		rightNode := m.findNode(hash, node.Right)
		if rightNode != nil {
			return rightNode
		}
	}

	return nil
}

func buildMerkleTree(data [][]byte) (*Node, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	// Step 1 - Create leaf nodes
	nodes := make([]*Node, 0, len(data))
	for _, d := range data {
		hash := sha256.Sum256(d)
		nodes = append(nodes, &Node{
			Hash:   hash,
			Left:   nil,
			Right:  nil,
			Parent: nil,
		})
	}
	// need to duplicate the last node in order to make a balanced tree
	// this one only applies for a single-item merkle tree
	if len(nodes)%2 != 0 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	// Step 2 - Build the tree
	for len(nodes) > 1 {
		// need to duplicate the last node in order to make a balanced tree
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}

		newNodes := make([]*Node, 0, len(nodes)/2)
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			right := nodes[i+1]
			hash := sha256.Sum256(append(left.Hash[:], right.Hash[:]...))

			parent := &Node{
				Hash:  hash,
				Left:  left,
				Right: right,
			}
			left.Parent = parent
			right.Parent = parent
			newNodes = append(newNodes, parent)
		}
		nodes = newNodes
	}

	return nodes[0], nil
}
