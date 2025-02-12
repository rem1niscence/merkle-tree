package main

import (
	"fmt"

	"github.com/rem1niscence/merkle_tree/merkle"
)

var hashes = [][]byte{
	[]byte("b9d582ea6a25e0fd5e08d64db4c80404ca2fac29dac8b65e3a4cc7f8460711b5"),
	[]byte("8216176841f0791a5dd7314669992c129d7520c6966b059bc88d8ef3e9237cb7"),
	[]byte("76353e1915deaf68e29b9c78f37ee984688a71192529d92a5e2082c68dc12f8f"),
	[]byte("f6c15745fe379b384d5663fe320cd303b2996fcdac0fb31f0c6ff67c8b7f3c04"),
	[]byte("2147d8cc72df0955cf8bb7ea002e1bead1097dd722626df742c015693aa2fc99"),
}

func main() {
	tree, err := merkle.NewMerkleTree(hashes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("tree: %+v\n", tree.Root)
}
