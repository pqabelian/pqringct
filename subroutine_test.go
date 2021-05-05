package pqringct

import (
	"fmt"
	"testing"
)

func TestIntBinaryNTT(t *testing.T) {
	pp := PublicParameter{}
	pp.paramD = 8

	v := uint64(9)
	binstr := intToBinary(v, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		k := binstr[i]
		fmt.Println(k)
	}
}

func TestMod(t *testing.T) {
	pp := PublicParameter{}
	pp.paramK = 4

	xi := 0
	tau := 1
	fmt.Println((xi - tau) % pp.paramK)
}
