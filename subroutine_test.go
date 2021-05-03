package pqringct

import (
	"fmt"
	"testing"
)

func TestIntBinaryNTT(t *testing.T) {
	pp := PublicParameter{}
	pp.paramD = 128

	v := uint64(2013)
	polyNTT := pp.intBinaryNTT(v)
	for i := 0; i < pp.paramD; i++ {
		k := polyNTT.coeffs[i]
		fmt.Println(k)
	}

}
