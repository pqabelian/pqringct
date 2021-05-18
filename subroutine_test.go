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

func TestSampleRandomnessA(t *testing.T) {
	pp := PublicParameter{}
	pp.paramKa = 10
	pp.paramLa = 8
	pp.paramQ = 4294962689

	A := pp.sampleRandomnessA()
	for i := 0 ; i < pp.paramKa ; i++ {
		for j := 0 ; j < pp.paramLa ; j++ {
			fmt.Print(A.polys[i].coeffs[j])
			fmt.Print(" ")
		}
		fmt.Print("\n")
	}
}
