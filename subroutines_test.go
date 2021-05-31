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


func TestSampleUniformPloyWithLowZeros(t *testing.T) {
	pp := PublicParameter{}
	pp.paramD = 20
	pp.paramSysBytes = 128
	pp.paramK = 4
	pp.paramQ = 4294962689

	myPoly := pp.sampleUniformPloyWithLowZeros()
	fmt.Println(myPoly)
}

func TestSampleUniformWithinEtaF(t *testing.T) {
	pp := PublicParameter{}
	pp.paramSysBytes = 128
	pp.paramD = 128
	pp.paramEtaF = 1024 - 1
	res, err := pp.sampleUniformWithinEtaF()
	if err != nil {
		t.Errorf("error")
	}
	fmt.Println(res)
}