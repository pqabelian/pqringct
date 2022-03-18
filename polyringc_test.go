package pqringct

import (
	"fmt"
	"math/big"
	"testing"
)

func TestReduce(t *testing.T) {
	var a big.Int
	var q int64
	q = 17
	a.SetInt64(-9)
	fmt.Println(reduceBigInt(&a, q))

}

func TestPublicParameterv2_NTTPolyC_NTTInvPolyC(t *testing.T) {
	pp := DefaultPPV2
	c := pp.NewPolyC()
	//for i := 0; i < pp.paramDC; i++ {
	//	c.coeffs[i] = int64(i + 1)
	//}
	c.coeffs[1] = 10
	cinv := pp.NTTPolyC(c)
	fmt.Println(cinv.coeffs)
	got := pp.NTTInvPolyC(cinv)
	fmt.Println(got.coeffs)

}
