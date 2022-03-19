package pqringct

import (
	"fmt"
	"math/big"
	"testing"
)

// Mul is help function for testint MulKaratsuba which computes by (F0+x^n*F1)(G0+x^n+G1)
func (pp *PublicParameter) Mul(a []int64, b []int64) []int64 {
	res := make([]int64, 64)
	bigQA := new(big.Int).SetInt64(pp.paramQA)
	for i := 0; i < 32; i++ {
		for j := 0; j < 32; j++ {
			left := new(big.Int).SetInt64(a[i])
			right := new(big.Int).SetInt64(b[j])
			left.Mul(left, right)
			left.Mod(left, bigQA)
			res[i+j] = reduceInt64(res[i+j]+left.Int64(), pp.paramQA)
		}
	}
	return res
}

func TestPublicParameter_MulKaratsuba(t *testing.T) {
	pp := DefaultPPV2
	length := 32
	seed := RandomBytes(pp.paramSeedBytesLen)
	a := rejectionUniformWithQa(seed, length, pp.paramQA)
	seedp := RandomBytes(pp.paramSeedBytesLen)
	b := rejectionUniformWithQa(seedp, length, pp.paramQA)
	ab := pp.Mul(a, b)
	got := pp.MulKaratsuba(a, b, length/2)
	for i := 0; i < 64; i++ {
		if ab[i] != got[i] {
			fmt.Println("i=", i, " got[i]=", got[i], " ab[i]=", ab[i])
		}
	}
}

func (pp *PublicParameter) PolyAMul(a *PolyA, b *PolyA) *PolyA {
	res := make([]int64, 2*pp.paramDA)
	bigQA := new(big.Int).SetInt64(pp.paramQA)
	for i := 0; i < pp.paramDA; i++ {
		for j := 0; j < pp.paramDA; j++ {
			left := new(big.Int).SetInt64(a.coeffs[i])
			right := new(big.Int).SetInt64(b.coeffs[j])
			left.Mul(left, right)
			left.Mod(left, bigQA)
			res[i+j] = reduceInt64(res[i+j]+left.Int64(), pp.paramQA)
		}
	}
	for i := 0; i < pp.paramDA; i++ {
		res[i] = reduceInt64(res[i]-res[i+pp.paramDA], pp.paramQA)
	}
	return &PolyA{coeffs: res[:pp.paramDA]}
}
func TestPublicParameter_PolyANTTMul(t *testing.T) {
	pp := DefaultPPV2
	seed := RandomBytes(pp.paramSeedBytesLen)
	tmpA := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	a := &PolyA{coeffs: tmpA}

	seedp := RandomBytes(pp.paramSeedBytesLen)
	tmpB := rejectionUniformWithQa(seedp, pp.paramDA, pp.paramQA)
	b := &PolyA{coeffs: tmpB}

	c := pp.PolyAMul(a, b)

	ntta := pp.NTTPolyA(a)
	nttb := pp.NTTPolyA(b)
	got := pp.PolyANTTMul(ntta, nttb)
	aMulb := pp.NTTInvPolyA(got)

	for i := 0; i < pp.paramDA; i++ {
		if aMulb.coeffs[i] != c.coeffs[i] {
			fmt.Println("i=", i, " aMulb[i]=", aMulb.coeffs[i], " c[i]=", c.coeffs[i])
		}
	}
}

func TestPublicParameter_NTTPolyA(t *testing.T) {
	pp := DefaultPPV2

	//bigQa := new(big.Int).SetInt64(pp.paramQA)
	//for i := 1; i < pp.paramZetaAOrder; i++ {
	//	a := new(big.Int).SetInt64(pp.paramZetasA[i])
	//	b := new(big.Int).SetInt64(pp.paramZetasA[pp.paramZetaAOrder-i])
	//	a.Mul(a, b)
	//	a.Mod(a, bigQa)
	//	fmt.Println(a.Int64())
	//}

	seed := RandomBytes(pp.paramSeedBytesLen)
	tmpA := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	//tmpA := make([]int64, pp.paramDA)
	//for i := 0; i < pp.paramDA; i++ {
	//	tmpA[i] = int64(1000 + i)
	//}
	//for i := 0; i < pp.paramDA; i++ {
	//	if i&1 == 1 {
	//		tmpA[i] = -tmpA[i]
	//	}
	//}
	//tmpA[0] = (pp.paramQA-1)/2 - 1
	ntta := pp.NTTPolyA(&PolyA{coeffs: tmpA})
	got := pp.NTTInvPolyA(ntta)
	for i := 0; i < pp.paramDA; i++ {
		if got.coeffs[i] != tmpA[i] {
			fmt.Println("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", tmpA[i])
		}
	}

}
