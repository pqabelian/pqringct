package pqringct

import "math/big"

type PolyA struct {
	coeffs []int64
}
type PolyANTT struct {
	coeffs []int64
}

type PolyAVec struct {
	polyAs []*PolyA
}
type PolyANTTVec struct {
	polyANTTs []*PolyANTT
}


func (pp *PublicParameterv2) NewPolyA() (*PolyA)  {
	return &PolyA{coeffs: make([]int64, pp.paramDA)}
}
func (pp *PublicParameterv2) NewPolyANTT() (*PolyANTT)  {
	return &PolyANTT{coeffs: make([]int64, pp.paramDA)}
}
func (pp *PublicParameterv2) NewZeroPolyANTT() (*PolyANTT)  {
	rst := &PolyANTT{coeffs: make([]int64, pp.paramDA)}
	for i := 0; i < pp.paramDA; i++ {
		rst.coeffs[i] = 0
	}
	return rst
}


func (polyA *PolyA) infNorm() (infNorm int64) {
	rst := int64(0)
	for _, coeff := range polyA.coeffs {
		if coeff > rst {
			rst = coeff
		} else if coeff < 0 && -coeff > rst {
			rst = -coeff
		}
	}
	return rst
}

func (polyAVec *PolyAVec) infNorm() (infNorm int64) {
	rst := int64(0)
	for _, p := range polyAVec.polyAs {
		tmp := p.infNorm()
		if tmp > rst {
			rst = tmp
		}
	}

	return rst
}


func (pp *PublicParameterv2) NTTPolyA(polyA *PolyA) *PolyANTT {
	//	NTT
	zetaAOrder := 16	//	todo: this should be set as a system parameter, together with zetaAs[], decided by d_a, q_a
	slotNum := zetaAOrder / 2	//	will factor to irreducible factors
	segNum := 1
	segLen := pp.paramDA
	factors := make([]int, 1)
	factors[0] = slotNum / 2

	coeffs := make([]int64, pp.paramDA)
	for i := 0; i < pp.paramDA; i++ {
		coeffs[i] = polyA.coeffs[i]
	}
	var qaBig, tmp, tmp1, tmp2, zetaTmp big.Int
	qaBig.SetInt64(pp.paramQA)
	for {
		segLenHalf := segLen / 2
		for k := 0; k < segNum; k++ {
			zetaTmp.SetInt64(zetaAs[factors[k]])
			for i := 0; i < segLenHalf; i++ {
				//	X^2 - Y^2 = (X+Y)(X-Y)
				//				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp.SetInt64(coeffs[k*segLen+i+segLenHalf])
				tmp.Mul(&tmp, &zetaTmp)
				tmp.Mod(&tmp, &qaBig)
				//				tmp1 := reduceToQc(int64(coeffs[k*segLen+i]) - tmp)
				//				tmp2 := reduceToQc(int64(coeffs[k*segLen+i]) + tmp)
				tmp1.SetInt64(coeffs[k*segLen+i])
				tmp2.SetInt64(coeffs[k*segLen+i])
				tmp1.Sub(&tmp1, &tmp)
				tmp2.Add(&tmp2, &tmp)
				//				coeffs[k*segLen+i] = tmp1
				//				coeffs[k*segLen+i+segLenHalf] = tmp2
				coeffs[k*segLen+i] = tmp1.Int64()
				coeffs[k*segLen+i+segLenHalf] = tmp2.Int64()
			}
		}
		segNum = segNum << 1
		segLen = segLen >> 1
		if segNum == slotNum {
			break
		}

		tmpFactors := make([]int, 2*len(factors))
		for i := 0; i < len(factors); i++ {
			tmpFactors[2*i] = (factors[i] + slotNum) / 2
			tmpFactors[2*i+1] = factors[i] / 2
		}
		factors = tmpFactors
	}

	//	factors: 7, 3, 5, 1
/*	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + slotNum
		finalFactors[2*i+1] = factors[i]
	}
	//	finalFactors: 15,7, 11,3, 13,5, 9,1*/

	rst := pp.NewPolyANTT()
	for i := 0; i < pp.paramDA; i++ {
		rst.coeffs[i] = reduceInt64(coeffs[i], pp.paramQA)
	}
	return rst
}

//	todo: this should be set as a system parameter, together with zetaAs[] and zetaAOrder, decided by d_a, q_a
var nttAFactors = []int{
	7, 3, 5, 1}


func (pp *PublicParameterv2) NTTInvPolyA(polyANTT *PolyANTT) (polyA *PolyA) {
	// NTT Inverse
	zetaAOrder := 16	//	todo: this should be set as a system parameter, together with zetaAs[], decided by d_a, q_a
	slotNum := zetaAOrder / 2	//	have been factored to irreducible factors
	segNum := slotNum
	segLen := pp.paramDA / segNum
	factors := nttAFactors

	nttCoeffs := make([]int64, pp.paramDA)
	for i := 0; i < pp.paramDC ; i++ {
		nttCoeffs[i] = polyANTT.coeffs[i]
	}
	// twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
	var qaBig, twoInv, tmp1, tmp2, tmpZetaInv big.Int
	qaBig.SetInt64(pp.paramQA)
	twoInv.SetInt64((pp.paramQA+1)/2 - pp.paramQA)

	for {
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			tmpZetaInv.SetInt64( zetaAs[zetaAOrder-factors[k]] )
			for i := 0; i < segLen; i++ {
				//				tmp1 := reduceToQc(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])+int64(nttCoeffs[k*segLenDouble+i])) * twoInv)
				//				nttCoeffs[k*segLenDouble+i] = tmp1
				tmp1.SetInt64(nttCoeffs[k*segLenDouble+i+segLen] + nttCoeffs[k*segLenDouble+i])
				tmp1.Mul(&tmp1, &twoInv)
				tmp1.Mod(&tmp1, &qaBig)
				//				tmp2 := reduceToQc(pp.reduceInt64(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])-int64(nttCoeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
				//				nttCoeffs[k*segLenDouble+i+segLen] = tmp2
				tmp2.SetInt64(nttCoeffs[k*segLenDouble+i+segLen] - nttCoeffs[k*segLenDouble+i])
				tmp2.Mul(&tmp2, &twoInv)
				tmp2.Mod(&tmp2, &qaBig)
				tmp2.Mul(&tmp2, &tmpZetaInv)
				tmp2.Mod(&tmp2, &qaBig)

				nttCoeffs[k*segLenDouble+i] = tmp1.Int64()
				nttCoeffs[k*segLenDouble+i+segLen] = tmp2.Int64()
			}
		}
		segNum = segNum >> 1
		segLen = segLen << 1
		if segNum == 1 {
			break
		}

		tmpFactors := make([]int, len(factors)/2)
		for i := 0; i < len(tmpFactors); i++ {
			tmpFactors[i] = factors[2*i+1] * 2
		}
		factors = tmpFactors
	}

	rst := pp.NewPolyA()
	for i := 0; i < pp.paramDA; i++ {
		rst.coeffs[i] = reduceInt64(nttCoeffs[i], pp.paramQA)
	}
	return rst
}


func PolyAEqualCheck(a *PolyA, b *PolyA) (eq bool) {
	if a == nil || b == nil {
		return false
	}
	if len(a.coeffs) != len( b.coeffs ) {
		return false
	}
	for i := 0; i < len(a.coeffs); i++ {
		if a.coeffs[i] != b.coeffs[i] {
			return false
		}
	}

	return true
}

func PolyANTTEqualCheck(a *PolyANTT, b *PolyANTT) (eq bool) {
	if a == nil || b == nil {
		return false
	}
	if len(a.coeffs) != len( b.coeffs) {
		return false
	}
	for i := 0; i < len(a.coeffs); i++ {
		if a.coeffs[i] != b.coeffs[i] {
			return false
		}
	}

	return true
}

func PolyANTTVecEqualCheck(a *PolyANTTVec, b *PolyANTTVec) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if a.polyANTTs == nil || b.polyANTTs == nil {
		return false
	}

	if len(a.polyANTTs) != len(b.polyANTTs) {
		return false
	}

	for i := 0; i < len(a.polyANTTs); i++ {
		if !PolyANTTEqualCheck(a.polyANTTs[i], b.polyANTTs[i]) {
			return false
		}
	}

	return true
}



func (pp *PublicParameterv2) NewPolyAVec(vecLen int) *PolyAVec {
	polys := make([]*PolyA, vecLen)
	for i := 0; i < vecLen; i++ {
		polys[i] = pp.NewPolyA()
	}
	return &PolyAVec{polyAs: polys}
}

func (pp *PublicParameterv2) NewPolyANTTVec(vecLen int) *PolyANTTVec {
	polyNTTs := make([]*PolyANTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polyNTTs[i] = pp.NewPolyANTT()
	}
	return &PolyANTTVec{polyANTTs: polyNTTs}
}



func (pp *PublicParameterv2) NTTPolyAVec(polyAVec *PolyAVec) *PolyANTTVec {
	if polyAVec == nil {
		return nil
	}

	r := &PolyANTTVec{}
	r.polyANTTs = make([]*PolyANTT, len(polyAVec.polyAs))

	for i := 0; i < len(polyAVec.polyAs); i++ {
		r.polyANTTs[i] = pp.NTTPolyA(polyAVec.polyAs[i])
	}
	return r
}

func (pp *PublicParameterv2) NTTInvPolyAVec(polyANTTVec *PolyANTTVec) (polyAVec *PolyAVec) {
	if polyANTTVec == nil {
		return nil
	}

	r := &PolyAVec{}
	r.polyAs = make([]*PolyA, len(polyANTTVec.polyANTTs))

	for i := 0; i < len(polyANTTVec.polyANTTs); i++ {
		r.polyAs[i] = pp.NTTInvPolyA(polyANTTVec.polyANTTs[i])
	}

	return r
}


func (pp *PublicParameterv2) PolyANTTAdd(a *PolyANTT, b *PolyANTT) (r *PolyANTT) {
	if len(a.coeffs) != pp.paramDA || len(b.coeffs) != pp.paramDA {
		panic("the length of the input polyANTT is not paramDA")
	}
	rst := pp.NewPolyANTT()
//	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDA; i++ {
/*		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmp.Add(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQA)*/
		rst.coeffs[i] = reduceInt64(a.coeffs[i] + b.coeffs[i], pp.paramQA)
	}
	return rst
}


func (pp *PublicParameterv2) PolyANTTSub(a *PolyANTT, b *PolyANTT) (r *PolyANTT) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		panic("the length of the input polyANTT is not paramDA")
	}
	rst := pp.NewPolyANTT()
//	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDA; i++ {
/*		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmp.Sub(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQA)*/
		rst.coeffs[i] = reduceInt64(a.coeffs[i] - b.coeffs[i], pp.paramQA)
	}
	return rst
}

/*
ToDO:
 */
func (pp *PublicParameterv2) PolyANTTMul(a *PolyANTT, b *PolyANTT) (r *PolyANTT) {
	panic("Implement me: PolyANTTMul")
	if len(a.coeffs) != pp.paramDA || len(b.coeffs) != pp.paramDA {
		panic("the length of the input polyANTT is not paramDC")
	}
	rst := pp.NewPolyANTT()
/*	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmp.Mul(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQC)
	}*/
	return rst
}

func (pp *PublicParameterv2) PolyANTTVecInnerProduct(a *PolyANTTVec, b *PolyANTTVec, vecLen int) (r *PolyANTT) {
	var rst = pp.NewZeroPolyANTT()
	for i := 0; i < vecLen; i++ {
		tmp := pp.PolyANTTMul(a.polyANTTs[i], b.polyANTTs[i])
		rst = pp.PolyANTTAdd(rst, tmp)
	}
	return rst
}

func (pp *PublicParameterv2) PolyANTTMatrixMulVector(M []*PolyANTTVec, vec *PolyANTTVec, rowNum int, vecLen int) (r *PolyANTTVec) {
	rst := &PolyANTTVec{}
	rst.polyANTTs = make([]*PolyANTT, rowNum)
	for i := 0; i < rowNum; i++ {
		rst.polyANTTs[i] = pp.PolyANTTVecInnerProduct(M[i], vec, vecLen)
	}
	return rst
}

func (pp *PublicParameterv2) PolyAAdd(a *PolyA, b *PolyA) (r *PolyA) {
	if len(a.coeffs) != pp.paramDA || len(b.coeffs) != pp.paramDA {
		panic("the length of the input polyANTT is not paramDC")
	}

	rst := pp.NewPolyA()
//	var tmp1, tmp2, tmpx big.Int
	for i := 0; i < pp.paramDA; i++ {
/*		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmpx.Add(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmpx, pp.paramQA)*/
		rst.coeffs[i] = reduceInt64(a.coeffs[i] + b.coeffs[i], pp.paramQA)
	}

	return rst
}

func (pp *PublicParameterv2) PolyASub(a *PolyA, b *PolyA) (r *PolyA) {
	if len(a.coeffs) != pp.paramDA || len(b.coeffs) != pp.paramDA {
		panic("the length of the input polyANTT is not paramDA")
	}

	rst := pp.NewPolyA()
//	var tmp1, tmp2, tmpx big.Int
	for i := 0; i < pp.paramDA; i++ {
/*		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmpx.Sub(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmpx, pp.paramQA)*/
		rst.coeffs[i] = reduceInt64(a.coeffs[i] - b.coeffs[i], pp.paramQA)
	}

	return rst
}

func (pp *PublicParameterv2) PolyAVecAdd(a *PolyAVec, b *PolyAVec, vecLen int) (r *PolyAVec) {
	if len(a.polyAs) != len(b.polyAs) {
		panic("the two input polyAVecs have different length")
	}
	rst := pp.NewPolyAVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyAs[i] = pp.PolyAAdd(a.polyAs[i], b.polyAs[i])
	}
	return rst
}

func (pp *PublicParameterv2) PolyAVecSub(a *PolyAVec, b *PolyAVec, vecLen int) (r *PolyAVec) {
	if len(a.polyAs) != len(b.polyAs) {
		panic("the two input polyAVecs have different length")
	}
	rst := pp.NewPolyAVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyAs[i] = pp.PolyAAdd(a.polyAs[i], b.polyAs[i])
	}
	return rst
}

//	todo: implement NTT on non-fully-spliting ring begin
/*
const (
	R1 = -16915236577
	R2 = -8376412603
	R3 = -3354919284
	R4 = 11667088462
	R5 = -12474372669
	R6 = -3077095668
	R7 = 14301820476
)

func BigNumberMultiplication(a int64, b int64) (ans int64) {
	var tmp1 [30]int64
	var an int64
	var count1, count2, i int = 0, 0, 0
	var t1, t2, t3, t4 int64
	an = 0
	if a < 0 {
		t1 = -a
	} else {
		t1 = a
	}
	if b < 0 {
		t2 = -b
	} else {
		t2 = b
	}
	t3 = t1
	t4 = t2
	//while (t1 != 0)
	for i = 0; i < 10; i-- {
		if t1 == 0 {
			break
		}
		count1++
		t1 = t1 / 10
	}
	//while (t2 != 0)
	for i = 0; i < 10; i-- {
		if t2 == 0 {
			break
		}
		count2++
		t2 = t2 / 10
	}
	if count1+count2 <= 18 {
		return reduceToQa(a * b)
	} else {
		for i = 0; i < 30; i++ {
			tmp1[i] = 0
		}
		t1 = t3 % 100000
		t2 = t3 / 100000
		t1 = t4 * t1
		t2 = t4 * t2
		count1 = 0
		//while (t1 != 0)
		for i = 0; i < 10; i-- {
			if t1 == 0 {
				break
			}
			tmp1[count1] = t1 % 10
			count1++
			t1 = t1 / 10
		}
		count1 = 5
		//while (t2 != 0)
		for i = 0; i < 10; i-- {
			if t2 == 0 {
				break
			}
			tmp1[count1] += t2 % 10
			count1++
			t2 = t2 / 10
		}
	}

	for i = 25; i >= 0; i-- {
		an = (an*10 + tmp1[i]) % 34360786961
	}
	if (a < 0 && b > 0) || (a > 0 && b < 0) {
		return -an
	}
	return reduceToQa(an)
}
func (pp *PublicParameterv2) MulLow16(a, b *Polyv2) *Polyv2 {
	res := NewPolyv2(R_QA, pp.paramDA)
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			m := i + j
			res.coeffs2[m] += BigNumberMultiplication(a.coeffs2[i], b.coeffs2[j])
			res.coeffs2[m] = reduceToQa(res.coeffs2[m])
		}
	}
	return res
}
func (pp *PublicParameterv2) MulKaratsuba(a, b *Polyv2) *Polyv2 {
	res := NewPolyv2(R_QA, pp.paramDA)
	var f, g, fg [2]*Polyv2
	for i := 0; i < 2; i++ {
		f[i] = NewPolyv2(R_QA, pp.paramDA)
		g[i] = NewPolyv2(R_QA, pp.paramDA)
	}
	// compute f0,f1,g0,g1
	for i := 0; i < 16; i++ {
		f[0].coeffs2[i] = a.coeffs2[i]
		f[1].coeffs2[i] = a.coeffs2[i+16]
		g[0].coeffs2[i] = b.coeffs2[i]
		g[1].coeffs2[i] = b.coeffs2[i+16]
	}
	// compute f0g0,f1g1
	for i := 0; i < 2; i++ {
		fg[i] = pp.MulLow16(f[i], g[i])
	}
	tmp := NewPolyv2(R_QA, pp.paramDA)
	for i := 0; i < 32; i++ {
		tmp.coeffs2[i] += fg[0].coeffs2[i]
		tmp.coeffs2[i] = reduceToQa(tmp.coeffs2[i])
		tmp.coeffs2[i+16] -= fg[1].coeffs2[i]
		tmp.coeffs2[i+16] = reduceToQa(tmp.coeffs2[i+16])
	}
	res1 := NewPolyv2(R_QA, pp.paramDA)
	for i := 0; i < 16; i++ {
		res1.coeffs2[i] = tmp.coeffs2[i]
	}
	for i := 16; i < 48; i++ {
		res1.coeffs2[i] = tmp.coeffs2[i] - tmp.coeffs2[i-16]
		res1.coeffs2[i] = reduceToQa(res1.coeffs2[i])
	}
	for i := 48; i < 64; i++ {
		res1.coeffs2[i] = -tmp.coeffs2[i-16]
		res1.coeffs2[i] = reduceToQa(res1.coeffs2[i])
	}
	f[0] = PolyAdd(f[0], f[1], R_QA)
	g[0] = PolyAdd(g[0], g[1], R_QA)
	tmp = pp.MulLow16(f[0], g[0])
	res = NewPolyv2(R_QA, pp.paramDA)
	for i := 0; i < 16; i++ {
		res.coeffs2[i] = res1.coeffs2[i]
	}
	for i := 16; i < 48; i++ {
		res.coeffs2[i] = res1.coeffs2[i] + tmp.coeffs2[i-16]
		res.coeffs2[i] = reduceToQa(res.coeffs2[i])
	}
	for i := 48; i < 64; i++ {
		res.coeffs2[i] = res1.coeffs2[i]
	}
	return res
}
func (pp *PublicParameterv2) Divide(z *Polyv2) (res [3][3][3]*Polyv2) {
	for i := 1; i < 3; i++ {
		for j := 1; j < 3; j++ {
			for k := 1; k < 3; k++ {
				res[i][j][k] = NewPolyv2(R_QA, pp.paramDA)
			}
		}
	}
	var a [3]*Polyv2  //a1=a[1],a2=a[2]
	var a1 [3]*Polyv2 //a11=a1[1],a12=a1[2]
	var a2 [3]*Polyv2 //a21=a2[1],a22=a2[2]
	for i := 1; i < 3; i++ {
		a[i] = NewPolyv2(R_QA, pp.paramDA)
		a1[i] = NewPolyv2(R_QA, pp.paramDA)
		a2[i] = NewPolyv2(R_QA, pp.paramDA)
	}

	var tmp [8]int64
	// compute a1,a2
	for i := 0; i < pp.paramDA/2; i++ {
		tmp[4] = BigNumberMultiplication(z.coeffs2[i+pp.paramDA/2], -R4)
		a[1].coeffs2[i] = reduceToQa(z.coeffs2[i] + tmp[4])
		a[2].coeffs2[i] = reduceToQa(z.coeffs2[i] - tmp[4])
	}
	// compute a11,a12,a21,a22
	for i := 0; i < pp.paramDA/4; i++ {
		tmp[2] = BigNumberMultiplication(a[2].coeffs2[i+pp.paramDA/4], -R2)
		tmp[6] = BigNumberMultiplication(a[1].coeffs2[i+pp.paramDA/4], -R6)
		a1[1].coeffs2[i] = reduceToQa(a[1].coeffs2[i] + tmp[6])
		a1[2].coeffs2[i] = reduceToQa(a[1].coeffs2[i] - tmp[6])
		a2[1].coeffs2[i] = reduceToQa(a[2].coeffs2[i] + tmp[2])
		a2[2].coeffs2[i] = reduceToQa(a[2].coeffs2[i] - tmp[2])
	}
	// compute a111~a222
	for i := 0; i < pp.paramDA/8; i++ {
		tmp[1] = BigNumberMultiplication(a2[2].coeffs2[i+pp.paramDA/8], -R1)
		tmp[3] = BigNumberMultiplication(a1[2].coeffs2[i+pp.paramDA/8], -R3)
		tmp[5] = BigNumberMultiplication(a2[1].coeffs2[i+pp.paramDA/8], -R5)
		tmp[7] = BigNumberMultiplication(a1[1].coeffs2[i+pp.paramDA/8], -R7)
		res[1][1][1].coeffs2[i] = reduceToQa(a1[1].coeffs2[i] + tmp[7]) //a111
		res[1][1][2].coeffs2[i] = reduceToQa(a1[1].coeffs2[i] - tmp[7]) //a112
		res[1][2][1].coeffs2[i] = reduceToQa(a1[2].coeffs2[i] + tmp[3]) //a121
		res[1][2][2].coeffs2[i] = reduceToQa(a1[2].coeffs2[i] - tmp[3]) //a122
		res[2][1][1].coeffs2[i] = reduceToQa(a2[1].coeffs2[i] + tmp[5]) //a211
		res[2][1][2].coeffs2[i] = reduceToQa(a2[1].coeffs2[i] - tmp[5]) //a212
		res[2][2][1].coeffs2[i] = reduceToQa(a2[2].coeffs2[i] + tmp[1]) //a221
		res[2][2][2].coeffs2[i] = reduceToQa(a2[2].coeffs2[i] - tmp[1]) //a222
	}
	return res
}
func (pp *PublicParameterv2) Mul(a, b *Polyv2) *Polyv2 {
	da := pp.Divide(a)
	db := pp.Divide(b)
	var dz [3][3][3]*Polyv2
	for i := 1; i < 3; i++ {
		for j := 1; j < 3; j++ {
			for k := 1; k < 3; k++ {
				dz[i][j][k] = pp.MulKaratsuba(da[i][j][k], db[i][j][k])
			}
		}
	}
	var res, res1, res2 [3]*Polyv2 //z1,z2,z11,z12,z21,z22

	// compute z111~z222
	for i := 0; i < 32; i++ {
		dz[1][1][1].coeffs2[i] -= reduceToQa(BigNumberMultiplication(dz[1][1][1].coeffs2[i+32], R7))
		dz[1][1][1].coeffs2[i] = reduceToQa(dz[1][1][1].coeffs2[i])

		dz[1][1][2].coeffs2[i] += reduceToQa(BigNumberMultiplication(dz[1][1][2].coeffs2[i+32], R7))
		dz[1][1][2].coeffs2[i] = reduceToQa(dz[1][1][2].coeffs2[i])

		dz[1][2][1].coeffs2[i] -= reduceToQa(BigNumberMultiplication(dz[1][2][1].coeffs2[i+32], R3))
		dz[1][2][1].coeffs2[i] = reduceToQa(dz[1][2][1].coeffs2[i])

		dz[1][2][2].coeffs2[i] += reduceToQa(BigNumberMultiplication(dz[1][2][2].coeffs2[i+32], R3))
		dz[1][2][2].coeffs2[i] = reduceToQa(dz[1][2][2].coeffs2[i])

		dz[2][1][1].coeffs2[i] -= reduceToQa(BigNumberMultiplication(dz[2][1][1].coeffs2[i+32], R5))
		dz[2][1][1].coeffs2[i] = reduceToQa(dz[2][1][1].coeffs2[i])

		dz[2][1][2].coeffs2[i] += reduceToQa(BigNumberMultiplication(dz[2][1][2].coeffs2[i+32], R5))
		dz[2][1][2].coeffs2[i] = reduceToQa(dz[2][1][2].coeffs2[i])

		dz[2][2][1].coeffs2[i] -= reduceToQa(BigNumberMultiplication(dz[2][2][1].coeffs2[i+32], R1))
		dz[2][2][1].coeffs2[i] = reduceToQa(dz[2][2][1].coeffs2[i])

		dz[2][2][2].coeffs2[i] += reduceToQa(BigNumberMultiplication(dz[2][2][2].coeffs2[i+32], R1))
		dz[2][2][2].coeffs2[i] = reduceToQa(dz[2][2][2].coeffs2[i])
	}
	for i := 0; i < 32; i++ {
		//c111
		dz[1][1][1].coeffs2[i+32] = dz[1][1][1].coeffs2[i]
		dz[1][1][1].coeffs2[i] = reduceToQa(reduceToQa(BigNumberMultiplication(dz[1][1][1].coeffs2[i], -R7)))
		//c112
		dz[1][1][2].coeffs2[i+32] = reduceToQa(-dz[1][1][2].coeffs2[i])
		dz[1][1][2].coeffs2[i] = reduceToQa(-BigNumberMultiplication(dz[1][1][2].coeffs2[i], R7))
		//c121
		dz[1][2][1].coeffs2[i+32] = dz[1][2][1].coeffs2[i]
		dz[1][2][1].coeffs2[i] = reduceToQa(BigNumberMultiplication(dz[1][2][1].coeffs2[i], -R3))
		//c122
		dz[1][2][2].coeffs2[i+32] = reduceToQa(-dz[1][2][2].coeffs2[i])
		dz[1][2][2].coeffs2[i] = reduceToQa(-BigNumberMultiplication(dz[1][2][2].coeffs2[i], R3))
		//c211
		dz[2][1][1].coeffs2[i+32] = dz[2][1][1].coeffs2[i]
		dz[2][1][1].coeffs2[i] = reduceToQa(BigNumberMultiplication(dz[2][1][1].coeffs2[i], -R5))
		//c212
		dz[2][1][2].coeffs2[i+32] = reduceToQa(-dz[2][1][2].coeffs2[i])
		dz[2][1][2].coeffs2[i] = reduceToQa(-BigNumberMultiplication(dz[2][1][2].coeffs2[i], R5))
		//c221
		dz[2][2][1].coeffs2[i+32] = dz[2][2][1].coeffs2[i]
		dz[2][2][1].coeffs2[i] = reduceToQa(BigNumberMultiplication(dz[2][2][1].coeffs2[i], -R1))
		//c222
		dz[2][2][2].coeffs2[i+32] = reduceToQa(-dz[2][2][2].coeffs2[i])
		dz[2][2][2].coeffs2[i] = reduceToQa(-BigNumberMultiplication(dz[2][2][2].coeffs2[i], R1))
	}

	// compute z11,z12,z21,z22
	res1[1] = PolyAdd(dz[1][1][1], dz[1][1][2], R_QA)
	res1[2] = PolyAdd(dz[1][2][1], dz[1][2][2], R_QA)
	res2[1] = PolyAdd(dz[2][1][1], dz[2][1][2], R_QA)
	res2[2] = PolyAdd(dz[2][2][1], dz[2][2][2], R_QA)
	for i := 0; i < 64; i++ {
		res1[1].coeffs2[i] = reduceToQa(BigNumberMultiplication(res1[1].coeffs2[i], reduceToQa(BigNumberMultiplication((pp.paramQA+1)/2, R1))))
		res1[2].coeffs2[i] = reduceToQa(BigNumberMultiplication(res1[2].coeffs2[i], reduceToQa(BigNumberMultiplication((pp.paramQA+1)/2, R5))))
		res2[1].coeffs2[i] = reduceToQa(BigNumberMultiplication(res2[1].coeffs2[i], reduceToQa(BigNumberMultiplication((pp.paramQA+1)/2, R3))))
		res2[2].coeffs2[i] = reduceToQa(BigNumberMultiplication(res2[2].coeffs2[i], reduceToQa(BigNumberMultiplication((pp.paramQA+1)/2, R7))))
	}
	for i := 0; i < 64; i++ {
		res1[1].coeffs2[i+64] = res1[1].coeffs2[i]
		res1[1].coeffs2[i] = reduceToQa(BigNumberMultiplication(res1[1].coeffs2[i], -R6))

		res1[2].coeffs2[i+64] = reduceToQa(-res1[2].coeffs2[i])
		res1[2].coeffs2[i] = reduceToQa(-BigNumberMultiplication(res1[2].coeffs2[i], R6))

		res2[1].coeffs2[i+64] = res2[1].coeffs2[i]
		res2[1].coeffs2[i] = reduceToQa(BigNumberMultiplication(res2[1].coeffs2[i], -R2))

		res2[2].coeffs2[i+64] = reduceToQa(-res2[2].coeffs2[i])
		res2[2].coeffs2[i] = reduceToQa(-BigNumberMultiplication(res2[2].coeffs2[i], R2))
	}

	//compute z1,z2
	res[1] = PolyAdd(res1[1], res1[2], R_QA)
	res[2] = PolyAdd(res2[1], res2[2], R_QA)
	for i := 0; i < 128; i++ {
		res[1].coeffs2[i] = reduceToQa(BigNumberMultiplication(res[1].coeffs2[i], reduceToQa(BigNumberMultiplication((pp.paramQA+1)/2, R2))))
		res[2].coeffs2[i] = reduceToQa(BigNumberMultiplication(res[2].coeffs2[i], reduceToQa(BigNumberMultiplication((pp.paramQA+1)/2, R6))))
	}
	for i := 0; i < 128; i++ {
		res[1].coeffs2[i+128] = res[1].coeffs2[i]
		res[1].coeffs2[i] = reduceToQa(BigNumberMultiplication(res[1].coeffs2[i], -R4))
		res[2].coeffs2[i+128] = reduceToQa(-res[2].coeffs2[i])
		res[2].coeffs2[i] = reduceToQa(-BigNumberMultiplication(res[2].coeffs2[i], R4))
	}
	ret := PolyAdd(res[1], res[2], R_QA)
	for i := 0; i < pp.paramDA; i++ {
		ret.coeffs2[i] = reduceToQa(BigNumberMultiplication(ret.coeffs2[i], BigNumberMultiplication((pp.paramQA+1)/2, R4)))
	}
	return ret
}
*/
//	todo: implement NTT on non-fully-spliting ring end

//	todo:
var zetaAs = []int64{
	0,	1,	2,	3,	4,	5,	6,	7,	8,	9,	10,	11,	12,	13,	14,	15 }
