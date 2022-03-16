package pqringct

import (
	"math/big"
)

type PolyC struct {
	coeffs []int64
}
type PolyCNTT struct {
	coeffs []int64
}
type PolyCVec struct {
	polyCs []*PolyC
}
type PolyCNTTVec struct {
	polyCNTTs []*PolyCNTT
}

func (pp *PublicParameterv2) NewPolyC() (*PolyC)  {
	return &PolyC{coeffs: make([]int64, pp.paramDC)}
}
func (pp *PublicParameterv2) NewZeroPolyC() (*PolyC)  {
	rst := &PolyC{coeffs: make([]int64, pp.paramDC)}
	for i := 0; i < pp.paramDC; i++ {
		rst.coeffs[i] = 0
	}
	return rst
}
func (pp *PublicParameterv2) NewPolyCNTT() (*PolyCNTT)  {
	return &PolyCNTT{coeffs: make([]int64, pp.paramDC)}
}
func (pp *PublicParameterv2) NewZeroPolyCNTT() (*PolyCNTT)  {
	rst := &PolyCNTT{coeffs: make([]int64, pp.paramDC)}
	for i := 0; i < pp.paramDC; i++ {
		rst.coeffs[i] = 0
	}
	return rst
}

func (pp *PublicParameterv2) NewZeroPolyCNTTVec(vecLen int) (*PolyCNTTVec)  {
	polyCNTTs := make([]*PolyCNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polyCNTTs[i] = pp.NewZeroPolyCNTT()
	}
	return &PolyCNTTVec{polyCNTTs}
}

func (polyC *PolyC) infNorm() (infNorm int64) {
	rst := int64(0)
	for _, coeff := range polyC.coeffs {
		if coeff > rst {
			rst = coeff
		} else if coeff < 0 && -coeff > rst {
			rst = -coeff
		}
	}
	return rst
}

func (polyCVec *PolyCVec) infNorm() (infNorm int64) {
	rst := int64(0)
	for _, p := range polyCVec.polyCs {
		tmp := p.infNorm()
		if tmp > rst {
			rst = tmp
		}
	}
	return rst
}

func (pp *PublicParameterv2) NTTPolyC(polyC *PolyC) *PolyCNTT {
	//	NTT
	zetaCOrder := 2 * pp.paramDC	//	todo: this should be set as a system parameter, together with zetaCs[], decided by d_c, q_c
	slotNum := zetaCOrder / 2	// fully splitting
	segNum := 1
	segLen := pp.paramDC
	factors := make([]int, 1)
	factors[0] = slotNum / 2

	coeffs := make([]big.Int, pp.paramDC)
	for i := 0; i < len(polyC.coeffs); i++ {
		coeffs[i].SetInt64(polyC.coeffs[i])
	}
	var tmp, tmp1, tmp2, zetaTmp big.Int
	for {
		segLenHalf := segLen / 2
		for k := 0; k < segNum; k++ {
			zetaTmp.SetInt64(zetas[factors[k]])
			for i := 0; i < segLenHalf; i++ {
				//				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp.Mul(&coeffs[k*segLen+i+segLenHalf], &zetaTmp)
				//				tmp1 := reduceToQc(int64(coeffs[k*segLen+i]) - tmp)
				tmp1.Sub(&coeffs[k*segLen+i], &tmp)
				//				coeffs[k*segLen+i] = tmp1
				coeffs[k*segLen+i].SetInt64(reduceBigInt(&tmp1, pp.paramQC))
				//				tmp2 := reduceToQc(int64(coeffs[k*segLen+i]) + tmp)
				tmp2.Add(&coeffs[k*segLen+i], &tmp)
				//				coeffs[k*segLen+i+segLenHalf] = tmp2
				coeffs[k*segLen+i+segLenHalf].SetInt64(reduceBigInt(&tmp2, pp.paramQC))
			}
		}
		segNum = segNum << 1
		segLen = segLen >> 1
		if segNum == slotNum {
			break
		}
		tmpFactors := make([]int, 2*len(factors))
		for i := 0; i < len(factors); i++ {
			tmpFactors[2*i] = (factors[i] + pp.paramDC) / 2
			tmpFactors[2*i+1] = factors[i] / 2
		}
		factors = tmpFactors
	}

/*	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + pp.paramDC
		finalFactors[2*i+1] = factors[i]
	}

	nttCoeffs := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[(finalFactors[i]-1)/2] = coeffs[i].Int64()
	}
	return &PolyCNTT{coeffs: nttCoeffs}*/

	rst := pp.NewPolyCNTT()
	for i := 0; i < pp.paramDC; i++ {
		rst.coeffs[i] = coeffs[i].Int64()
	}
	return rst
}

//	todo: this should be set as a system parameter, together with zetaCs[], decided by d_c, q_c
var nttCFactors = []int{
	127, 63, 95, 31, 111, 47, 79, 15, 119, 55, 87, 23,
	103, 39, 71, 7, 123, 59, 91, 27, 107, 43, 75, 11, 115,
	51, 83, 19, 99, 35, 67, 3, 125, 61, 93, 29, 109, 45, 77, 13,
	117, 53, 85, 21, 101, 37, 69, 5, 121, 57, 89, 25, 105, 41, 73,
	9, 113, 49, 81, 17, 97, 33, 65, 1,
}

func (pp *PublicParameterv2) NTTInvPolyC(polyCNTT *PolyCNTT) (polyC *PolyC) {
	//	NTT Inverse
	zetaCOrder := 2 * pp.paramDC	//	todo: this should be set as a system parameter, together with zetaCs[], decided by d_c, q_c
	slotNum := zetaCOrder / 2 //	have been factored to irreducible factors, i.e., fully splitting
	segNum := slotNum
	segLen := 1
	factors := nttFactors

/*	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + pp.paramDC
		finalFactors[2*i+1] = factors[i]
	}
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[i].SetInt64( polyCNTT.coeffs[(finalFactors[i]-1)/2] )
	}*/

	nttCoeffs := make([]big.Int, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[i].SetInt64( polyCNTT.coeffs[i] )
	}
	// twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
	var twoInv, tmp1, tmp2, tmpZetaInv big.Int
	twoInv.SetInt64((pp.paramQC+1)/2 - pp.paramQC)

	for {
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			// tmpZeta.SetInt64( zetas[2*pp.paramDC-factors[k]] )
			tmpZetaInv.SetInt64( zetas[zetaCOrder - factors[k]] )
			for i := 0; i < segLen; i++ {
				//				tmp1 := reduceToQc(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])+int64(nttCoeffs[k*segLenDouble+i])) * twoInv)
				//				nttCoeffs[k*segLenDouble+i] = tmp1
				tmp1.Add(&nttCoeffs[k*segLenDouble+i+segLen],&nttCoeffs[k*segLenDouble+i])
				tmp1.Mul(&tmp1, &twoInv)
				nttCoeffs[k*segLenDouble+i].SetInt64(reduceBigInt(&tmp1, pp.paramQC))
				//				tmp2 := reduceToQc(pp.reduceInt64(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])-int64(nttCoeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
				//				nttCoeffs[k*segLenDouble+i+segLen] = tmp2
				tmp2.Sub(&nttCoeffs[k*segLenDouble+i+segLen], &nttCoeffs[k*segLenDouble+i])
				tmp2.Mul(&tmp2, &twoInv)
				tmp2.Mul(&tmp2, &tmpZetaInv)
				nttCoeffs[k*segLenDouble+i+segLen].SetInt64(reduceBigInt(&tmp2, pp.paramQC))
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

	rst := pp.NewPolyC()
	for i := 0; i < pp.paramDC; i++ {
		rst.coeffs[i] = nttCoeffs[i].Int64()
	}
	return rst
}


func PolyCEqualCheck(a *PolyC, b *PolyC) (eq bool) {
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

func PolyCNTTEqualCheck(a *PolyCNTT, b *PolyCNTT) (eq bool) {
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

func PolyCNTTVecEqualCheck(a *PolyCNTTVec, b *PolyCNTTVec) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if a.polyCNTTs == nil || b.polyCNTTs == nil {
		return false
	}

	if len(a.polyCNTTs) != len(b.polyCNTTs) {
		return false
	}

	for i := 0; i < len(a.polyCNTTs); i++ {
		if !PolyCNTTEqualCheck(a.polyCNTTs[i], b.polyCNTTs[i]) {
			return false
		}
	}

	return true
}


func (pp *PublicParameterv2) NewPolyCVec(vecLen int) *PolyCVec {
	polys := make([]*PolyC, vecLen)
	for i := 0; i < vecLen; i++ {
		polys[i] = pp.NewPolyC()
	}
	return &PolyCVec{polyCs: polys}
}

func (pp *PublicParameterv2) NewPolyCNTTVec(vecLen int) *PolyCNTTVec {
	polyNTTs := make([]*PolyCNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polyNTTs[i] = pp.NewPolyCNTT()
	}
	return &PolyCNTTVec{polyCNTTs: polyNTTs}
}


func (pp *PublicParameterv2) NTTPolyCVec(polyCVec *PolyCVec) *PolyCNTTVec {
	if polyCVec == nil {
		return nil
	}

	r := &PolyCNTTVec{}
	r.polyCNTTs = make([]*PolyCNTT, len(polyCVec.polyCs))

	for i := 0; i < len(polyCVec.polyCs); i++ {
		r.polyCNTTs[i] = pp.NTTPolyC(polyCVec.polyCs[i])
	}
	return r
}

func (pp *PublicParameterv2) NTTInvPolyCVec(polyCNTTVec *PolyCNTTVec) (polyCVec *PolyCVec) {
	if polyCNTTVec == nil {
		return nil
	}

	r := &PolyCVec{}
	r.polyCs = make([]*PolyC, len(polyCNTTVec.polyCNTTs))

	for i := 0; i < len(polyCNTTVec.polyCNTTs); i++ {
		r.polyCs[i] = pp.NTTInvPolyC(polyCNTTVec.polyCNTTs[i])
	}

	return r
}


func (pp *PublicParameterv2) PolyCNTTAdd(a *PolyCNTT, b *PolyCNTT) (r *PolyCNTT) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		panic("the length of the input polyCNTT is not paramDC")
	}
	rst := pp.NewPolyCNTT()
	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmp.Add(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQC)
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTSub(a *PolyCNTT, b *PolyCNTT) (r *PolyCNTT) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		panic("the length of the input polyCNTT is not paramDC")
	}
	rst := pp.NewPolyCNTT()
	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmp.Sub(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQC)
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTMul(a *PolyCNTT, b *PolyCNTT) (r *PolyCNTT) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		panic("the length of the input polyCNTT is not paramDC")
	}
	rst := pp.NewPolyCNTT()
	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmp.Mul(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmp, pp.paramQC)
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTVecAdd(a *PolyCNTTVec, b *PolyCNTTVec, vecLen int) (r *PolyCNTTVec) {
	var rst = pp.NewPolyCNTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyCNTTs[i]= pp.PolyCNTTAdd(a.polyCNTTs[i], b.polyCNTTs[i])
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTVecSub(a *PolyCNTTVec, b *PolyCNTTVec, vecLen int) (r *PolyCNTTVec) {
	var rst = pp.NewPolyCNTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyCNTTs[i]= pp.PolyCNTTSub(a.polyCNTTs[i], b.polyCNTTs[i])
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTVecInnerProduct(a *PolyCNTTVec, b *PolyCNTTVec, vecLen int) (r *PolyCNTT) {
	var rst = pp.NewZeroPolyCNTT()
	for i := 0; i < vecLen; i++ {
		tmp := pp.PolyCNTTMul(a.polyCNTTs[i], b.polyCNTTs[i])
		rst = pp.PolyCNTTAdd(rst, tmp)
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTMatrixMulVector(M []*PolyCNTTVec, vec *PolyCNTTVec, rowNum int, vecLen int) (r *PolyCNTTVec) {
	rst := &PolyCNTTVec{}
	rst.polyCNTTs = make([]*PolyCNTT, rowNum)
	for i := 0; i < rowNum; i++ {
		rst.polyCNTTs[i] = pp.PolyCNTTVecInnerProduct(M[i], vec, vecLen)
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTVecScaleMul(polyCNTTScale *PolyCNTT, polyCNTTVec *PolyCNTTVec, vecLen int) (r *PolyCNTTVec) {
	if polyCNTTScale == nil || polyCNTTVec == nil {
		return nil
	}
	if vecLen > len(polyCNTTVec.polyCNTTs) {
		panic("vecLen is bigger than the length of polyCNTTVec")
	}

	rst := pp.NewPolyCNTTVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyCNTTs[i] = pp.PolyCNTTMul(polyCNTTScale, polyCNTTVec.polyCNTTs[i])
	}
	return rst
}

// todo
func (pp *PublicParameterv2) sigmaPowerPolyCNTT(polyCNTT *PolyCNTT, t int) (r *PolyCNTT) {
	rst := pp.NewPolyCNTT()
	for i := 0; i < pp.paramDC; i++ {
		rst.coeffs[i] = polyCNTT.coeffs[pp.paramSigmaPermutations[t][i]]
	}
	return rst
}


func (pp *PublicParameterv2) PolyCAdd(a *PolyC, b *PolyC) (r *PolyC) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		panic("the length of the input polyCNTT is not paramDC")
	}

	rst := pp.NewPolyC()
	var tmp1, tmp2, tmpx big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmpx.Add(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmpx, pp.paramQC)
	}

	return rst
}

func (pp *PublicParameterv2) PolyCSub(a *PolyC, b *PolyC) (r *PolyC) {
	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		panic("the length of the input polyCNTT is not paramDC")
	}

	rst := pp.NewPolyC()
	var tmp1, tmp2, tmpx big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.coeffs[i])
		tmp2.SetInt64(b.coeffs[i])
		tmpx.Sub(&tmp1, &tmp2)
		rst.coeffs[i] = reduceBigInt(&tmpx, pp.paramQC)
	}

	return rst
}

func (pp *PublicParameterv2) PolyCVecAdd(a *PolyCVec, b *PolyCVec, vecLen int) (r *PolyCVec) {
	if len(a.polyCs) != len(b.polyCs) {
		panic("the two input polyCVecs have different length")
	}
	rst := pp.NewPolyCVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyCs[i] = pp.PolyCAdd(a.polyCs[i], b.polyCs[i])
	}
	return rst
}

func (pp *PublicParameterv2) PolyCVecSub(a *PolyCVec, b *PolyCVec, vecLen int) (r *PolyCVec) {
	if len(a.polyCs) != len(b.polyCs) {
		panic("the two input polyCVecs have different length")
	}
	rst := pp.NewPolyCVec(vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyCs[i] = pp.PolyCAdd(a.polyCs[i], b.polyCs[i])
	}
	return rst
}



