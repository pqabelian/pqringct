package pqringct

import (
	"math/big"
)

type PolyC struct {
	coeffs []int64
}
type PolyCNTT struct {
	nttcoeffs []int64
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
func (pp *PublicParameterv2) NewPolyCNTT() (*PolyCNTT)  {
	return &PolyCNTT{nttcoeffs: make([]int64, pp.paramDC)}
}
func (pp *PublicParameterv2) NewZeroPolyCNTT() (*PolyCNTT)  {
	rst := &PolyCNTT{nttcoeffs: make([]int64, pp.paramDC)}
	for i := 0; i < pp.paramDC; i++ {
		rst.nttcoeffs[i] = 0
	}
	return rst
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
	coeffs := make([]big.Int, pp.paramDC)
	for i := 0; i < len(polyC.coeffs); i++ {
		coeffs[i].SetInt64(polyC.coeffs[i])
	}

	//	NTT
	segNum := 1
	segLen := pp.paramDC
	factors := make([]int, 1)
	factors[0] = pp.paramDC / 2

	var tmp, xtmp, zetaTmp big.Int
	for {
		segLenHalf := segLen / 2
		for k := 0; k < segNum; k++ {
			zetaTmp.SetInt64(zetas[factors[k]])
			for i := 0; i < segLenHalf; i++ {
				//				tmpx := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp.Mul(&coeffs[k*segLen+i+segLenHalf], &zetaTmp)
				//				tmp1 := reduceToQc(int64(coeffs[k*segLen+i]) - tmp)
				xtmp.Sub(&coeffs[k*segLen+i], &tmp)
				//				coeffs[k*segLen+i] = tmp1
				coeffs[k*segLen+i].SetInt64(reduce(&xtmp, pp.paramQC))
				//				tmp2 := reduceToQc(int64(coeffs[k*segLen+i]) + tmp)
				xtmp.Add(&coeffs[k*segLen+i], &tmp)
				//				coeffs[k*segLen+i+segLenHalf] = tmp2
				coeffs[k*segLen+i+segLenHalf].SetInt64(reduce(&xtmp, pp.paramQC))
			}
		}
		segNum = segNum << 1
		segLen = segLen >> 1
		if segNum == pp.paramDC {
			break
		}
		tmpFactors := make([]int, 2*len(factors))
		for i := 0; i < len(factors); i++ {
			tmpFactors[2*i] = (factors[i] + pp.paramDC) / 2
			tmpFactors[2*i+1] = factors[i] / 2
		}
		factors = tmpFactors
	}

	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + pp.paramDC
		finalFactors[2*i+1] = factors[i]
	}
	nttCoeffs := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[(finalFactors[i]-1)/2] = coeffs[i].Int64()
	}
	return &PolyCNTT{nttcoeffs: nttCoeffs}
}

func (pp *PublicParameterv2) NTTInvPolyC(polyCNTT *PolyCNTT) (polyC *PolyC) {
	nttCoeffs := make([]big.Int, pp.paramDC)
	segNum := pp.paramDC
	segLen := 1
	factors := nttFactors

	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + pp.paramDC
		finalFactors[2*i+1] = factors[i]
	}
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[i].SetInt64( polyCNTT.nttcoeffs[(finalFactors[i]-1)/2] )
	}
	// twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
	var twoInv, tmp1, tmp2, tmpZeta big.Int
	twoInv.SetInt64((pp.paramQC+1)/2 - pp.paramQC)

	for {
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			tmpZeta.SetInt64( zetas[2*pp.paramDC-factors[k]] )
			for i := 0; i < segLen; i++ {
				//				tmp1 := reduceToQc(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])+int64(nttCoeffs[k*segLenDouble+i])) * twoInv)
				//				nttCoeffs[k*segLenDouble+i] = tmp1
				tmp1.Add(&nttCoeffs[k*segLenDouble+i+segLen],&nttCoeffs[k*segLenDouble+i])
				tmp1.Mul(&tmp1, &twoInv)
				nttCoeffs[k*segLenDouble+i].SetInt64(reduce(&tmp1, pp.paramQC))
				//				tmp2 := reduceToQc(pp.reduceInt64(pp.reduceInt64(int64(nttCoeffs[k*segLenDouble+i+segLen])-int64(nttCoeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
				//				nttCoeffs[k*segLenDouble+i+segLen] = tmp2
				tmp2.Sub(&nttCoeffs[k*segLenDouble+i+segLen], &nttCoeffs[k*segLenDouble+i])
				tmp2.Mul(&tmp2, &tmpZeta)
				nttCoeffs[k*segLenDouble+i+segLen].SetInt64(reduce(&tmp2, pp.paramQC))
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

	coeffs := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = nttCoeffs[i].Int64()
	}
	return &PolyC{coeffs: coeffs}
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
	if len(a.nttcoeffs) != len( b.nttcoeffs ) {
		return false
	}
	for i := 0; i < len(a.nttcoeffs); i++ {
		if a.nttcoeffs[i] != b.nttcoeffs[i] {
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
	if len(a.nttcoeffs) != pp.paramDC || len(b.nttcoeffs) != pp.paramDC {
		panic("the length of the input polyCNTT is not paramDC")
	}
	rst := pp.NewPolyCNTT()
	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.nttcoeffs[i])
		tmp2.SetInt64(b.nttcoeffs[i])
		tmp.Add(&tmp1, &tmp2)
		rst.nttcoeffs[i] = reduce(&tmp, pp.paramQC)
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTSub(a *PolyCNTT, b *PolyCNTT) (r *PolyCNTT) {
	if len(a.nttcoeffs) != pp.paramDC || len(b.nttcoeffs) != pp.paramDC {
		panic("the length of the input polyCNTT is not paramDC")
	}
	rst := pp.NewPolyCNTT()
	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.nttcoeffs[i])
		tmp2.SetInt64(b.nttcoeffs[i])
		tmp.Sub(&tmp1, &tmp2)
		rst.nttcoeffs[i] = reduce(&tmp, pp.paramQC)
	}
	return rst
}

func (pp *PublicParameterv2) PolyCNTTMul(a *PolyCNTT, b *PolyCNTT) (r *PolyCNTT) {
	if len(a.nttcoeffs) != pp.paramDC || len(b.nttcoeffs) != pp.paramDC {
		panic("the length of the input polyCNTT is not paramDC")
	}
	rst := pp.NewPolyCNTT()
	var tmp, tmp1, tmp2 big.Int
	for i := 0; i < pp.paramDC; i++ {
		tmp1.SetInt64(a.nttcoeffs[i])
		tmp2.SetInt64(b.nttcoeffs[i])
		tmp.Mul(&tmp1, &tmp2)
		rst.nttcoeffs[i] = reduce(&tmp, pp.paramQC)
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

func (pp *PublicParameterv2) sigmaPowerPolyNTT(polyCNTT *PolyCNTT, t int) (r *PolyCNTT) {
	rst := pp.NewPolyCNTT()
	for i := 0; i < pp.paramDC; i++ {
		rst.nttcoeffs[i] = polyCNTT.nttcoeffs[pp.paramSigmaPermutations[t][i]]
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
		rst.coeffs[i] = reduce(&tmpx, pp.paramQC)
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
		rst.coeffs[i] = reduce(&tmpx, pp.paramQC)
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

/*
q is assumed to be an odd number
*/
func reduce(a *big.Int, q int64) int64  {
	var b, rst big.Int

	b.SetInt64(q)

	// make sure a is positive, so that the initial remainder is positive
	if a.Sign() < 0 {
		rst.Add(a, &b)
	}
	rst.Mod(&rst, &b)

	r := rst.Int64()

	//	make sure the result in the scope [-(q-1)/2, (q-1)/2]
	if r > ((q-1) >> 1) {
		r = r - q
	}
	return r
}
