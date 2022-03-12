package pqringct

import "log"

type reduceType int

const (
	R_QC reduceType = iota
	R_QA
)

type Polyv2 struct {
	coeffs1 []int32
	coeffs2 []int64
}
type PolyNTTv2 struct {
	coeffs1 []int32
	coeffs2 []int64
}
type PolyVecv2 struct {
	polys []*Polyv2
}

type PolyNTTVecv2 struct {
	polyNTTs []*PolyNTTv2
}

func NewPolyv2(rtp reduceType, length int) *Polyv2 {
	switch rtp {
	case R_QC:
		return &Polyv2{coeffs1: make([]int32, length)}
	case R_QA:
		return &Polyv2{coeffs2: make([]int64, length)}
	default:
		log.Fatalln("Unsupported type for reducing")
		return nil
	}
}
func NewPolyNTTv2(rtp reduceType, length int) *PolyNTTv2 {
	switch rtp {
	case R_QC:
		return &PolyNTTv2{coeffs1: make([]int32, length)}
	case R_QA:
		return &PolyNTTv2{coeffs2: make([]int64, length)}
	default:
		log.Fatalln("Unsupported type for reducing")
		return nil
	}
}

func (p *Polyv2) infNormQc() (infNorm int32) {
	rst := int32(0)
	for _, coeff := range p.coeffs1 {
		if coeff > rst {
			rst = coeff
		} else if coeff < 0 && -coeff > rst {
			rst = -coeff
		}
	}
	return rst
}
func (p *Polyv2) infNormQa() (infNorm int64) {
	rst := int64(0)
	for _, coeff := range p.coeffs2 {
		if coeff > rst {
			rst = coeff
		} else if coeff < 0 && -coeff > rst {
			rst = -coeff
		}
	}
	return rst
}
func (pv *PolyVecv2) infNormQc() (infNorm int32) {
	rst := int32(0)
	for _, p := range pv.polys {
		tmp := p.infNormQc()
		if tmp > rst {
			rst = tmp
		}
	}

	return rst
}
func (pv *PolyVecv2) infNormQa() (infNorm int64) {
	rst := int64(0)
	for _, p := range pv.polys {
		tmp := p.infNormQa()
		if tmp > rst {
			rst = tmp
		}
	}

	return rst
}
func (pp *PublicParameterv2) NTTInRQc(p *Polyv2) *PolyNTTv2 {
	coeffs := make([]int32, pp.paramDC)
	copy(coeffs, p.coeffs1)

	//	NTT
	segNum := 1
	segLen := pp.paramDC
	factors := make([]int, 1)
	factors[0] = pp.paramDC / 2

	for {
		segLenHalf := segLen / 2
		for k := 0; k < segNum; k++ {
			for i := 0; i < segLenHalf; i++ {
				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp1 := reduceToQc(int64(coeffs[k*segLen+i]) - tmp)
				tmp2 := reduceToQc(int64(coeffs[k*segLen+i]) + tmp)
				coeffs[k*segLen+i] = tmp1
				coeffs[k*segLen+i+segLenHalf] = tmp2
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
	nttCoeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[(finalFactors[i]-1)/2] = coeffs[i]
	}
	return &PolyNTTv2{coeffs1: nttCoeffs}
}
func (pp *PublicParameterv2) NTTInRQa(p *Polyv2) *PolyNTTv2 {
	panic("implement me")
	coeffs := make([]int32, pp.paramDC)
	copy(coeffs, p.coeffs1)

	//	NTT
	segNum := 1
	segLen := pp.paramDC
	factors := make([]int, 1)
	factors[0] = pp.paramDC / 2

	for {
		segLenHalf := segLen / 2
		for k := 0; k < segNum; k++ {
			for i := 0; i < segLenHalf; i++ {
				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp1 := reduceToQc(int64(coeffs[k*segLen+i]) - tmp)
				tmp2 := reduceToQc(int64(coeffs[k*segLen+i]) + tmp)
				coeffs[k*segLen+i] = tmp1
				coeffs[k*segLen+i+segLenHalf] = tmp2
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
	nttCoeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[(finalFactors[i]-1)/2] = coeffs[i]
	}
	return &PolyNTTv2{coeffs1: nttCoeffs}
}
func (pp *PublicParameterv2) NTTInvInRQc(polyntt *PolyNTTv2) (poly *Polyv2) {
	coeffs := make([]int32, pp.paramDC)
	segNum := pp.paramDC
	segLen := 1
	factors := nttFactors

	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + pp.paramDC
		finalFactors[2*i+1] = factors[i]
	}
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = polyntt.coeffs1[(finalFactors[i]-1)/2]
	}
	twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
	for {
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			for i := 0; i < segLen; i++ {
				tmp1 := reduceToQc(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen])+int64(coeffs[k*segLenDouble+i])) * twoInv)
				tmp2 := reduceToQc(pp.reduceInt64(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen])-int64(coeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
				coeffs[k*segLenDouble+i] = tmp1
				coeffs[k*segLenDouble+i+segLen] = tmp2
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
	return &Polyv2{coeffs1: coeffs}
}
func (pp *PublicParameterv2) NTTInvInRQa(polyntt *PolyNTTv2) (poly *Polyv2) {
	panic("implement me")
	coeffs := make([]int32, pp.paramDC)
	segNum := pp.paramDC
	segLen := 1
	factors := nttFactors

	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = factors[i] + pp.paramDC
		finalFactors[2*i+1] = factors[i]
	}
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = polyntt.coeffs1[(finalFactors[i]-1)/2]
	}
	twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
	for {
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			for i := 0; i < segLen; i++ {
				tmp1 := reduceToQc(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen])+int64(coeffs[k*segLenDouble+i])) * twoInv)
				tmp2 := reduceToQc(pp.reduceInt64(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen])-int64(coeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
				coeffs[k*segLenDouble+i] = tmp1
				coeffs[k*segLenDouble+i+segLen] = tmp2
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
	return &Polyv2{coeffs1: coeffs}
}

func (pp *PublicParameterv2) PolyEqualCheck(a *Polyv2, b *Polyv2, rtp reduceType) (eq bool) {
	if a == nil || b == nil {
		return false
	}
	switch rtp {
	case R_QC:
		if len(a.coeffs1) != pp.paramDC || len(b.coeffs1) != pp.paramDC {
			return false
		}

		for i := 0; i < pp.paramDC; i++ {
			if a.coeffs1[i] != b.coeffs1[i] {
				return false
			}
		}
	case R_QA:
		if len(a.coeffs2) != pp.paramDA || len(b.coeffs2) != pp.paramDA {
			return false
		}
		for i := 0; i < pp.paramDA; i++ {
			if a.coeffs2[i] != b.coeffs2[i] {
				return false
			}
		}
	default:
		panic("Unspported type")
		return false
	}
	return true
}
func (pp *PublicParameterv2) PolyNTTEqualCheck(a *PolyNTTv2, b *PolyNTTv2, rtp reduceType) (eq bool) {
	if a == nil || b == nil {
		return false
	}
	switch rtp {
	case R_QC:
		if len(a.coeffs1) != pp.paramDC || len(b.coeffs1) != pp.paramDC {
			return false
		}

		for i := 0; i < pp.paramDC; i++ {
			if a.coeffs1[i] != b.coeffs1[i] {
				return false
			}
		}
	case R_QA:
		if len(a.coeffs2) != pp.paramDA || len(b.coeffs2) != pp.paramDA {
			return false
		}
		for i := 0; i < pp.paramDA; i++ {
			if a.coeffs2[i] != b.coeffs2[i] {
				return false
			}
		}
	default:
		panic("Unspported type")
		return false
	}
	return true
}
func (pp *PublicParameterv2) PolyNTTVecEqualCheck(a *PolyNTTVecv2, b *PolyNTTVecv2, rtp reduceType) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if a.polyNTTs == nil || b.polyNTTs == nil {
		return false
	}

	if len(a.polyNTTs) != len(b.polyNTTs) {
		return false
	}

	for i := 0; i < len(a.polyNTTs); i++ {
		if !pp.PolyNTTEqualCheck(a.polyNTTs[i], b.polyNTTs[i], rtp) {
			return false
		}
	}

	return true
}
func NewPolyVecv2(rtp reduceType, length int, vecLen int) *PolyVecv2 {
	polys := make([]*Polyv2, vecLen)
	for i := 0; i < vecLen; i++ {
		polys[i] = NewPolyv2(rtp, length)
	}
	return &PolyVecv2{polys: polys}
}
func NewPolyNTTVecv2(rtp reduceType, length int, vecLen int) *PolyNTTVecv2 {
	polys := make([]*PolyNTTv2, vecLen)
	for i := 0; i < vecLen; i++ {
		polys[i] = NewPolyNTTv2(rtp, length)
	}
	return &PolyNTTVecv2{polyNTTs: polys}
}
func (pp *PublicParameterv2) NTTVecInRQc(p *PolyVecv2) *PolyNTTVecv2 {

	if p == nil {
		return nil
	}

	r := &PolyNTTVecv2{}
	r.polyNTTs = make([]*PolyNTTv2, len(p.polys))

	for i := 0; i < len(p.polys); i++ {
		r.polyNTTs[i] = pp.NTTInRQc(p.polys[i])
	}

	return r
}
func (pp *PublicParameterv2) NTTVecInRQa(p *PolyVecv2) *PolyNTTVecv2 {
	if p == nil {
		return nil
	}

	r := &PolyNTTVecv2{}
	r.polyNTTs = make([]*PolyNTTv2, len(p.polys))

	for i := 0; i < len(p.polys); i++ {
		r.polyNTTs[i] = pp.NTTInRQa(p.polys[i])
	}

	return r
}
func (pp *PublicParameterv2) NTTInvVecInRQc(polyNTTVec *PolyNTTVecv2) (polyVec *PolyVecv2) {
	if polyNTTVec == nil {
		return nil
	}

	r := &PolyVecv2{}
	r.polys = make([]*Polyv2, len(polyNTTVec.polyNTTs))

	for i := 0; i < len(polyNTTVec.polyNTTs); i++ {
		r.polys[i] = pp.NTTInvInRQc(polyNTTVec.polyNTTs[i])
	}

	return r
}
func (pp *PublicParameterv2) NTTInvVecInRQa(polyNTTVec *PolyNTTVecv2) (polyVec *PolyVecv2) {
	if polyNTTVec == nil {
		return nil
	}

	r := &PolyVecv2{}
	r.polys = make([]*Polyv2, len(polyNTTVec.polyNTTs))

	for i := 0; i < len(polyNTTVec.polyNTTs); i++ {
		r.polys[i] = pp.NTTInvInRQa(polyNTTVec.polyNTTs[i])
	}

	return r
}
func PolyNTTMatrixMulVector(M []*PolyNTTVecv2, vec *PolyNTTVecv2, rtp reduceType, rowNum int, vecLen int) (r *PolyNTTVecv2) {
	rst := &PolyNTTVecv2{}
	rst.polyNTTs = make([]*PolyNTTv2, rowNum)
	for i := 0; i < rowNum; i++ {
		rst.polyNTTs[i] = PolyNTTVecInnerProduct(M[i], vec, rtp, vecLen)
	}
	return rst
}
func (pp *PublicParameterv2) PolyMatrixMulVector(M []*PolyVecv2, vec *PolyVecv2, rtp reduceType, rowNum int, vecLen int) (r *PolyVecv2) {
	rst := &PolyVecv2{}
	rst.polys = make([]*Polyv2, rowNum)
	for i := 0; i < rowNum; i++ {
		rst.polys[i] = pp.PolyVecInnerProduct(M[i], vec, rtp, vecLen)
	}
	return rst
}
func PolyNTTVecInnerProduct(a *PolyNTTVecv2, b *PolyNTTVecv2, rtp reduceType, vecLen int) (r *PolyNTTv2) {
	var rst *PolyNTTv2
	switch rtp {
	case R_QC:
		rst = NewPolyNTTv2(rtp, len(a.polyNTTs[0].coeffs1))
	case R_QA:
		rst = NewPolyNTTv2(rtp, len(a.polyNTTs[0].coeffs2))
	default:
		log.Fatalln("Unsupported type")
	}

	for i := 0; i < vecLen; i++ {
		tmp := PolyNTTMul(a.polyNTTs[i], b.polyNTTs[i], rtp)
		rst = PolyNTTAdd(rst, tmp, rtp)
	}
	return rst
}
func (pp *PublicParameterv2) PolyVecInnerProduct(a *PolyVecv2, b *PolyVecv2, rtp reduceType, vecLen int) (r *Polyv2) {
	rst := NewPolyv2(R_QA, pp.paramDA)
	for i := 0; i < vecLen; i++ {
		rst = PolyAdd(rst, pp.Mul(a.polys[i], b.polys[i]), rtp)
	}
	return rst
}

// PolyAdd
// Please check the length before calling this function
// Otherwise will panic
func PolyAdd(a *Polyv2, b *Polyv2, rtp reduceType) *Polyv2 {
	switch rtp {
	case R_QC:
		if len(a.coeffs1) != len(b.coeffs1) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs1)
		coeffs := make([]int32, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQc(int64(a.coeffs1[i]) + int64(b.coeffs1[i]))
		}
		return &Polyv2{coeffs1: coeffs}
	case R_QA:
		if len(a.coeffs2) != len(b.coeffs2) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs2)
		coeffs := make([]int64, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQa(a.coeffs2[i] + b.coeffs2[i])
		}
		return &Polyv2{coeffs2: coeffs}
	default:
		log.Fatalln("Unsupported type for reducing")
		return nil
	}
}
func PolySub(a *Polyv2, b *Polyv2, rtp reduceType) *Polyv2 {
	switch rtp {
	case R_QC:
		if len(a.coeffs1) != len(b.coeffs1) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs1)
		coeffs := make([]int32, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQc(int64(a.coeffs1[i]) - int64(b.coeffs1[i]))
		}
		return &Polyv2{coeffs1: coeffs}
	case R_QA:
		if len(a.coeffs2) != len(b.coeffs2) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs2)
		coeffs := make([]int64, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQa(a.coeffs2[i] - b.coeffs2[i])
		}
		return &Polyv2{coeffs2: coeffs}
	default:
		log.Fatalln("Unsupported type for reducing")
		return nil
	}
}
func PolyVecAdd(a *PolyVecv2, b *PolyVecv2, rtp reduceType, vecLen int) (r *PolyVecv2) {
	rst := &PolyVecv2{}
	rst.polys = make([]*Polyv2, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polys[i] = PolyAdd(a.polys[i], b.polys[i], rtp)
	}
	return rst
}
func PolyVecSub(a *PolyVecv2, b *PolyVecv2, rtp reduceType, vecLen int) (r *PolyVecv2) {
	rst := &PolyVecv2{}
	rst.polys = make([]*Polyv2, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polys[i] = PolySub(a.polys[i], b.polys[i], rtp)
	}
	return rst
}

func PolyNTTAdd(a *PolyNTTv2, b *PolyNTTv2, rtp reduceType) *PolyNTTv2 {
	switch rtp {
	case R_QC:
		if len(a.coeffs1) != len(b.coeffs1) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs1)
		coeffs := make([]int32, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQc(int64(a.coeffs1[i]) + int64(b.coeffs1[i]))
		}
		return &PolyNTTv2{coeffs1: coeffs}
	case R_QA:
		if len(a.coeffs2) != len(b.coeffs2) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs2)
		coeffs := make([]int64, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQa(a.coeffs2[i] + b.coeffs2[i])
		}
		return &PolyNTTv2{coeffs2: coeffs}
	default:
		log.Fatalln("Unsupported type for reducing")
		return nil
	}
}
func PolyNTTVecAdd(a *PolyNTTVecv2, b *PolyNTTVecv2, rtp reduceType, vecLen int) (r *PolyNTTVecv2) {
	rst := &PolyNTTVecv2{}
	rst.polyNTTs = make([]*PolyNTTv2, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = PolyNTTAdd(a.polyNTTs[i], b.polyNTTs[i], rtp)
	}
	return rst
}

func PolyNTTSub(a *PolyNTTv2, b *PolyNTTv2, rtp reduceType) *PolyNTTv2 {
	switch rtp {
	case R_QC:
		if len(a.coeffs1) != len(b.coeffs1) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs1)
		coeffs := make([]int32, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQc(int64(a.coeffs1[i]) - int64(b.coeffs1[i]))
		}
		return &PolyNTTv2{coeffs1: coeffs}
	case R_QA:
		if len(a.coeffs2) != len(b.coeffs2) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs2)
		coeffs := make([]int64, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQa(a.coeffs2[i] - b.coeffs2[i])
		}
		return &PolyNTTv2{coeffs2: coeffs}
	default:
		log.Fatalln("Unsupported type for reducing")
		return nil
	}
}
func PolyNTTVecSub(a *PolyNTTVecv2, b *PolyNTTVecv2, rtp reduceType, vecLen int) (r *PolyNTTVecv2) {
	rst := &PolyNTTVecv2{}
	rst.polyNTTs = make([]*PolyNTTv2, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = PolyNTTSub(a.polyNTTs[i], b.polyNTTs[i], rtp)
	}
	return rst
}
func PolyNTTMul(a *PolyNTTv2, b *PolyNTTv2, rtp reduceType) (r *PolyNTTv2) {
	switch rtp {
	case R_QC:
		if len(a.coeffs1) != len(b.coeffs1) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs1)
		coeffs := make([]int32, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQc(int64(a.coeffs1[i]) * int64(b.coeffs1[i]))
		}
		return &PolyNTTv2{coeffs1: coeffs}
	case R_QA:
		if len(a.coeffs2) != len(b.coeffs2) {
			panic("the length of two poly is not equal")
		}
		length := len(a.coeffs2)
		coeffs := make([]int64, length)
		for i := 0; i < length; i++ {
			coeffs[i] = reduceToQa(a.coeffs2[i] * b.coeffs2[i])
		}
		return &PolyNTTv2{coeffs2: coeffs}
	default:
		log.Fatalln("Unsupported type for reducing")
		return nil
	}
}

func PolyNTTVecScaleMul(polyNTTScale *PolyNTTv2, polyNTTVec *PolyNTTVecv2, rtp reduceType, vecLen int) (r *PolyNTTVecv2) {
	rst := &PolyNTTVecv2{}
	rst.polyNTTs = make([]*PolyNTTv2, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = PolyNTTMul(polyNTTScale, polyNTTVec.polyNTTs[i], rtp)
	}
	return rst
}
func (pp *PublicParameterv2) PolyVecScaleMul(polyScale *Polyv2, polyVec *PolyVecv2, rtp reduceType, vecLen int) (r *PolyVecv2) {
	rst := &PolyVecv2{}
	rst.polys = make([]*Polyv2, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polys[i] = pp.Mul(polyScale, polyVec.polys[i])
	}
	return rst
}

func (pp *PublicParameterv2) sigmaPowerPolyNTT(polyNTT *PolyNTTv2, rtp reduceType, t int) (r *PolyNTTv2) {
	if rtp != R_QC {
		panic("Unsupported type")
	}
	coeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = polyNTT.coeffs1[pp.paramSigmaPermutations[t][i]]
	}
	return &PolyNTTv2{coeffs1: coeffs}
}

// TODO: check its functionality
func (pp *PublicParameterv2) reduceInt64(a int64) int64 {
	rst := a % int64(pp.paramQC)
	rst = (rst + int64(pp.paramQC)) % int64(pp.paramQC)
	if rst > int64(pp.paramQCm) {
		rst = rst - int64(pp.paramQC)
	}
	return rst
}

func reduceToQc(a int64) int32 {
	rst := a % 4294962689
	rst = (rst + 4294962689) % 4294962689
	if rst > 2147481344 {
		rst = rst - 4294962689
	}
	return int32(rst)
}

func reduceToQa(a int64) int64 {
	var tmp int64
	tmp = a % 34360786961
	if tmp > 17180393480 {
		tmp -= 34360786961
	}
	if tmp < -17180393480 {
		tmp += 34360786961
	}
	return tmp
}

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
