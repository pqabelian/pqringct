package pqringct

/**
Note we do everything on Ring over some PublicParameter.
*/
// Poly why do export?
type Poly struct {
	coeffs []int32
}

func NewPoly(length int) *Poly {
	res := make([]int32, length)
	return &Poly{coeffs: res}
}

/*
The NTT-form poly in a fully-splitting ring
*/
type PolyNTT struct {
	coeffs []int32
}

func NewPolyNTT(length int) *PolyNTT {
	res := make([]int32, length)
	return &PolyNTT{coeffs: res}
}

// NewPoly create a struct with coeffs and if the length of coeffs must be more than parameter D of Public Parameter
func (pp *PublicParameter) NewPoly(coeffs []int32) *Poly {
	tmp := make([]int32, pp.paramD)
	for i := 0; i < len(tmp); i++ {
		tmp[i] = coeffs[i]
	}
	return &Poly{coeffs: tmp}
}

/*
	todo: output a Poly with all coefficients are 0.
*/
func (pp *PublicParameter) NewZeroPoly() (r *Poly) {
	return
}

func (pp *PublicParameter) NTT(poly *Poly) (polyntt *PolyNTT) {
	coeffs := make([]int32, pp.paramD)

	var x int64

	zeta := int64(pp.paramZeta)
	zeta2 := int64(pp.reduce(zeta * zeta)) // zeta^2
	for i := 0; i < pp.paramD; i++ {
		// rst[i] = a_0 + a_1 ((pp.paramZeta)^{2i+1})^1 + a_2 ((pp.paramZeta)^{2i+1})^2 + ... + a_j ((pp.paramZeta)^{2i+1})^j + ... + a_{d-1} () ((pp.paramZeta)^{2i+1})^{d-1}
		//	rst[0] : (pp.paramZeta)^{1};
		//	rst[1] : (pp.paramZeta)^{3}
		//	...
		//	rst[d-1] : (pp.paramZeta)^{2d-1}

		coeffs[i] = 0
		x = int64(1)
		for j := 0; j < pp.paramD; j++ {
			coeffs[i] = pp.reduce(int64(coeffs[i]) + int64(pp.reduce(int64(poly.coeffs[j])*x)))

			x = x * zeta
		}

		zeta = int64(pp.reduce(zeta * zeta2)) // zeta = pp.paramZeta, pp.paramZeta^3, pp.paramZeta^5, ..., pp.paramZeta^{2d-1}
	}

	return &PolyNTT{coeffs: coeffs}
}

/*
todo:
*/
func (pp *PublicParameter) NTTInv(polyntt *PolyNTT) (poly *Poly) {
	return nil
}

/*
Transfer a vector of polys to a vector of polyNTTs
*/
func (pp *PublicParameter) NTTVec(polyVec *PolyVec) (polyNTTVec *PolyNTTVec) {
	if polyVec == nil {
		return nil
	}

	r := &PolyNTTVec{}
	r.polyNTTs = make([]*PolyNTT, len(polyVec.polys))

	for i := 0; i < len(polyVec.polys); i++ {
		r.polyNTTs[i] = pp.NTT(polyVec.polys[i])
	}

	return r
}

func (pp *PublicParameter) NTTInvVec(polyNTTVec *PolyNTTVec) (polyVec *PolyVec) {
	if polyNTTVec == nil {
		return nil
	}

	r := &PolyVec{}
	r.polys = make([]*Poly, len(polyNTTVec.polyNTTs))

	for i := 0; i < len(polyNTTVec.polyNTTs); i++ {
		r.polys[i] = pp.NTTInv(polyNTTVec.polyNTTs[i])
	}

	return r
}

func (pp *PublicParameter) PolyAdd(a *Poly, b *Poly) (r *Poly) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) + int64(b.coeffs[i]))
	}
	return &Poly{coeffs: coeffs}
}

func (pp *PublicParameter) PolySub(a *Poly, b *Poly) (r *Poly) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) - int64(b.coeffs[i]))
	}
	return &Poly{coeffs: coeffs}
}

func (pp *PublicParameter) PolyMul(a *Poly, b *Poly) (r *Poly) {
	var antt = pp.NTT(a)
	var bntt = pp.NTT(b)
	var rntt = pp.PolyNTTMul(antt, bntt)

	return pp.NTTInv(rntt)
}

/*
	todo: output a PolyNTT with all coefficients are 0.
*/
func (pp *PublicParameter) NewZeroPolyNTT() (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	return &PolyNTT{coeffs}
}

/*
todo： utput a PolyNTTVec with all polyNTTs are zero-PolyNTT.
*/
func (pp *PublicParameter) NewZeroPolyNTTVec(vecLen int) (r *PolyNTTVec) {
	return
}

func (pp *PublicParameter) PolyNTTAdd(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) + int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

func (pp *PublicParameter) PolyNTTSub(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) - int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

func (pp *PublicParameter) PolyNTTMul(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

func (pp *PublicParameter) PolyNTTPower(a *PolyNTT, e uint) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	// todo
	for i := 0; i < pp.paramD; i++ {

	}
	return &PolyNTT{coeffs: coeffs}
}

func (pp *PublicParameter) PolyNTTEqualCheck(a *PolyNTT, b *PolyNTT) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if len(a.coeffs) != pp.paramD || len(b.coeffs) != pp.paramD {
		return false
	}

	for i := 0; i < pp.paramD; i++ {
		if a.coeffs[i] != b.coeffs[i] {
			return false
		}
	}

	return true
}

func (pp *PublicParameter) PolyNTTVecAdd(a *PolyNTTVec, b *PolyNTTVec, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = pp.PolyNTTAdd(a.polyNTTs[i], b.polyNTTs[i])
	}

	return rst
}

func (pp *PublicParameter) PolyNTTVecSub(a *PolyNTTVec, b *PolyNTTVec, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = pp.PolyNTTSub(a.polyNTTs[i], b.polyNTTs[i])
	}

	return rst
}

func (pp *PublicParameter) PolyNTTVecEqualCheck(a *PolyNTTVec, b *PolyNTTVec) (eq bool) {
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
		if pp.PolyNTTEqualCheck(a.polyNTTs[i], b.polyNTTs[i]) != true {
			return false
		}
	}

	return true
}

func (pp *PublicParameter) PolyNTTVecScaleMul(polyNTTScale *PolyNTT, polyNTTVec *PolyNTTVec, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = pp.PolyNTTMul(polyNTTScale, polyNTTVec.polyNTTs[i])
	}
	return rst
}

func (pp *PublicParameter) PolyNTTVecInnerProduct(a *PolyNTTVec, b *PolyNTTVec, vecLen int) (r *PolyNTT) {
	rst := pp.NewZeroPolyNTT()
	for i := 0; i < vecLen; i++ {
		rst = pp.PolyNTTAdd(rst, pp.PolyNTTMul(a.polyNTTs[i], b.polyNTTs[i]))
	}

	return rst
}

func (pp *PublicParameter) PolyNTTMatrixMulVector(M []*PolyNTTVec, vec *PolyNTTVec, rowNum int, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, rowNum)
	for i := 0; i < rowNum; i++ {
		rst.polyNTTs[i] = pp.PolyNTTVecInnerProduct(M[i], vec, vecLen)
	}
	return rst
}

func (p *Poly) infNorm() (infNorm int32) {
	rst := int32(0)
	for _, coeff := range p.coeffs {
		if coeff > rst {
			rst = coeff
		} else if coeff < 0 && -coeff > rst {
			rst = -coeff
		}
	}

	return rst
}

func (pv *PolyVec) infNorm() (infNorm int32) {
	rst := int32(0)
	for _, p := range pv.polys {
		tmp := p.infNorm()
		if tmp > rst {
			rst = tmp
		}
	}

	return rst
}

//	private functions	begin

//	private functions	end
