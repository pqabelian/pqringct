package pqringct

/**
Note we do everything on Ring over some PublicParameter.
*/
// Poly why do export?
type Poly struct {
	coeffs []int32
}

// NewPoly create a struct with coeffs and if the length of coeffs must be more than parameter D of Public Parameter
func (pp *PublicParameter) NewPoly(coeffs []int32) *Poly {
	tmp := make([]int32, pp.paramD)
	for i := 0; i < len(tmp); i++ {
		tmp[i] = coeffs[i]
	}
	return &Poly{coeffs: tmp}
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
The NTT-form poly in a fully-splitting ring
*/
type PolyNTT struct {
	coeffs []int32
}

/*
	todo: output a PolyNTT with all coefficients are 0.
 */
func NewZeroPolyNTT() (r *PolyNTT) {
	return nil
}

/*
todo:
*/
func (pp *PublicParameter) NTTInv(polyntt *PolyNTT) (poly *Poly) {
	return nil
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

func (pp *PublicParameter) PolyNTTVecInnerProduct(a *PolyNTTVec, b *PolyNTTVec, len int) (r *PolyNTT) {
	r = NewZeroPolyNTT()
	for i := 0; i < len; i++ {
		r = pp.PolyNTTAdd(r, pp.PolyNTTMul(a.vec[i], b.vec[i]))
	}

	return r
}


//	private functions	begin
func (pp *PublicParameter) reduce(a int64) int32 {
	qm := int64(pp.paramQm)

	rst := a % int64(pp.paramQ)

	if rst > qm {
		rst = rst - qm
	} else if rst < -qm {
		rst = rst + qm
	}

	return int32(rst)
}

//	private functions	end