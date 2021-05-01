package pqringct

type Poly struct {
	// the length must be paramD
	coeffs []int32
}

func (poly *Poly) NTT() (polyntt *PolyNTT) {
	return nil
}

func PolyAdd(pp *PublicParameter, a *Poly, b *Poly) (r *Poly) {
	var ret Poly
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) + int64(b.coeffs[i])
		ret.coeffs[i] = reduce(pp, tmp)
	}
	return &ret
}

func PolySub(pp *PublicParameter, a *Poly, b *Poly) (r *Poly) {
	var ret Poly
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) - int64(b.coeffs[i])
		ret.coeffs[i] = reduce(pp, tmp)
	}
	return &ret
}

func PolyMul(pp *PublicParameter, a *Poly, b *Poly) (r *Poly) {
	var antt = a.NTT()
	var bntt = b.NTT()

	var rntt = PolyNTTMul(pp, antt, bntt)

	return rntt.NTTInv()
}

/*
The NTT-form poly in a fully-splitting ring
*/
type PolyNTT struct {
	coeffs [PP_d]int32
}

func (polyntt *PolyNTT) NTTInv() (poly *Poly) {
	return nil
}

func PolyNTTAdd(pp *PublicParameter, a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	var ret PolyNTT
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) + int64(b.coeffs[i])
		ret.coeffs[i] = reduce(pp, tmp)
	}
	return &ret
}

func PolyNTTSub(pp *PublicParameter, a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	var ret PolyNTT
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) - int64(b.coeffs[i])
		ret.coeffs[i] = reduce(pp, tmp)
	}
	return &ret
}

func PolyNTTMul(pp *PublicParameter, a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	var ret PolyNTT
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) * int64(b.coeffs[i])
		ret.coeffs[i] = reduce(pp, tmp)
	}
	return &ret
}
