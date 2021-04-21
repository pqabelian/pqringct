package pqringct

type Poly struct {
	coeffs [PP_d]int32
}

func (poly *Poly) NTT() (polyntt *PolyNTT) {
	return nil
}

func PolyAdd(a *Poly, b *Poly) (r *Poly) {
	var ret Poly
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) + int64(b.coeffs[i])
		ret.coeffs[i] = reduce(tmp)
	}
	return &ret
}

func PolySub(a *Poly, b *Poly) (r *Poly) {
	var ret Poly
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) - int64(b.coeffs[i])
		ret.coeffs[i] = reduce(tmp)
	}
	return &ret
}

func PolyMul(a *Poly, b *Poly) (r *Poly) {
	var antt = a.NTT()
	var bntt = b.NTT()

	var rntt = PolyNTTMul(antt, bntt)

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

func PolyNTTAdd(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	var ret PolyNTT
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) + int64(b.coeffs[i])
		ret.coeffs[i] = reduce(tmp)
	}
	return &ret
}

func PolyNTTSub(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	var ret PolyNTT
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) - int64(b.coeffs[i])
		ret.coeffs[i] = reduce(tmp)
	}
	return &ret
}

func PolyNTTMul(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	var ret PolyNTT
	var tmp int64
	for i := 0; i < PP_d; i++ {
		tmp = int64(a.coeffs[i]) * int64(b.coeffs[i])
		ret.coeffs[i] = reduce(tmp)
	}
	return &ret
}

//	private functions	begin
func reduce(a int64) int32 {
	var tmp int64
	tmp = a % PP_q
	if tmp > PP_q_m {
		tmp = tmp - PP_q
	} else if tmp < -PP_q_m {
		tmp = tmp + PP_q
	}

	return int32(tmp)
}

//	private functions	end
