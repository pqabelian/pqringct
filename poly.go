package pqringct

/**
Note we do everything on Ring over some PublicParameter.
*/

// Poly uses coefficient notation to define a polynomial in Zq
type Poly struct {
	coeffs []int32
}

/*
The NTT-form poly in a fully-splitting ring
*/

// PolyNTT defines a polynomial in the NTT domain
type PolyNTT struct {
	coeffs []int32
}

// PolyVec defines a polynomial vector in Zq
type PolyVec struct {
	// the length must be paramLa?
	polys []*Poly
}

// PolyNTTVec defines a polynomial vector in the NTT domain
type PolyNTTVec struct {
	// the length must be paramLa?
	polyNTTs []*PolyNTT
}

// NewPoly creates a Poly with all coefficients are default initial value.
// If need to set the coefficients, please use the self-contained way in Golang.
func (pp *PublicParameter) NewPoly() *Poly {
	tmp := make([]int32, pp.paramD)
	return &Poly{coeffs: tmp}
}

// NewZeroPoly returns a Poly with all coefficients are 0.
// This function is encapsulated for requirements.
func (pp *PublicParameter) NewZeroPoly() (r *Poly) {
	tmp := make([]int32, pp.paramD)
	// The following loop is clear that all coefficient are 0
	for i := 0; i < len(tmp); i++ {
		tmp[i] = 0
	}
	return &Poly{coeffs: tmp}
}

// NewPolyVec creates a PolyVec with all coefficients are default initial value.
// If need to set the coefficients, please use the self-contained way in Golang.
func (pp *PublicParameter) NewPolyVec(vecLen int) (r *PolyVec) {
	polys := make([]*Poly, vecLen)
	for i := 0; i < vecLen; i++ {
		polys[i] = pp.NewPoly()
	}
	return &PolyVec{polys: polys}
}

// NewZeroPolyVec returns a PolyVec with all coefficients are 0.
// This function is encapsulated for requirements.
func (pp *PublicParameter) NewZeroPolyVec(vecLen int) (r *PolyVec) {
	polys := make([]*Poly, vecLen)
	for i := 0; i < vecLen; i++ {
		polys[i] = pp.NewZeroPoly()
	}
	return &PolyVec{polys: polys}
}

// PolyAdd performances polynomial addition, and return a result Poly.
func (pp *PublicParameter) PolyAdd(a *Poly, b *Poly) (r *Poly) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) + int64(b.coeffs[i]))
	}
	return &Poly{coeffs: coeffs}
}

// PolySub performances polynomial subtraction, and return a result Poly.
func (pp *PublicParameter) PolySub(a *Poly, b *Poly) (r *Poly) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) - int64(b.coeffs[i]))
	}
	return &Poly{coeffs: coeffs}
}

// PolyMul performances polynomial muitlplication, and return a result Poly.
// It uses fast number theory transformation to accelerate the calculation process.
func (pp *PublicParameter) PolyMul(a *Poly, b *Poly) (r *Poly) {
	var antt = pp.NTT(a)
	var bntt = pp.NTT(b)
	var rntt = pp.PolyNTTMul(antt, bntt)

	return pp.NTTInv(rntt)
}

// NewZeroPolyNTT creates a PolyNTT with all coefficients are 0.
// This function is encapsulated for requirements.
func (pp *PublicParameter) NewZeroPolyNTT() (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	return &PolyNTT{coeffs}
}

// NewZeroPolyNTTVec creates a PolyNTTVec with all coefficients are default initial value.
// This function is encapsulated for requirements.
func (pp *PublicParameter) NewZeroPolyNTTVec(vecLen int) (r *PolyNTTVec) {
	polyNTTs := make([]*PolyNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polyNTTs[i] = pp.NewZeroPolyNTT()
	}
	return &PolyNTTVec{
		polyNTTs,
	}
}

// PolyNTTAdd performances polynomial addition, and return a result PolyNTT.
func (pp *PublicParameter) PolyNTTAdd(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) + int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

// PolyNTTSub performances polynomial subtraction, and return a result PolyNTT.
func (pp *PublicParameter) PolyNTTSub(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) - int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

// PolyNTTMul performances the component-wise multiplication of vectors, and return a result PolyNTT.
func (pp *PublicParameter) PolyNTTMul(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

// PolyNTTPower performs exponentiation for all coefficients
func (pp *PublicParameter) PolyNTTPower(a *PolyNTT, e uint) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	var res,cnt int64
	var tmp uint
	for i := 0; i < pp.paramD; i++ {
		res=int64(1)
		tmp=e
		cnt=int64(a.coeffs[i])
		for tmp!=0 {
			if tmp & 1 ==1 {
				res = int64(pp.reduce(res * cnt))
			}
			cnt= int64(pp.reduce(cnt * cnt))
			tmp >>= 1
		}
	}
	return &PolyNTT{coeffs: coeffs}
}

// PolyNTTEqualCheck reports whether a and b are the same length and contain the same content.
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

// PolyNTTVecAdd performs the addition of polynomial vectors in the NTT domain
func (pp *PublicParameter) PolyNTTVecAdd(a *PolyNTTVec, b *PolyNTTVec, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = pp.PolyNTTAdd(a.polyNTTs[i], b.polyNTTs[i])
	}

	return rst
}

// PolyNTTVecSub performs the subtraction of polynomial vectors in the NTT domain
func (pp *PublicParameter) PolyNTTVecSub(a *PolyNTTVec, b *PolyNTTVec, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = pp.PolyNTTSub(a.polyNTTs[i], b.polyNTTs[i])
	}

	return rst
}

// PolyNTTVecEqualCheck reports whether a and b are the same length and contain the same content.
// if any of inputs is nil, it will return false
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

// PolyNTTVecScaleMul performances the scale multiplication using polynomial as basic element
func (pp *PublicParameter) PolyNTTVecScaleMul(polyNTTScale *PolyNTT, polyNTTVec *PolyNTTVec, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		rst.polyNTTs[i] = pp.PolyNTTMul(polyNTTScale, polyNTTVec.polyNTTs[i])
	}
	return rst
}

// PolyNTTVecInnerProduct performances the inner product operation of polynomial vectors in the NTT domain
func (pp *PublicParameter) PolyNTTVecInnerProduct(a *PolyNTTVec, b *PolyNTTVec, vecLen int) (r *PolyNTT) {
	rst := pp.NewZeroPolyNTT()
	for i := 0; i < vecLen; i++ {
		rst = pp.PolyNTTAdd(rst, pp.PolyNTTMul(a.polyNTTs[i], b.polyNTTs[i]))
	}

	return rst
}

// PolyNTTMatrixMulVector performances the multiplication of polynomial matrix and polynomial vectors in the NTT domain
func (pp *PublicParameter) PolyNTTMatrixMulVector(M []*PolyNTTVec, vec *PolyNTTVec, rowNum int, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, rowNum)
	for i := 0; i < rowNum; i++ {
		rst.polyNTTs[i] = pp.PolyNTTVecInnerProduct(M[i], vec, vecLen)
	}
	return rst
}

// infNorm calculates the infinite norm of a polynomial in Zq
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

// infNorm calculates the infinite norm of a polynomial vector in Zq
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

// zetas is used for ntt and inv-ntt
// where zetas[1] is the element whose order is 256.
// In other word, zetas[1] is the primitive 256-th root of unity
var zetas []int64 = []int64{
	1, 27080629, -117148420, -184539775, -2101142946, -1302981885, 1892424754, -476807304,
	980252025, -116677063, -169607930, -493656413, 461633757, 1788171609, 965426373, 719032860,
	230521401, 693020064, -46808259, 1012065793, 1575911121, -426488185, -1323729221, 822594634,
	2064059405, -431866113, -1106864632, 1398707051, -1931327003, 1617469426, -1640163766, -560681706,
	-1039642628, -91102394, -1960073135, 268973648, -1975704623, 1264355536, 1853662297, -1837947712,
	601144801, 1862610191, -445190388, 1845557350, 872539281, -770316000, 561634378, 155760493,
	676997819, 1791293172, 1399284602, 553881927, 977589823, 1022335433, -1832286136, -1937715817,
	-1797176282, 1922387663, 1004451199, -965526926, -751175871, -1688101068, 1096159031, -1531139891,
	-111411333, 2054698751, 162829990, -859390743, 1863017546, 1520250555, -2113596960, -1890522966,
	1194468157, 159939512, -1126734380, 1935361546, 1083815339, 471402711, -1314627969, 2017533877,
	-804957008, 1731369037, 1063839313, 557969974, 903459722, -1704926051, 1090467289, 136377223,
	-1601642876, 242328406, -977319085, -768311354, -692152248, -985889685, 1776494806, -1871507778,
	-105536246, 508237158, -2110558367, -2070966520, 1333159417, 630153399, -1502735901, 51037300,
	-1101821189, 1193962498, -1062787467, -99232288, -520895632, 824518067, 532046570, -941238966,
	1896557509, -1009654371, 635909761, -1269821458, -865373539, -1433286680, -1162534279, -1394720400,
	470897089, -1535371675, -1289455571, -1499260483, 1039111165, 158743006, -2063290838, 320463862,
	-1, -27080629, 117148420, 184539775, 2101142946, 1302981885, -1892424754, 476807304,
	-980252025, 116677063, 169607930, 493656413, -461633757, -1788171609, -965426373, -719032860,
	-230521401, -693020064, 46808259, -1012065793, -1575911121, 426488185, 1323729221, -822594634,
	-2064059405, 431866113, 1106864632, -1398707051, 1931327003, -1617469426, 1640163766, 560681706,
	1039642628, 91102394, 1960073135, -268973648, 1975704623, -1264355536, -1853662297, 1837947712,
	-601144801, -1862610191, 445190388, -1845557350, -872539281, 770316000, -561634378, -155760493,
	-676997819, -1791293172, -1399284602, -553881927, -977589823, -1022335433, 1832286136, 1937715817,
	1797176282, -1922387663, -1004451199, 965526926, 751175871, 1688101068, -1096159031, 1531139891,
	111411333, -2054698751, -162829990, 859390743, -1863017546, -1520250555, 2113596960, 1890522966,
	-1194468157, -159939512, 1126734380, -1935361546, -1083815339, -471402711, 1314627969, -2017533877,
	804957008, -1731369037, -1063839313, -557969974, -903459722, 1704926051, -1090467289, -136377223,
	1601642876, -242328406, 977319085, 768311354, 692152248, 985889685, -1776494806, 1871507778,
	105536246, -508237158, 2110558367, 2070966520, -1333159417, -630153399, 1502735901, -51037300,
	1101821189, -1193962498, 1062787467, 99232288, 520895632, -824518067, -532046570, 941238966,
	-1896557509, 1009654371, -635909761, 1269821458, 865373539, 1433286680, 1162534279, 1394720400,
	-470897089, 1535371675, 1289455571, 1499260483, -1039111165, -158743006, 2063290838, -320463862,
}

// tree is the 7-bit reverse mapping, used for ntt and inv_ntt
var tree []int32 = []int32{
	0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120, 4,
	68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124, 2,
	66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122, 6,
	70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126, 1,
	65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121, 5,
	69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125, 3,
	67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123, 7,
	71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127,
}

// NTT performance in-place number-theoretic transform (NTT) in Rq.
// The input is in standard order, output is in standard order.
func (pp *PublicParameter) NTT(poly *Poly) (polyntt *PolyNTT) {
	//TODO: optimize the NTT algorithm by adjusting the order of zetas
	coeffs := make([]int64, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = int64(pp.reduce(int64(poly.coeffs[tree[i]])))
	}

	for step := 1; step <= pp.paramD/2; step <<= 1 {
		for start := 0; start+step < pp.paramD; start += step << 1 {
			zeta := zetas[0]
			for i := start; i < start+step; i++ {
				tmp := pp.reduce(coeffs[i+step] * zeta)
				coeffs[i], coeffs[i+step] = int64(pp.reduce(coeffs[i]+int64(tmp))), int64(pp.reduce(coeffs[i]-int64(tmp)))
				zeta = zetas[(i-start+1)*(pp.paramD/step)]
			}
		}
	}

	coeffs1 := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs1[i] = pp.reduce(coeffs[i])
	}
	return &PolyNTT{coeffs1}
}

// NTTInv performance inverse in-place number-theoretic transform (NTT) in Rq.
// The input is in standard order, output is in standard order.
func (pp *PublicParameter) NTTInv(polyntt *PolyNTT) (poly *Poly) {
	coeffs := make([]int64, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = int64(polyntt.coeffs[tree[i]])
	}

	for step := 1; step <= pp.paramD/2; step <<= 1 {
		for start := 0; start+step < pp.paramD; start += step << 1 {
			zeta := zetas[0]
			for i := start; i < start+step; i++ {
				tmp := pp.reduce(coeffs[i+step] * zeta)
				coeffs[i], coeffs[i+step] = int64(pp.reduce(coeffs[i]+int64(tmp))), int64(pp.reduce(coeffs[i]-int64(tmp)))
				zeta = zetas[2*pp.paramD-(i-start+1)*(pp.paramD/step)]
			}
		}
	}
	coeffs1 := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs1[i] = pp.reduce(coeffs[i] * int64(pp.paramDInv))
	}
	return &Poly{coeffs1}
}

// NTTVec performances the number-theoretic transform for every polynomial,
// and it return a vector of polyNTTs(PolyNTTVec)
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

// NTTInvVec performances the inverse number-theoretic transform for every polynomial,
// and it return a vector of polyNTTs(PolyVec)
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

//	private functions	begin

//	private functions	end
