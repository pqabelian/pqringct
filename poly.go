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
	todo_DONE: output a Poly with all coefficients are 0.
*/
// NewZeroPoly return a Poly with all coefficients are 0.
func (pp *PublicParameter) NewZeroPoly() (r *Poly) {
	tmp := make([]int32, pp.paramD)
	for i := 0; i < len(tmp); i++ {
		tmp[i] = 0
	}
	return &Poly{coeffs: tmp}
}

// zetas is used for ntt and inv-ntt
// zetas[1] is the element whose order is 256. In other word, zetas[1] is the
// primitive 256-th root of unity
var zetas []int64 = []int64{
	1, 27080629, 4177814269, 4110422914, 2193819743, 2991980804, 1892424754, 3818155385,
	980252025, 4178285626, 4125354759, 3801306276, 461633757, 1788171609, 965426373, 719032860,
	230521401, 693020064, 4248154430, 1012065793, 1575911121, 3868474504, 2971233468, 822594634,
	2064059405, 3863096576, 3188098057, 1398707051, 2363635686, 1617469426, 2654798923, 3734280983,
	3255320061, 4203860295, 2334889554, 268973648, 2319258066, 1264355536, 1853662297, 2457014977,
	601144801, 1862610191, 3849772301, 1845557350, 872539281, 3524646689, 561634378, 155760493,
	676997819, 1791293172, 1399284602, 553881927, 977589823, 1022335433, 2462676553, 2357246872,
	2497786407, 1922387663, 1004451199, 3329435763, 3543786818, 2606861621, 1096159031, 2763822798,
	4183551356, 2054698751, 162829990, 3435571946, 1863017546, 1520250555, 2181365729, 2404439723,
	1194468157, 159939512, 3168228309, 1935361546, 1083815339, 471402711, 2980334720, 2017533877,
	3490005681, 1731369037, 1063839313, 557969974, 903459722, 2590036638, 1090467289, 136377223,
	2693319813, 242328406, 3317643604, 3526651335, 3602810441, 3309073004, 1776494806, 2423454911,
	4189426443, 508237158, 2184404322, 2223996169, 1333159417, 630153399, 2792226788, 51037300,
	3193141500, 1193962498, 3232175222, 4195730401, 3774067057, 824518067, 532046570, 3353723723,
	1896557509, 3285308318, 635909761, 3025141231, 3429589150, 2861676009, 3132428410, 2900242289,
	470897089, 2759591014, 3005507118, 2795702206, 1039111165, 158743006, 2231671851, 320463862,
	4294962688, 4267882060, 117148420, 184539775, 2101142946, 1302981885, 2402537935, 476807304,
	3314710664, 116677063, 169607930, 493656413, 3833328932, 2506791080, 3329536316, 3575929829,
	4064441288, 3601942625, 46808259, 3282896896, 2719051568, 426488185, 1323729221, 3472368055,
	2230903284, 431866113, 1106864632, 2896255638, 1931327003, 2677493263, 1640163766, 560681706,
	1039642628, 91102394, 1960073135, 4025989041, 1975704623, 3030607153, 2441300392, 1837947712,
	3693817888, 2432352498, 445190388, 2449405339, 3422423408, 770316000, 3733328311, 4139202196,
	3617964870, 2503669517, 2895678087, 3741080762, 3317372866, 3272627256, 1832286136, 1937715817,
	1797176282, 2372575026, 3290511490, 965526926, 751175871, 1688101068, 3198803658, 1531139891,
	111411333, 2240263938, 4132132699, 859390743, 2431945143, 2774712134, 2113596960, 1890522966,
	3100494532, 4135023177, 1126734380, 2359601143, 3211147350, 3823559978, 1314627969, 2277428812,
	804957008, 2563593652, 3231123376, 3736992715, 3391502967, 1704926051, 3204495400, 4158585466,
	1601642876, 4052634283, 977319085, 768311354, 692152248, 985889685, 2518467883, 1871507778,
	105536246, 3786725531, 2110558367, 2070966520, 2961803272, 3664809290, 1502735901, 4243925389,
	1101821189, 3101000191, 1062787467, 99232288, 520895632, 3470444622, 3762916119, 941238966,
	2398405180, 1009654371, 3659052928, 1269821458, 865373539, 1433286680, 1162534279, 1394720400,
	3824065600, 1535371675, 1289455571, 1499260483, 3255851524, 4136219683, 2063290838, 3974498827,
}
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
// The input is in standard order, output is in bit-reversed order
func (pp *PublicParameter) NTT(poly *Poly) (polyntt *PolyNTT) {

	//coeffs := make([]int32, pp.paramD)
	//
	//var x int64
	//
	//zeta := int64(pp.paramZeta)
	//zeta2 := int64(pp.reduce(zeta * zeta)) // zeta^2
	//for i := 0; i < pp.paramD; i++ {
	//	// rst[i] = a_0 + a_1 ((pp.paramZeta)^{2i+1})^1 + a_2 ((pp.paramZeta)^{2i+1})^2 + ... + a_j ((pp.paramZeta)^{2i+1})^j + ... + a_{d-1} () ((pp.paramZeta)^{2i+1})^{d-1}
	//	//	rst[0] : (pp.paramZeta)^{1};
	//	//	rst[1] : (pp.paramZeta)^{3}
	//	//	...
	//	//	rst[d-1] : (pp.paramZeta)^{2d-1}
	//
	//	coeffs[i] = 0
	//	x = int64(1)
	//	for j := 0; j < pp.paramD; j++ {
	//		coeffs[i] = pp.reduce(int64(coeffs[i]) + int64(pp.reduce(int64(poly.coeffs[j])*x)))
	//
	//		x = x * zeta
	//	}
	//
	//	zeta = int64(pp.reduce(zeta * zeta2)) // zeta = pp.paramZeta, pp.paramZeta^3, pp.paramZeta^5, ..., pp.paramZeta^{2d-1}
	//}
	//
	//return &PolyNTT{coeffs: coeffs}

	coeffs := make([]int64, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = int64(poly.coeffs[i])
	}
	for i := 0; i < pp.paramD/2; i++ {
		coeffs[i], coeffs[tree[i]] = coeffs[tree[i]], coeffs[i]
	}
	for step := 1; step <= pp.paramD/2; step <<= 1 {
		for start := 0; start+step < pp.paramD; start += step << 1 {
			zeta := zetas[0]
			for i := start; i < start+step; i++ {
				coeffs[i], coeffs[i+step] = (coeffs[i]+coeffs[i+step]*zeta%int64(pp.paramQ)+int64(pp.paramQ))%int64(pp.paramQ), (coeffs[i]-coeffs[i+step]*zeta%int64(pp.paramQ)+int64(pp.paramQ))%int64(pp.paramQ)
				zeta = zetas[(i-start+1)*(pp.paramD/step)]
			}
		}
	}
	res := NewPolyNTT(pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		res.coeffs[i] = int32(coeffs[i])
	}
	return res
	// TODO: optimize the NTT algorithm
}

/*
todo:
*/
func (pp *PublicParameter) NTTInv(polyntt *PolyNTT) (poly *Poly) {

	//coeffs:=make([]int32,pp.paramD)
	//for i := 0; i < pp.paramD; i++ {
	//	coeffs[i]=polyntt.coeffs[i]
	//}
	//for step := 1; step <= pp.paramD/2; step <<= 1 {
	//	for group := 0; group+step < pp.paramD; group += 2 * step {
	//		zeta := zetas[0]
	//		for start := group; start < group+step; start++ {
	//			coeffs[start], coeffs[start+step] = coeffs[start]+coeffs[start+step]*zeta, coeffs[start]-coeffs[start+step]*zeta
	//			zeta = zetas[2*pp.paramD-(start-group+1)*(pp.paramD/step)]
	//
	//		}
	//	}
	//}
	//return &Poly{coeffs: coeffs}

	coeffs := make([]int64, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = int64(poly.coeffs[i])
	}
	for i := 0; i < pp.paramD/2; i++ {
		coeffs[i], coeffs[tree[i]] = coeffs[tree[i]], coeffs[i]
	}
	for step := 1; step <= pp.paramD/2; step <<= 1 {
		for start := 0; start+step < pp.paramD; start += step << 1 {
			zeta := zetas[0]
			for i := start; i < start+step; i++ {
				coeffs[i], coeffs[i+step] = (coeffs[i]+coeffs[i+step]*zeta%int64(pp.paramQ)+int64(pp.paramQ))%int64(pp.paramQ), (coeffs[i]-coeffs[i+step]*zeta%int64(pp.paramQ)+int64(pp.paramQ))%int64(pp.paramQ)
				zeta = zetas[2*pp.paramD-(i-start+1)*(pp.paramD/step)]
			}
		}
	}
	res := NewPoly(pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		res.coeffs[i] = int32(coeffs[i])
	}
	return res
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
	todo_DONE: output a PolyNTT with all coefficients are 0.
*/
func (pp *PublicParameter) NewZeroPolyNTT() (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	return &PolyNTT{coeffs}
}

/*
todo_DONE： utput a PolyNTTVec with all polyNTTs are zero-PolyNTT.
*/
func (pp *PublicParameter) NewZeroPolyNTTVec(vecLen int) (r *PolyNTTVec) {
	polys := make([]*PolyNTT, vecLen)
	for i := 0; i < vecLen; i++ {
		polys = append(polys, pp.NewZeroPolyNTT())
	}
	return &PolyNTTVec{polyNTTs: polys}
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
