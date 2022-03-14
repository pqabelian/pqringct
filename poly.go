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
	// the length must be paramLA?
	polys []*Poly
}

// PolyNTTVec defines a polynomial vector in the NTT domain
type PolyNTTVec struct {
	// the length must be paramLA?
	polyNTTs []*PolyNTT
}

// NewPoly creates a Poly with all coefficients are default initial value.
// If need to set the coefficients, please use the self-contained way in Golang.
func (pp *PublicParameter) NewPoly() *Poly {
	tmp := make([]int32, pp.paramDC)
	return &Poly{coeffs: tmp}
}

// NewZeroPoly returns a Poly with all coefficients are 0.
// This function is encapsulated for requirements.
func (pp *PublicParameter) NewZeroPoly() (r *Poly) {
	tmp := make([]int32, pp.paramDC)
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
	coeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) + int64(b.coeffs[i]))
	}
	return &Poly{coeffs: coeffs}
}

// PolySub performances polynomial subtraction, and return a result Poly.
func (pp *PublicParameter) PolySub(a *Poly, b *Poly) (r *Poly) {
	coeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
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
	coeffs := make([]int32, pp.paramDC)
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
	coeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) + int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

// PolyNTTSub performances polynomial subtraction, and return a result PolyNTT.
func (pp *PublicParameter) PolyNTTSub(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) - int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

// PolyNTTMul performances the component-wise multiplication of vectors, and return a result PolyNTT.
func (pp *PublicParameter) PolyNTTMul(a *PolyNTT, b *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = pp.reduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))
	}
	return &PolyNTT{coeffs: coeffs}
}

// PolyNTTPower performs exponentiation for all coefficients
func (pp *PublicParameter) PolyNTTPower(a *PolyNTT, e uint) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramDC)
	var res, cnt int64
	var tmp uint
	for i := 0; i < pp.paramDC; i++ {
		res = int64(1)
		tmp = e
		cnt = int64(a.coeffs[i])
		for tmp != 0 {
			if tmp&1 == 1 {
				res = int64(pp.reduce(res * cnt))
			}
			cnt = int64(pp.reduce(cnt * cnt))
			tmp >>= 1
		}
		coeffs[i] = int32(res)
	}
	return &PolyNTT{coeffs: coeffs}
}

// PolyNTTEqualCheck reports whether a and b are the same length and contain the same content.
func (pp *PublicParameter) PolyNTTEqualCheck(a *PolyNTT, b *PolyNTT) (eq bool) {
	if a == nil || b == nil {
		return false
	}

	if len(a.coeffs) != pp.paramDC || len(b.coeffs) != pp.paramDC {
		return false
	}

	for i := 0; i < pp.paramDC; i++ {
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
	1, -3961374278055081, -487081804016741, 56807364056412, -209446675903496, -3320644667016755, 1235339660893204, 3177746876019938, 3324120893893148, -2809209154262447, 3570330720599504, -3789723097646819, 4291993112190803, -285109037807932, 2126397607436323, 1916577482572563,
	-761022583694177, -3161479553462537, 3230643855107398, 2601088006592536, 2657374389201696, 2735015901925624, -4112352015282259, 830348738505628, -779271690604860, 3268383744978856, 3430853966845812, 1409765623493868, 755888051309162, 909423274414275, -180377490591752, -2913941871500558,
	3149486122865713, 1316313565646285, 2116581535505578, 3834153319180747, -1916794337699962, 2754108174766989, 839617742569024, 4364965041330057, 3586538940438984, 3283669304324960, 4062842700397063, -2672248561687506, -2211000588744934, -1502299676536323, 153395894778707, 3464686322270529,
	-4309990868079881, -2312805408439568, -3731883304150621, 2426045101333804, 2556100355075324, 1315239407433206, -4127404929959196, -126186431270781, -3549664814570546, -1907958117290069, 700267283382223, -1286606476423911, 3287646596695158, 4174038308563495, -4078975042978053, 847389579951156,
	-1134984324428686, -1310079364563958, 3664019702021674, 4312694295940838, 2794253362467402, -862388718457096, 1409565467861153, 1840703711379297, -4348742164984118, -3858795557519968, -1514188999093909, -3964662985966212, -2476669558495582, 684765896750486, 1676945732293755, -3714337976354567,
	-1902022558587715, -2761566121836952, 2660282187226757, -3060726388802589, 3289389929335456, 42144009743450, -496058590710439, -3202459420343070, 1777729189763447, -2973566751085068, 4281094531015949, 1508808648250530, -2212593406219976, -2320875089381437, -1629835288103919, -2863349907382619,
	2591437167729197, 3587956889474540, 2627315022122870, -1378624817114285, 3056035099209235, -4402069314132481, -2329544375212846, -608489155261415, -1558851215300917, -3146447031958762, -3381369741326533, -1780634911355959, 1066726237284269, 3063145714250878, -1115266612081824, 4251810147364781,
	-111908736495927, -1939143976070083, -447636955646952, 110862947627575, 2150651187371711, 3405673976476454, 1880054812739477, -4470372104219697, -4325092240305982, 3666798320569316, 2203782973968284, 192041854865278, -2002045091367077, -690900637470986, 1588670982653407, 4313289694613290,
	-1, 3961374278055081, 487081804016741, -56807364056412, 209446675903496, 3320644667016755, -1235339660893204, -3177746876019938, -3324120893893148, 2809209154262447, -3570330720599504, 3789723097646819, -4291993112190803, 285109037807932, -2126397607436323, -1916577482572563,
	761022583694177, 3161479553462537, -3230643855107398, -2601088006592536, -2657374389201696, -2735015901925624, 4112352015282259, -830348738505628, 779271690604860, -3268383744978856, -3430853966845812, -1409765623493868, -755888051309162, -909423274414275, 180377490591752, 2913941871500558,
	-3149486122865713, -1316313565646285, -2116581535505578, -3834153319180747, 1916794337699962, -2754108174766989, -839617742569024, -4364965041330057, -3586538940438984, -3283669304324960, -4062842700397063, 2672248561687506, 2211000588744934, 1502299676536323, -153395894778707, -3464686322270529,
	4309990868079881, 2312805408439568, 3731883304150621, -2426045101333804, -2556100355075324, -1315239407433206, 4127404929959196, 126186431270781, 3549664814570546, 1907958117290069, -700267283382223, 1286606476423911, -3287646596695158, -4174038308563495, 4078975042978053, -847389579951156,
	1134984324428686, 1310079364563958, -3664019702021674, -4312694295940838, -2794253362467402, 862388718457096, -1409565467861153, -1840703711379297, 4348742164984118, 3858795557519968, 1514188999093909, 3964662985966212, 2476669558495582, -684765896750486, -1676945732293755, 3714337976354567,
	1902022558587715, 2761566121836952, -2660282187226757, 3060726388802589, -3289389929335456, -42144009743450, 496058590710439, 3202459420343070, -1777729189763447, 2973566751085068, -4281094531015949, -1508808648250530, 2212593406219976, 2320875089381437, 1629835288103919, 2863349907382619,
	-2591437167729197, -3587956889474540, -2627315022122870, 1378624817114285, -3056035099209235, 4402069314132481, 2329544375212846, 608489155261415, 1558851215300917, 3146447031958762, 3381369741326533, 1780634911355959, -1066726237284269, -3063145714250878, 1115266612081824, -4251810147364781,
	111908736495927, 1939143976070083, 447636955646952, -110862947627575, -2150651187371711, -3405673976476454, -1880054812739477, 4470372104219697, 4325092240305982, -3666798320569316, -2203782973968284, -192041854865278, 2002045091367077, 690900637470986, -1588670982653407, -4313289694613290,
}

// tree is the 7-bit reverse mapping, used for ntt and inv_ntt
//var tree []int32 = []int32{
//	0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120, 4,
//	68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124, 2,
//	66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122, 6,
//	70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126, 1,
//	65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121, 5,
//	69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125, 3,
//	67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123, 7,
//	71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127,
//}

//
var nttFactors []int = []int{
	127, 63, 95, 31, 111, 47, 79, 15, 119, 55, 87, 23,
	103, 39, 71, 7, 123, 59, 91, 27, 107, 43, 75, 11, 115,
	51, 83, 19, 99, 35, 67, 3, 125, 61, 93, 29, 109, 45, 77, 13,
	117, 53, 85, 21, 101, 37, 69, 5, 121, 57, 89, 25, 105, 41, 73,
	9, 113, 49, 81, 17, 97, 33, 65, 1,
}

// NTT performance in-place number-theoretic transform (NTT) in Rq.
// The input is in standard order, output is in standard order.
func (pp *PublicParameter) NTT(poly *Poly) (polyntt *PolyNTT) {
	//for i := 0; i <len(poly.coeffs) ; i++ {
	//	poly.coeffs[i]=DefaultPP.reduce(int64(poly.coeffs[i])*zetas[i])
	//}
	////TODO: optimize the NTT algorithm by adjusting the order of zetas
	//coeffs := make([]int64, pp.paramDC)
	//for i := 0; i < pp.paramDC; i++ {
	//	coeffs[i] = int64(pp.reduce(int64(poly.coeffs[tree[i]])))
	//}
	//for step := 1; step <= pp.paramDC/2; step <<= 1 {
	//	for start := 0; start+step < pp.paramDC; start += step << 1 {
	//		zeta := zetas[0]
	//		for i := start; i < start+step; i++ {
	//			tmp := pp.reduce(coeffs[i+step] * zeta)
	//			coeffs[i], coeffs[i+step] = int64(pp.reduce(coeffs[i]+int64(tmp))), int64(pp.reduce(coeffs[i]-int64(tmp)))
	//			zeta = zetas[(i-start+1)*(pp.paramDC/step)]
	//		}
	//	}
	//}
	//
	//coeffs1 := make([]int32, pp.paramDC)
	//for i := 0; i < pp.paramDC; i++ {
	//	coeffs1[i] = pp.reduce(coeffs[i])
	//}
	//return &PolyNTT{coeffs1}

	//coeffs := make([]int64, pp.paramDC)
	//for i := 0; i < pp.paramDC; i++ {
	//	for j := 0; j < pp.paramDC; j++ {
	//		coeffs[i] = int64(pp.reduce(coeffs[i] + int64(poly.coeffs[j])*zetas[(i*j)%128]))
	//	}
	//}
	//coeffs1 := make([]int32, pp.paramDC)
	//for i := 0; i < pp.paramDC; i++ {
	//	coeffs1[i] = pp.reduce(coeffs[i])
	//}
	//return &PolyNTT{coeffs1}

	coeffs := make([]int32, pp.paramDC)
	copy(coeffs, poly.coeffs)

	//	NTT
	segNum := 1
	segLen := pp.paramDC
	factors := make([]int, 1)
	factors[0] = pp.paramDC / 2

	for {
		//fmt.Println(factors)

		segLenHalf := segLen / 2

		for k := 0; k < segNum; k++ {
			for i := 0; i < segLenHalf; i++ {
				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp1 := pp.reduce(int64(coeffs[k*segLen+i]) - tmp)
				tmp2 := pp.reduce(int64(coeffs[k*segLen+i]) + tmp)

				coeffs[k*segLen+i] = tmp1
				coeffs[k*segLen+i+segLenHalf] = tmp2
				//				fmt.Println(k*segLen+i, k*segLen+i+segLenHalf, k*segLen+i, factors[k])
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

	//fmt.Println("final factors:")
	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = (factors[i] + pp.paramDC)
		finalFactors[2*i+1] = factors[i]
	}
	//fmt.Println("final factors:", finalFactors)
	//fmt.Println("(Native) NTT coeffs:", coeffs)

	// SigmaNTT may need the NTT coefficients  to be arranges as 1, 3, 5, ..., 2d-1
	nttCoeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		nttCoeffs[(finalFactors[i]-1)/2] = coeffs[i]
	}
	//fmt.Println("Ordered NTT coeffs:", nttCoeffs)
	return &PolyNTT{coeffs: nttCoeffs}
}

// NTTInv performance inverse in-place number-theoretic transform (NTT) in Rq.
// The input is in standard order, output is in standard order.
func (pp *PublicParameter) NTTInv(polyntt *PolyNTT) (poly *Poly) {
	//coeffs := make([]int64, pp.paramDC)
	//for i := 0; i < pp.paramDC; i++ {
	//	coeffs[i] = int64(polyntt.coeffs[tree[i]])
	//}
	//
	//for step := 1; step <= pp.paramDC/2; step <<= 1 {
	//	for start := 0; start+step < pp.paramDC; start += step << 1 {
	//		zeta := zetas[0]
	//		for i := start; i < start+step; i++ {
	//			tmp := pp.reduce(coeffs[i+step] * zeta)
	//			coeffs[i], coeffs[i+step] = int64(pp.reduce(coeffs[i]+int64(tmp))), int64(pp.reduce(coeffs[i]-int64(tmp)))
	//			zeta = zetas[2*pp.paramDC-(i-start+1)*(pp.paramDC/step)]
	//		}
	//	}
	//}
	//coeffs1 := make([]int32, pp.paramDC)
	//for i := 0; i < pp.paramDC; i++ {
	//	coeffs1[i] = pp.reduce(coeffs[i] * int64(pp.paramDCInv))
	//}
	//resp:=make([]int32,pp.paramDC)
	//for i := 0; i < len(resp); i++ {
	//	resp[i]=DefaultPP.reduce(int64(coeffs1[i])*zetas[(2*pp.paramDC-i)%(2*pp.paramDC)])
	//}
	//return &Poly{resp}

	//coeffs := make([]int64, pp.paramDC)
	//for i := 0; i < pp.paramDC; i++ {
	//	for j := 0; j < pp.paramDC; j++ {
	//		coeffs[i] = int64(DefaultPP.reduce(coeffs[i] + int64(polyntt.coeffs[j])*zetas[((128-i)*j)%128]))
	//	}
	//}
	//coeffs1 := make([]int32, pp.paramDC)
	//for i := 0; i < pp.paramDC; i++ {
	//	coeffs1[i] = pp.reduce(coeffs[i] * int64(pp.paramDCInv))
	//}
	//return &Poly{coeffs1}
	coeffs := make([]int32, pp.paramDC)
	segNum := pp.paramDC
	segLen := 1
	factors := nttFactors

	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = (factors[i] + pp.paramDC)
		finalFactors[2*i+1] = factors[i]
	}

	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = polyntt.coeffs[(finalFactors[i]-1)/2]
	}

	twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
	//fmt.Println("2^{-1}:", twoInv)

	for {
		//		fmt.Println(factors)
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			for i := 0; i < segLen; i++ {
				tmp1 := pp.reduce(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen])+int64(coeffs[k*segLenDouble+i])) * twoInv)
				tmp2 := pp.reduce(pp.reduceInt64(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen])-int64(coeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
				coeffs[k*segLenDouble+i] = tmp1
				coeffs[k*segLenDouble+i+segLen] = tmp2

				//				fmt.Println(k*segLenDouble+i, k*segLenDouble+i+segLen, k*segLenDouble+i, k*segLenDouble+i+segLen )
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
	//fmt.Println("NTTInv Result:", coeffs)
	return &Poly{coeffs: coeffs}
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
