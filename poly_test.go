package pqringct

//func TestPublicParameter_NTTAndNTTInv(t *testing.T) {
//	pp := DefaultPP
//	coeffs, _ := randomnessFromEtaA(nil, pp.paramDC)
//	//coeffs := []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128}
//	//coeffs := []int32{-670655946,1505811237,3332332,4421, 861, 1, 1, 1, 1, 1, 1, 987, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
//	poly := &Poly{coeffs: coeffs}
//	for i := 0; i < pp.paramDC; i++ {
//		poly.coeffs[i] = pp.reduce(int64(poly.coeffs[i]))
//	}
//	type args struct {
//		poly *Poly
//	}
//	tests := []struct {
//		name     string
//		args     args
//		wantPoly *Poly
//	}{
//		{
//			name:     "test one",
//			args:     args{poly: poly},
//			wantPoly: poly,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			if gotPoly := pp.NTTInv(pp.NTT(tt.args.poly)); !reflect.DeepEqual(gotPoly, tt.wantPoly) {
//				t.Errorf("\ngotPoly = %v \n want %v", gotPoly, tt.wantPoly)
//			}
//		})
//	}
//}
//func PolyMul(a *Poly, b *Poly) *Poly {
//	pp := DefaultPP
//	//res := make([]int64, 2*pp.paramDC-1)
//	//for i := 0; i < len(res); i++ {
//	//	for j := 0; j <= i; j++ {
//	//		if j<pp.paramDC &&i-j < pp.paramDC {
//	//			res[i]=pp.reduceInt64(res[i]+int64(a.coeffs[j])*int64(b.coeffs[i-j]))
//	//		}
//	//	}
//	//}
//	//for i := pp.paramDC; i < len(res); i++ {
//	//	res[i-pp.paramDC]=pp.reduceInt64(res[i-pp.paramDC]-res[i])
//	//}
//	//ret:=pp.NewPoly()
//	//for i := 0; i < pp.paramDC; i++ {
//	//	ret.coeffs[i]=pp.reduceBigInt(res[i])
//	//}
//	//return ret
//
//	res := pp.NewZeroPoly()
//	for i := 0; i < pp.paramDC; i++ {
//		for j := 0; j < pp.paramDC; j++ {
//			if i+j >= pp.paramDC {
//				res.coeffs[(i+j)%pp.paramDC] = pp.reduce(int64(res.coeffs[(i+j)%pp.paramDC]) - int64(a.coeffs[i])*int64(b.coeffs[j]))
//			} else {
//				res.coeffs[(i+j)%pp.paramDC] = pp.reduce(int64(res.coeffs[(i+j)%pp.paramDC]) + int64(a.coeffs[i])*int64(b.coeffs[j]))
//			}
//		}
//	}
//	return res
//}
//func TestPublicParameter_PolyNTTMul(t *testing.T) {
//	pp := DefaultPP
//	a, _ := randomnessFromEtaA(nil, pp.paramDC)
//	b, _ := randomnessFromEtaA(nil, pp.paramDC)
//	nttA := pp.NTT(&Poly{coeffs: a})
//	nttB := pp.NTT(&Poly{coeffs: b})
//	nttC := pp.PolyNTTMul(nttA, nttB)
//	got := pp.NTTInv(nttC)
//	want := PolyMul(&Poly{coeffs: a}, &Poly{coeffs: b})
//	if !reflect.DeepEqual(got, want) {
//		t.Errorf("error")
//	}
//
//}
//func TestPublicParameter_PolyNTTPower(t *testing.T) {
//
//	type args struct {
//		a *PolyNTT
//		e uint
//	}
//	tests := []struct {
//		name  string
//		args  args
//		wantR *PolyNTT
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			pp := DefaultPP
//			if gotR := pp.PolyNTTPower(tt.args.a, tt.args.e); !reflect.DeepEqual(gotR, tt.wantR) {
//				t.Errorf("PolyNTTPower() = %v, want %v", gotR, tt.wantR)
//			}
//		})
//	}
//}
//
////var coeffs = make([]int32, DefaultPP.paramDC)
//func TestNTT1(t *testing.T) {
//	pp := DefaultPP
//	originalCoeffs := []int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
//	poly := &Poly{coeffs: originalCoeffs}
//	res := pp.NTT(poly)
//	fmt.Println(res)
//
//}
//func TestNTT(t *testing.T) {
//	pp := DefaultPP
//	//originalCoeffs := make([]int32, pp.paramDC)
//	//for i := 0; i < pp.paramDC; i++ {
//	//	originalCoeffs[i] = int32(i)
//	//}
//	//originalCoeffs,_ :=randomnessFromEtaA(nil,pp.paramDC)
//	originalCoeffs := []int32{3193417, -6979316, -2480726, 5747719, 894065, 6831037, 8356300, 22901, -951913, 7235424, 6781865, 7612582, 2907085, 543066, 8290770, 101295, 720577, 1101778, 6100913, 841066, 2120884, 7842174, 8257577, 112018, 8168555, 3602678, 4337509, 7207797, 5448411, 4727991, 8061281, 46948, -3425797, 4018412, 3004930, 7744954, 1703878, 4000546, 7078123, 12695, 4484259, 4177470, 7537649, 5013307, 4352814, 713660, 8257833, 93661, 3012262, 3447253, 3058483, -2978604, 7416822, -6899266, 8290552, -97114, 1553980, 8283464, -5332648, 4503197, 943166, -2729184, 4096350, 74357, -5316758, 4523883, 5711522, -6646406, 3787633, 1183846, 7766417, 39498, -8234730, 4732806, 7803629, 1173370, 5664025, 7550695, 2916656, 69917, 4776410, 2440680, 2539446, 4293774, 2725400, 5309094, 3572113, 26016, -6124071, 7308435, 5704304, 3275642, 5069929, 5384587, 6193427, 119371, 2938103, 1205185, 79482, 977587, 1077124, 1449446, 8159669, 17376, -7873496, 6010240, 6597307, 2692089, 5037811, 1472532, 7504324, 29697, -4272635, 7116169, 3418056, 7705230, 5836031, 7917588, 6455701, 56370, -4810348, 671158, 8325399, 360064, 7259622, 3230271, 7832016, 37860}
//
//	coeffs := make([]int32, pp.paramDC)
//	copy(coeffs, originalCoeffs)
//
//	fmt.Println("original:", originalCoeffs)
//
//	//	NTT
//	fmt.Println("test NTT")
//	segNum := 1
//	segLen := pp.paramDC
//	factors := make([]int, 1)
//	factors[0] = pp.paramDC / 2
//
//	for {
//		fmt.Println(factors)
//
//		segLenHalf := segLen / 2
//
//		for k := 0; k < segNum; k++ {
//			for i := 0; i < segLenHalf; i++ {
//				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
//				tmp1 := pp.reduce(int64(coeffs[k*segLen+i]) - tmp)
//				tmp2 := pp.reduce(int64(coeffs[k*segLen+i]) + tmp)
//
//				coeffs[k*segLen+i] = tmp1
//				coeffs[k*segLen+i+segLenHalf] = tmp2
//				//				fmt.Println(k*segLen+i, k*segLen+i+segLenHalf, k*segLen+i, factors[k])
//			}
//		}
//
//		segNum = segNum << 1
//		segLen = segLen >> 1
//		if segNum == pp.paramDC {
//			break
//		}
//
//		tmpFactors := make([]int, 2*len(factors))
//		for i := 0; i < len(factors); i++ {
//			tmpFactors[2*i] = (factors[i] + pp.paramDC) / 2
//			tmpFactors[2*i+1] = factors[i] / 2
//		}
//		factors = tmpFactors
//	}
//
//	fmt.Println("final factors:")
//	finalFactors := make([]int, 2*len(factors))
//	for i := 0; i < len(factors); i++ {
//		finalFactors[2*i] = (factors[i] + pp.paramDC)
//		finalFactors[2*i+1] = factors[i]
//	}
//	fmt.Println("final factors:", finalFactors)
//	fmt.Println("(Native) NTT coeffs:", coeffs)
//
//	// SigmaNTT may need the NTT coefficients  to be arranges as 1, 3, 5, ..., 2d-1
//	nttCoeffs := make([]int32, pp.paramDC)
//	for i := 0; i < pp.paramDC; i++ {
//		nttCoeffs[(finalFactors[i]-1)/2] = coeffs[i]
//	}
//	fmt.Println("Ordered NTT coeffs:", nttCoeffs)
//	fmt.Printf("Matrix %v\n", DefaultPP.NTT(&Poly{originalCoeffs}))
//	//	NTTInv
//
//	//	initial the NTT end-status
//	fmt.Println("test NTTInv")
//
//	//	Initialize the ending status of NTT
//	segNum = 1
//	segLen = pp.paramDC
//	factors = make([]int, 1)
//	factors[0] = pp.paramDC / 2
//
//	for true {
//		//		fmt.Println(factors)
//
//		//		segLenHalf := segLen/2
//
//		/*		for k := 0; k < segNum; k++ {
//				for i := 0; i < segLenHalf; i++ {
//					tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
//					coeffs[k*segLen+i] = pp.reduceBigInt( int64(coeffs[k*segLen+i]) - tmp )
//					coeffs[k*segLen+i+segLenHalf] = pp.reduceBigInt( int64(coeffs[k*segLen+i]) + tmp )
//					//				fmt.Println(k*segLen+i, k*segLen+i+segLenHalf, k*segLen+i, factors[k])
//				}
//			}*/
//
//		segNum = segNum << 1
//		segLen = segLen >> 1
//		if segNum == pp.paramDC {
//			break
//		}
//
//		tmpFactors := make([]int, 2*len(factors))
//		for i := 0; i < len(factors); i++ {
//			tmpFactors[2*i] = (factors[i] + pp.paramDC) / 2
//			tmpFactors[2*i+1] = factors[i] / 2
//		}
//		factors = tmpFactors
//	}
//	finalFactors = make([]int, 2*len(factors))
//	for i := 0; i < len(factors); i++ {
//		finalFactors[2*i] = (factors[i] + pp.paramDC)
//		finalFactors[2*i+1] = factors[i]
//	}
//	fmt.Println("final factors:", finalFactors)
//	for i := 0; i < pp.paramDC; i++ {
//		coeffs[i] = nttCoeffs[(finalFactors[i]-1)/2]
//	}
//
//	fmt.Println("NTTInv ...")
//	//	segNum == pp.paramDC, segLen = 1, len(factors) = pp.paramDC/2
//
//	twoInv := int64((pp.paramQC+1)/2) - int64(pp.paramQC)
//	fmt.Println("2^{-1}:", twoInv)
//
//	for {
//		//		fmt.Println(factors)
//		segLenDouble := segLen * 2
//
//		for k := 0; k < segNum/2; k++ {
//			for i := 0; i < segLen; i++ {
//				tmp1 := pp.reduce(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen])+int64(coeffs[k*segLenDouble+i])) * twoInv)
//				tmp2 := pp.reduce(pp.reduceInt64(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen])-int64(coeffs[k*segLenDouble+i]))*twoInv) * zetas[2*pp.paramDC-factors[k]])
//				coeffs[k*segLenDouble+i] = tmp1
//				coeffs[k*segLenDouble+i+segLen] = tmp2
//
//				//				fmt.Println(k*segLenDouble+i, k*segLenDouble+i+segLen, k*segLenDouble+i, k*segLenDouble+i+segLen )
//			}
//		}
//
//		segNum = segNum >> 1
//		segLen = segLen << 1
//		if segNum == 1 {
//			break
//		}
//
//		tmpFactors := make([]int, len(factors)/2)
//		for i := 0; i < len(tmpFactors); i++ {
//			tmpFactors[i] = factors[2*i+1] * 2
//		}
//		factors = tmpFactors
//
//	}
//	fmt.Println("NTTInv Result:", coeffs)
//
//}
//
//func TestPublicParameter_PolyNTTPower1(t *testing.T) {
//	pp := DefaultPP
//	type args struct {
//		a *PolyNTT
//		e uint
//	}
//	a1, _ := randomnessFromEtaA(nil, pp.paramDC)
//	a := &Poly{a1}
//	b := pp.NTT(a)
//	var x uint
//	for k := 0; k < 100; k++ {
//		x = uint(k)
//		res := make([]int32, pp.paramDC)
//		res[0] = 1
//		wantRes := pp.NTT(&Poly{res})
//		for i := 0; i < int(x); i++ {
//			wantRes = pp.PolyNTTMul(wantRes, b)
//		}
//		tests := []struct {
//			name  string
//			args  args
//			wantR *PolyNTT
//		}{
//			// TODO: Add test cases.
//			{
//				name: "test1",
//				args: args{
//					a: b,
//					e: x,
//				},
//				wantR: wantRes,
//			},
//		}
//		for _, tt := range tests {
//			t.Run(tt.name, func(t *testing.T) {
//				if gotR := pp.PolyNTTPower(tt.args.a, tt.args.e); !reflect.DeepEqual(gotR, tt.wantR) {
//					t.Errorf("PolyNTTPower() = %v, want %v", gotR, tt.wantR)
//				}
//			})
//		}
//	}
//}
//func TestPublicParameter_NewPoly(t *testing.T) {
//	pp := DefaultPP
//	for i := 0; i < pp.paramDC; i++ {
//		cnt := (i * 65) / 128
//		remainder := (i * 65) % 128
//		if cnt&1 == 1 {
//			fmt.Printf("-")
//		}
//		fmt.Printf("%d, ", remainder)
//	}
//	fmt.Println()
//	fmt.Printf("%032b\n", 0)
//	fmt.Printf("%032b\n", -0)
//}
