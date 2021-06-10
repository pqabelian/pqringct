package pqringct

import (
	"fmt"
	"reflect"
	"testing"
)

func TestIntBinaryNTT(t *testing.T) {
	pp := PublicParameter{}
	pp.paramD = 8

	v := uint64(9)
	binstr := intToBinary(v, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		k := binstr[i]
		fmt.Println(k)
	}
}

func TestMod(t *testing.T) {
	pp := PublicParameter{}
	pp.paramK = 4

	xi := 0
	tau := 1
	fmt.Println((xi - tau) % pp.paramK)
}

func TestSampleUniformPloyWithLowZeros(t *testing.T) {
	pp := PublicParameter{}
	pp.paramD = 20
	pp.paramSysBytes = 128
	pp.paramK = 4
	pp.paramQ = 4294962689

	myPoly := pp.sampleUniformPloyWithLowZeros()
	fmt.Println(myPoly)
}

func TestSampleUniformWithinEtaF(t *testing.T) {
	pp := PublicParameter{}
	pp.paramSysBytes = 128
	pp.paramD = 128
	pp.paramEtaF = 1024 - 1
	res, err := pp.sampleUniformWithinEtaF()
	if err != nil {
		t.Errorf("error")
	}
	fmt.Println(res)
}
func sigma(a []int32, k int) []int32 {
	pp := DefaultPP
	res := make([]int32, len(a))
	j := 0
	for i := 0; i < pp.paramD; i++ {
		x := a[i]
		// j&N取第8位，如果j的第8位为0，则-(j&N)为0x00000000，右移31位后还是0x00000000，如果j的第8位为1， 则-(j&N)为-128的补码0xFFFFFFF8，右移31位后为0xFFFFFFFF
		// x ^ -x 将最低有效位去掉，高位置1
		// 整体的结果取决于 j 的第8位，如果是0，则为x，否则为-x
		x ^= int32(-(j&pp.paramD)>>31) & (x ^ -x)
		res[j&(pp.paramD-1)] = x
		j += k
	}
	return res
}
func sigma1(a []int32, k int) []int32 {
	pp := DefaultPP
	res := make([]int32, len(a))
	for i := 0; i < pp.paramD; i++ {
		quotient := (i * k) / 128
		remainder := (i * k) % 128
		if quotient&1 == 1 {
			res[remainder] = -a[i]
		} else {
			res[remainder] = a[i]
		}
	}
	return res
}
func Test_222(t *testing.T) {
	pp := DefaultPP
	f, _ := randomnessFromEtaA(nil, pp.paramD)
	k := 193
	f1 := sigma(f, k)
	f2 := sigma1(f, k)
	if !reflect.DeepEqual(f1, f2) {
		t.Errorf("error")
	}
}
func TestPublicParameter_sigmaPowerPolyNTT(t *testing.T) {
	// ntt( sigma(f)) == sigma_ntt(ntt(f)) <=> sigma(f) == invntt(sigma_ntt(ntt(f)))
	pp := DefaultPP
	//f,_ :=randomnessFromEtaA(nil,pp.paramD)
	f := []int32{617098079, 888976855, 37740892, 412733221, 785245544, 163371564, 780306816, 703186513, 794557760, 620518208, 61812886, 18737084, 341485081, 716703218, 532786294, 1072666219, 1017778630, 605846189, 454516855, 707192092, 549481533, 935047144, 609022876, 905921008, 946211112, 201300466, 64148636, 994076530, 587174595, 101389602, 927439398, 1052279688, 504282642, 885843723, 257790532, 690549047, 652421676, 161571590, 66365599, 260760145, 765079718, 1036959557, 25296503, 307589082, 92569797, 361953622, 233971403, 18423977, 624807120, 704853513, 689185691, 884049572, 625956729, 830601660, 740041194, 536890086, 727602215, 958449412, 647271183, 568183614, 654288412, 332086484, 908099909, 307740158, 956194998, 559419898, 1020462919, 704740995, 279876736, 904554580, 702765596, 249768839, 1052707816, 701128581, 200537061, 148774154, 294861086, 294544648, 377734661, 406992752, 110211064, 747286497, 1070288789, 778183943, 685467750, 642793106, 75648453, 503704012, 267786791, 1070949372, 114250784, 945681952, 211383247, 347896957, 1013286847, 97882862, 947150053, 852447379, 910468089, 729313072, 326962256, 758668402, 153495233, 580452571, 991413911, 461710545, 429757142, 487692964, 188073492, 237965250, 516563400, 76304886, 1006262949, 112340601, 928056089, 16446390, 733303030, 944381859, 62502190, 187879406, 985378185, 794365083, 891529414, 738759396, 844100879, 424426291, 265204374, 666962361}
	fmt.Println(f)
	sigma65 := sigma(f, 65)
	fmt.Println(sigma65)
	sigma129 := sigma(f, 129)
	fmt.Println(sigma129)
	sigma193 := sigma(f, 193)
	fmt.Println(sigma193)
	nttF := pp.NTT(&Poly{f})
	fmt.Println(f)
	fmt.Println(nttF.coeffs)
	type args struct {
		a *PolyNTT
		e int
	}
	tests := []struct {
		name  string
		args  args
		wantR []int32
	}{
		// TODO: Add test cases.
		{
			name: "test 0",
			args: args{
				a: nttF,
				e: 0,
			},
			wantR: f,
		},
		{
			// sigma(nttF,1) == NTT(sigma(f))
			name: "test 1",
			args: args{
				a: nttF,
				e: 1,
			},
			wantR: sigma65,
		},
		{
			name: "test 2",
			args: args{
				a: nttF,
				e: 2,
			},
			wantR: sigma129,
		},
		{
			name: "test 3",
			args: args{
				a: nttF,
				e: 3,
			},
			wantR: sigma193,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotR := pp.NTTInv(pp.sigmaPowerPolyNTT(tt.args.a, tt.args.e)); !reflect.DeepEqual(gotR.coeffs, tt.wantR) {
				t.Errorf("sigmaPowerPolyNTT() = \n%v, \nwant \n%v\n", gotR, tt.wantR)
			}
		})
	}

}
func Test_11(t *testing.T) {
	pp := DefaultPP
	f, _ := randomnessFromEtaA(nil, pp.paramD)
	p := &Poly{coeffs: f}
	sigmaf := sigma(f, 65)
	nttF := pp.NTT(p)
	sigma65_ntt_f := pp.sigmaPowerPolyNTT(nttF, 1)
	got := pp.NTT(&Poly{coeffs: sigmaf})
	if !reflect.DeepEqual(got, sigma65_ntt_f) {
		t.Errorf("error")
		fmt.Println(got)
		fmt.Println(sigma65_ntt_f)
	}
	//sigmfa:=sigma([]int32{912210275, 140610747, 997724590, 1029111095, 706852024, 86483400, 1055148559, 65569626, 1018450129, 925998364, 114046004, 495242290, 984623100, 89044476, 416825808, 603760292, 179341495, 787150347, 319413684, 1015198938, 620042710, 494241682, 420455786, 345355767, 886538499, 928465373, 681348647, 749168824, 646473346, 508821633, 7380036, 1039902010, 315122115, 312500164, 423109099, 1020839347, 173660029, 265078857, 582977049, 876545995, 208453846, 654327601, 974765498, 726145682, 421874950, 335610096, 1006807688, 1029125461, 120506836, 268015402, 150505124, 42304371, 825107267, 272778091, 739384563, 66903968, 820610951, 1050474174, 878616118, 770031888, 365347200, 73315898, 376431190, 148138300, 566513267, 539102752, 559590304, 996374892, 1053403751, 928966312, 472045052, 503508827, 317525385, 457517152, 810755015, 201108856, 720243920, 1012196808, 954422915, 274542471, 534575619, 916297900, 1055037045, 64423097, 463855378, 439351374, 262025688, 267227205, 888014845, 852697634, 155217761, 316596199, 419547757, 140368833, 521616849, 867126834, 286006076, 148627013, 27239252, 279442024, 479714221, 891730284, 150349286, 447427938, 347242635, 911677852, 374954761, 1065546536, 389477639, 326237125, 595735527, 945729920, 228295247, 382001896, 286129585, 994123481, 1026488387, 279383673, 579222543, 922088007, 429968721, 24751546, 64667489, 750809152, 825789163, 727438224, 115229391, 312288538},65)
	//for i := 0; i < pp.paramD; i++ {
	//	fmt.Printf("%d, ",sigmfa[i])
	//}

}
func TestPublicParameter_Simga(t *testing.T) {
	pp := DefaultPP
	f, _ := randomnessFromEtaA(nil, pp.paramD)
	sigmaF := sigma(f, 65)
	p := &Poly{coeffs: f}
	nttP := pp.NTT(p)
	nttSigmaP := pp.NTT(&Poly{coeffs: sigmaF})
	m := map[int32]int{}
	for i := 0; i < pp.paramD; i++ {
		m[nttP.coeffs[i]] = i
	}
	for i := 0; i < pp.paramD; i++ {
		if loc, ok := m[nttSigmaP.coeffs[i]]; ok {
			fmt.Printf("%d, ", loc)
		} else {
			fmt.Printf("error in %d", i)
		}
		if i%16 == 15 {
			fmt.Println()
		}
	}

}
func TestPublicParameter_SigmaAndSigmaInv(t *testing.T) {
	pp := DefaultPP
	f, _ := randomnessFromEtaA(nil, pp.paramD)
	p := &Poly{coeffs: f}
	nttP := pp.NTT(p)
	for k := 0; k < pp.paramK; k++ {
		got := pp.sigmaInvPolyNTT(pp.sigmaPowerPolyNTT(nttP, k), k)
		if !reflect.DeepEqual(got, nttP) {
			fmt.Println(got)
			fmt.Println(nttP)
		}
	}

}
func TestPublicParameter_sigmaPowerPolyNTTAndSigmaInv(t *testing.T) {
	pp := DefaultPP
	type args struct {
		polyNTT *PolyNTT
		t       int
	}
	a1, _ := randomnessFromEtaA(nil, pp.paramD)
	a := &Poly{a1}
	b := pp.NTT(a)
	tests := []struct {
		name  string
		args  args
		wantR *PolyNTT
	}{
		{
			name: "test zero",
			args: args{
				polyNTT: b,
				t:       0,
			},
			wantR: b,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotR := pp.sigmaPowerPolyNTT(tt.args.polyNTT, tt.args.t); !reflect.DeepEqual(gotR, tt.wantR) {
				t.Errorf("sigmaPowerPolyNTT() = \n%v\n, want\n %v\n", gotR, tt.wantR)
			}
		})
	}
	sigma1 := sigma(b.coeffs, 65)
	sigma2 := sigma(b.coeffs, 129)
	sigma3 := sigma(b.coeffs, 193)
	//sigma1inv1 := pp.sigmaInvPolyNTT(sigma1, 1)
	//sigma2inv2 := pp.sigmaInvPolyNTT(sigma2, 2)
	//sigma3inv3 := pp.sigmaInvPolyNTT(sigma3, 3)
	sigmainvTests := []struct {
		name  string
		args  args
		wantR *PolyNTT
	}{
		{
			name: "test one",
			args: args{
				polyNTT: b,
				t:       1,
			},
			wantR: pp.NTT(&Poly{sigma1}),
		},
		{
			name: "test two",
			args: args{
				polyNTT: b,
				t:       2,
			},
			wantR: pp.NTT(&Poly{sigma2}),
		},
		{
			name: "test three",
			args: args{
				polyNTT: b,
				t:       3,
			},
			wantR: pp.NTT(&Poly{sigma3}),
		},
	}
	for _, tt := range sigmainvTests {
		t.Run(tt.name, func(t *testing.T) {
			if gotR := pp.sigmaPowerPolyNTT(tt.args.polyNTT, tt.args.t); !reflect.DeepEqual(gotR, tt.wantR) {
				t.Errorf("sigmaPowerPolyNTT() = \n%v\n, want\n %v\n", gotR, tt.wantR)
			}
		})
	}
}
func TestPublicParameter_Tree(t *testing.T) {
	//sigma65ntt := []int{32, 97, 34, 99, 36, 101, 38, 103, 40, 105, 42, 107, 44, 109, 46, 111,
	//	48, 113, 50, 115, 52, 117, 54, 119, 56, 121, 58, 123, 60, 125, 62, 127,
	//	64, 1, 66, 3, 68, 5, 70, 7, 72, 9, 74, 11, 76, 13, 78, 15,
	//	80, 17, 82, 19, 84, 21, 86, 23, 88, 25, 90, 27, 92, 29, 94, 31,
	//	96, 33, 98, 35, 100, 37, 102, 39, 104, 41, 106, 43, 108, 45, 110, 47,
	//	112, 49, 114, 51, 116, 53, 118, 55, 120, 57, 122, 59, 124, 61, 126, 63,
	//	0, 65, 2, 67, 4, 69, 6, 71, 8, 73, 10, 75, 12, 77, 14, 79,
	//	16, 81, 18, 83, 20, 85, 22, 87, 24, 89, 26, 91, 28, 93, 30, 95}
	//may := []int{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	//	8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7,
	//	48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
	//	40, 41, 42, 43, 44, 45, 46, 47, 32, 33, 34, 35, 36, 37, 38, 39,
	//	88, 89, 90, 91, 92, 93, 94, 95, 80, 81, 82, 83, 84, 85, 86, 87,
	//	64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
	//	120, 121, 122, 123, 124, 125, 126, 127, 112, 113, 114, 115, 116, 117, 118, 119,
	//	96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111}
	//m:=map[int]int{}
	//for i := 0; i < len(sigma65ntt); i++ {
	//	m[sigma65ntt[i]]=i
	//}
	//for i := 0; i < len(may); i++ {
	//	if loc,ok:=m[may[i]];ok{
	//		fmt.Printf("%d, ",loc)
	//	}else{
	//		fmt.Printf("error in %d",i)
	//	}
	//}
	pp := DefaultPP
	a1, _ := randomnessFromEtaA(nil, pp.paramD)
	a := &Poly{a1}
	fmt.Println("a = ", a1)
	sigmaA := sigma(a1, 193)
	fmt.Println("sigma(a)", sigmaA)
	ntt_sigmaA := pp.NTT(&Poly{coeffs: sigmaA})
	fmt.Println("ntt(sigma(a))", ntt_sigmaA)
	nttA := pp.NTT(a)
	fmt.Println("ntt(a)", nttA.coeffs)
	sigmanttNTTA := pp.sigmaPowerPolyNTT(nttA, 3)
	fmt.Println("sigma_NTT(ntt(a)", sigmanttNTTA)
}

func Test_expandBinaryMatrix(t *testing.T) {
	type args struct {
		seed   []byte
		rownum int
		colnum int
	}
	tests := []struct {
		name     string
		args     args
		wantBinM [][]byte
		wantErr  bool
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{
				seed: []byte{
					48, 113, 50, 115, 52, 117, 54, 119, 56, 121, 58, 123, 60, 125, 62, 127,
					64, 1, 66, 3, 68, 5, 70, 7, 72, 9, 74, 11, 76, 13, 78, 15,
				},
				rownum: 128,
				colnum: 128,
			},
			wantBinM: [][]byte{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBinM, err := expandBinaryMatrix(tt.args.seed, tt.args.rownum, tt.args.colnum)
			if (err != nil) != tt.wantErr {
				t.Errorf("expandBinaryMatrix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotBinM, tt.wantBinM) {
				t.Errorf("expandBinaryMatrix() gotBinM = %v, want %v", gotBinM, tt.wantBinM)
			}
		})
	}
}
