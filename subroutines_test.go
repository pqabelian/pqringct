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
func TestPublicParameter_sigmaPowerPolyNTT(t *testing.T) {
	pp := DefaultPP
	a1, _ := randomnessFromEtaA(nil, pp.paramD)
	a := &Poly{a1}
	nttA := pp.NTT(a)
	nttA65 := pp.PolyNTTPower(nttA, 65)
	swap := []int{32, 97, 34, 99, 36, 101, 38, 103, 40, 105, 42, 107, 44, 109, 46, 111, 48, 113, 5,
		0, 115, 52, 117, 54, 119, 56, 121, 58, 123, 60, 125, 62, 127, 64, 1, 66, 3, 68,
		5, 70, 7, 72, 9, 74, 11, 76, 13, 78, 15, 80, 17, 82, 19, 84, 21, 86, 23, 88, 25,
		90, 27, 92, 29, 94, 31, 96, 33, 98, 35, 100, 37, 102, 39, 104, 41, 106, 43, 108,
		45, 110, 47, 112, 49, 114, 51, 116, 53, 118, 55, 120, 57, 122, 59, 124, 61, 12,
		6, 63, 0, 65, 2, 67, 4, 69, 6, 71, 8, 73, 10, 75, 12, 77, 14, 79, 16, 81, 18, 83,
		20, 85, 22, 87, 24, 89, 26, 91, 28, 93, 30, 95}
	sigma := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		sigma[i] = nttA65.coeffs[swap[i]]
	}

	// sigma_inv
	nttA65AND193 := pp.PolyNTTPower(&PolyNTT{coeffs: sigma}, 193)
	swap2 := []int{96, 33, 98, 35, 100, 37, 102, 39, 104, 41, 106, 43, 108, 45, 110, 47, 112, 49, 1,
		14, 51, 116, 53, 118, 55, 120, 57, 122, 59, 124, 61, 126, 63, 0, 65, 2, 67, 4, 6,
		9, 6, 71, 8, 73, 10, 75, 12, 77, 14, 79, 16, 81, 18, 83, 20, 85, 22, 87, 24, 89,
		26, 91, 28, 93, 30, 95, 32, 97, 34, 99, 36, 101, 38, 103, 40, 105, 42, 107, 44,
		109, 46, 111, 48, 113, 50, 115, 52, 117, 54, 119, 56, 121, 58, 123, 60, 125, 62,
		127, 64, 1, 66, 3, 68, 5, 70, 7, 72, 9, 74, 11, 76, 13, 78, 15, 80, 17, 82, 19,
		84, 21, 86, 23, 88, 25, 90, 27, 92, 29, 94, 31,
	}
	res := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		res[i] = nttA65AND193.coeffs[swap2[i]]
	}
	for i := 0; i < pp.paramD; i++ {
		if res[i] != nttA.coeffs[i] {
			fmt.Println("error")
		}
	}
	fmt.Println(nttA.coeffs)
	fmt.Println(res)

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
	sigma1 := pp.sigmaPowerPolyNTT(b, 1)
	sigma2 := pp.sigmaPowerPolyNTT(b, 2)
	sigma3 := pp.sigmaPowerPolyNTT(b, 3)
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
				polyNTT: sigma1,
				t:       1,
			},
			wantR: b,
		},
		{
			name: "test two",
			args: args{
				polyNTT: sigma2,
				t:       2,
			},
			wantR: b,
		},
		{
			name: "test three",
			args: args{
				polyNTT: sigma3,
				t:       3,
			},
			wantR: b,
		},
	}
	for _, tt := range sigmainvTests {
		t.Run(tt.name, func(t *testing.T) {
			if gotR := pp.sigmaInvPolyNTT(tt.args.polyNTT, tt.args.t); !reflect.DeepEqual(gotR, tt.wantR) {
				t.Errorf("sigmaPowerPolyNTT() = \n%v\n, want\n %v\n", gotR, tt.wantR)
			}
		})
	}
}
