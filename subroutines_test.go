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
func TestPublicParameter_sigmaPowerPolyNTT(t *testing.T){
	pp:=DefaultPP
	a1, _ := randomnessFromEtaA(nil, pp.paramD)
	a := &Poly{a1}
	nttA := pp.NTT(a)
	nttA65:=pp.PolyNTTPower(nttA,65)
	nttA65AND193:=pp.PolyNTTPower(nttA65,65)
	fmt.Println(nttA65AND193)
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
		name   string
		args   args
		wantR  *PolyNTT
	}{
		{
			name:"test zero",
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
	sigma3 :=pp.sigmaPowerPolyNTT(b, 3)
	//sigma1inv1 := pp.sigmaInvPolyNTT(sigma1, 1)
	//sigma2inv2 := pp.sigmaInvPolyNTT(sigma2, 2)
	//sigma3inv3 := pp.sigmaInvPolyNTT(sigma3, 3)
	sigmainvTests := []struct {
		name   string
		args   args
		wantR  *PolyNTT
	}{
		{
			name:"test one",
			args: args{
				polyNTT: sigma1,
				t:       1,
			},
			wantR: b,
		},
		{
			name:"test two",
			args: args{
				polyNTT: sigma2,
				t:       2,
			},
			wantR: b,
		},
		{
			name:"test three",
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