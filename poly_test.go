package pqringct

import (
	"reflect"
	"testing"
)

func TestPublicParameter_NTTAndNTTInv(t *testing.T) {
	pp := DefaultPP
	coeffs,_:=randomnessFromEtaA(nil,pp.paramD)
	//coeffs := []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128}
	//coeffs := []int32{-670655946,1505811237,3332332,4421, 861, 1, 1, 1, 1, 1, 1, 987, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	poly := &Poly{coeffs: coeffs}
	for i := 0; i < pp.paramD; i++ {
		poly.coeffs[i] = pp.reduce(int64(poly.coeffs[i]))
	}
	type args struct {
		poly *Poly
	}
	tests := []struct {
		name     string
		args     args
		wantPoly *Poly
	}{
		{
			name:     "test one",
			args:     args{poly: poly},
			wantPoly: poly,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotPoly := pp.NTTInv(pp.NTT(tt.args.poly)); !reflect.DeepEqual(gotPoly, tt.wantPoly) {
				t.Errorf("\ngotPoly = %v \n want %v", gotPoly, tt.wantPoly)
			}
		})
	}
}

func TestPublicParameter_PolyNTTPower(t *testing.T) {

	type args struct {
		a *PolyNTT
		e uint
	}
	tests := []struct {
		name   string
		args   args
		wantR  *PolyNTT
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pp := DefaultPP
			if gotR := pp.PolyNTTPower(tt.args.a, tt.args.e); !reflect.DeepEqual(gotR, tt.wantR) {
				t.Errorf("PolyNTTPower() = %v, want %v", gotR, tt.wantR)
			}
		})
	}
}