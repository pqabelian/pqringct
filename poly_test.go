package pqringct

import (
	"fmt"
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

//var nttcoeffs = make([]int32, DefaultPP.paramD)

func TestNTT(t *testing.T) {
	pp := DefaultPP
	originalCoeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		originalCoeffs[i] = int32(i)
	}

	coeffs := make([]int32, pp.paramD)
	copy(coeffs, originalCoeffs)

	fmt.Println("original:", originalCoeffs)

	//	NTT
	fmt.Println("test NTT")
	segNum := 1
	segLen := pp.paramD
	factors := make([]int,1)
	factors[0] = pp.paramD/2

	for true {
		//		fmt.Println(factors)

		segLenHalf := segLen/2

		for k := 0; k < segNum; k++ {
			for i := 0; i < segLenHalf; i++ {
				tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
				tmp1 := pp.reduce( int64(coeffs[k*segLen+i]) - tmp )
				tmp2 := pp.reduce( int64(coeffs[k*segLen+i]) + tmp )

				coeffs[k*segLen+i] = tmp1
				coeffs[k*segLen+i+segLenHalf] = tmp2
				//				fmt.Println(k*segLen+i, k*segLen+i+segLenHalf, k*segLen+i, factors[k])
			}
		}

		segNum = segNum<<1
		segLen = segLen>>1
		if segNum == pp.paramD {
			break
		}

		tmpFactors := make([]int, 2*len(factors))
		for i := 0; i < len(factors); i++ {
			tmpFactors[2*i] = (factors[i] + pp.paramD)/2
			tmpFactors[2*i+1] = factors[i]/2
		}
		factors = tmpFactors
	}

	fmt.Println("final factors:")
	finalFactors := make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = (factors[i] + pp.paramD)
		finalFactors[2*i+1] = factors[i]
	}
	fmt.Println("final factors:", finalFactors)
	fmt.Println("(Native) NTT coeffs:", coeffs)

	// SigmaNTT may need the NTT coefficients  to be arranges as 1, 3, 5, ..., 2d-1
	nttCoeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		nttCoeffs[(finalFactors[i]-1)/2] = coeffs[i]
	}
	fmt.Println("Ordered NTT coeffs:", nttCoeffs)

	//	NTTInv

	//	initial the NTT end-status
	fmt.Println("test NTTInv")

	//	Initialize the ending status of NTT
	segNum = 1
	segLen = pp.paramD
	factors = make([]int,1)
	factors[0] = pp.paramD/2

	for true {
		//		fmt.Println(factors)

		//		segLenHalf := segLen/2

		/*		for k := 0; k < segNum; k++ {
				for i := 0; i < segLenHalf; i++ {
					tmp := int64(coeffs[k*segLen+i+segLenHalf]) * zetas[factors[k]]
					coeffs[k*segLen+i] = pp.reduce( int64(coeffs[k*segLen+i]) - tmp )
					coeffs[k*segLen+i+segLenHalf] = pp.reduce( int64(coeffs[k*segLen+i]) + tmp )
					//				fmt.Println(k*segLen+i, k*segLen+i+segLenHalf, k*segLen+i, factors[k])
				}
			}*/

		segNum = segNum<<1
		segLen = segLen>>1
		if segNum == pp.paramD {
			break
		}

		tmpFactors := make([]int, 2*len(factors))
		for i := 0; i < len(factors); i++ {
			tmpFactors[2*i] = (factors[i] + pp.paramD)/2
			tmpFactors[2*i+1] = factors[i]/2
		}
		factors = tmpFactors
	}
	finalFactors = make([]int, 2*len(factors))
	for i := 0; i < len(factors); i++ {
		finalFactors[2*i] = (factors[i] + pp.paramD)
		finalFactors[2*i+1] = factors[i]
	}
	fmt.Println("final factors:", finalFactors)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = nttCoeffs[(finalFactors[i]-1)/2]
	}

	fmt.Println("NTTInv ...")
	//	segNum == pp.paramD, segLen = 1, len(factors) = pp.paramD/2

	twoInv := int64((pp.paramQ+1)/2) - int64(pp.paramQ)
	fmt.Println("2^{-1}:", twoInv)

	for true {
		//		fmt.Println(factors)
		segLenDouble := segLen * 2

		for k := 0; k < segNum/2; k++ {
			for i := 0; i < segLen; i++ {
				tmp1 := pp.reduce(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen]) + int64(coeffs[k*segLenDouble+i])) * twoInv)
				tmp2 := pp.reduce(pp.reduceInt64(pp.reduceInt64(int64(coeffs[k*segLenDouble+i+segLen]) - int64(coeffs[k*segLenDouble+i])) * twoInv) * zetas[2*pp.paramD - factors[k]])
				coeffs[k*segLenDouble+i] = tmp1
				coeffs[k*segLenDouble+i+segLen] = tmp2

				//				fmt.Println(k*segLenDouble+i, k*segLenDouble+i+segLen, k*segLenDouble+i, k*segLenDouble+i+segLen )
			}
		}

		segNum = segNum>>1
		segLen = segLen<<1
		if segNum == 1 {
			break
		}

		tmpFactors := make([]int, len(factors)/2)
		for i := 0; i < len(tmpFactors); i++ {
			tmpFactors[i] = factors[2*i+1] * 2
		}
		factors = tmpFactors

	}
	fmt.Println("NTTInv Result:", coeffs)



}