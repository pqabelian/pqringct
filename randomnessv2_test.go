package pqringct

import (
	"fmt"
	"log"
	"reflect"
	"testing"
)

//	new test cases begin
func TestNaive_randomBytes(t *testing.T) {

	testManual := true
	count0 := 0
	count1 := 0

	var rst []byte
	for t := 0; t < 1000; t++ {
		rst = RandomBytes(RandSeedBytesLen)
		for i := 0; i < RandSeedBytesLen; i++ {
			byte := rst[i]
			for j := 0; j < 8; j++ {
				if (byte>>j)&1 == 1 {
					count1++
				} else {
					count0++
				}
			}
		}
	}

	total := float64(count0 + count1)
	fmt.Println("number of 0:", count0, "persent:", float64(count0)/total)
	fmt.Println("number of 1:", count0, "persent:", float64(count1)/total)

	if testManual {
		for i := 0; i < len(rst); i++ {
			fmt.Println("i=", i, "byte:", rst[i])
		}
	}

}

func TestNaive_randomnessPolyAForResponseZetaA(t *testing.T) {
	pp := DefaultPP

	manualCheck := true

	count := make([]int, 10)
	slots := make([]int64, 10)
	step := (pp.paramEtaA - int64(pp.paramBetaA)) / 5
	start := -(pp.paramEtaA - int64(pp.paramBetaA))
	end := (pp.paramEtaA - int64(pp.paramBetaA))
	for i := 0; i < 10; i++ {
		slots[i] = start + int64(i)*step
		count[i] = 0
	}
	leftOut := 0
	rightOut := 0

	var polyA *PolyA
	var err error
	for t := 0; t < 10000; t++ {
		polyA, err = pp.randomPolyAForResponseZetaA()
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyA.coeffs[i] < slots[0] {
				leftOut++
			} else if polyA.coeffs[i] < slots[1] {
				count[0] = count[0] + 1
			} else if polyA.coeffs[i] < slots[2] {
				count[1] = count[1] + 1
			} else if polyA.coeffs[i] < slots[3] {
				count[2] = count[2] + 1
			} else if polyA.coeffs[i] < slots[4] {
				count[3] = count[3] + 1
			} else if polyA.coeffs[i] < slots[5] {
				count[4] = count[4] + 1
			} else if polyA.coeffs[i] < slots[6] {
				count[5] = count[5] + 1
			} else if polyA.coeffs[i] < slots[7] {
				count[6] = count[6] + 1
			} else if polyA.coeffs[i] < slots[8] {
				count[7] = count[7] + 1
			} else if polyA.coeffs[i] < slots[9] {
				count[8] = count[8] + 1
			} else if polyA.coeffs[i] <= end {
				count[9] = count[9] + 1
			} else {
				rightOut++
			}
		}
	}

	if leftOut > 0 {
		log.Fatalln("ERROR: Sample in left out")
	}
	if rightOut > 0 {
		log.Fatalln("ERROR: Sample in right out")
	}

	total := 0
	for i := 0; i < 10; i++ {
		total += count[i]
	}
	for i := 0; i < 10; i++ {
		fmt.Println("slot ", i, "number:", count[i], "percent:", float64(count[i])/float64(total))
	}

	if manualCheck {
		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyA.coeffs[i])
		}
	}
}

func TestNaive_randomnessPolyCForResponseZetaC(t *testing.T) {
	pp := DefaultPP

	manualCheck := true

	count := make([]int, 10)
	slots := make([]int64, 10)
	step := (pp.paramEtaC - int64(pp.paramBetaC)) / 5
	start := -(pp.paramEtaC - int64(pp.paramBetaC))
	end := (pp.paramEtaC - int64(pp.paramBetaC))
	for i := 0; i < 10; i++ {
		slots[i] = start + int64(i)*step
		count[i] = 0
	}
	leftOut := 0
	rightOut := 0

	var polyC *PolyC
	var err error
	for t := 0; t < 10000; t++ {
		polyC, err = pp.randomPolyCForResponseZetaC()
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDC; i++ {
			if polyC.coeffs[i] < slots[0] {
				leftOut++
			} else if polyC.coeffs[i] < slots[1] {
				count[0] = count[0] + 1
			} else if polyC.coeffs[i] < slots[2] {
				count[1] = count[1] + 1
			} else if polyC.coeffs[i] < slots[3] {
				count[2] = count[2] + 1
			} else if polyC.coeffs[i] < slots[4] {
				count[3] = count[3] + 1
			} else if polyC.coeffs[i] < slots[5] {
				count[4] = count[4] + 1
			} else if polyC.coeffs[i] < slots[6] {
				count[5] = count[5] + 1
			} else if polyC.coeffs[i] < slots[7] {
				count[6] = count[6] + 1
			} else if polyC.coeffs[i] < slots[8] {
				count[7] = count[7] + 1
			} else if polyC.coeffs[i] < slots[9] {
				count[8] = count[8] + 1
			} else if polyC.coeffs[i] <= end {
				count[9] = count[9] + 1
			} else {
				rightOut++
			}
		}
	}

	if leftOut > 0 {
		log.Fatalln("ERROR: Sample in left out")
	}
	if rightOut > 0 {
		log.Fatalln("ERROR: Sample in right out")
	}

	total := 0
	for i := 0; i < 10; i++ {
		total += count[i]
	}
	for i := 0; i < 10; i++ {
		fmt.Println("slot ", i, "number:", count[i], "percent:", float64(count[i])/float64(total))
	}

	if manualCheck {
		for i := 0; i < pp.paramDC; i++ {
			fmt.Println(polyC.coeffs[i])
		}
	}
}

func TestNaive_randomPolyCinEtaC(t *testing.T) {
	pp := DefaultPP

	manualCheck := true

	count := make([]int, 10)
	slots := make([]int64, 10)
	step := pp.paramEtaC / 5
	start := -pp.paramEtaC
	end := pp.paramEtaC
	for i := 0; i < 10; i++ {
		slots[i] = start + int64(i)*step
		count[i] = 0
	}
	leftOut := 0
	rightOut := 0

	var polyC *PolyC
	var err error
	for t := 0; t < 10000; t++ {
		polyC, err = pp.randomPolyCinEtaC()
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDC; i++ {
			if polyC.coeffs[i] < slots[0] {
				leftOut++
			} else if polyC.coeffs[i] < slots[1] {
				count[0] = count[0] + 1
			} else if polyC.coeffs[i] < slots[2] {
				count[1] = count[1] + 1
			} else if polyC.coeffs[i] < slots[3] {
				count[2] = count[2] + 1
			} else if polyC.coeffs[i] < slots[4] {
				count[3] = count[3] + 1
			} else if polyC.coeffs[i] < slots[5] {
				count[4] = count[4] + 1
			} else if polyC.coeffs[i] < slots[6] {
				count[5] = count[5] + 1
			} else if polyC.coeffs[i] < slots[7] {
				count[6] = count[6] + 1
			} else if polyC.coeffs[i] < slots[8] {
				count[7] = count[7] + 1
			} else if polyC.coeffs[i] < slots[9] {
				count[8] = count[8] + 1
			} else if polyC.coeffs[i] <= end {
				count[9] = count[9] + 1
			} else {
				rightOut++
			}
		}
	}

	if leftOut > 0 {
		log.Fatalln("ERROR: Sample in left out")
	}
	if rightOut > 0 {
		log.Fatalln("ERROR: Sample in right out")
	}

	total := 0
	for i := 0; i < 10; i++ {
		total += count[i]
	}
	for i := 0; i < 10; i++ {
		fmt.Println("slot ", i, "number:", count[i], "percent:", float64(count[i])/float64(total))
	}

	if manualCheck {
		for i := 0; i < pp.paramDC; i++ {
			fmt.Println(polyC.coeffs[i])
		}
	}
}

func TestNaive_randomPolyAinEtaA(t *testing.T) {
	pp := DefaultPP

	manualCheck := true

	count := make([]int, 10)
	slots := make([]int64, 10)
	step := pp.paramEtaA / 5
	start := -pp.paramEtaA
	end := pp.paramEtaA
	for i := 0; i < 10; i++ {
		slots[i] = start + int64(i)*step
		count[i] = 0
	}
	leftOut := 0
	rightOut := 0

	var polyA *PolyA
	var err error
	for t := 0; t < 10000; t++ {
		polyA, err = pp.randomPolyAinEtaA()
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyA.coeffs[i] < slots[0] {
				leftOut++
			} else if polyA.coeffs[i] < slots[1] {
				count[0] = count[0] + 1
			} else if polyA.coeffs[i] < slots[2] {
				count[1] = count[1] + 1
			} else if polyA.coeffs[i] < slots[3] {
				count[2] = count[2] + 1
			} else if polyA.coeffs[i] < slots[4] {
				count[3] = count[3] + 1
			} else if polyA.coeffs[i] < slots[5] {
				count[4] = count[4] + 1
			} else if polyA.coeffs[i] < slots[6] {
				count[5] = count[5] + 1
			} else if polyA.coeffs[i] < slots[7] {
				count[6] = count[6] + 1
			} else if polyA.coeffs[i] < slots[8] {
				count[7] = count[7] + 1
			} else if polyA.coeffs[i] < slots[9] {
				count[8] = count[8] + 1
			} else if polyA.coeffs[i] <= end {
				count[9] = count[9] + 1
			} else {
				rightOut++
			}
		}
	}

	if leftOut > 0 {
		log.Fatalln("ERROR: Sample in left out")
	}
	if rightOut > 0 {
		log.Fatalln("ERROR: Sample in right out")
	}

	total := 0
	for i := 0; i < 10; i++ {
		total += count[i]
	}
	for i := 0; i < 10; i++ {
		fmt.Println("slot ", i, "number:", count[i], "percent:", float64(count[i])/float64(total))
	}

	if manualCheck {
		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyA.coeffs[i])
		}
	}
}

func TestNaive_randomPolyAinGammaA5(t *testing.T) {
	pp := DefaultPP

	manualCheck := true

	count := make([]int, 11)
	slots := make([]int64, 11)
	for i := 0; i < 11; i++ {
		slots[i] = int64(-5 + i)
		count[i] = 0
	}
	leftOut := 0
	rightOut := 0

	var polyA *PolyA
	var err error
	for t := 0; t < 10000; t++ {
		polyA, err = pp.randomPolyAinGammaA5(nil)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyA.coeffs[i] < -5 {
				leftOut++
			} else if polyA.coeffs[i] > 5 {
				rightOut++
			} else {
				count[polyA.coeffs[i]+5] = count[polyA.coeffs[i]+5] + 1
			}
		}
	}

	if leftOut > 0 {
		log.Fatalln("ERROR: Sample in left out")
	}
	if rightOut > 0 {
		log.Fatalln("ERROR: Sample in right out")
	}

	total := 0
	for i := 0; i < 11; i++ {
		total += count[i]
	}
	for i := 0; i < 11; i++ {
		fmt.Println("slot ", i, "number:", count[i], "percent:", float64(count[i])/float64(total))
	}

	if manualCheck {
		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyA.coeffs[i])
		}
	}
}

//	new test cases end
func Test_randomBytes(t *testing.T) {
	type args struct {
		length int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "1",
			args: args{length: 32},
			want: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RandomBytes(tt.args.length)
			fmt.Println(got)
			if reflect.DeepEqual(got, tt.want) {
				t.Errorf("RandomBytes() = %value, want %value", got, tt.want)
			}
		})
	}
}

func Test_randomPolyAinGammaA5(t *testing.T) {
	pp := DefaultPP
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    []int32
		wantErr bool
	}{
		{
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pp.randomPolyAinGammaA5(tt.args.seed)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomPolyAinGammaA5() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < int64(-DefaultPP.paramGammaA) || got.coeffs[i] > int64(DefaultPP.paramGammaA) {
					t.Errorf("randomPolyAinGammaA5() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}

func Test_sampleMaskingVecA(t *testing.T) {
	pp := DefaultPP
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    []int32
		wantErr bool
	}{
		{
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pp.randomPolyAinEtaA()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomPolyAinGammaA5() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < int64(-DefaultPP.paramEtaA) || got.coeffs[i] > int64(DefaultPP.paramEtaA) {
					t.Errorf("randomPolyAinEtaA() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}

func Test_randomnessPolyCForResponseZetaC(t *testing.T) {
	pp := DefaultPP
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    []int32
		wantErr bool
	}{
		{
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pp.randomPolyCForResponseZetaC()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomPolyCForResponseZetaC() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < -(DefaultPP.paramEtaC-int64(DefaultPP.paramBetaC)) || got.coeffs[i] > (DefaultPP.paramEtaC-int64(DefaultPP.paramBetaC)) {
					t.Errorf("randomPolyCForResponseZetaC() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}

func Test_randomnessFromZetaAv2(t *testing.T) {
	pp := DefaultPP

	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    []int32
		wantErr bool
	}{
		{
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pp.randomPolyAForResponseZetaA()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomPolyAForResponseZetaA() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < -(DefaultPP.paramEtaA-int64(DefaultPP.paramThetaA*DefaultPP.paramGammaA)) || got.coeffs[i] > DefaultPP.paramEtaA-int64(DefaultPP.paramThetaA*DefaultPP.paramGammaA) {
					t.Errorf("randomPolyAForResponseZetaA() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}

func Test_randomPolyCinEtaC(t *testing.T) {
	pp := DefaultPP
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    []int32
		wantErr bool
	}{
		{
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pp.randomPolyCinEtaC()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomPolyCinEtaC() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < -(DefaultPP.paramEtaC) || got.coeffs[i] > (DefaultPP.paramEtaC) {
					t.Errorf("randomPolyCinEtaC() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}
