package pqringct

import (
	"fmt"
	"log"
	"testing"
)

func TestNaive_randomBytes(t *testing.T) {
	tests := []struct {
		name      string
		times     int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			precision: 1e-3,
			baseline:  0.5,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			precision: 1e-3,
			baseline:  0.5,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			precision: 1e-4,
			baseline:  0.5,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count0 := 0
			count1 := 0
			var rst []byte
			for count := 0; count < tt.times; count++ {
				rst = RandomBytes(RandSeedBytesLen)
				for i := 0; i < RandSeedBytesLen; i++ {
					tmp := rst[i]
					for j := 0; j < 8; j++ {
						if (tmp>>j)&1 == 1 {
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
			if float64(count0)/total-tt.baseline > tt.precision || float64(count0)/total-tt.baseline < -tt.precision {
				t.Errorf("uneven")
			}
			if float64(count1)/total-tt.baseline > tt.precision || float64(count1)/total-tt.baseline < -tt.precision {
				t.Errorf("uneven")
			}
			if tt.manual {
				for i := 0; i < len(rst); i++ {
					fmt.Println("i=", i, "byte:", rst[i])
				}
			}
		})
	}
}

func TestNaive_randomnessPolyAForResponseA(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   10,
			precision: 1e-1,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   10,
			precision: 1e-3,
			baseline:  0.1,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			step := (pp.paramEtaA - int64(pp.paramBetaA) + 4) / 5
			start := -(pp.paramEtaA - int64(pp.paramBetaA))
			end := pp.paramEtaA - int64(pp.paramBetaA)
			var polyA *PolyA
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				polyA, err = pp.randomPolyAForResponseA()
				if err != nil {
					t.Fatal(err)
				}

				for i := 0; i < pp.paramDA; i++ {
					switch {
					case polyA.coeffs[i] < start:
						t.Fatal("ERROR: Sample in left out")
					case polyA.coeffs[i] > end:
						t.Fatal("ERROR: Sample in right out")
					default:
						slot := (polyA.coeffs[i] - start) / step
						count[slot] = count[slot] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDA; i++ {
					fmt.Println(polyA.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomnessPolyCForResponseC(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   10,
			precision: 1e-1,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   10,
			precision: 1e-3,
			baseline:  0.1,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			step := (pp.paramEtaC - int64(pp.paramBetaC) + 4) / 5
			start := -(pp.paramEtaC - int64(pp.paramBetaC))
			end := pp.paramEtaC - int64(pp.paramBetaC)

			var polyC *PolyC
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				polyC, err = pp.randomPolyCForResponseC()
				if err != nil {
					log.Fatal(err)
				}

				for i := 0; i < pp.paramDC; i++ {
					switch {
					case polyC.coeffs[i] < start:
						t.Fatal("ERROR: Sample in left out")
					case polyC.coeffs[i] > end:
						t.Fatal("ERROR: Sample in right out")
					default:
						slot := (polyC.coeffs[i] - start) / step
						count[slot] = count[slot] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDC; i++ {
					fmt.Println(polyC.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomPolyCinEtaC(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   10,
			precision: 1e-1,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   10,
			precision: 1e-3,
			baseline:  0.1,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			start := -pp.paramEtaC
			end := pp.paramEtaC + 1
			step := (end - start) / 10

			var polyC *PolyC
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				polyC, err = pp.randomPolyCinEtaC()
				if err != nil {
					log.Fatal(err)
				}

				for i := 0; i < pp.paramDC; i++ {
					switch {
					case polyC.coeffs[i] < start:
						t.Fatal("ERROR: Sample in left out")
					case polyC.coeffs[i] >= end:
						t.Fatal("ERROR: Sample in right out")
					default:
						slot := (polyC.coeffs[i] - start) / step
						count[slot] = count[slot] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDC; i++ {
					fmt.Println(polyC.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomPolyAinEtaA(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   10,
			precision: 1e-1,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   10,
			precision: 1e-3,
			baseline:  0.1,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			step := (pp.paramEtaA + 4) / 5
			start := -pp.paramEtaA
			end := pp.paramEtaA
			var polyA *PolyA
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				polyA, err = pp.randomPolyAinEtaA()
				if err != nil {
					t.Fatal(err)
				}

				for i := 0; i < pp.paramDA; i++ {
					switch {
					case polyA.coeffs[i] < start:
						t.Fatal("ERROR: Sample in left out")
					case polyA.coeffs[i] > end:
						t.Fatal("ERROR: Sample in right out")
					default:
						slot := (polyA.coeffs[i] - start) / step
						count[slot] = count[slot] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDA; i++ {
					fmt.Println(polyA.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomPolyAinGammaA5(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   11,
			precision: 1e-1,
			baseline:  float64(1) / float64(11),
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   11,
			precision: 1e-2,
			baseline:  float64(1) / float64(11),
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   11,
			precision: 1e-3,
			baseline:  float64(1) / float64(11),
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			start := int64(-5)
			end := int64(5)
			var polyA *PolyA
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				polyA, err = pp.randomPolyAinGammaA5(RandomBytes(RandSeedBytesLen))
				if err != nil {
					t.Fatal(err)
				}

				for i := 0; i < pp.paramDA; i++ {
					switch {
					case polyA.coeffs[i] < start:
						t.Fatal("ERROR: Sample in left out")
					case polyA.coeffs[i] > end:
						t.Fatal("ERROR: Sample in right out")
					default:
						count[polyA.coeffs[i]-start] = count[polyA.coeffs[i]-start] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDA; i++ {
					fmt.Println(polyA.coeffs[i])
				}
			}
		})
	}
}

func TestPublicParameter_randomPolyCinDistributionChi(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  []float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   3,
			precision: 1e-1,
			baseline:  []float64{float64(5) / float64(16), float64(6) / float64(16), float64(5) / float64(16)},
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   3,
			precision: 1e-3,
			baseline:  []float64{float64(5) / float64(16), float64(6) / float64(16), float64(5) / float64(16)},
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   3,
			precision: 1e-3,
			baseline:  []float64{float64(5) / float64(16), float64(6) / float64(16), float64(5) / float64(16)},
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			var polyC *PolyC
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				polyC, err = pp.randomPolyCinDistributionChi(RandomBytes(RandSeedBytesLen))
				if err != nil {
					t.Fatal(err)
				}

				for i := 0; i < pp.paramDC; i++ {
					switch polyC.coeffs[i] {
					case -1:
						count[0]++
					case 0:
						count[1]++
					case 1:
						count[2]++
					default:
						t.Fatal("ERROR: Sample in out")
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline[i] > tt.precision || ratio-tt.baseline[i] < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v, expecte:%v", i, count[i], ratio, tt.baseline[i])
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDC; i++ {
					fmt.Println(polyC.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomDcIntegersInQc(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   10,
			precision: 1e-1,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   10,
			precision: 1e-3,
			baseline:  0.1,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			start := -pp.paramQC >> 1
			end := pp.paramQC>>1 + 1
			step := (end - start) / 10
			var coeffs []int64
			for cnt := 0; cnt < tt.times; cnt++ {
				coeffs = pp.randomDcIntegersInQc(nil)

				for i := 0; i < pp.paramDC; i++ {
					switch {
					case coeffs[i] < start:
						t.Fatalf("ERROR: Sample in left out with %v", coeffs[i])
					case coeffs[i] >= end:
						t.Fatalf("ERROR: Sample in right out with %v", coeffs[i])
					default:
						slot := (coeffs[i] - start) / step
						count[slot] = count[slot] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDC; i++ {
					fmt.Println(coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomDcIntegersInQcEtaF(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   10,
			precision: 1e-1,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   10,
			precision: 1e-3,
			baseline:  0.1,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			start := -pp.paramEtaF
			end := pp.paramEtaF + 1
			step := (end - start + 9) / 10
			var coeffs []int64
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				coeffs, err = pp.randomDcIntegersInQcEtaF()
				if err != nil {
					t.Fatalf(err.Error())
				}

				for i := 0; i < pp.paramDC; i++ {
					switch {
					case coeffs[i] < start:
						t.Fatalf("ERROR: Sample in left out with %v", coeffs[i])
					case coeffs[i] >= end:
						t.Fatalf("ERROR: Sample in right out with %v", coeffs[i])
					default:
						slot := (coeffs[i] - start) / step
						count[slot] = count[slot] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDC; i++ {
					fmt.Println(coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomDcIntegersInQa(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   10,
			precision: 1e-3,
			baseline:  0.1,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			start := -pp.paramQA >> 1
			end := pp.paramQA>>1 + 1
			step := (end - start) / 10
			var coeffs []int64
			for cnt := 0; cnt < tt.times; cnt++ {
				coeffs = pp.randomDaIntegersInQa(nil)

				for i := 0; i < pp.paramDA; i++ {
					switch {
					case coeffs[i] < start:
						t.Fatalf("ERROR: Sample in left out with %v", coeffs[i])
					case coeffs[i] >= end:
						t.Fatalf("ERROR: Sample in right out with %v", coeffs[i])
					default:
						slot := (coeffs[i] - start) / step
						count[slot] = count[slot] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDA; i++ {
					fmt.Println(coeffs[i])
				}
			}
		})
	}
}

func TestNaive_expandChallengeA(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  []float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   3,
			precision: 1e-1,
			baseline:  []float64{float64(pp.paramThetaA>>1) / float64(pp.paramDA), float64(pp.paramDA-pp.paramThetaA) / float64(pp.paramDA), float64(pp.paramThetaA>>1) / float64(pp.paramDA)},
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   3,
			precision: 1e-2,
			baseline:  []float64{float64(pp.paramThetaA>>1) / float64(pp.paramDA), float64(pp.paramDA-pp.paramThetaA) / float64(pp.paramDA), float64(pp.paramThetaA>>1) / float64(pp.paramDA)},
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   3,
			precision: 1e-2,
			baseline:  []float64{float64(pp.paramThetaA>>1) / float64(pp.paramDA), float64(pp.paramDA-pp.paramThetaA) / float64(pp.paramDA), float64(pp.paramThetaA>>1) / float64(pp.paramDA)},
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([][]int, pp.paramDA)
			for i := 0; i < pp.paramDA; i++ {
				count[i] = make([]int, 3)
			}
			var polyA *PolyA
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				polyA, err = pp.expandChallengeA(RandomBytes(RandSeedBytesLen))
				if err != nil {
					t.Errorf(err.Error())
				}

				for i := 0; i < pp.paramDA; i++ {
					switch polyA.coeffs[i] {
					case -1:
						count[i][0] = count[i][0] + 1
					case 0:
						count[i][1] = count[i][1] + 1
					case 1:
						count[i][2] = count[i][2] + 1
					default:
						t.Fatalf("ERROR: Sample in right out with %v", polyA.coeffs[i])

					}
				}
			}
			total := make([]int, pp.paramDA)
			for i := 0; i < pp.paramDA; i++ {
				for j := 0; j < tt.slotNum; j++ {
					total[i] += count[i][j]
				}
			}
			for i := 0; i < pp.paramDA; i++ {
				for j := 0; j < tt.slotNum; j++ {
					ratio := float64(count[i][j]) / float64(total[i])
					if ratio-tt.baseline[j] > tt.precision || ratio-tt.baseline[j] < -tt.precision {
						t.Errorf("slot %d, number %v, percent:%v, expected:%v", j, count[i], ratio, tt.baseline[j])
					}
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDA; i++ {
					fmt.Println(polyA.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_expandChallengeC(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  []float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   3,
			precision: 1e-1,
			baseline:  []float64{0.25, 0.5, 0.25},
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   3,
			precision: 1e-2,
			baseline:  []float64{0.25, 0.5, 0.25},
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   3,
			precision: 1e-2,
			baseline:  []float64{0.25, 0.5, 0.25},
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([][]int, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				count[i] = make([]int, 3)
			}
			var polyC *PolyC
			var err error
			for cnt := 0; cnt < tt.times; cnt++ {
				polyC, err = pp.expandChallengeC(RandomBytes(RandSeedBytesLen))
				if err != nil {
					t.Errorf(err.Error())
				}

				for i := 0; i < pp.paramDC; i++ {
					switch polyC.coeffs[i] {
					case -1:
						count[i][0] = count[i][0] + 1
					case 0:
						count[i][1] = count[i][1] + 1
					case 1:
						count[i][2] = count[i][2] + 1
					default:
						t.Fatalf("ERROR: Sample in right out with %v", polyC.coeffs[i])

					}
				}
			}
			total := make([]int, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				for j := 0; j < tt.slotNum; j++ {
					total[i] += count[i][j]
				}
			}
			for i := 0; i < pp.paramDC; i++ {
				for j := 0; j < tt.slotNum; j++ {
					ratio := float64(count[i][j]) / float64(total[i])
					if ratio-tt.baseline[j] > tt.precision || ratio-tt.baseline[j] < -tt.precision {
						t.Errorf("slot %d, number %v, percent:%v, expected:%v", j, count[i], ratio, tt.baseline[j])
					}
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDC; i++ {
					fmt.Println(polyC.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_samplePloyCWithLowZeros(t *testing.T) {
	pp := Initialize(nil)
	tests := []struct {
		name      string
		times     int
		slotNum   int
		precision float64
		baseline  float64
		manual    bool
	}{
		{
			name:      "10000Time",
			times:     10_000,
			slotNum:   10,
			precision: 1e-1,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "50000Time",
			times:     50_000,
			slotNum:   10,
			precision: 1e-2,
			baseline:  0.1,
			manual:    false,
		},
		{
			name:      "100000Time",
			times:     100_000,
			slotNum:   10,
			precision: 1e-3,
			baseline:  0.1,
			manual:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := make([]int, tt.slotNum)
			start := -pp.paramQC >> 1
			end := pp.paramQC>>1 + 1
			step := (end - start) / 10
			var polyC *PolyC
			for cnt := 0; cnt < tt.times; cnt++ {
				polyC = pp.samplePloyCWithLowZeros()

				for i := 0; i < pp.paramK; i++ {
					if polyC.coeffs[i] != 0 {
						t.Fatalf("ERROR: Sample in left out with %v in %d", polyC.coeffs[i], i)
					}
				}

				for i := pp.paramK; i < pp.paramDC; i++ {
					switch {
					case polyC.coeffs[i] < start:
						t.Fatalf("ERROR: Sample in left out with %v", polyC.coeffs[i])
					case polyC.coeffs[i] >= end:
						t.Fatalf("ERROR: Sample in right out with %v", polyC.coeffs[i])
					default:
						slot := (polyC.coeffs[i] - start) / step
						count[slot] = count[slot] + 1
					}
				}
			}
			total := 0
			for i := 0; i < tt.slotNum; i++ {
				total += count[i]
			}
			for i := 0; i < tt.slotNum; i++ {
				ratio := float64(count[i]) / float64(total)
				if ratio-tt.baseline > tt.precision || ratio-tt.baseline < -tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDC; i++ {
					fmt.Println(polyC.coeffs[i])
				}
			}
		})
	}
}
