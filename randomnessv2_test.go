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
			if float64(count0)/total-tt.baseline > tt.precision {
				t.Errorf("uneven")
			}
			if float64(count0)/total-tt.baseline > tt.precision {
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

func TestNaive_randomnessPolyAForResponseZetaA(t *testing.T) {
	pp := DefaultPP
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
				polyA, err = pp.randomPolyAForResponseZetaA()
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
				if ratio-tt.baseline > tt.precision {
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

func TestNaive_randomnessPolyCForResponseZetaC(t *testing.T) {
	pp := DefaultPP
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
				polyC, err = pp.randomPolyCForResponseZetaC()
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
				if ratio-tt.baseline > tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDA; i++ {
					fmt.Println(polyC.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomPolyCinEtaC(t *testing.T) {
	pp := DefaultPP
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
			step := (pp.paramEtaC + 4) / 5
			start := -pp.paramEtaC
			end := pp.paramEtaC

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
				if ratio-tt.baseline > tt.precision {
					t.Errorf("slot %d, number %v, percent:%v", i, count[i], ratio)
				}
			}

			if tt.manual {
				for i := 0; i < pp.paramDA; i++ {
					fmt.Println(polyC.coeffs[i])
				}
			}
		})
	}
}

func TestNaive_randomPolyAinEtaA(t *testing.T) {
	pp := DefaultPP
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
				if ratio-tt.baseline > tt.precision {
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
	pp := DefaultPP
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
				if ratio-tt.baseline > tt.precision {
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
