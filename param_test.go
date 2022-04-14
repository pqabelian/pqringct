package pqringct

import (
	"fmt"
	"log"
	"math"
	"testing"
)

func TestGeneratePolyANTTMatrix(t *testing.T) {
	pp := Initialize(nil)

	slotNum := 100
	start := -(pp.paramQA - 1) / 2
	end := (pp.paramQA-1)/2 + 1
	step := (end - start) / int64(slotNum)
	count := make([]int, slotNum)
	for i := 0; i < slotNum; i++ {
		count[i] = 0
	}

	for i := 0; i < 10; i++ {
		crsByte := RandomBytes(RandSeedBytesLen)
		matrixA, err := pp.generatePolyANTTMatrix(crsByte, pp.paramKA, 1+pp.paramLambdaA)
		if err != nil {
			log.Fatal(err)
		}
		for j := 0; j < pp.paramKA; j++ {
			for k := 0; k < 1+pp.paramLambdaA; k++ {
				for h := 0; h < pp.paramDA; h++ {
					coeff := matrixA[j].polyANTTs[k].coeffs[h]
					if coeff < start {
						log.Fatal("Left out")
					} else if coeff >= end {
						log.Fatal("Right out")
					}
					for slot := 0; slot < slotNum; slot++ {
						left := start + int64(slot)*step
						right := start + (int64(slot)+1)*step
						if slot == slotNum-1 {
							right = end
						}
						if coeff >= left && coeff < right {
							count[slot] = count[slot] + 1
							break
						}
					}
				}
			}
		}
	}

	total := 0
	for i := 0; i < slotNum; i++ {
		total += count[i]
	}

	standRatio := 1.0 / float64(slotNum)
	errTolerate := standRatio * 0.1
	for i := 0; i < slotNum; i++ {
		ratio := float64(count[i]) / float64(total)

		if math.Abs(ratio-standRatio) > errTolerate {
			fmt.Println("i:", i, "count:", count[i], "percent:", ratio)
		}
		//fmt.Println("i:", i, "count:", count[i], "percent:", ratio)
	}

}

func TestGeneratePolyCNTTMatrix(t *testing.T) {
	pp := Initialize(nil)

	slotNum := 100
	start := -(pp.paramQC - 1) / 2
	end := (pp.paramQC-1)/2 + 1
	step := (end - start) / int64(slotNum)
	count := make([]int, slotNum)
	for i := 0; i < slotNum; i++ {
		count[i] = 0
	}

	for i := 0; i < 10; i++ {
		crsByte := RandomBytes(RandSeedBytesLen)
		matrixA, err := pp.generatePolyCNTTMatrix(crsByte, pp.paramKC, 1+pp.paramLambdaC)
		if err != nil {
			log.Fatal(err)
		}
		for j := 0; j < pp.paramKC; j++ {
			for k := 0; k < 1+pp.paramLambdaC; k++ {
				for h := 0; h < pp.paramDC; h++ {
					coeff := matrixA[j].polyCNTTs[k].coeffs[h]
					if coeff < start {
						log.Fatal("Left out")
					} else if coeff >= end {
						log.Fatal("Right out")
					}
					for slot := 0; slot < slotNum; slot++ {
						left := start + int64(slot)*step
						right := start + (int64(slot)+1)*step
						if slot == slotNum-1 {
							right = end
						}
						if coeff >= left && coeff < right {
							count[slot] = count[slot] + 1
							break
						}
					}
				}
			}
		}
	}

	total := 0
	for i := 0; i < slotNum; i++ {
		total += count[i]
	}

	standRatio := 1.0 / float64(slotNum)
	errTolerate := standRatio * 0.1
	for i := 0; i < slotNum; i++ {
		ratio := float64(count[i]) / float64(total)

		if math.Abs(ratio-standRatio) > errTolerate {
			fmt.Println("i:", i, "count:", count[i], "percent:", ratio)
		}
		//fmt.Println("i:", i, "count:", count[i], "percent:", ratio)
	}

}
