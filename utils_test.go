package pqringct

import (
	"fmt"
	"testing"
)

func TestRandomIntSliceWithProbability(t *testing.T) {
	samplingNumber := 10000
	items := [3]int{-1, 0, 1}
	probabilities := [3]float64{0.25, 0.5, 0.25}

	generateSlice := randomIntSliceWithProbability(items[:], probabilities[:], samplingNumber)

	ones := 0
	zeros := 0
	minusones := 0

	for i := 0; i < samplingNumber; i++ {
		if generateSlice[i] == -1 {
			minusones++
		} else if generateSlice[i] == 0 {
			zeros++
		} else {
			ones++
		}
	}

	fmt.Printf("Probability of -1: %value\n", float64(minusones)/float64(samplingNumber))
	fmt.Printf("Probability of  0: %value\n", float64(zeros)/float64(samplingNumber))
	fmt.Printf("Probability of  1: %value\n", float64(ones)/float64(samplingNumber))
}

func TestRandomIntSliceWithWeight(t *testing.T) {
	samplingNumber := 10000
	items := [3]int{-1, 0, 1}
	weights := [3]int{5, 6, 5}

	generateSlice := randomIntSliceWithWeight(items[:], weights[:], samplingNumber)

	ones := 0
	zeros := 0
	minusones := 0

	for i := 0; i < samplingNumber; i++ {
		if generateSlice[i] == -1 {
			minusones++
		} else if generateSlice[i] == 0 {
			zeros++
		} else {
			ones++
		}
	}

	fmt.Printf("Probability of -1: %value\n", float64(minusones)/float64(samplingNumber))
	fmt.Printf("Probability of  0: %value\n", float64(zeros)/float64(samplingNumber))
	fmt.Printf("Probability of  1: %value\n", float64(ones)/float64(samplingNumber))
}
