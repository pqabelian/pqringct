package pqringct

import (
	"crypto/rand"
	"log"
	"math/big"
)

// TODO: random benchmark with CCS20
// generate single int with given probabilities
func randomIntWithProbability(items []int, probabilities []float64) int {
	if len(items) != len(probabilities) {
		log.Fatalln("items length and probabilities length unmatch")
	}
	rng := rand.Reader
	num, err := rand.Int(rng, big.NewInt(256))
	if err != nil {
		log.Fatalln("randInt error")
	}
	var normalizedNum float64 = float64(num.Int64()) / 256

	curr := 0.0
	cnt := 0
	for _, probability := range probabilities {
		curr += probability
		if normalizedNum < curr {
			break
		}
		cnt++
	}
	return items[cnt]
}

// TODO change the name to randomnessFromDistribution
// generate single int with given weights
func randomIntWithWeight(items []int, weights []int) int {
	if len(items) != len(weights) {
		log.Fatalln("items length and weight length unmatch")
	}

	totalWeight := 0
	for _, weight := range weights {
		totalWeight += weight
	}

	rng := rand.Reader
	num, err := rand.Int(rng, big.NewInt(int64(totalWeight)))
	if err != nil {
		log.Fatalln("randInt error")
	}
	var num2 int = int(num.Int64())

	curr := 0
	cnt := 0
	for _, weight := range weights {
		curr += weight
		if num2 < curr {
			break
		}
		cnt++
	}
	return items[cnt]
}

// generate int slice with given probabilities
func randomIntSliceWithProbability(items []int, probabilities []float64, n int) []int {
	// check parameter validity
	if n <= 0 {
		log.Fatalln("generate array with zero length error")
	}
	if len(items) != len(probabilities) {
		log.Fatalln("items length and probabilities length unmatch error")
	}
	if len(items) == 0 {
		log.Fatalln("empty items array error")
	}

	generateSlice := make([]int, n, n)
	rng := rand.Reader

	for i := 0; i < n; i++ {
		num, err := rand.Int(rng, big.NewInt(256))
		if err != nil {
			log.Fatalln("randInt error")
		}
		var normalizedNum float64 = float64(num.Int64()) / 256

		curr := 0.0
		cnt := 0
		for _, probability := range probabilities {
			curr += probability
			if normalizedNum < curr {
				break
			}
			cnt++
		}
		generateSlice[i] = items[cnt]
	}
	return generateSlice
}

// generate int slice with given weights
// SampleFromRand and ExtendFromSeed
func randomIntSliceWithWeight(items []int, weights []int, n int) (res []int) {
	// check parameter validity
	if n <= 0 {
		log.Fatalln("generate array with zero length error")
	}
	if len(items) != len(weights) {
		log.Fatalln("items length and weight length unmatch")
	}
	if len(items) == 0 {
		log.Fatalln("empty items array error")
	}

	totalWeight := 0
	for _, weight := range weights {
		totalWeight += weight
	}

	generateSlice := make([]int, n, n)
	rng := rand.Reader
	//TODO: rng from seed not from rand.Reader
	for i := 0; i < n; i++ {
		num, err := rand.Int(rng, big.NewInt(int64(totalWeight)))
		if err != nil {
			log.Fatalln("randInt error")
		}
		var num2 int = int(num.Int64())

		curr := 0
		cnt := 0
		for _, weight := range weights {
			curr += weight
			if num2 < curr {
				break
			}
			cnt++
		}
		generateSlice[i] = items[cnt]
	}
	return generateSlice
}

func reduce(pp *PublicParameter, a int64) int32 {
	var tmp int64
	tmp = a % int64(pp.paramQ)
	if tmp > int64(pp.paramQ>>1) {
		tmp = tmp - int64(pp.paramQ)
	} else if tmp < -int64(pp.paramQ>>1) {
		tmp = tmp + int64(pp.paramQ)
	}
	return int32(tmp)
}