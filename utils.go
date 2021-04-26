package pqringct

import (
	"crypto/rand"
	"log"
	"math/big"
)

func randomInt(items []int, probabilities []float64) int {
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

func randomInt2(items []int, weights []int) int {
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
