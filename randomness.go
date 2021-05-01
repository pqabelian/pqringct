package pqringct

import (
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"log"
)

// Distribution defines the distribution in pqringct
type Distribution struct {
	totalWeight int
	values      []int
	weights     []int
}

var Sc Distribution = Distribution{
	totalWeight: 4,
	values:      []int{-1, 0, 1},
	weights:     []int{1, 2, 1},
}
var Sr Distribution = Distribution{
	totalWeight: 16,
	values:      []int{-1, 0, 1},
	weights:     []int{5, 6, 5},
}

func randomBytes(length int) []byte {
	res := make([]byte, length)
	for length > 0 {
		tmp := make([]byte, length)
		n, err := rand.Read(tmp)
		if err != nil {
			log.Fatalln(err)
			return nil
		}
		res = append(res, tmp[:n]...)
		length -= n
	}
	return res
}

// TODO: using randomnessFromDistribution to implement others

func randomFromDistribution(seed []byte, dist Distribution, length int) ([]byte, []int) {
	// TODO: consider add a parameter System Parameter for seed ?
	if seed == nil || len(seed) == 0 {
		seed = randomBytes(64)
	}
	res := make([]int, length)
	// expand the seed with prf
	shake256 := sha3.NewShake256()
	nonce := 0
	_, _ = shake256.Write(seed)
	_, _ = shake256.Write([]byte{byte(nonce)})
	tmp := make([]byte, 32)
	pool := make([]byte, 64)
	cur := 0
	// generate from expanded seed
	for length > 0 {
		_, _ = shake256.Read(tmp)
		// TODO: random a number in distribution
		if cur >= len(pool) {
			_, _ = shake256.Write([]byte{byte(nonce)})
			_, _ = shake256.Read(tmp)
			pool = append(pool, tmp...)
		}
		panic("This function is not completed")
	}
	return seed, res

}

func sampleRandomness4A() {
	//	todo: (S_r)^{l_a}
	panic("implement me")

}
func sampleRandomness4C() {
	//	todo: (S_r)^{l_c}
	panic("implement me")
}
func sampleEtaA() {
	//	todo: (S_{eta_a})^{l_c}
	panic("implement me")
}

func sampleEtaC() {
	//	todo: (S_{eta_c})^{l_c}
	panic("implement me")
}

func sampleZetaA() {
	panic("implement me")
}

func sampleZetaC() {
	panic("implement me")
}

func sampleZetaC2() {
	panic("implement me")
}

func generateChallenge() {
	panic("implement me")
}
