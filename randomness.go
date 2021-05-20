package pqringct

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/sha3"
	"log"
)

var ErrLength = errors.New("invalid length")

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

// randomBytes returns a byte array with given length from crypto/rand.Reader
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

// randomnessFromProbabilityDistributions sample randomness the distribution {-1,0,1} with P(0)=6/16 and P(1)=P(-1)=5/16
// and return an array with given length. If the length of seed is not 0 or length/2, will return ErrLength, and if the
// seed is nil, then there will get a seed from the machine.
func randomnessFromProbabilityDistributions(seed []byte, length int) ([]int32, error) {
	res := make([]int32, length)
	// if the seed is nil, acquire the seed from crypto/rand.Reader
	if seed == nil {
		seed = randomBytes(length / 2)
	}
	// check the length of seed, make sure the randomness is enough
	if len(seed) < length/2 {
		return nil, ErrLength
	}
	var a1, a2, b1, b2 int32
	for i := 0; i < length/2; i++ {
		a1 = int32((seed[i] & (1 << 3)) >> 3)
		a2 = int32((seed[i] & (1 << 2)) >> 2)
		b1 = int32((seed[i] & (1 << 1)) >> 1)
		b2 = int32((seed[i] & (1 << 0)) >> 0)
		res[2*i] = a1 + a2 - b1 - b2
		a1 = int32((seed[i] & (1 << 7)) >> 7)
		a2 = int32((seed[i] & (1 << 6)) >> 6)
		b1 = int32((seed[i] & (1 << 5)) >> 5)
		b2 = int32((seed[i] & (1 << 4)) >> 4)
		res[2*i+1] = a1 + a2 - b1 - b2
	}
	for i := 0; i < length; i++ {
		if res[i] < -1 {
			res[i] += 3
		}
		if res[i] > 1 {
			res[i] -= 3
		}
	}
	return res, nil
}

// randomnessFromProbabilityDistributions sample randomness the distribution {-1,0,1} with P(0)=1/2 and P(1)=P(-1)=1/4
// and return an array with given length
func randomnessFromChallengeSpace(seed []byte, length int) ([]int32, error) {
	res := make([]int32, length)
	// if the seed is nil, acquire the seed from crypto/rand.Reader
	if seed == nil {
		seed = randomBytes(length / 4)
	}
	// check the length of seed, make sure the randomness is enough
	if len(seed) < length/4 {
		return nil, ErrLength
	}
	var a1, a2, a3, a4, b1, b2, b3, b4 int32
	for i := 0; i < length/4; i++ {
		a1 = int32((seed[i] & (1 << 0)) >> 0)
		b1 = int32((seed[i] & (1 << 1)) >> 1)
		a2 = int32((seed[i] & (1 << 2)) >> 2)
		b2 = int32((seed[i] & (1 << 3)) >> 3)
		a3 = int32((seed[i] & (1 << 4)) >> 4)
		b3 = int32((seed[i] & (1 << 5)) >> 5)
		a4 = int32((seed[i] & (1 << 6)) >> 6)
		b4 = int32((seed[i] & (1 << 7)) >> 7)
		res[2*i+0] = a1 - b1
		res[2*i+1] = a2 - b2
		res[2*i+2] = a3 - b3
		res[2*i+3] = a4 - b4
	}
	return res, nil
}

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
