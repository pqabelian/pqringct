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
	res := make([]byte, 0, length)
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
func randomnessFromProbabilityDistributions(seed []byte, length int) ([]byte, []int32, error) {
	res := make([]int32, length)
	// if the seed is nil, acquire the seed from crypto/rand.Reader
	if seed == nil {
		seed = randomBytes(length / 2)
	}
	// check the length of seed, make sure the randomness is enough
	if len(seed) < length/2 {
		return seed, nil, ErrLength
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
	return seed, res, nil
}

func randomnessFromEtaC(seed []byte, length int) ([]int32, error) {
	// 1<<18 -1
	bytes := make([]byte, (19*length+7)/8)
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(bytes)
	if err != nil {
		return nil, err
	}
	res := make([]int32, length)
	pos := 0
	for pos/9*4+3 < length {
		res[pos/9*4+0] = int32(bytes[pos+0]&0xFF)<<10 | int32(bytes[pos+1])<<2 | int32(bytes[pos+2]&0xC0)>>6
		res[pos/9*4+1] = int32(bytes[pos+2]&0x3F)<<12 | int32(bytes[pos+3])<<4 | int32(bytes[pos+4]&0xF0)>>4
		res[pos/9*4+2] = int32(bytes[pos+4]&0x0F)<<14 | int32(bytes[pos+5])<<6 | int32(bytes[pos+6]&0xFC)>>2
		res[pos/9*4+3] = int32(bytes[pos+6]&0x03)<<16 | int32(bytes[pos+7])<<8 | int32(bytes[pos+8]&0xFF)>>0
		pos += 9
	}
	for i := 0; i < length; i += 8 {
		for j := 0;  j < 8 &&i+j<length; j++ {
			if (bytes[pos]>>j)&1 == 0 {
				res[i+j] = -res[i+j]
			}
		}
		pos++
	}
	return res[:length], nil
}
func randomnessFromEtaA(seed []byte, length int) ([]int32, error) {
	// 1<<15-1
	bytes := make([]byte, (15*length+7)/8)
	if seed == nil {
		seed = randomBytes(32)
	}
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(bytes)
	if err != nil {
		return nil, err
	}
	res := make([]int32, length)
	pos := 0
	for pos < len(bytes) {
		res[pos/2+0] = int32(bytes[pos+0])<<8 | int32(bytes[pos+1])<<0
		res[pos/2+1] = int32(bytes[pos+2])<<8 | int32(bytes[pos+3])<<0
		pos += 4
	}
	return res[:length], nil
}
func randomnessFromEtaC2(seed []byte, length int) ([]int32, error) {
	// 1<<16-1
	bytes := make([]byte, 2*length)
	if seed == nil {
		seed = randomBytes(32)
	}
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(bytes)
	if err != nil {
		return nil, err
	}
	res := make([]int32, length)
	pos := 0
	for pos < len(bytes) {
		res[pos/2+0] = int32(bytes[pos+0])<<8 | int32(bytes[pos+1])<<0
		res[pos/2+1] = int32(bytes[pos+2])<<8 | int32(bytes[pos+3])<<0
		pos += 4
	}
	for i := 0; i < length; i += 8 {
		for j := 0; j < 8; j++ {
			if (bytes[pos]>>j)&1 == 0 {
				res[i] = -res[i]
			}
		}
		pos++
	}
	return res[:length], nil
}

func randomnessFromZetaA(seed []byte, length int) ([]int32, error) {
	// etaA - betaA = 1<<15-1 - 256
	res := make([]int32, 0, length)
	bytes := make([]byte, (length+7)/8)
	if seed == nil {
		seed = randomBytes(32)
	}
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(append(seed, byte(0)))
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(bytes)
	if err != nil {
		return nil, err
	}
	pos := 0
	for i := 0; i < length; i += 8 {
		for j := 0; j < 8; j++ {
			if (bytes[pos]>>j)&1 == 0 {
				res = append(res, -1)
			} else {
				res = append(res, 1)
			}
		}
	}
	cnt := 1
	cur := 0
	for len(res) < length {
		bytes = make([]byte, 2*(length-len(res)))
		xof.Reset()
		_, err := xof.Read(append(seed, byte(cnt)))
		if err != nil {
			return nil, err
		}
		_, err = xof.Read(bytes)
		if err != nil {
			return nil, err
		}
		pos = 0
		var value int32
		for pos < len(bytes) {
			value = int32(bytes[pos+0]&0xFF)<<7 | int32(bytes[pos+1]&0xFE)>>1
			if value < 1<<15-257 {
				res[cur] *= value
				cur++
			}
			value = int32(bytes[pos+1]&0x01)<<14 | int32(bytes[pos+2])<<6 | int32(bytes[pos+3]&0xFC)>>2
			if value < 1<<15-257 {
				res[cur] *= value
				cur++
			}
			value = int32(bytes[pos+3]&0x03)<<13 | int32(bytes[pos+4])<<5 | int32(bytes[pos+5]&0xF8)>>3
			if value < 1<<15-257 {
				res[cur] *= value
				cur++
			}
			value = int32(bytes[pos+5]&0x07)<<12 | int32(bytes[pos+6])<<4 | int32(bytes[pos+7]&0xF0)>>4
			if value < 1<<15-257 {
				res[cur] *= value
				cur++
			}
			value = int32(bytes[pos+7]&0x0F)<<11 | int32(bytes[pos+8])<<3 | int32(bytes[pos+9]&0xE0)>>5
			if value < 1<<15-257 {
				res[cur] *= value
				cur++
			}
			value = int32(bytes[pos+9]&0x1F)<<10 | int32(bytes[pos+10])<<2 | int32(bytes[pos+11]&0xC0)>>6
			if value < 1<<15-257 {
				res[cur] *= value
				cur++
			}
			value = int32(bytes[pos+11]&0x3F)<<9 | int32(bytes[pos+12])<<1 | int32(bytes[pos+13]&0x80)>>7
			if value < 1<<15-257 {
				res[cur] *= value
				cur++
			}
			value = int32(bytes[pos+13]&0x7F)<<8 | int32(bytes[pos+14])>>0
			if value < 1<<15-257 {
				res[cur] *= value
				cur++
			}
			pos += 15
		}
	}

	return res[:length], nil
}
func randomnessFromZetaC2(seed []byte, length int) ([]int32, error) {
	// etaC2 - betaC2 = 1<<16-1 - 256
	res := make([]int32, 0, length)
	bytes := make([]byte, (length+7)/8)
	if seed == nil {
		seed = randomBytes(32)
	}
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(append(seed, byte(0)))
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(bytes)
	if err != nil {
		return nil, err
	}
	pos := 0
	for i := 0; i < length; i += 8 {
		for j := 0; j < 8; j++ {
			if (bytes[pos]>>j)&1 == 0 {
				res = append(res, -1)
			} else {
				res = append(res, 1)
			}
		}
	}
	cnt := 1
	cur := 0
	for len(res) < length {
		bytes = make([]byte, 2*(length-len(res)))
		xof.Reset()
		_, err := xof.Write(append(seed, byte(cnt)))
		if err != nil {
			return nil, err
		}
		_, err = xof.Read(bytes)
		if err != nil {
			return nil, err
		}
		pos = 0
		var value int32
		for pos < len(bytes) {
			value= int32(bytes[pos+0])<<8 | int32(bytes[pos+1])
			if value< 1<<16-256 {
				res[cur]*=value
				cur++
			}
			value= int32(bytes[pos+2])<<8 | int32(bytes[pos+3])
			if value< 1<<16-256 {
				res[cur]*=value
				cur++
			}
			pos += 4
		}
	}

	return res[:length], nil
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

//func sampleRandomness4A() {
//
//	panic("implement me")
//
//}
//func sampleRandomness4C() {
//
//	panic("implement me")
//}
//func sampleEtaA() {
//
//	panic("implement me")
//}
//
//func sampleEtaC() {
//
//	panic("implement me")
//}
//
//func sampleZetaA() {
//	panic("implement me")
//}
//
//func sampleZetaC() {
//	panic("implement me")
//}
//
//func sampleZetaC2() {
//	panic("implement me")
//}
//
//func generateChallenge() {
//	panic("implement me")
//}
