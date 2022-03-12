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
	// 1<<25-1
	bytes := make([]byte, (26*length+7)/8)
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
	for pos/25*8+7 < length {
		res[pos/25*8+0] = int32(bytes[pos+0]&0xFF)<<17 | int32(bytes[pos+1])<<9 | int32(bytes[pos+2])<<1 | int32(bytes[pos+3]&0x80)>>7
		res[pos/25*8+1] = int32(bytes[pos+3]&0x7F)<<18 | int32(bytes[pos+4])<<10 | int32(bytes[pos+5])<<2 | int32(bytes[pos+6]&0xC0)>>6
		res[pos/25*8+2] = int32(bytes[pos+6]&0x3F)<<19 | int32(bytes[pos+7])<<11 | int32(bytes[pos+8])<<3 | int32(bytes[pos+9]&0xE0)>>5
		res[pos/25*8+3] = int32(bytes[pos+9]&0x1F)<<20 | int32(bytes[pos+10])<<12 | int32(bytes[pos+11])<<4 | int32(bytes[pos+12]&0xF0)>>4
		res[pos/25*8+4] = int32(bytes[pos+12]&0x0F)<<21 | int32(bytes[pos+13])<<13 | int32(bytes[pos+14])<<5 | int32(bytes[pos+15]&0xF8)>>3
		res[pos/25*8+5] = int32(bytes[pos+15]&0x07)<<22 | int32(bytes[pos+16])<<14 | int32(bytes[pos+17])<<6 | int32(bytes[pos+18]&0xFC)>>2
		res[pos/25*8+6] = int32(bytes[pos+18]&0x03)<<23 | int32(bytes[pos+19])<<15 | int32(bytes[pos+20])<<7 | int32(bytes[pos+21]&0xFE)>>1
		res[pos/25*8+7] = int32(bytes[pos+21]&0x01)<<24 | int32(bytes[pos+22])<<16 | int32(bytes[pos+23])<<8 | int32(bytes[pos+24]&0xFF)>>0
		pos += 25
	}
	for i := 0; i < length; i += 8 {
		for j := 0; j < 8 && i+j < length; j++ {
			if (bytes[pos]>>j)&1 == 0 {
				res[i+j] = -res[i+j]
			}
		}
		pos++
	}
	return res[:length], nil
}
func randomnessFromEtaA(seed []byte, length int) ([]int32, error) {
	// 1<<22-1
	bytes := make([]byte, (24*length+7)/8)
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
	for pos/11*8+7 < length {
		res[pos/11*8+0] = int32(bytes[pos+0]&0xFF)<<14 | int32(bytes[pos+1])<<6 | int32(bytes[pos+2]&0xFC)>>2
		res[pos/11*8+1] = int32(bytes[pos+2]&0x03)<<20 | int32(bytes[pos+3])<<12 | int32(bytes[pos+4])<<4 | int32(bytes[pos+5]&0xF0)>>4
		res[pos/11*8+2] = int32(bytes[pos+5]&0x0F)<<18 | int32(bytes[pos+6])<<10 | int32(bytes[pos+7])<<2 | int32(bytes[pos+8]&0xC0)>>6
		res[pos/11*8+3] = int32(bytes[pos+8]&0x3F)<<16 | int32(bytes[pos+9])<<8 | int32(bytes[pos+10]&0xFF)>>0
		pos += 11
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
func randomnessFromEtaC2(seed []byte, length int) ([]int32, error) {
	// 1<<23-1
	bytes := make([]byte, (24*length+7)/8)
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
	for pos/23*8+7 < length {
		res[pos/23*8+0] = int32(bytes[pos+0]&0xFF)<<15 | int32(bytes[pos+1])<<7 | int32(bytes[pos+2]&0xFE)>>1
		res[pos/23*8+1] = int32(bytes[pos+2]&0x01)<<22 | int32(bytes[pos+3])<<14 | int32(bytes[pos+4])<<6 | int32(bytes[pos+5]&0xFC)>>2
		res[pos/23*8+2] = int32(bytes[pos+5]&0x03)<<21 | int32(bytes[pos+6])<<13 | int32(bytes[pos+7])<<5 | int32(bytes[pos+8]&0xF8)>>3
		res[pos/23*8+3] = int32(bytes[pos+8]&0x07)<<20 | int32(bytes[pos+9])<<12 | int32(bytes[pos+10])<<4 | int32(bytes[pos+11]&0xF0)>>4
		res[pos/23*8+4] = int32(bytes[pos+11]&0x0F)<<19 | int32(bytes[pos+12])<<11 | int32(bytes[pos+13])<<3 | int32(bytes[pos+14]&0xE0)>>5
		res[pos/23*8+5] = int32(bytes[pos+14]&0x1F)<<18 | int32(bytes[pos+15])<<10 | int32(bytes[pos+16])<<2 | int32(bytes[pos+17]&0xC0)>>6
		res[pos/23*8+6] = int32(bytes[pos+17]&0x3F)<<17 | int32(bytes[pos+18])<<15 | int32(bytes[pos+19])<<1 | int32(bytes[pos+20]&0x80)>>7
		res[pos/23*8+7] = int32(bytes[pos+20]&0x01)<<16 | int32(bytes[pos+21])<<8 | int32(bytes[pos+22]&0xFF)
		pos += 23
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
			value = int32(bytes[pos+0])<<8 | int32(bytes[pos+1])
			if value < 1<<16-256 {
				res[cur] *= value
				cur++
			}
			value = int32(bytes[pos+2])<<8 | int32(bytes[pos+3])
			if value < 1<<16-256 {
				res[cur] *= value
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
