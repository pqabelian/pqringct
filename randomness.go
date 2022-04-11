package pqringct

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/sha3"
)

var ErrLength = errors.New("invalid length")

const RandSeedBytesLen = 64 // 512-bits

// extendable output function is instanced as sha3.Shake128()
// to get expected length number but the input of sha3.Shake128()
// is output of sha3.Sha512() function.

func fillWithBound(buf []byte, length int, bitNum int, bound int64) []int64 {
	res := make([]int64, 0, length)
	// 首先计算bitNum和8的最小公倍数，每次可以拿出needPer个byte生成
	g := gcd(bitNum, 8)
	needPer, gotPer := bitNum/g, 8/g
	pos := 0
	// 每次取needPer个byte
	for pos+needPer-1 < len(buf) {
		for i := 0; i < gotPer; i++ {
			t := int64(0)
			// [0,needPer*8] 中取出 [i*bitNum,(i+1)*bitNum]
			for j := i * bitNum; j < (i+1)*bitNum; j++ {
				t |= int64((buf[pos+j/8]&(1<<(j%8)))>>(j%8)) << (j - i*bitNum)
			}
			if t <= bound {
				res = append(res, t)
				if len(res) == length {
					return res
				}
			}
		}
		pos += needPer
	}
	return res
}
func gcd(a int, b int) int {
	if b == 0 {
		return a
	}
	return gcd(b, a%b)
}

// RandomBytes returns a byte array with given length from crypto/rand.Reader
func RandomBytes(length int) []byte {
	res := make([]byte, 0, length)
	var tmp []byte
	for length > 0 {
		tmp = make([]byte, length)
		// n == len(b) if and only if err == nil.
		n, err := rand.Read(tmp)
		if err != nil {
			continue
		}
		res = append(res, tmp[:n]...)
		length -= n
	}
	return res
}

// 523987 = 0111_1111_1110_1101_0011
// randomPolyAForResponseZetaA() returns a PolyA, where each coefficient lies in [-(eta_a - beta_a), (eta_a - beta_a)],
// where eta_a = 2^{19}-1 and beta=300
func (pp *PublicParameter) randomPolyAForResponseZetaA() (*PolyA, error) {
	bound := int64(523987) // 1 << 19 - 1 - 300
	length := pp.paramDA   // 128
	coeffs := make([]int64, length)

	seed := RandomBytes(RandSeedBytesLen)
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte
	// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	// 2*bound=0b1111_1111_1101_1010_0110, means that an element needs 20 bits
	// expected (20 * length * (1<<19) / bound + 7 ) / 8 bytes
	buf = make([]byte, (20*int64(length)*(1<<19)/bound+7)/8)
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	cur := 0
	res := fillWithBound(buf, length, 20, 2*bound)
	for i := 0; i < len(res); i++ {
		coeffs[cur+i] = res[i] - bound
	}
	cur += len(res)
	for cur < length {
		// uniform reject sample from the buf
		buf = make([]byte, 5) // gcd(20,8)=4*5*2=8*5
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-cur, 20, 2*bound)
		for i := 0; i < len(res); i++ {
			coeffs[cur+i] = res[i] - bound
		}
		cur += len(res)
	}
	return &PolyA{coeffs}, nil
}

// 16777087 = 1111_1111_1111_1111_0111_1111
// randomPolyCForResponseZetaC() returns a PolyC, where each coefficient lies in [-(eta_c - beta_c), (eta_c - beta_c)],
// where eta_c = 2^{24}-1 and beta_c=128
func (pp *PublicParameter) randomPolyCForResponseZetaC() (*PolyC, error) {
	bound := int64(16777087)
	length := pp.paramDC
	coeffs := make([]int64, length)

	seed := RandomBytes(RandSeedBytesLen)
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte
	// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	// 2*bound=0b00001_1111_1111_1111_1110_1111_1110, means that an element needs 25 bits
	// expected (25 * length * (1<<24) / bound + 7 ) / 8 bytes
	buf = make([]byte, (25*int64(length)*(1<<24)/bound+7)/8)
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	cur := 0
	// uniform reject sample from the buf
	res := fillWithBound(buf, length, 25, 2*bound)
	for i := 0; i < len(res); i++ {
		coeffs[cur+i] = res[i] - bound
	}
	cur += len(res)
	for cur < length {
		// uniform reject sample from the buf
		buf = make([]byte, 25) // gcd(25,8)=8*25
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-cur, 25, 2*bound)
		for i := 0; i < len(res); i++ {
			coeffs[cur+i] = res[i] - bound
		}
		cur += len(res)
	}

	return &PolyC{coeffs}, nil
}

// 2^24-1= 1111_1111_1111_1111_1111_1111
//	randomPolyCinEtaC() outputs a PolyC, where each coefficient lies in [-eta_c, eta_c].
//	eta_c = 2^{24}-1, so that each coefficient needs 3 bytes (for absolute) and 1 bit (for signal)
func (pp *PublicParameter) randomPolyCinEtaC() (*PolyC, error) {
	bound := int64(1<<24 - 1)
	length := pp.paramDC
	coeffs := make([]int64, length)

	seed := RandomBytes(RandSeedBytesLen)
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte
	// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	// 2*bound=0b00001_1111_1111_1111_1110_1111_1110, means that an element needs 25 bits
	// expected (25 * length * (1<<24) / bound + 7 ) / 8 bytes
	buf = make([]byte, (25*int64(length)*(1<<24)/bound+7)/8)
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	cur := 0
	// uniform reject sample from the buf
	res := fillWithBound(buf, length, 25, 2*bound)
	for i := 0; i < len(res); i++ {
		coeffs[cur+i] = res[i] - bound
	}
	cur += len(res)
	for cur < length {
		// uniform reject sample from the buf
		buf = make([]byte, 25) // gcd(25,8)=8*25
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-cur, 25, 2*bound)
		for i := 0; i < len(res); i++ {
			coeffs[cur+i] = res[i] - bound
		}
		cur += len(res)
	}

	return &PolyC{coeffs}, nil
}

//	randomPolyAinEtaA() outputs a PolyA, where each coefficient lies in [-eta_a, eta_a].
//	eta_a = 2^{19}-1, so that each coefficient needs 20 bits to sample, say 19 bits (for absolute) and 1 bit (for signal).
//	That is, we can use 5 byets to sample 2 coefficients.
func (pp *PublicParameter) randomPolyAinEtaA() (*PolyA, error) {
	bound := int64(1<<19 - 1)
	length := pp.paramDA
	coeffs := make([]int64, length)

	seed := RandomBytes(RandSeedBytesLen)
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte
	// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	// 2*bound=0b00001_1111_1111_1111_1110_1111_1110, means that an element needs 25 bits
	// expected (25 * length * (1<<24) / bound + 7 ) / 8 bytes
	buf = make([]byte, (20*int64(length)*(1<<19)/bound+7)/8)
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	cur := 0
	// uniform reject sample from the buf
	res := fillWithBound(buf, length, 20, 2*bound)
	for i := 0; i < len(res); i++ {
		coeffs[cur+i] = res[i] - bound
	}
	cur += len(res)
	for cur < length {
		// uniform reject sample from the buf
		buf = make([]byte, 5) // gcd(20,8)=4*5*2=8*5
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-cur, 20, 2*bound)
		for i := 0; i < len(res); i++ {
			coeffs[cur+i] = res[i] - bound
		}
		cur += len(res)
	}

	return &PolyA{coeffs}, nil
}

// [-5,5]
func (pp *PublicParameter) randomPolyAinGammaA5(seed []byte) (*PolyA, error) {
	bound := int64(5)
	length := pp.paramDA
	coeffs := make([]int64, length)

	if seed == nil {
		seed = RandomBytes(RandSeedBytesLen)
	}
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}
	var buf []byte
	// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	// 2*bound=0b1111_1111_1101_1010_0110, means that an element needs 20 bits
	// expected (20 * length * (1<<19) / bound + 7 ) / 8 bytes
	buf = make([]byte, (4*int64(length)*(1<<3)/bound+7)/8)
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	cur := 0
	res := fillWithBound(buf, length, 4, 2*bound)
	for i := 0; i < len(res); i++ {
		coeffs[cur+i] = res[i] - bound
	}
	cur += len(res)
	for cur < length {
		// uniform reject sample from the buf
		buf = make([]byte, 3) // gcd(20,8)=4*5*2=8*5
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-cur, 4, 2*bound)
		for i := 0; i < len(res); i++ {
			coeffs[cur+i] = res[i] - bound
		}
		cur += len(res)
	}
	return &PolyA{coeffs}, nil
}
