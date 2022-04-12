package pqringct

import (
	"bytes"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/sha3"
	"io"
	"math/big"
)

var ErrLength = errors.New("invalid length")

const RandSeedBytesLen = 64 // 512-bits

// extendable output function is instanced as sha3.Shake128()
// to get expected length number but the input of sha3.Shake128()
// is output of sha3.Sha512() function.

func fillWithBound(buf []byte, expectCount int, bitNum int, bound int64) []int64 {
	res := make([]int64, 0, expectCount)
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
				if len(res) == expectCount {
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
// randomPolyAForResponseA() returns a PolyA, where each coefficient lies in [-(eta_a - beta_a), (eta_a - beta_a)],
// where eta_a = 2^{19}-1 and beta=300
func (pp *PublicParameter) randomPolyAForResponseA() (*PolyA, error) {
	bound := int64(523987) // 1 << 19 - 1 - 300
	length := pp.paramDA   // 128
	coeffs := make([]int64, 0, length)

	seed := RandomBytes(RandSeedBytesLen)
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(seed)
	if err != nil {
		return nil, err
	}

	// random the number in range [0,2*bound], and then reduce to [-bound, bound]
	// 2*bound=0b1111_1111_1101_1010_0110, means that an element needs 20 bits
	// expected (20 * length * (1<<19) / bound + 7 ) / 8 bytes
	buf := make([]byte, (20*int64(length)*(1<<19)/bound+7)/8)
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	res := fillWithBound(buf, length, 20, 2*bound)
	coeffs = append(coeffs, res...)
	for len(coeffs) < length {
		// uniform reject sample from the buf
		buf = make([]byte, 5) // gcd(20,8)=4*5*2=8*5
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-len(coeffs), 20, 2*bound)
		coeffs = append(coeffs, res...)
	}
	for i := 0; i < length; i++ {
		coeffs[i] = coeffs[i] - bound
	}
	return &PolyA{coeffs}, nil
}

// 16777087 = 1111_1111_1111_1111_0111_1111
// randomPolyCForResponseC() returns a PolyC, where each coefficient lies in [-(eta_c - beta_c), (eta_c - beta_c)],
// where eta_c = 2^{24}-1 and beta_c=128
func (pp *PublicParameter) randomPolyCForResponseC() (*PolyC, error) {
	bound := int64(16777087)
	length := pp.paramDC
	coeffs := make([]int64, 0, length)

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
	// uniform reject sample from the buf
	res := fillWithBound(buf, length, 25, 2*bound)
	coeffs = append(coeffs, res...)
	for len(coeffs) < length {
		// uniform reject sample from the buf
		buf = make([]byte, 25) // gcd(25,8)=8*25
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-len(coeffs), 25, 2*bound)
		coeffs = append(coeffs, res...)
	}
	for i := 0; i < length; i++ {
		coeffs[i] = coeffs[i] - bound
	}
	return &PolyC{coeffs}, nil
}

// 2^24-1= 1111_1111_1111_1111_1111_1111
//	randomPolyCinEtaC() outputs a PolyC, where each coefficient lies in [-eta_c, eta_c].
//	eta_c = 2^{24}-1, so that each coefficient needs 3 bytes (for absolute) and 1 bit (for signal)
func (pp *PublicParameter) randomPolyCinEtaC() (*PolyC, error) {
	bound := int64(1<<24 - 1)
	length := pp.paramDC
	coeffs := make([]int64, 0, length)

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
	// uniform reject sample from the buf
	res := fillWithBound(buf, length, 25, 2*bound)
	coeffs = append(coeffs, res...)
	for len(coeffs) < length {
		// uniform reject sample from the buf
		buf = make([]byte, 25) // gcd(25,8)=8*25
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-len(coeffs), 25, 2*bound)
		coeffs = append(coeffs, res...)

	}
	for i := 0; i < length; i++ {
		coeffs[i] = coeffs[i] - bound
	}
	return &PolyC{coeffs}, nil
}

//	randomPolyAinEtaA() outputs a PolyA, where each coefficient lies in [-eta_a, eta_a].
//	eta_a = 2^{19}-1, so that each coefficient needs 20 bits to sample, say 19 bits (for absolute) and 1 bit (for signal).
//	That is, we can use 5 byets to sample 2 coefficients.
func (pp *PublicParameter) randomPolyAinEtaA() (*PolyA, error) {
	bound := int64(1<<19 - 1)
	length := pp.paramDA
	coeffs := make([]int64, 0, length)

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
	// uniform reject sample from the buf
	res := fillWithBound(buf, length, 20, 2*bound)
	coeffs = append(coeffs, res...)
	for len(coeffs) < length {
		// uniform reject sample from the buf
		buf = make([]byte, 5) // gcd(20,8)=4*5*2=8*5
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, length-len(coeffs), 20, 2*bound)
		coeffs = append(coeffs, res...)
	}
	for i := 0; i < length; i++ {
		coeffs[i] = coeffs[i] - bound
	}
	return &PolyA{coeffs}, nil
}

// [-5,5]
func (pp *PublicParameter) randomPolyAinGammaA5(seed []byte) (*PolyA, error) {
	bound := int64(5)
	length := pp.paramDA
	coeffs := make([]int64, 0, length)

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
	res := fillWithBound(buf, length, 4, 2*bound)
	coeffs = append(coeffs, res...)
	for len(coeffs) < length {
		// uniform reject sample from the buf
		expectedNum := length - len(coeffs)
		buf = make([]byte, (4*int64(expectedNum)*(1<<3)/bound+7)/8) // gcd(20,8)=4*5*2=8*5
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		res = fillWithBound(buf, expectedNum, 4, 2*bound)
		coeffs = append(coeffs, res...)
	}
	for i := 0; i < length; i++ {
		coeffs[i] = coeffs[i] - bound
	}
	return &PolyA{coeffs}, nil
}

//	expandValuePadRandomness() return pp.TxoValueBytesLen() bytes,
//	which will be used to encrypt the value-bytes.
//	pp.TxoValueBytesLen() is 7, which means we use XOF to generate 7*8 = 56 bits.
//	For security, the length of output does not matter,
//	since the seed (KEM-generated key) is used only once.
func (pp *PublicParameter) expandValuePadRandomness(seed []byte) ([]byte, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}

	buf := make([]byte, pp.TxoValueBytesLen())
	realSeed := append([]byte{'V'}, seed...)

	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err := XOF.Write(realSeed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

//	expandAddressSKsp() expand s \in (S_{\gamma_a})^{L_a} from input seed.
//	To be self-completed, this function append 'ASKSP' before seed to form the real used seed.
func (pp *PublicParameter) expandAddressSKsp(seed []byte) (*PolyAVec, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}

	realSeed := append([]byte{'A', 'S', 'K', 'S', 'P'}, seed...) // AskSp

	tmpSeedLen := len(realSeed) + 1
	tmpSeed := make([]byte, tmpSeedLen) // 1 byte for index i \in [0, paramLA -1], where paramLA is assumed to be smaller than 127

	rst := pp.NewPolyAVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		copy(tmpSeed, realSeed)
		tmpSeed[tmpSeedLen-1] = byte(i)
		tmp, err := pp.randomPolyAinGammaA5(tmpSeed)
		if err != nil {
			return nil, err
		}
		rst.polyAs[i] = tmp
	}
	return rst, nil
}

//	expandAddressSKsn() expand AddressSKsn from an input seed, and directly output the NTT form.
//	To be self-completed, this function append 'ASKSN' before seed to form the real used seed.
func (pp *PublicParameter) expandAddressSKsn(seed []byte) (*PolyANTT, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}

	realSeed := append([]byte{'A', 'S', 'K', 'S', 'N'}, seed...) // AskSn

	coeffs := pp.randomDaIntegersInQa(realSeed)

	return &PolyANTT{coeffs: coeffs}, nil
}

// expandValueCmtRandomness() expand r \in (\chi^{d_c})^{L_c} from a given seed.
// \chi^{d_c} is regarded as a polyC, and r is regarded as a PolyCVec
func (pp *PublicParameter) expandValueCmtRandomness(seed []byte) (*PolyCVec, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}
	realSeed := append([]byte{'C', 'M', 'T', 'R'}, seed...) // CmtR

	tmpSeedLen := len(realSeed) + 1
	tmpSeed := make([]byte, tmpSeedLen) // 1 byte for index i \in [0, paramLc -1], where paramLc is assumed to be smaller than 127

	var err error
	rst := pp.NewPolyCVec(pp.paramLC)
	for i := 0; i < pp.paramLC; i++ {
		copy(tmpSeed, realSeed)
		tmpSeed[tmpSeedLen-1] = byte(i)
		rst.polyCs[i], err = pp.randomPolyCinDistributionChi(tmpSeed)
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

// sampleValueCmtRandomness() return a random r \in (\chi^{d_c})^{L_c}.
// \chi^{d_c} is regarded as a polyC, and r is regarded as a PolyCVec
func (pp *PublicParameter) sampleValueCmtRandomness() (*PolyCVec, error) {
	var err error
	rst := pp.NewPolyCVec(pp.paramLC)
	for i := 0; i < pp.paramLC; i++ {
		rst.polyCs[i], err = pp.randomPolyCinDistributionChi(nil)
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

//	Each coefficient of PolyCinDistributionChi is sampled from {-1, 0, 1}, where both 1 and -1 has probability 5/16, and 0 has probability 6/16.
func (pp *PublicParameter) randomPolyCinDistributionChi(seed []byte) (*PolyC, error) {
	if len(seed) == 0 {
		seed = RandomBytes(RandSeedBytesLen)
	}

	coeffs := make([]int64, pp.paramDC)

	buf := make([]byte, pp.paramDC/2) //	each coefficient needs 4 bits to sample
	XOF := sha3.NewShake128()
	XOF.Reset()

	_, err := XOF.Write(seed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}

	var tmp byte
	t := 0
	for i := 0; i < pp.paramDC/2; i++ {
		tmp = buf[i] & 0x0F // low 4 bits
		if tmp < 5 {
			coeffs[t] = -1
		} else if tmp < 10 {
			coeffs[t] = 1
		} else {
			coeffs[t] = 0
		}

		t += 1

		tmp = buf[i] >> 4 // high 4 bits
		if tmp < 5 {
			coeffs[t] = -1
		} else if tmp < 10 {
			coeffs[t] = 1
		} else {
			coeffs[t] = 0
		}

		t += 1
	}

	return &PolyC{coeffs}, nil
}

// sampleMaskingVecA() returns a masking vector y \in (S_{eta_a})^{L_a}.
func (pp PublicParameter) sampleMaskingVecA() (*PolyAVec, error) {
	rst := pp.NewPolyAVec(pp.paramLA)

	var err error
	for i := 0; i < pp.paramLA; i++ {
		rst.polyAs[i], err = pp.randomPolyAinEtaA()
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

// sampleMaskingVecC() returns a masking vector y \in (S_{eta_c})^{L_c}
func (pp *PublicParameter) sampleMaskingVecC() (*PolyCVec, error) {
	// etaC
	var err error

	polys := make([]*PolyC, pp.paramLC)

	for i := 0; i < pp.paramLC; i++ {
		polys[i], err = pp.randomPolyCinEtaC()
		if err != nil {
			return nil, err
		}
	}

	return &PolyCVec{
		polyCs: polys,
	}, nil

}

//	sampleResponseA() returns a PolyAVec with length paramLa,
//	where each coefficient lies in [-eta_a, eta_a], where eta_a = 2^{19}-1
func (pp *PublicParameter) sampleResponseA() (*PolyAVec, error) {
	rst := pp.NewPolyAVec(pp.paramLA)

	var err error
	for i := 0; i < pp.paramLA; i++ {
		rst.polyAs[i], err = pp.randomPolyAForResponseA()
		if err != nil {
			return nil, err
		}
	}

	return rst, nil
}

// sampleResponseC() returns a PolyCVec with length paramLc,
// where each coefficient lies in [-(eta_c - beta_c), (eta_c - beta_c)]
func (pp PublicParameter) sampleResponseC() (*PolyCVec, error) {
	rst := pp.NewPolyCVec(pp.paramLC)

	var err error
	for i := 0; i < pp.paramLC; i++ {
		rst.polyCs[i], err = pp.randomPolyCForResponseC()
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

// 9007199254746113 = 0010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0001_0100_0000_0001
// 4503599627373056 = 0001_0000_0000_0000_0000_0000_0000_0000_0000_0000_000_1010_0000_0000
//	randomDcIntegersInQc() outputs Dc int64,  by sampling uniformly (when seed is nil) or expanding from a seed (when seed is not nil)
//	Each integer lies in [-(Q_c-1)/2, (Q_c-2)/2].
func (pp *PublicParameter) randomDcIntegersInQc(seed []byte) []int64 {
	var tmpSeed []byte
	if len(seed) == 0 {
		tmpSeed = RandomBytes(RandSeedBytesLen)
	} else {
		tmpSeed = make([]byte, len(seed))
		copy(tmpSeed, seed)
	}
	bitNum := 54
	bound := pp.paramQC
	xof := sha3.NewShake128()
	xof.Reset()
	length := pp.paramDC
	coeffs := make([]int64, 0, length)
	xof.Write(tmpSeed)
	buf := make([]byte, (int64(bitNum)*int64(length)+7)/8)
	xof.Read(buf)
	tmp := fillWithBound(buf, length, bitNum, bound)
	coeffs = append(coeffs, tmp...)
	for len(coeffs) < length {
		buf = make([]byte, 27) // gcd(54,8)=2*27*4=27*8
		xof.Read(buf)
		tmp = fillWithBound(buf, length-len(coeffs), bitNum, bound)
		coeffs = append(coeffs, tmp...)
	}

	for i := 0; i < length; i++ {
		coeffs[i] = reduceInt64(coeffs[i], pp.paramQC)
	}
	return coeffs
}

//	randomDcIntegersInQcEtaF() outputs Dc int64,  by sampling uniformly.
//	Each integer lies in [-eta_f, eta_f].
//	eta_f = 2^23-1.
func (pp *PublicParameter) randomDcIntegersInQcEtaF() ([]int64, error) {
	bitNum := 24
	bound := pp.paramEtaF
	length := pp.paramDC

	coeffs := make([]int64, 0, length)

	xof := sha3.NewShake128()
	xof.Reset()
	xof.Write(RandomBytes(RandSeedBytesLen))

	buf := make([]byte, (24*int64(length)*(1<<23)/bound+7)/8)
	xof.Read(buf)
	tmp := fillWithBound(buf, length-len(coeffs), bitNum, 2*bound)
	coeffs = append(coeffs, tmp...)
	for len(coeffs) < length {
		buf = make([]byte, 3) // gcd(24,8)=3*8
		xof.Read(buf)
		tmp = fillWithBound(buf, length-len(coeffs), bitNum, 2*bound)
		coeffs = append(coeffs, tmp...)
	}

	for i := 0; i < length; i++ {
		coeffs[i] = coeffs[i] - bound
	}

	return coeffs, nil

}

// 137438953937= 0010_0000_0000_0000_0000_0000_0000_0001_1101_0001
// 0001_0000_0000_0000_0000_0000_0000_0000_1110_1000
//	randomDaIntegersInQa() returns paramDA int64, each in the scope [-(q_a-1)/2, (q_a-1)/2].
func (pp *PublicParameter) randomDaIntegersInQa(seed []byte) []int64 {
	var tmpSeed []byte
	if len(seed) == 0 {
		tmpSeed = RandomBytes(RandSeedBytesLen)
	} else {
		tmpSeed = make([]byte, len(seed))
		copy(tmpSeed, seed)
	}

	bitNum := 38 // bits number of pp.paramQA
	bound := pp.paramQA
	length := pp.paramDA
	res := make([]int64, 0, length)
	xof := sha3.NewShake128()
	xof.Reset()

	xof.Write(tmpSeed)

	buf := make([]byte, (int64(bitNum*length)*(1<<bitNum)/bound+7)/8)
	xof.Read(buf)
	tmp := fillWithBound(buf, length, bitNum, bound)
	res = append(res, tmp...)

	for len(res) < length {
		buf = make([]byte, 19) // gcd(38,8)=2*19*4=19*8
		xof.Read(buf)
		tmp = fillWithBound(buf, length-len(res), bitNum, bound)
		res = append(res, tmp...)
	}

	for k := 0; k < length; k++ {
		res[k] = reduceInt64(res[k], pp.paramQA)
	}
	return res
}

// expandSigACh should output a {-1,0,1}^DC vector with the number of not-0 is theta_a from a byte array
// Firstly, set the 1 or -1 with total number is theta
// Secondly, shuffle the array using the Knuth-Durstenfeld Shuffle
func (pp *PublicParameter) expandChallengeA(seed []byte) (*PolyA, error) {
	tmpSeed := make([]byte, len(seed))
	copy(tmpSeed, seed)
	tmpSeed = append([]byte{'C', 'H', 'A'}, tmpSeed...)

	coeffs := make([]int64, pp.paramDA)
	// cnt is used for resetting the buf
	// cur is used for loop the buf
	xof := sha3.NewShake128()
	xof.Reset()
	xof.Write(tmpSeed)
	// because the ThetaA must less than DC, so there would use the
	// 8-th binary for Setting and 0-th to 7-th for Shuffling.
	// Setting
	buf := make([]byte, (pp.paramThetaA+7)/8)
	xof.Read(buf)
	for i := 0; i < pp.paramThetaA; i++ {
		if buf[i/8]&(1<<(i%8))>>(i%8) == 0 {
			coeffs[i] = -1
		} else {
			coeffs[i] = 1
		}
	}
	// Shuffling
	buf = make([]byte, pp.paramDA)
	xof.Read(buf)
	reader := bytes.NewReader(buf)
	k := pp.paramDA
	for k > 0 {
		n, err := rand.Int(reader, big.NewInt(int64(k)))
		if err == io.EOF {
			buf = make([]byte, pp.paramDA)
			xof.Read(buf)
			reader = bytes.NewReader(buf)
			continue
		}
		p := n.Int64()
		coeffs[p], coeffs[k-1] = coeffs[k-1], coeffs[p]
		k--
	}
	return &PolyA{coeffs: coeffs}, nil
}

//	expandChallengeC() returns a challenge for proof in value commitment, say a PolyC, //
//	where each coefficient is sampled from {-1, 0, 1}, with Pr(0)=1/2, Pr(1)=Pr(-1)= 1/4.
func (pp PublicParameter) expandChallengeC(seed []byte) (*PolyC, error) {
	tmpSeed := make([]byte, len(seed))
	copy(tmpSeed, seed)

	tmpSeed = append([]byte{'C', 'H', 'C'}, tmpSeed...)

	var err error
	// extend seed via sha3.Shake128
	rst := pp.NewPolyC()
	buf := make([]byte, pp.paramDC/4) //	Each coefficient needs 2 bits, each byte can be used to generate 4 coefficients.
	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err = XOF.Write(tmpSeed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}

	var a1, a2, a3, a4, b1, b2, b3, b4 int64
	t := 0
	for i := 0; i < pp.paramDC/4; i++ {
		a1 = int64((buf[i] & (1 << 0)) >> 0)
		b1 = int64((buf[i] & (1 << 1)) >> 1)
		a2 = int64((buf[i] & (1 << 2)) >> 2)
		b2 = int64((buf[i] & (1 << 3)) >> 3)
		a3 = int64((buf[i] & (1 << 4)) >> 4)
		b3 = int64((buf[i] & (1 << 5)) >> 5)
		a4 = int64((buf[i] & (1 << 6)) >> 6)
		b4 = int64((buf[i] & (1 << 7)) >> 7)

		rst.coeffs[t] = a1 - b1
		rst.coeffs[t+1] = a2 - b2
		rst.coeffs[t+2] = a3 - b3
		rst.coeffs[t+3] = a4 - b4

		t += 4
	}
	return rst, nil
}

func (pp *PublicParameter) samplePloyCWithLowZeros() *PolyC {
	rst := pp.NewZeroPolyC()
	bitNum := 54
	bound := pp.paramQC
	xof := sha3.NewShake128()
	xof.Reset()
	length := pp.paramDC
	coeffs := make([]int64, pp.paramK, length)
	xof.Write(RandomBytes(RandSeedBytesLen))
	buf := make([]byte, (int64(bitNum*(length-pp.paramK))+7)/8)
	xof.Read(buf)
	tmp := fillWithBound(buf, length, bitNum, bound)
	coeffs = append(coeffs, tmp...)
	for len(coeffs) < length {
		buf = make([]byte, 27) // gcd(54,8)=2*27*8=27*8
		xof.Read(buf)
		tmp = fillWithBound(buf, length-len(coeffs), bitNum, bound)
		coeffs = append(coeffs, tmp...)
	}

	for i := pp.paramK; i < pp.paramDC; i++ {
		rst.coeffs[i] = reduceInt64(coeffs[i], pp.paramQC)
	}
	return rst
}

//	todo: review
func expandBinaryMatrix(seed []byte, rownum int, colnum int) (binM [][]byte, err error) {
	binM = make([][]byte, rownum)
	XOF := sha3.NewShake128()
	for i := 0; i < rownum; i++ {
		buf := make([]byte, (colnum+7)/8)
		binM[i] = make([]byte, (colnum+7)/8)
		XOF.Reset()
		_, err = XOF.Write(append(seed, byte(i)))
		if err != nil {
			return nil, err
		}
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, err
		}
		binM[i] = buf
	}
	return binM, nil
}
