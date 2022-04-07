package pqringct

import (
	"golang.org/x/crypto/sha3"
	"math/big"
)

// RpUlpType is the type for difference transaction
type RpUlpType uint8

const (
	RpUlpTypeCbTx1 RpUlpType = 0
	RpUlpTypeCbTx2 RpUlpType = 1
	RpUlpTypeTrTx1 RpUlpType = 2
	RpUlpTypeTrTx2 RpUlpType = 3
)

//	todo: review
//	expandValuePadRandomness() return pp.TxoValueBytesLen() bytes, which will be used to encrypt the value-bytes.
//	pp.TxoValueBytesLen() is 7, which means we use XOF to generate 7*8 = 56 bits.
//	This does not matter, since the seed (KEM-generated key) is used only once.
func (pp *PublicParameter) expandValuePadRandomness(seed []byte) ([]byte, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}

	buf := make([]byte, pp.TxoValueBytesLen())
	realSeed := append([]byte{'V'}, seed...)
	//	todo: 202203 check the security
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

func (pp *PublicParameter) generateBits(seed []byte, length int) ([]byte, error) {
	var err error
	// check the length of seed
	res := make([]byte, length)
	buf := make([]byte, (length+7)/8)
	XOF := sha3.NewShake128()

	XOF.Reset()
	_, err = XOF.Write(seed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}
	for i := 0; i < (length+7)/8; i++ {
		for j := 0; j < 8 && 8*i+j < length; j++ {
			res[8*i+j] = buf[i] & (1 << j) >> j
		}
	}
	return res[:length], nil
}

// todo: review
//func (pp *PublicParameter) expandRandomnessA(seed []byte) (*PolyAVec, error) {
//	res := pp.NewPolyAVec(pp.paramLA)
//	seed = append([]byte{'A'}, seed...)
//	for i := 0; i < pp.paramLA; i++ {
//		tSeed := make([]byte, len(seed)+1)
//		for j := 0; j < len(seed); j++ {
//			tSeed[j] = seed[j]
//		}
//		tSeed[len(seed)] = byte(i)
//		tmp, err := randomPolyAinGammaA5(tSeed, pp.paramDA)
//		if err != nil {
//			return nil, err
//		}
//		res.polyAs[i] = &PolyA{coeffs: tmp}
//	}
//
//	return res, nil
//}

// todo: review
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

//	todo: review
//	expandAddressSKsn() expand AddressSKsn from an input seed, and directly output the NTT form.
//	To be self-completed, this function append 'ASKSN' before seed to form the real used seed.
func (pp *PublicParameter) expandAddressSKsn(seed []byte) (*PolyANTT, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}

	realSeed := append([]byte{'A', 'S', 'K', 'S', 'N'}, seed...) // AskSn

	ma_ntt := pp.randomDaIntegersInQa(realSeed)

	return &PolyANTT{coeffs: ma_ntt}, nil
}

//	todo: review
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

//func (pp *PublicParameter) expandValueCmtRandomness(seed []byte) (r *PolyCVec, err error) {
//	if len(seed) == 0 {
//		return nil, ErrLength
//	}
//	seed = append(seed, 'C')
//	r, err = pp.generatePolyVecWithProbabilityDistributions(seed, pp.paramLC)
//	if err != nil {
//		return nil, err
//	}
//	return r, nil
//}

// todo: review
//	todo (to remove): not used any more
func (pp *PublicParameter) generatePolyVecWithProbabilityDistributions(seed []byte, vecLen int) (*PolyCVec, error) {
	var err error
	// check the length of seed
	ret := pp.NewPolyCVec(vecLen)
	buf := make([]byte, pp.paramDC*4)
	XOF := sha3.NewShake128()
	for i := 0; i < vecLen; i++ {
		XOF.Reset()
		_, err = XOF.Write(seed)
		if err != nil {
			return nil, err
		}
		_, err = XOF.Write([]byte{byte(i)})
		if err != nil {
			return nil, err
		}
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, err
		}
		_, got, err := randomnessFromProbabilityDistributions(buf, pp.paramDC)
		if len(got) < pp.paramLC {
			newBuf := make([]byte, pp.paramDC)
			_, err = XOF.Read(newBuf)
			if err != nil {
				return nil, err
			}
			_, newGot, err := randomnessFromProbabilityDistributions(newBuf, pp.paramDC-len(got))
			if err != nil {
				return nil, err
			}
			got = append(got, newGot...)
		}
		for k := 0; k < pp.paramDC; k++ {
			ret.polyCs[i].coeffs[k] = got[k]
		}
	}
	return ret, nil
}

// todo: review
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

//	todo: review
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

//	todo: review
//	sampleResponseZetaA() returns a PolyAVec with length paramLa,
//	where each coefficient lies in [-eta_a, eta_a], where eta_a = 2^{19}-1
func (pp *PublicParameter) sampleResponseZetaA() (*PolyAVec, error) {
	rst := pp.NewPolyAVec(pp.paramLA)

	var err error
	for i := 0; i < pp.paramLA; i++ {
		rst.polyAs[i], err = pp.randomnessPolyAForResponseZetaA()
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

//	todo: review
// sampleResponseZetaC() returns a PolyCVec with length paramLc,
// where each coefficient lies in [-(eta_c - beta_c), (eta_c - beta_c)]
func (pp PublicParameter) sampleResponseZetaC() (*PolyCVec, error) {
	rst := pp.NewPolyCVec(pp.paramLC)

	var err error
	for i := 0; i < pp.paramLC; i++ {
		rst.polyCs[i], err = pp.randomnessPolyCForResponseZetaC()
		if err != nil {
			return nil, err
		}
	}
	return rst, nil
}

func (pp *PublicParameter) sampleUniformWithinEtaFv2() ([]int64, error) {
	//  qc =					0010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0001_0100_0000_0001
	// <(qc-1)/16 = 562949953421632 = 	0010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0001_0100_0000<qc/12
	// 1<<49-1
	seed := RandomBytes(pp.paramSeedBytesLen)
	length := pp.paramDC
	res := make([]int64, 0, length)
	buf := make([]byte, (length+7)/8)
	var t int64
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(append(seed, byte(0)))
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	pos := 0
	for i := 0; i < length; i += 8 {
		for j := 0; j < 8; j++ {
			if (buf[pos]>>j)&1 == 0 {
				res = append(res, -1)
			} else {
				res = append(res, 1)
			}
		}
		pos++
	}
	cnt := 1
	curr := 0
	for len(res) < length {
		buf = make([]byte, 50*(length+7)/8)
		xof.Reset()
		_, err := xof.Write(append(seed, byte(cnt)))
		if err != nil {
			continue
		}
		_, err = xof.Read(buf)
		if err != nil {
			continue
		}
		pos = 0
		for pos+24 < len(buf) {
			t = int64(buf[pos+0]) << 0
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]) << 16
			t |= int64(buf[pos+3]) << 24
			t |= int64(buf[pos+4]) << 32
			t |= int64(buf[pos+5]) << 40
			t |= int64(buf[pos+6]&0x01) << 48
			t &= 0x01FFFFFFFFFFFF
			res[curr] *= reduceInt64(t-pp.paramQC, pp.paramQC)
			curr++

			t = int64(buf[pos+6]&0xFE) >> 1
			t |= int64(buf[pos+7]) << 7
			t |= int64(buf[pos+8]) << 15
			t |= int64(buf[pos+9]) << 23
			t |= int64(buf[pos+10]) << 31
			t |= int64(buf[pos+11]) << 39
			t |= int64(buf[pos+12]&0x03) << 47
			t &= 0x01FFFFFFFFFFFF
			res[curr] *= reduceInt64(t-pp.paramQC, pp.paramQC)
			curr++

			t = int64(buf[pos+12]&0xFC) >> 2
			t |= int64(buf[pos+13]) << 6
			t |= int64(buf[pos+14]) << 14
			t |= int64(buf[pos+15]) << 22
			t |= int64(buf[pos+16]) << 30
			t |= int64(buf[pos+17]) << 38
			t |= int64(buf[pos+18]&0x07) << 46
			t &= 0x01FFFFFFFFFFFF
			res[curr] *= reduceInt64(t-pp.paramQC, pp.paramQC)
			curr++

			t = int64(buf[pos+18]&0xF8) >> 3
			t |= int64(buf[pos+19]) << 5
			t |= int64(buf[pos+20]) << 13
			t |= int64(buf[pos+21]) << 21
			t |= int64(buf[pos+22]) << 29
			t |= int64(buf[pos+23]) << 38
			t |= int64(buf[pos+24]&0x0F) << 45
			t &= 0x01FFFFFFFFFFFF

			t = int64(buf[pos+24]&0xF0) >> 4
			t |= int64(buf[pos+25]) << 4
			t |= int64(buf[pos+26]) << 12
			t |= int64(buf[pos+27]) << 20
			t |= int64(buf[pos+28]) << 28
			t |= int64(buf[pos+29]) << 37
			t |= int64(buf[pos+30]&0x1F) << 44
			t &= 0x01FFFFFFFFFFFF

			t = int64(buf[pos+30]&0xE0) >> 5
			t |= int64(buf[pos+31]) << 3
			t |= int64(buf[pos+32]) << 11
			t |= int64(buf[pos+33]) << 19
			t |= int64(buf[pos+34]) << 28
			t |= int64(buf[pos+35]) << 36
			t |= int64(buf[pos+36]&0x3F) << 43
			t &= 0x01FFFFFFFFFFFF

			t = int64(buf[pos+36]&0xC0) >> 6
			t |= int64(buf[pos+37]) << 2
			t |= int64(buf[pos+39]) << 10
			t |= int64(buf[pos+40]) << 18
			t |= int64(buf[pos+41]) << 27
			t |= int64(buf[pos+42]) << 35
			t |= int64(buf[pos+43]&0x7F) << 42
			t &= 0x01FFFFFFFFFFFF

			t = int64(buf[pos+43]&0x80) >> 7
			t |= int64(buf[pos+44]) << 1
			t |= int64(buf[pos+45]) << 9
			t |= int64(buf[pos+46]) << 17
			t |= int64(buf[pos+47]) << 26
			t |= int64(buf[pos+48]) << 34
			t |= int64(buf[pos+49]) << 41
			t &= 0x01FFFFFFFFFFFF

			pos += 50
		}
		cnt++
	}
	return res, nil
}

// generatePolyCNTTMatrix generate a matrix with rowLength * colLength, and the element in matrix is length
func (pp *PublicParameter) generatePolyCNTTMatrix(seed []byte, rowLength int, colLength int) ([]*PolyCNTTVec, error) {
	// check the length of seed

	tmpSeedLen := len(seed) + 2
	tmpSeed := make([]byte, tmpSeedLen) //	1 byte for row index, and 1 byte for col index, assuming the row and col number is smaller than 127

	rst := make([]*PolyCNTTVec, rowLength)
	for i := 0; i < rowLength; i++ {
		rst[i] = pp.NewPolyCNTTVec(colLength)
		for j := 0; j < colLength; j++ {
			copy(tmpSeed, seed)
			tmpSeed[tmpSeedLen-2] = byte(i)
			tmpSeed[tmpSeedLen-1] = byte(j)
			rst[i].polyCNTTs[j].coeffs = pp.randomDcIntegersInQc(tmpSeed)
			//got := pp.randomDcIntegersInQc(tmpSeed)
			//for t := 0; t < pp.paramDC; t++ {
			//	rst[i].polyCNTTs[j].coeffs[t] = got[t]
			//}
		}
	}
	return rst, nil
}

// todo: review 20220404
// generatePolyANTTMatrix() expands the seed to a polyANTT matrix.
func (pp *PublicParameter) generatePolyANTTMatrix(seed []byte, rowLength int, colLength int) ([]*PolyANTTVec, error) {
	// check the length of seed

	tmpSeedLen := len(seed) + 2
	tmpSeed := make([]byte, tmpSeedLen)

	rst := make([]*PolyANTTVec, rowLength)
	for i := 0; i < rowLength; i++ {
		rst[i] = pp.NewZeroPolyANTTVec(colLength)
		for j := 0; j < colLength; j++ {
			copy(tmpSeed, seed)
			tmpSeed[tmpSeedLen-2] = byte(i)
			tmpSeed[tmpSeedLen-1] = byte(j)
			rst[i].polyANTTs[j].coeffs = pp.randomDaIntegersInQa(tmpSeed)
			//got := pp.randomDaIntegersInQa(tmpSeed)
			//for t := 0; t < pp.paramDA; t++ {
			//	rst[i].polyANTTs[j].coeffs[t] = got[t]
			//}
		}
	}
	return rst, nil
}

// 9007199254746113 = 0010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0001_0100_0000_0001
// 4503599627373056 = 0001_0000_0000_0000_0000_0000_0000_0000_0000_0000_000_1010_0000_0000
//	todo: 202203 Qc hard code, but withQa does not hard code, make them consistent

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
	//	todo: by fixing length by paramDC, optimize
	//	todo: even can making use of the fixed value of Qc
	length := pp.paramDC
	bound := int64(9007199254746113)

	res := make([]int64, length)
	var curr int
	var pos int
	var t int64

	xof := sha3.NewShake128()
	cnt := 1
	for curr < length {
		buf := make([]byte, (length-curr)*28)
		xof.Reset()
		_, err := xof.Write(append(tmpSeed, byte(cnt)))
		if err != nil {
			continue
		}
		_, err = xof.Read(buf)
		if err != nil {
			continue
		}
		pos = 0
		//
		for pos+27 < len(buf) {
			// read 4 byte from buf and view it as a uint32
			t = int64(buf[pos])
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]) << 16
			t |= int64(buf[pos+3]) << 24
			t |= int64(buf[pos+4]) << 32
			t |= int64(buf[pos+5]) << 40
			t |= int64(buf[pos+6]) << 48
			t |= int64(buf[pos+7]&0x3F) << 56
			t &= 0x3F_FFFF_FFFF_FFFF
			// if t is in [0,4294962689] then accept
			// otherwise reject this one
			if t < 9007199254746113 {
				res[curr] = reduceInt64(t, bound)
				curr += 1
				if curr >= length {
					break
				}
			}
			t = int64(buf[pos+7]&0xC0) >> 6
			t |= int64(buf[pos+8]) << 2
			t |= int64(buf[pos+9]) << 10
			t |= int64(buf[pos+10]) << 18
			t |= int64(buf[pos+11]) << 26
			t |= int64(buf[pos+12]) << 34
			t |= int64(buf[pos+13]) << 42
			t |= int64(buf[pos+14]&0x0F) << 50
			t &= 0x3F_FFFF_FFFF_FFFF
			// if t is in [0,4294962689] then accept
			// otherwise reject this one
			if t < 9007199254746113 {
				res[curr] = reduceInt64(t, bound)
				curr += 1
				if curr >= length {
					break
				}
			}
			t = int64(buf[pos+14]&0xF0) >> 4
			t |= int64(buf[pos+15]) << 4
			t |= int64(buf[pos+16]) << 12
			t |= int64(buf[pos+17]) << 20
			t |= int64(buf[pos+18]) << 28
			t |= int64(buf[pos+19]) << 36
			t |= int64(buf[pos+20]) << 44
			t |= int64(buf[pos+21]&0x03) << 52
			t &= 0x3F_FFFF_FFFF_FFFF
			// if t is in [0,4294962689] then accept
			// otherwise reject this one
			if t < 9007199254746113 {
				res[curr] = reduceInt64(t, bound)
				curr += 1
				if curr >= length {
					break
				}
			}
			t = int64(buf[pos+21]&0xFC) >> 2
			t |= int64(buf[pos+22]) << 6
			t |= int64(buf[pos+23]) << 14
			t |= int64(buf[pos+24]) << 22
			t |= int64(buf[pos+25]) << 30
			t |= int64(buf[pos+26]) << 38
			t |= int64(buf[pos+27]) << 46
			t &= 0x3F_FFFF_FFFF_FFFF
			// if t is in [0,4294962689] then accept
			// otherwise reject this one
			if t < 9007199254746113 {
				res[curr] = reduceInt64(t, bound)
				curr += 1
				if curr >= length {
					break
				}
			}
			pos += 28
		}
		cnt++
	}
	return res
}

//	randomDcIntegersInQcEtaF() outputs Dc int64,  by sampling uniformly.
//	Each integer lies in [-eta_f, eta_f].
//	eta_f = 2^23-1.
//	We can use 3 bytes to sample an integer in [-eta_f, eta_f], say 23 bits for absolute, and 1 bit for signal.
func (pp *PublicParameter) randomDcIntegersInQcEtaF() ([]int64, error) {

	rst := make([]int64, pp.paramDC)

	buf := make([]byte, pp.paramDC*3)

	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err := XOF.Write(RandomBytes(RandSeedBytesLen))
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}

	var abs uint32
	t := 0
	for i := 0; i < pp.paramDC; i++ {
		abs = uint32(buf[t]) << 0
		abs |= uint32(buf[t+1]) << 8
		abs |= uint32(buf[t+2]&0x7F) << 16

		if buf[t+2]&0x80 == 0x80 {
			//	- signal
			rst[i] = (-1) * int64(abs)
		} else {
			rst[i] = int64(abs)
		}

		t += 3
	}

	return rst, nil
}

// 137438953937= 0010_0000_0000_0000_0000_0000_0000_0001_1101_0001
// 0001_0000_0000_0000_0000_0000_0000_0000_1110_1000
// todo: 20220330 with name Q_a, shall we remove bound, and use PP and hardcode Q_a
//	randomDaIntegersInQa() returns paramDA int64, each in the scope [-(q_a-1)/2, (q_a-1)/2].
func (pp *PublicParameter) randomDaIntegersInQa(seed []byte) []int64 {
	// todo: for fixing lenth, optimize
	bound := pp.paramQA
	length := pp.paramDA

	var tmpSeed []byte
	if len(seed) == 0 {
		tmpSeed = RandomBytes(RandSeedBytesLen)
	} else {
		tmpSeed = make([]byte, len(seed))
		copy(tmpSeed, seed)
	}

	rst := make([]int64, length)
	xof := sha3.NewShake128()
	cnt := 1
	cur := 0
	var pos int
	var t int64
	for cur < length {
		buf := make([]byte, (length-cur)*19)
		xof.Reset()
		_, err := xof.Write(append(tmpSeed, byte(cnt)))
		if err != nil {
			continue
		}
		_, err = xof.Read(buf)
		if err != nil {
			continue
		}
		pos = 0
		for pos+19 < len(buf) {
			t = int64(buf[pos+0])
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]) << 16
			t |= int64(buf[pos+3]) << 24
			t |= (int64(buf[pos+4] & 0x3F)) << 32
			t &= 0x3FFFFFFFFF
			if t < bound { // [0,bound]  ->  [-(bound-1)/2,(bound-1)/2]
				rst[cur] = reduceInt64(t, bound)
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+4]&0xC0) >> 6
			t |= int64(buf[pos+5]) << 2
			t |= int64(buf[pos+6]) << 10
			t |= int64(buf[pos+7]) << 18
			t |= int64(buf[pos+8]) << 26
			t |= int64(buf[pos+9]&0x0F) << 34
			t &= 0x3FFFFFFFFF
			if t < bound {
				rst[cur] = reduceInt64(t, bound)
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+9]&0xF0) >> 4
			t |= int64(buf[pos+10]) << 4
			t |= int64(buf[pos+11]) << 12
			t |= int64(buf[pos+12]) << 20
			t |= int64(buf[pos+13]) << 28
			t |= int64(buf[pos+14]&0x03) << 36
			t &= 0x3FFFFFFFFF
			if t < bound {
				rst[cur] = reduceInt64(t, bound)
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+14]&0xFC) >> 2
			t |= int64(buf[pos+15]) << 6
			t |= int64(buf[pos+16]) << 14
			t |= int64(buf[pos+17]) << 22
			t |= int64(buf[pos+18]) << 30
			t &= 0x3FFFFFFFFF
			if t < bound {
				rst[cur] = reduceInt64(t, bound)
				cur++
				if cur >= length {
					break
				}
			}

			pos += 19
		}
		cnt++
	}
	return rst
}

//func (pp *PublicParameter) randomDaIntegersInQa(seed []byte, length int, bound int64) []int64 {
//	res := make([]int64, length)
//	xof := sha3.NewShake128()
//	cnt := 1
//	cur := 0
//	var pos int
//	var t int64
//	for cur < length {
//		buf := make([]byte, (length-cur)*19)
//		xof.Reset()
//		_, err := xof.Write(append(seed, byte(cnt)))
//		if err != nil {
//			continue
//		}
//		_, err = xof.Read(buf)
//		if err != nil {
//			continue
//		}
//		pos = 0
//		for pos+19 < len(buf) {
//			t = int64(buf[pos+0])
//			t |= int64(buf[pos+1]) << 8
//			t |= int64(buf[pos+2]) << 16
//			t |= int64(buf[pos+3]) << 24
//			t |= (int64(buf[pos+4] & 0x3F)) << 32
//			t &= 0x3FFFFFFFFF
//			if t < bound { // [0,bound]  ->  [-(bound-1)/2,(bound-1)/2]
//				res[cur] = reduceInt64(t, bound)
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			t = int64(buf[pos+4]&0xC0) >> 6
//			t |= int64(buf[pos+5]) << 2
//			t |= int64(buf[pos+6]) << 10
//			t |= int64(buf[pos+7]) << 18
//			t |= int64(buf[pos+8]) << 26
//			t |= int64(buf[pos+9]&0x0F) << 34
//			t &= 0x3FFFFFFFFF
//			if t < bound {
//				res[cur] = reduceInt64(t, bound)
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			t = int64(buf[pos+9]&0xF0) >> 4
//			t |= int64(buf[pos+10]) << 4
//			t |= int64(buf[pos+11]) << 12
//			t |= int64(buf[pos+12]) << 20
//			t |= int64(buf[pos+13]) << 28
//			t |= int64(buf[pos+14]&0x03) << 36
//			t &= 0x3FFFFFFFFF
//			if t < bound {
//				res[cur] = reduceInt64(t, bound)
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			t = int64(buf[pos+14]&0xFC) >> 2
//			t |= int64(buf[pos+15]) << 6
//			t |= int64(buf[pos+16]) << 14
//			t |= int64(buf[pos+17]) << 22
//			t |= int64(buf[pos+18]) << 30
//			t &= 0x3FFFFFFFFF
//			if t < bound {
//				res[cur] = reduceInt64(t, bound)
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//
//			pos += 19
//		}
//		cnt++
//	}
//	return res
//}

// todo: review
// expandSigACh should output a {-1,0,1}^DC vector with the number of not-0 is theta_a from a byte array
// Firstly, set the 1 or -1 with total number is theta
// Secondly, shuffle the array using the Knuth-Durstenfeld Shuffle
func (pp *PublicParameter) expandChallengeA(seed []byte) (*PolyA, error) {
	tmpSeed := make([]byte, len(seed))
	//for i := 0; i < len(seed); i++ {
	//	seed[i] = seeds[i]
	//}
	copy(tmpSeed, seed)
	tmpSeed = append([]byte{'C', 'H', 'A'}, tmpSeed...)

	coeffs := make([]int64, pp.paramDA)
	buf := make([]byte, pp.paramDA)
	var err error
	// cnt is used for resetting the buf
	// cur is used for loop the buf
	var p, cnt, cur int
	xof := sha3.NewShake128()
	resetBuf := func() error {
		xof.Reset()
		_, err = xof.Write(append(tmpSeed, byte(cnt)))
		if err != nil {
			return err
		}
		_, err = xof.Read(buf)
		if err != nil {
			return err
		}
		cnt++
		cur = 0
		return nil
	}
	// Prepare the data in buf
	err = resetBuf()
	if err != nil {
		return nil, err
	}
	//	todo: 20220405 optime?
	// TODO : About optimization, because the ThetaA must less than DC? so there would use the
	// 8-th binary for Setting and 0-th to 7-th for Shuffling.
	// Setting
	for i := 0; i < pp.paramThetaA; i += 8 {
		for j := 0; j < 8; j++ {
			if buf[cur]&1<<j == 0 {
				coeffs[i+j] = -1
			} else {
				coeffs[i+j] = 1
			}
		}
		cur++
	}
	// Shuffling
	for k := len(coeffs); k > 0; k-- {
		// read 1 byte from the buf
		if cur == len(buf) {
			err = resetBuf()
			if err != nil {
				return nil, err
			}
		}
		// discard the 8-th in buf[cur]
		p = int(buf[cur] & 0x7F)
		cur++
		coeffs[p], coeffs[k-1] = coeffs[k-1], coeffs[p]
	}
	return &PolyA{coeffs: coeffs}, nil
}

//	todo: review
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

//func (pp *PublicParameter) sampleValueCmtRandomness() (*PolyCVec, error) {
//	polys := make([]*PolyC, pp.paramLC)
//	var err error
//	for i := 0; i < pp.paramLC; i++ {
//		var tmp []int64
//		_, tmp, err = randomnessFromProbabilityDistributions(nil, pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &PolyC{coeffs: tmp}
//	}
//	res := &PolyCVec{
//		polyCs: polys,
//	}
//	return res, nil
//}

// todo: review
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

// todo: review
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

// todo: review
func (pp *PublicParameter) samplePloyCWithLowZeros() *PolyC {
	rst := pp.NewZeroPolyC()
	tmp := pp.randomDcIntegersInQc(nil)
	for i := pp.paramK; i < pp.paramDC; i++ {
		rst.coeffs[i] = tmp[i]
	}
	return rst
}

func (pp *PublicParameter) collectBytesForRPULP1(message []byte, cmts []*ValueCommitment, n uint8,
	b_hat *PolyCNTTVec, c_hats []*PolyCNTT, n2 uint8, n1 uint8,
	rpulpType RpUlpType, binMatrixB [][]byte, I uint8, J uint8, m uint8, u_hats [][]int64,
	c_waves []*PolyCNTT, c_hat_g *PolyCNTT, cmt_ws [][]*PolyCNTTVec,
	delta_waves [][]*PolyCNTT, delta_hats [][]*PolyCNTT, ws []*PolyCNTTVec) []byte {

	length := len(message) + // message
		int(n)*(pp.paramKC+1)*pp.paramDC*8 + // cmts []*ValueCommitment length 8, (k_c+1) PolyCNTT
		1 + // n
		pp.paramKC*pp.paramDC*8 + // b_hat *PolyCNTTVec, length K_c
		int(n2)*pp.paramDC*8 + // c_hats length n2 PolyCNTT
		1 + 1 + // n2, n1
		1 + // rpulpType
		len(binMatrixB)*len(binMatrixB[0]) + 1 + 1 + 1 + // binMatrixB [][]byte, I uint8, J uint8, m uint8
		int(m)*pp.paramDC*8 + // u_hats [][]int64
		int(n)*pp.paramDC*8 + // c_waves []*PolyCNTT, length n
		pp.paramDC*8 + // c_hat_g *PolyCNTT
		pp.paramK*int(n)*(pp.paramLC*pp.paramDC*8) + //
		int(n)*pp.paramK*pp.paramDC*8*2 + // delta_waves [][]*PolyCNTT, delta_hats [][]*PolyCNTT,
		pp.paramK*(pp.paramLC*pp.paramDC*8) // ws []*PolyCNTTVec

	rst := make([]byte, 0, length)

	appendPolyNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))
		}
	}
	appendInt64ToBytes := func(a int64) {
		rst = append(rst, byte(a>>0))
		rst = append(rst, byte(a>>8))
		rst = append(rst, byte(a>>16))
		rst = append(rst, byte(a>>24))
		rst = append(rst, byte(a>>32))
		rst = append(rst, byte(a>>40))
		rst = append(rst, byte(a>>48))
		rst = append(rst, byte(a>>56))
	}

	// message
	rst = append(rst, message...)

	//	cmts with length n
	for i := 0; i < len(cmts); i++ {
		for j := 0; j < len(cmts[i].b.polyCNTTs); j++ {
			appendPolyNTTToBytes(cmts[i].b.polyCNTTs[j])
		}
		appendPolyNTTToBytes(cmts[i].c)
	}

	//	n uint8
	rst = append(rst, n)

	// b_hat
	for i := 0; i < pp.paramKC; i++ {
		appendPolyNTTToBytes(b_hat.polyCNTTs[i])
	}
	// c_hats []*PolyCNTT with length n2
	for i := 0; i < len(c_hats); i++ {
		appendPolyNTTToBytes(c_hats[i])
	}

	//	n2 uint8
	rst = append(rst, n2)

	//	n1 uint8
	rst = append(rst, n1)

	//TODO_DONE:A = ulpType B I J m
	rst = append(rst, byte(rpulpType))
	// B
	appendBinaryMartix := func(data [][]byte) {
		for i := 0; i < len(data); i++ {
			rst = append(rst, data[i]...)
		}
	}
	appendBinaryMartix(binMatrixB)
	// I
	rst = append(rst, I)
	// J
	rst = append(rst, J)

	// m
	rst = append(rst, m)

	//u_hats length m
	for i := 0; i < len(u_hats); i++ {
		for j := 0; j < len(u_hats[i]); j++ {
			appendInt64ToBytes(u_hats[i][j])
		}
	}

	//c_waves
	for i := 0; i < len(c_waves); i++ {
		appendPolyNTTToBytes(c_waves[i])
	}

	//c_hat_g [n2+1]
	appendPolyNTTToBytes(c_hat_g)

	// cmt_ws [][]*PolyCNTTVec
	for i := 0; i < len(cmt_ws); i++ {
		for j := 0; j < len(cmt_ws[i]); j++ {
			for k := 0; k < len(cmt_ws[i][j].polyCNTTs); k++ {
				appendPolyNTTToBytes(cmt_ws[i][j].polyCNTTs[k])
			}
		}
	}

	// delta_waves [][]*PolyCNTT
	for i := 0; i < len(delta_waves); i++ {
		for j := 0; j < len(delta_waves[i]); j++ {
			appendPolyNTTToBytes(delta_waves[i][j])
		}
	}
	// delta_hats [][]*PolyCNTT
	for i := 0; i < len(delta_hats); i++ {
		for j := 0; j < len(delta_hats[i]); j++ {
			appendPolyNTTToBytes(delta_hats[i][j])

		}
	}

	// ws []*PolyCNTTVec
	for i := 0; i < len(ws); i++ {
		for j := 0; j < len(ws[i].polyCNTTs); j++ {
			appendPolyNTTToBytes(ws[i].polyCNTTs[j])
		}
	}

	return rst
}

// collectBytesForRPULP2 is an auxiliary function for rpulpProve and rpulpVerify to collect some information into a byte slice
func (pp *PublicParameter) collectBytesForRPULP2(
	preMsg []byte,
	psi *PolyCNTT, psip *PolyCNTT, phi *PolyCNTT, phips []*PolyCNTT) []byte {

	length := len(preMsg) + 3*pp.paramDC*8 + len(phips)*pp.paramDC*8
	rst := make([]byte, 0, length)
	rst = append(rst, preMsg...)

	appendPolyNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))
		}
	}

	// psi
	appendPolyNTTToBytes(psi)

	// psip
	appendPolyNTTToBytes(psip)

	// phi
	appendPolyNTTToBytes(phi)

	// phips
	for i := 0; i < len(phips); i++ {
		appendPolyNTTToBytes(phips[i])
	}
	return rst
}

// todo: review
func (pp *PublicParameter) expandCombChallengeInRpulp(seed []byte, n1 uint8, m uint8) (alphas []*PolyCNTT, betas []*PolyCNTT, gammas [][][]int64, err error) {
	alphas = make([]*PolyCNTT, n1)
	betas = make([]*PolyCNTT, pp.paramK)
	gammas = make([][][]int64, pp.paramK)
	// check the length of seed

	// alpha
	alphaSeed := append([]byte{'A'}, seed...)
	tmpSeedLen := len(alphaSeed) + 1 //	1 byte for index in [0, n1-1]
	tmpSeed := make([]byte, tmpSeedLen)
	for i := 0; i < int(n1); i++ {
		copy(tmpSeed, alphaSeed)
		tmpSeed = append(tmpSeed, byte(i))
		coeffs := pp.randomDcIntegersInQc(tmpSeed)
		alphas[i] = &PolyCNTT{coeffs}
	}

	// betas
	betaSeed := append([]byte{'B'}, seed...)
	tmpSeedLen = len(betaSeed) + 1 //	1 byte for index in [0, paramK]
	tmpSeed = make([]byte, tmpSeedLen)
	for i := 0; i < pp.paramK; i++ {
		copy(tmpSeed, betaSeed)
		tmpSeed = append(tmpSeed, byte(i))
		coeffs := pp.randomDcIntegersInQc(tmpSeed)
		betas[i] = &PolyCNTT{coeffs}
	}

	// gammas
	gammaSeed := append([]byte{'G'}, seed...)
	tmpSeedLen = len(gammaSeed) + 2 //	1 byte for index in [0, paramK], 1 byte for index in [0, m-1]
	tmpSeed = make([]byte, tmpSeedLen)
	for i := 0; i < pp.paramK; i++ {
		gammas[i] = make([][]int64, m)
		for j := 0; j < int(m); j++ {
			copy(tmpSeed, gammaSeed)
			tmpSeed = append(tmpSeed, byte(i))
			tmpSeed = append(tmpSeed, byte(j))
			gammas[i][j] = pp.randomDcIntegersInQc(tmpSeed)
		}
	}

	return alphas, betas, gammas, nil
}

func (pp *PublicParameter) sigmaInvPolyCNTT(polyCNTT *PolyCNTT, t int) (r *PolyCNTT) {
	coeffs := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = polyCNTT.coeffs[pp.paramSigmaPermutations[(pp.paramK-t)%pp.paramK][i]]
	}
	return &PolyCNTT{coeffs: coeffs}
}

func (pp *PublicParameter) sigmaInvPolyNTT(polyNTT *PolyCNTT, t int) (r *PolyCNTT) {
	coeffs := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = polyNTT.coeffs[pp.paramSigmaPermutations[(pp.paramK-t)%pp.paramK][i]]
	}
	return &PolyCNTT{coeffs: coeffs}
}

func (pp *PublicParameter) genUlpPolyCNTTs(rpulpType RpUlpType, binMatrixB [][]byte, I uint8, J uint8, gammas [][][]int64) (ps [][]*PolyCNTT) {
	p := make([][]*PolyCNTT, pp.paramK)
	//	var tmp1, tmp2 big.Int

	switch rpulpType {
	case RpUlpTypeCbTx1:
		break
	case RpUlpTypeCbTx2:
		n := J
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)
			for j := uint8(0); j < n; j++ {
				p[t][j] = &PolyCNTT{coeffs: gammas[t][0]}
			}
			//	p[t][n] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				// F^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)
				if i == 0 {
					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] + gammas[t][0][i]))
					//					coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else if i < (pp.paramN - 1) {
					//coeffs[i] = reduceToQc()(int64(coeffs[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*				tmp1.SetInt64(coeffs[i])
									tmp2.SetInt64(gammas[t][0][i-1])
									tmp2.Add(&tmp2, &tmp2)
									tmp1.Sub(&tmp1, &tmp2)
									tmp2.SetInt64(gammas[t][0][i])
									tmp1.Add(&tmp1, &tmp2)
									coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else { // i in [N-1, d-1]
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				}
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs}

			p[t][n+1] = &PolyCNTT{coeffs: gammas[t][2]}
		}
	case RpUlpTypeTrTx1:
		n := I + J
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			p[t][0] = &PolyCNTT{coeffs: gammas[t][0]}

			minuscoeffs := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				minuscoeffs[i] = -gammas[t][0][i]
			}
			for j := uint8(1); j < n; j++ {
				p[t][j] = &PolyCNTT{coeffs: minuscoeffs}
			}

			//	p[t][n] = NTT^{-1}((-F)^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//(-F)^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)
				if i == 0 {
					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] - gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]-gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Sub(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else if i < (pp.paramN - 1) {
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+2*gammas[t][0][i-1]-gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Sub(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else { // i in [N-1, d-1]
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
					//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
					coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]+2*gammas[t][0][i-1]-gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs[i])
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Sub(&tmp1, &tmp2)
										coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				}
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs}

			p[t][n+1] = &PolyCNTT{coeffs: gammas[t][2]}
		}
	case RpUlpTypeTrTx2:
		n := int(I + J)
		n2 := n + 4
		//	B : d rows 2d columns
		//	m = 5
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			for j := uint8(0); j < I; j++ {
				p[t][j] = &PolyCNTT{coeffs: gammas[t][0]}
			}
			for j := I; j < I+J; j++ {
				p[t][j] = &PolyCNTT{coeffs: gammas[t][1]}
			}

			coeffs_n := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//coeffs_n[i] = reduceToQc(int64(-gammas[t][0][i]) + int64(-gammas[t][1][i]))
				coeffs_n[i] = reduceInt64(-gammas[t][0][i]-gammas[t][1][i], pp.paramQC)
				// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				/*				tmp1.SetInt64(-gammas[t][0][i])
								tmp2.SetInt64(-gammas[t][1][i])
								tmp1.Add(&tmp1, &tmp2)
								coeffs_n[i] = reduceBigInt(&tmp1, pp.paramQC)*/
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs_n}

			//	p[t][n+1] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][2] + B_1^T gamma[t][4])
			coeffs_np1 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][0] + F_1^T[i] gamma[t][2] + B^T[i] gamma[t][4]
				coeffs_np1[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][4], pp.paramDC)
				if i == 0 {
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] + gammas[t][0][i]))
					//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) + int64(gammas[t][0][i]))
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]+gammas[t][2][i]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*				tmp1.SetInt64(coeffs_np1[i])
									tmp2.SetInt64(gammas[t][2][i])
									tmp1.Add(&tmp1, &tmp2)
									tmp2.SetInt64(gammas[t][0][i])
									tmp1.Add(&tmp1, &tmp2)
									coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else if i < (pp.paramN - 1) {
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np1[i])
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else { // i in [N-1, d-1]
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]+gammas[t][2][i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np1[i])
										tmp2.SetInt64(gammas[t][2][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][0][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				}
			}
			p[t][n+1] = &PolyCNTT{coeffs: coeffs_np1}

			//	p[t][n+2] = NTT^{-1}(F^T gamma[t][1] + F_1^T gamma[t][3] + B_2^T gamma[t][4])
			coeffs_np2 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][1] + F_1^T[i] gamma[t][3] + B_2^T[i] gamma[t][4]
				coeffs_np2[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, pp.paramDC+i), gammas[t][4], pp.paramDC)
				if i == 0 {
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] + gammas[t][1][i]))
					//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) + int64(gammas[t][1][i]))
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]+gammas[t][3][i]+gammas[t][1][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np2[i])
										tmp2.SetInt64(gammas[t][3][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else if i < (pp.paramN - 1) {
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
					//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]-2*gammas[t][1][i-1]+gammas[t][1][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np2[i])
										tmp2.SetInt64(gammas[t][1][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				} else { // i in [N-1, d-1]
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
					//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]+gammas[t][3][i]-2*gammas[t][1][i-1]+gammas[t][1][i], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
					/*					tmp1.SetInt64(coeffs_np2[i])
										tmp2.SetInt64(gammas[t][3][i])
										tmp1.Add(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][1][i-1])
										tmp2.Add(&tmp2, &tmp2)
										tmp1.Sub(&tmp1, &tmp2)
										tmp2.SetInt64(gammas[t][1][i])
										tmp1.Add(&tmp1, &tmp2)
										coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				}
			}
			p[t][n+2] = &PolyCNTT{coeffs: coeffs_np2}

			p[t][n+3] = &PolyCNTT{coeffs: gammas[t][4]}
		}
	}

	return p
}

func (pp *PublicParameter) intVecInnerProductWithReductionQc(a []int64, b []int64, vecLen int) (r int64) {
	var tmp1, tmp2 big.Int
	bigQc := new(big.Int).SetInt64(pp.paramQC)

	rst := new(big.Int).SetInt64(0)
	for i := 0; i < vecLen; i++ {
		tmp1.SetInt64(a[i])
		tmp2.SetInt64(b[i])
		tmp1.Mul(&tmp1, &tmp2)
		tmp1.Mod(&tmp1, bigQc)

		rst.Add(rst, &tmp1)
		rst.Mod(rst, bigQc)
	}

	return reduceInt64(rst.Int64(), pp.paramQC)
}

func (pp *PublicParameter) intMatrixInnerProductWithReductionQc(a [][]int64, b [][]int64, rowNum int, colNum int) (r int64) {
	var tmp1, tmp2 big.Int

	rst := new(big.Int).SetInt64(0)
	bigQc := new(big.Int).SetInt64(pp.paramQC)
	for i := 0; i < rowNum; i++ {
		for j := 0; j < colNum; j++ {
			tmp1.SetInt64(a[i][j])
			tmp2.SetInt64(b[i][j])
			tmp1.Mul(&tmp1, &tmp2)
			tmp1.Mod(&tmp1, bigQc)

			rst.Add(rst, &tmp1)
			rst.Mod(rst, bigQc)
		}
	}

	return reduceInt64(rst.Int64(), pp.paramQC)
}

////q is assumed to be an odd number
//func reduceBigInt(a *big.Int, q int64) int64 {
//	var b, rst big.Int
//
//	b.SetInt64(q)
//
//	rst.Mod(a, &b)
//
//	r := rst.Int64()
//
//	//	make sure the result in the scope [-(q-1)/2, (q-1)/2]
//	if r > ((q - 1) >> 1) {
//		r = r - q
//	}
//	return r
//}

// q is assumed to be an odd number
//	applied to q_a and q_c
func reduceInt64(a int64, q int64) int64 {
	r := a % q

	m := (q - 1) >> 1

	//	make sure the result in the scope [-(q-1)/2, (q-1)/2]
	if r < (-m) {
		r = r + q
	} else if r > m {
		r = r - q
	}

	return r
}

// todo: review
//	intToBinary() returns the bits representation of v, supposing paramDc >= 64
func (pp *PublicParameter) intToBinary(v uint64) (bits []int64) {
	rstBits := make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		rstBits[i] = int64((v >> i) & 1)
	}
	return rstBits
}
func binaryToInt64(v uint64, bitNum int) (bits []int64) {
	rstbits := make([]int64, bitNum)
	for i := 0; i < bitNum; i++ {
		rstbits[i] = int64((v >> i) & 1)
	}
	return rstbits
}

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

func getMatrixColumn(matrix [][]byte, rowNum int, j int) (col []int64) {
	retcol := make([]int64, rowNum)
	for i := 0; i < rowNum; i++ {
		retcol[i] = int64((matrix[i][j/8] >> (j % 8)) & 1)
	}
	return retcol
}
