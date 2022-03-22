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

// todo: 8 byte, to support at most 64 bits
func (pp *PublicParameter) expandRandomBitsInBytesV(seed []byte) (r []byte, err error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}

	buf := make([]byte, pp.TxoValueBytesLen())
	seed = append(seed, 'V')
	//	todo: 202203 check the security
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

func (pp *PublicParameter) expandRandomnessA(seed []byte) (*PolyAVec, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}
	res := pp.NewPolyAVec(pp.paramLA)
	seed = append([]byte{'A'}, seed...)
	for i := 0; i < pp.paramLA; i++ {
		tSeed := make([]byte, len(seed)+1)
		for j := 0; j < len(seed); j++ {
			tSeed[j] = seed[j]
		}
		tSeed[len(seed)] = byte(i)
		tmp, err := randomnessFromGammaA5(tSeed, pp.paramDA)
		if err != nil {
			return nil, err
		}
		res.polyAs[i] = &PolyA{coeffs: tmp}
	}

	return res, nil
}
func (pp *PublicParameter) expandRandomnessC(seed []byte) (r *PolyCVec, err error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}
	seed = append(seed, 'C')
	r, err = pp.generatePolyVecWithProbabilityDistributions(seed, pp.paramLC)
	if err != nil {
		return nil, err
	}
	return r, nil
}
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
func (pp PublicParameter) sampleMaskA() (r *PolyAVec, err error) {
	// 1000_1000_1001_1100_0101
	res := pp.NewPolyAVec(pp.paramLA)

	for i := 0; i < pp.paramLA; i++ {
		tmp, err := randomnessFromEtaAv2(nil, pp.paramDA)
		if err != nil {
			return nil, err
		}
		res.polyAs[i] = &PolyA{coeffs: tmp}
	}
	return res, nil
}

func (pp *PublicParameter) sampleZetaA() (*PolyAVec, error) {
	// 1000_1000_1000_1001_1001
	res := pp.NewPolyAVec(pp.paramLA)

	for i := 0; i < pp.paramLA; i++ {
		tmp, err := randomnessFromZetaAv2(nil, pp.paramDA)
		if err != nil {
			return nil, err
		}
		res.polyAs[i] = &PolyA{coeffs: tmp}
	}
	return res, nil
}

func (pp PublicParameter) sampleZetaC2v2() (r *PolyCVec, err error) {
	res := pp.NewPolyCVec(pp.paramLC)

	for i := 0; i < pp.paramLC; i++ {
		tmp, err := randomnessFromZetaC2v2(nil, pp.paramDC)
		if err != nil {
			return nil, err
		}
		res.polyCs[i] = &PolyC{coeffs: tmp}
	}
	return res, nil
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
	res := make([]*PolyCNTTVec, rowLength)
	for i := 0; i < rowLength; i++ {
		res[i] = pp.NewPolyCNTTVec(colLength)
		for j := 0; j < colLength; j++ {
			tmpSeed := make([]byte, len(seed))
			copy(tmpSeed, seed)
			tmpSeed = append(tmpSeed, byte(i))
			tmpSeed = append(tmpSeed, byte(j))
			got := rejectionUniformWithQc(tmpSeed, pp.paramDC)
			for t := 0; t < pp.paramDC; t++ {
				res[i].polyCNTTs[j].coeffs[t] = got[t]
			}
		}
	}
	return res, nil
}
func (pp *PublicParameter) generatePolyANTTMatrix(seed []byte, rowLength int, colLength int) ([]*PolyANTTVec, error) {
	// check the length of seed
	res := make([]*PolyANTTVec, rowLength)
	for i := 0; i < rowLength; i++ {
		res[i] = pp.NewZeroPolyANTTVec(colLength)
		for j := 0; j < colLength; j++ {
			tmpSeed := make([]byte, len(seed))
			copy(tmpSeed, seed)
			tmpSeed = append(tmpSeed, byte(i))
			tmpSeed = append(tmpSeed, byte(j))
			got := rejectionUniformWithQa(tmpSeed, pp.paramDA, pp.paramQA)
			for t := 0; t < pp.paramDA; t++ {
				res[i].polyANTTs[j].coeffs[t] = got[t]
			}
		}
	}
	return res, nil
}

// 9007199254746113 = 0010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0001_0100_0000_0001
// 4503599627373056 = 0001_0000_0000_0000_0000_0000_0000_0000_0000_0000_000_1010_0000_0000
//	todo: 202203 Qc hard code, but withQa does not hard code, make them consistent
func rejectionUniformWithQc(seed []byte, length int) []int64 {
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
		_, err := xof.Write(append(seed, byte(cnt)))
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

// 137438953937= 0010_0000_0000_0000_0000_0000_0000_0001_1101_0001
// 0001_0000_0000_0000_0000_0000_0000_0000_1110_1000
func rejectionUniformWithQa(seed []byte, length int, bound int64) []int64 {
	res := make([]int64, length)
	xof := sha3.NewShake128()
	cnt := 1
	cur := 0
	var pos int
	var t int64
	for cur < length {
		buf := make([]byte, (length-cur)*19)
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
		for pos+19 < len(buf) {
			t = int64(buf[pos+0])
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]) << 16
			t |= int64(buf[pos+3]) << 24
			t |= (int64(buf[pos+4] & 0x3F)) << 32
			t &= 0x3FFFFFFFFF
			if t < bound { // [0,bound]  ->  [-(bound-1)/2,(bound-1)/2]
				res[cur] = reduceInt64(t, bound)
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
				res[cur] = reduceInt64(t, bound)
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
				res[cur] = reduceInt64(t, bound)
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
				res[cur] = reduceInt64(t, bound)
				cur++
				if cur >= length {
					break
				}
			}

			pos += 19
		}
		cnt++
	}
	return res
}

// expandSigACh should output a {-1,0,1}^DC vector with the number of not-0 is theta_a from a byte array
// Firstly, set the 1 or -1 with total number is theta
// Secondly, shuffle the array using the Knuth-Durstenfeld Shuffle
func (pp PublicParameter) expandChallengeA(seeds []byte) (*PolyA, error) {
	seed := make([]byte, len(seeds)+2)
	for i := 0; i < len(seeds); i++ {
		seed[i] = seeds[i]
	}
	seed = append([]byte{'A', 'C'}, seed...)
	length := pp.paramDA
	res := make([]int64, length)
	buf := make([]byte, length)
	var err error
	// cnt is used for resetting the buf
	// cur is used for loop the buf
	var p, cnt, cur int
	xof := sha3.NewShake128()
	resetBuf := func() error {
		xof.Reset()
		_, err = xof.Write(append(seed, byte(cnt)))
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
	// TODO : About optimization, because the ThetaA must less than DC? so there would use the
	// 8-th binary for Setting and 0-th to 7-th for Shuffling.
	// Setting
	for i := 0; i < pp.paramThetaA; i += 8 {
		for j := 0; j < 8; j++ {
			if buf[cur]&1<<j == 0 {
				res[i+j] = -1
			} else {
				res[i+j] = 1
			}
		}
		cur++
	}
	// Shuffling
	for k := len(res); k > 0; k-- {
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
		res[p], res[k-1] = res[k-1], res[p]
	}
	return &PolyA{coeffs: res}, nil
}

func (pp PublicParameter) expandChallengeC(seeds []byte) (*PolyC, error) {
	seed := make([]byte, len(seeds))
	for i := 0; i < len(seeds); i++ {
		seed[i] = seeds[i]
	}
	seed = append([]byte{byte('C'), byte('h')}, seed...)
	var err error
	// extend seed via sha3.Shake128
	ret := pp.NewPolyC()
	buf := make([]byte, pp.paramDC)
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
	got, err := randomnessFromChallengeSpace(buf, pp.paramDC)
	if err != nil {
		return nil, err
	}
	for i := 0; i < pp.paramDC; i++ {
		ret.coeffs[i] = got[i]
	}
	return ret, nil
}

func (pp *PublicParameter) sampleRandomnessRC() (*PolyCVec, error) {
	polys := make([]*PolyC, pp.paramLC)
	var err error
	for i := 0; i < pp.paramLC; i++ {
		var tmp []int64
		_, tmp, err = randomnessFromProbabilityDistributions(nil, pp.paramDC)
		if err != nil {
			return nil, err
		}
		polys[i] = &PolyC{coeffs: tmp}
	}
	res := &PolyCVec{
		polyCs: polys,
	}
	return res, nil
}

func (pp *PublicParameter) sampleMaskCv2() (r *PolyCVec, err error) {
	// etaC
	polys := make([]*PolyC, pp.paramLC)

	for i := 0; i < pp.paramLC; i++ {
		tmp, err := randomnessFromEtaCv2(RandomBytes(pp.paramSeedBytesLen), pp.paramDC)
		if err != nil {
			return nil, err
		}
		polys[i] = &PolyC{coeffs: tmp}
	}
	rst := &PolyCVec{
		polyCs: polys,
	}
	return rst, nil
}
func (pp *PublicParameter) sampleUniformPloyWithLowZeros() (r *PolyC) {
	ret := pp.NewPolyC()
	seed := RandomBytes(pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQc(seed, pp.paramDC-pp.paramK)
	for i := pp.paramK; i < pp.paramDC; i++ {
		ret.coeffs[i] = tmp[i-pp.paramK]
	}
	return ret
}

func (pp *PublicParameter) collectBytesForRPULP1(message []byte,
	n int, n1 int, n2 int, binMatrixB [][]byte, m int,
	cmts []*ValueCommitment, b_hat *PolyCNTTVec, c_hats []*PolyCNTT,
	rpulpType RpUlpType, I int, J int, u_hats [][]int64, c_waves []*PolyCNTT,
	cmt_ws [][]*PolyCNTTVec, ws []*PolyCNTTVec, c_hat_g *PolyCNTT) []byte {
	tmp := make([]byte, 0,
		(pp.paramKC*pp.paramDC*4+pp.paramDC*4)*n+pp.paramKC*pp.paramDC*4+pp.paramDC*4*n2+4+1+len(binMatrixB)*len(binMatrixB[0])+1+1+m*pp.paramDC*4+pp.paramDC*4*n+(pp.paramKC*pp.paramDC*4)*n*pp.paramK+(pp.paramKC*pp.paramDC*4)*pp.paramK+pp.paramDC*4+
			pp.paramDC*4*(n*pp.paramK*2+3+pp.paramK))
	appendPolyNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			tmp = append(tmp, byte(a.coeffs[k]>>0))
			tmp = append(tmp, byte(a.coeffs[k]>>8))
			tmp = append(tmp, byte(a.coeffs[k]>>16))
			tmp = append(tmp, byte(a.coeffs[k]>>24))
			tmp = append(tmp, byte(a.coeffs[k]>>32))
			tmp = append(tmp, byte(a.coeffs[k]>>40))
			tmp = append(tmp, byte(a.coeffs[k]>>48))
			tmp = append(tmp, byte(a.coeffs[k]>>56))
		}
	}
	appendInt32ToBytes := func(a int64) {
		tmp = append(tmp, byte(a>>0))
		tmp = append(tmp, byte(a>>8))
		tmp = append(tmp, byte(a>>16))
		tmp = append(tmp, byte(a>>24))
		tmp = append(tmp, byte(a>>32))
		tmp = append(tmp, byte(a>>40))
		tmp = append(tmp, byte(a>>48))
		tmp = append(tmp, byte(a>>56))
	}
	// message
	tmp = append(tmp, message...)
	// b_i_arrow , c_i
	for i := 0; i < len(cmts); i++ {
		for j := 0; j < len(cmts[i].b.polyCNTTs); j++ {
			appendPolyNTTToBytes(cmts[i].b.polyCNTTs[j])
		}
		appendPolyNTTToBytes(cmts[i].c)
	}
	// b_hat
	for i := 0; i < pp.paramKC; i++ {
		appendPolyNTTToBytes(b_hat.polyCNTTs[i])
	}
	// c_i_hat
	for i := 0; i < n2; i++ {
		appendPolyNTTToBytes(c_hats[i])
	}
	// n1
	appendInt32ToBytes(int64(n1)) //
	//TODO_DONE:A = ulpType B I J
	tmp = append(tmp, byte(rpulpType))
	// B
	appendBinaryMartix := func(data [][]byte) {
		for i := 0; i < len(data); i++ {
			tmp = append(tmp, data[i]...)
		}
	}
	appendBinaryMartix(binMatrixB)
	// I
	tmp = append(tmp, byte(I))
	// J
	tmp = append(tmp, byte(J))
	//u_hats
	for i := 0; i < len(u_hats); i++ {
		for j := 0; j < len(u_hats[i]); j++ {
			appendInt32ToBytes(u_hats[i][j])
		}
	}
	//c_waves
	for i := 0; i < len(c_waves); i++ {
		appendPolyNTTToBytes(c_waves[i])
	}
	// omega_i^j
	for i := 0; i < len(cmt_ws); i++ {
		for j := 0; j < len(cmt_ws[i]); j++ {
			for k := 0; k < len(cmt_ws[i][j].polyCNTTs); k++ {
				appendPolyNTTToBytes(cmt_ws[i][j].polyCNTTs[k])
			}
		}
	}
	// omega^i
	for i := 0; i < len(ws); i++ {
		for j := 0; j < len(ws[i].polyCNTTs); j++ {
			appendPolyNTTToBytes(ws[i].polyCNTTs[j])
		}
	}
	//c_hat[n2+1]
	appendPolyNTTToBytes(c_hat_g)
	return tmp
}

// collectBytesForRPULP2 is an auxiliary function for rpulpProve and rpulpVerify to collect some information into a byte slice
func (pp *PublicParameter) collectBytesForRPULP2(
	tmp []byte, delta_waves [][]*PolyCNTT, delta_hats [][]*PolyCNTT,
	psi *PolyCNTT, psip *PolyCNTT, phi *PolyCNTT, phips []*PolyCNTT) []byte {

	appendPolyNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			tmp = append(tmp, byte(a.coeffs[k]>>0))
			tmp = append(tmp, byte(a.coeffs[k]>>8))
			tmp = append(tmp, byte(a.coeffs[k]>>16))
			tmp = append(tmp, byte(a.coeffs[k]>>24))
			tmp = append(tmp, byte(a.coeffs[k]>>32))
			tmp = append(tmp, byte(a.coeffs[k]>>40))
			tmp = append(tmp, byte(a.coeffs[k]>>48))
			tmp = append(tmp, byte(a.coeffs[k]>>56))
		}
	}
	// delta_waves_i^j
	for i := 0; i < len(delta_waves); i++ {
		for j := 0; j < len(delta_waves[i]); j++ {
			appendPolyNTTToBytes(delta_waves[i][j])
		}
	}
	// delta_hat_i^j
	for i := 0; i < len(delta_hats); i++ {
		for j := 0; j < len(delta_hats[i]); j++ {
			appendPolyNTTToBytes(delta_hats[i][j])

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
	return tmp
}

func (pp *PublicParameter) expandUniformRandomnessInRqZqC(seed []byte, n1 int, m int) (alphas []*PolyCNTT, betas []*PolyCNTT, gammas [][][]int64, err error) {
	alphas = make([]*PolyCNTT, n1)
	betas = make([]*PolyCNTT, pp.paramK)
	gammas = make([][][]int64, pp.paramK)
	// check the length of seed

	XOF := sha3.NewShake128()
	// alpha
	XOF.Reset()
	_, err = XOF.Write(append(seed, 0))
	if err != nil {
		return nil, nil, nil, err
	}
	buf := make([]byte, n1*pp.paramDC*4)
	for i := 0; i < n1; i++ {
		alphas[i] = pp.NewPolyCNTT()
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, nil, nil, err
		}
		got := rejectionUniformWithQc(buf, pp.paramDC)
		if len(got) < pp.paramLC {
			newBuf := make([]byte, pp.paramDC*4)
			_, err = XOF.Read(newBuf)
			if err != nil {
				return nil, nil, nil, err
			}
			got = append(got, rejectionUniformWithQc(newBuf, pp.paramDC-len(got))...)
		}
		for k := 0; k < pp.paramDC; k++ {
			alphas[i].coeffs[k] = got[k]
		}
	}
	// betas
	XOF.Reset()
	_, err = XOF.Write(append(seed, 1))
	if err != nil {
		return nil, nil, nil, err
	}
	buf = make([]byte, pp.paramK*pp.paramDC*4)
	for i := 0; i < pp.paramK; i++ {
		betas[i] = pp.NewPolyCNTT()
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, nil, nil, err
		}
		got := rejectionUniformWithQc(buf, pp.paramDC)
		if len(got) < pp.paramLC {
			newBuf := make([]byte, pp.paramDC*4)
			_, err = XOF.Read(newBuf)
			if err != nil {
				return nil, nil, nil, err
			}
			got = append(got, rejectionUniformWithQc(newBuf, pp.paramDC-len(got))...)
		}
		for k := 0; k < pp.paramDC; k++ {
			betas[i].coeffs[k] = got[k]
		}
	}
	// gammas
	XOF.Reset()
	_, err = XOF.Write(append(seed, 2))
	if err != nil {
		return nil, nil, nil, err
	}
	buf = make([]byte, m*pp.paramDC*4)
	for i := 0; i < pp.paramK; i++ {
		gammas[i] = make([][]int64, m)
		_, err = XOF.Read(buf)
		for j := 0; j < m; j++ {
			gammas[i][j] = make([]int64, pp.paramDC)
			got := rejectionUniformWithQc(buf, pp.paramDC)
			if len(got) < pp.paramLC {
				newBuf := make([]byte, pp.paramDC*4)
				_, err = XOF.Read(newBuf)
				if err != nil {
					return nil, nil, nil, err
				}
				got = append(got, rejectionUniformWithQc(newBuf, pp.paramDC-len(got))...)
			}
			for k := 0; k < pp.paramDC; k++ {
				gammas[i][j][k] = got[k]
			}
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

func (pp *PublicParameter) genUlpPolyCNTTs(rpulpType RpUlpType, binMatrixB [][]byte, I int, J int, gammas [][][]int64) (ps [][]*PolyCNTT) {
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
			for j := 0; j < n; j++ {
				p[t][j] = &PolyCNTT{coeffs: gammas[t][0]}
			}
			//	p[t][n] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				// F^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = intVecInnerProductWithReduction(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC, pp.paramQC)
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
			for j := 1; j < n; j++ {
				p[t][j] = &PolyCNTT{coeffs: minuscoeffs}
			}

			//	p[t][n] = NTT^{-1}((-F)^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//(-F)^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = intVecInnerProductWithReduction(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC, pp.paramQC)
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
		n := I + J
		n2 := n + 4
		//	B : d rows 2d columns
		//	m = 5
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			for j := 0; j < I; j++ {
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
				coeffs_np1[i] = intVecInnerProductWithReduction(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][4], pp.paramDC, pp.paramQC)
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
				coeffs_np2[i] = intVecInnerProductWithReduction(getMatrixColumn(binMatrixB, pp.paramDC, pp.paramDC+i), gammas[t][4], pp.paramDC, pp.paramQC)
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

func intVecInnerProductWithReduction(a []int64, b []int64, vecLen int, q int64) (r int64) {
	var rst big.Int
	var tmp1, tmp2 big.Int
	rst.SetInt64(0)
	for i := 0; i < vecLen; i++ {
		tmp1.SetInt64(a[i])
		tmp2.SetInt64(b[i])
		tmp1.Mul(&tmp1, &tmp2)
		tmp1.SetInt64(reduceBigInt(&tmp1, q))
		rst.Add(&rst, &tmp1)
		rst.SetInt64(reduceBigInt(&rst, q))
	}
	return rst.Int64()
}

func intMatrixInnerProductWithReduction(a [][]int64, b [][]int64, rowNum int, colNum int, q int64) (r int64) {
	rst := int64(0)

	var tmp1, tmp2 big.Int
	for i := 0; i < rowNum; i++ {
		for j := 0; j < colNum; j++ {
			tmp1.SetInt64(a[i][j])
			tmp2.SetInt64(b[i][j])
			tmp1.Mul(&tmp1, &tmp2)
			rst = rst + reduceBigInt(&tmp1, q)
			rst = reduceInt64(rst, q)
		}
	}

	return rst
}

/*
q is assumed to be an odd number
*/
func reduceBigInt(a *big.Int, q int64) int64 {
	var b, rst big.Int

	b.SetInt64(q)

	rst.Mod(a, &b)

	r := rst.Int64()

	//	make sure the result in the scope [-(q-1)/2, (q-1)/2]
	if r > ((q - 1) >> 1) {
		r = r - q
	}
	return r
}

/*
q is assumed to be an odd number
*/
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

func intToBinary(v uint64, bitNum int) (bits []int64) {
	rstbits := make([]int64, bitNum)
	for i := 0; i < bitNum; i++ {
		rstbits[i] = int64((v >> i) & 1)
	}
	return rstbits
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
