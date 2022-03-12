package pqringct

import (
	"golang.org/x/crypto/sha3"
	"log"
)

func (pp *PublicParameterv2) expandRandomnessAv2(seed []byte) (*PolyVecv2, error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}
	res := &PolyVecv2{polys: make([]*Polyv2, pp.paramLA)}
	seed = append(seed, 'A')
	for i := 0; i < pp.paramLA; i++ {
		tSeed := make([]byte, len(seed)+1)
		for j := 0; j < len(seed); j++ {
			tSeed[j] = seed[j]
		}
		tSeed[len(seed)] = byte(i)
		tmp, err := randomnessFromGammaAv2(tSeed, pp.paramDA)
		if err != nil {
			return nil, err
		}
		res.polys[i] = &Polyv2{coeffs2: tmp}
	}

	return res, nil
}
func (pp PublicParameterv2) sampleMaskAv2() (r *PolyVecv2, err error) {
	// 1000_1000_1001_1100_0101
	polys := make([]*Polyv2, pp.paramLA)

	for i := 0; i < pp.paramLA; i++ {
		tmp, err := randomnessFromEtaAv2(nil, pp.paramDA)
		if err != nil {
			return nil, err
		}
		polys[i] = &Polyv2{coeffs2: tmp}
	}
	rst := &PolyVecv2{polys: polys}
	return rst, nil
}
func (pp *PublicParameterv2) sampleZetaAv2() (*PolyVecv2, error) {
	// 1000_1000_1000_1001_1001
	polys := make([]*Polyv2, pp.paramLA)

	for i := 0; i < pp.paramLA; i++ {
		tmp, err := randomnessFromZetaAv2(nil, pp.paramDA)
		if err != nil {
			return nil, err
		}
		polys[i] = &Polyv2{coeffs2: tmp}
	}
	rst := &PolyVecv2{polys}
	return rst, nil
}
func (pp PublicParameterv2) sampleZetaC2v2() (r *PolyVecv2, err error) {
	polys := make([]*Polyv2, pp.paramLC)

	for i := 0; i < pp.paramLC; i++ {
		tmp, err := randomnessFromZetaC2v2(nil, pp.paramDC)
		if err != nil {
			return nil, err
		}
		polys[i] = &Polyv2{coeffs1: tmp}
	}
	rst := &PolyVecv2{
		polys: polys,
	}
	return rst, nil
}
func (pp *PublicParameterv2) sampleUniformWithinEtaFv2() ([]int32, error) {
	//  qc =					1111_1111_1111_1111_1110_1110_0000_0001
	// (qc-1)/16 = 268435168 = 	1111_1111_1111_1111_1110_1110_0000
	seed := randomBytes(pp.paramSysBytes)
	length := pp.paramDC
	res := make([]int32, 0, length)
	var curr int
	var pos int
	var t uint32
	xof := sha3.NewShake128()
	cnt := 1
	for len(res) < length {
		buf := make([]byte, (length-len(res))*4)
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
		for pos < len(buf) {
			// 从buf中读取32个bit（4byte）
			t = uint32(buf[pos])
			t |= uint32(buf[pos+1]) << 8
			t |= uint32(buf[pos+2]) << 16
			t |= uint32(buf[pos+3]&0x0F) << 24
			if t < pp.paramQC {
				res = append(res, int32(t-pp.paramQC))
				curr += 1
				if curr >= length {
					break
				}
			}
			t = uint32(buf[pos+3]&0xF0) >> 4
			t |= uint32(buf[pos+4]) << 4
			t |= uint32(buf[pos+5]) << 12
			t |= uint32(buf[pos+6]) << 20
			if t < pp.paramQC {
				res = append(res, int32(t-pp.paramQC))
				curr += 1
				if curr >= length {
					break
				}
			}
			pos += 7
		}
		cnt++
	}
	return res, nil
}
func (pp *PublicParameterv2) expandPubVecAv2(seed []byte) (*PolyVecv2, error) {
	// [0 ... 0(k_a) 1 r ... r(lambda_a)]
	res := NewPolyVecv2(R_QA, pp.paramDA, pp.paramLA)
	for i := 0; i < pp.paramDA; i++ {
		res.polys[pp.paramKA].coeffs2[i] = 1
	}
	// generate the remained sub-matrix
	matrix, err := generateMatrix(seed, R_QA, pp.paramDA, 1, pp.paramLambdaA)
	if err != nil {
		return nil, err
	}
	for i := 0; i < pp.paramLambdaA; i++ {
		res.polys[i+pp.paramKA+1] = matrix[0].polys[i]
	}
	return res, nil
}
func (pp *PublicParameterv2) expandPubMatrixB(seed []byte) (matrixB []*PolyNTTVecv2, err error) {
	res := make([]*PolyNTTVecv2, pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		res[i] = NewPolyNTTVecv2(R_QC, pp.paramDC, pp.paramLC)
		for k := 0; k < pp.paramDC; k++ {
			res[i].polyNTTs[i].coeffs1[k] = 1
		}
	}
	// generate the remained sub-matrix
	matrix, err := generateNTTMatrix(seed, R_QC, pp.paramDC, pp.paramKC, pp.paramI+pp.paramJ+7+pp.paramLambdaC)
	if err != nil {
		return nil, err
	}
	for i := 0; i < pp.paramKC; i++ {
		for j := 0; j < pp.paramI+pp.paramJ+7+pp.paramLambdaC; j++ {
			for k := 0; k < pp.paramDC; k++ {
				res[i].polyNTTs[j+pp.paramKC].coeffs1[k] = matrix[i].polyNTTs[j].coeffs1[k]
			}
		}
	}
	return res, nil
}
func (pp *PublicParameterv2) expandPubMatrixH(seed []byte) (matrixH []*PolyNTTVecv2, err error) {
	res := make([]*PolyNTTVecv2, pp.paramI+pp.paramJ+7)

	unitPoly := NewPolyv2(R_QC, pp.paramDC)
	var tmp *PolyNTTv2
	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
		res[i] = NewPolyNTTVecv2(R_QC, pp.paramDC, pp.paramLC)
		unitPoly.coeffs1[i] = 1
		tmp = pp.NTTInRQc(unitPoly)
		for j := 0; j < pp.paramDC; j++ {
			res[i].polyNTTs[pp.paramKC].coeffs1[j] = tmp.coeffs1[j]
		}
		unitPoly.coeffs1[i] = 0
	}

	// generate the remained sub-matrix
	matrix, err := generateNTTMatrix(seed, R_QC, pp.paramDC, pp.paramI+pp.paramJ+7, pp.paramLambdaC)
	if err != nil {
		return nil, err
	}
	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
		for j := 0; j < pp.paramLambdaC; j++ {
			for k := 0; k < pp.paramDC; k++ {
				res[i].polyNTTs[pp.paramKC+pp.paramI+pp.paramJ+7+j].coeffs1[k] = matrix[i].polyNTTs[j].coeffs1[k]
			}
		}
	}
	return res, nil
}

// generateNTTMatrix generate a matrix with rowLength * colLength, and the element in matrix is length
func generateNTTMatrix(seed []byte, rtp reduceType, length int, rowLength int, colLength int) ([]*PolyNTTVecv2, error) {
	// check the length of seed
	res := make([]*PolyNTTVecv2, rowLength)
	for i := 0; i < rowLength; i++ {
		res[i] = NewPolyNTTVecv2(rtp, length, colLength)
		for j := 0; j < colLength; j++ {
			tmpSeed := make([]byte, len(seed))
			copy(tmpSeed, seed)
			tmpSeed = append(tmpSeed, byte(i))
			tmpSeed = append(tmpSeed, byte(j))
			switch rtp {
			case R_QC:
				got := rejectionUniformWithQc(tmpSeed, length)
				for k := 0; k < length; k++ {
					res[i].polyNTTs[j].coeffs1[k] = got[k]
				}
			case R_QA:
				got := rejectionUniformWithQa(tmpSeed, length)
				for k := 0; k < length; k++ {
					res[i].polyNTTs[j].coeffs2[k] = got[k]
				}
			default:
				log.Fatalln("Unsupported type for reducing")
				return nil, nil
			}
		}
	}
	return res, nil
}
func generateMatrix(seed []byte, rtp reduceType, length int, rowLength int, colLength int) ([]*PolyVecv2, error) {
	// check the length of seed
	res := make([]*PolyVecv2, rowLength)
	for i := 0; i < rowLength; i++ {
		res[i] = NewPolyVecv2(rtp, length, colLength)
		for j := 0; j < colLength; j++ {
			tmpSeed := make([]byte, len(seed))
			copy(tmpSeed, seed)
			tmpSeed = append(tmpSeed, byte(i))
			tmpSeed = append(tmpSeed, byte(j))
			switch rtp {
			case R_QC:
				got := rejectionUniformWithQc(tmpSeed, length)
				for k := 0; k < length; k++ {
					res[i].polys[j].coeffs1[k] = got[k]
				}
			case R_QA:
				got := rejectionUniformWithQa(tmpSeed, length)
				for k := 0; k < length; k++ {
					res[i].polys[j].coeffs2[k] = got[k]
				}
			default:
				log.Fatalln("Unsupported type for reducing")
				return nil, nil
			}
		}
	}
	return res, nil
}

// 4294962689 = 1111_1111_1111_1111_1110_1110_0000_0001
func rejectionUniformWithQc(seed []byte, length int) []int32 {
	res := make([]int32, length)
	var curr int
	var pos int
	var t uint32

	xof := sha3.NewShake128()
	cnt := 1
	for curr < length {
		buf := make([]byte, (length-curr)*4)
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
		for pos < len(buf) {
			// read 4 byte from buf and view it as a uint32
			t = uint32(buf[pos])
			t |= uint32(buf[pos+1]) << 8
			t |= uint32(buf[pos+2]) << 16
			t |= uint32(buf[pos+3]) << 24
			// if t is in [0,4294962689] then accept
			// otherwise reject this one
			if t < 4294962689 {
				// 0111_1111_1111_1111_1111_0111_0000_0000
				res[curr] = int32(t - 2147481344)
				curr += 1
				if curr >= length {
					break
				}
			}
			pos += 4
		}
		cnt++
	}
	return res
}

// 34360786961 = 1000_0000_0000_0001_0000_0000_0000_0001_0001
// 17180393480 = 0100_0000_0000_0000_1000_0000_0000_0000_1000
func rejectionUniformWithQa(seed []byte, length int) []int64 {
	res := make([]int64, length)
	xof := sha3.NewShake128()
	cnt := 1
	cur := 0
	var pos int
	var t int64
	for cur < length {
		buf := make([]byte, (length-cur)*9)
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
		for pos+8 < len(buf) {
			t = int64(buf[pos+0])
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]) << 16
			t |= int64(buf[pos+3]) << 24
			t |= (int64(buf[pos]+4) & 0x0F) << 32
			t &= 0xFFFFFFFFF
			if t < 34360786961 {
				res[cur] = t - 17180393480
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+4]&0xF0) >> 4
			t |= int64(buf[pos+5]) << 4
			t |= int64(buf[pos+6]) << 12
			t |= int64(buf[pos+7]) << 20
			t |= int64(buf[pos+8]) << 28
			t &= 0xFFFFFFFFF
			if t < 34360786961 {
				res[cur] = t - 17180393480
				cur++
				if cur >= length {
					break
				}
			}
			pos += 9
		}
		cnt++
	}
	return res
}

// expandSigACh should output a {-1,0,1}^DC vector with the number of not-0 is theta_a from a byte array
// Firstly, set the 1 or -1 with total number is theta
// Secondly, shuffle the array using the Knuth-Durstenfeld Shuffle
func (pp PublicParameterv2) expandSigAChv2(seeds []byte) (*Polyv2, error) {
	seed := make([]byte, len(seeds)+2)
	for i := 0; i < len(seeds); i++ {
		seed[i] = seeds[i]
	}
	seed = append(seed, 'A', 'C')
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
	for i := 0; i < int(pp.paramThetaA); i += 8 {
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
	return &Polyv2{coeffs2: res}, nil
}

func (pp PublicParameterv2) expandSigCChv2(seeds []byte) (*Polyv2, error) {
	seed := make([]byte, len(seeds))
	for i := 0; i < len(seeds); i++ {
		seed[i] = seeds[i]
	}
	seed = append(seed, byte('C'), byte('h'))
	var err error
	// extend seed via sha3.Shake128
	ret := NewPolyv2(R_QC, pp.paramDC)
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
		ret.coeffs1[i] = got[i]
	}
	return ret, nil
}

func (pp *PublicParameterv2) sampleRandomnessRv2() (r *PolyVecv2, err error) {
	polys := make([]*Polyv2, pp.paramLC)

	for i := 0; i < pp.paramLC; i++ {
		var tmp []int32
		_, tmp, err = randomnessFromProbabilityDistributions(nil, pp.paramDC)
		if err != nil {
			return nil, err
		}
		polys[i] = &Polyv2{coeffs1: tmp}
	}
	rst := &PolyVecv2{
		polys: polys,
	}
	return rst, nil
}

func (pp *PublicParameterv2) sampleMaskCv2() (r *PolyVecv2, err error) {
	// etaC
	polys := make([]*Polyv2, pp.paramLC)

	for i := 0; i < pp.paramLC; i++ {
		tmp, err := randomnessFromEtaCv2(randomBytes(pp.paramSysBytes), pp.paramDC)
		if err != nil {
			return nil, err
		}
		polys[i] = &Polyv2{coeffs1: tmp}
	}
	rst := &PolyVecv2{
		polys: polys,
	}
	return rst, nil
}
func (pp *PublicParameterv2) sampleUniformPloyWithLowZeros() (r *Polyv2) {
	ret := NewPolyv2(R_QC, pp.paramDC)
	seed := randomBytes(pp.paramSysBytes)
	tmp := rejectionUniformWithQc(seed, pp.paramDC-pp.paramK)
	for i := pp.paramK; i < pp.paramDC; i++ {
		ret.coeffs1[i] = tmp[i-pp.paramK]
	}
	return ret
}

func (pp *PublicParameterv2) collectBytesForRPULP1(
	n int, n1 int, n2 int, binMatrixB [][]byte, m int,
	cmts []*Commitmentv2, b_hat *PolyNTTVecv2, c_hats []*PolyNTTv2,
	rpulpType RpUlpType, I int, J int, u_hats [][]int32, c_waves []*PolyNTTv2,
	cmt_ws [][]*PolyNTTVecv2, ws []*PolyNTTVecv2, c_hat_g *PolyNTTv2) []byte {
	tmp := make([]byte, 0,
		(pp.paramKC*pp.paramDC*4+pp.paramDC*4)*n+pp.paramKC*pp.paramDC*4+pp.paramDC*4*n2+4+1+len(binMatrixB)*len(binMatrixB[0])+1+1+m*pp.paramDC*4+pp.paramDC*4*n+(pp.paramKC*pp.paramDC*4)*n*pp.paramK+(pp.paramKC*pp.paramDC*4)*pp.paramK+pp.paramDC*4+
			pp.paramDC*4*(n*pp.paramK*2+3+pp.paramK))
	appendPolyNTTToBytes := func(a *PolyNTTv2) {
		for k := 0; k < pp.paramDC; k++ {
			tmp = append(tmp, byte(a.coeffs1[k]>>0))
			tmp = append(tmp, byte(a.coeffs1[k]>>8))
			tmp = append(tmp, byte(a.coeffs1[k]>>16))
			tmp = append(tmp, byte(a.coeffs1[k]>>24))
		}
	}
	appendInt32ToBytes := func(a int32) {
		tmp = append(tmp, byte(a>>0))
		tmp = append(tmp, byte(a>>8))
		tmp = append(tmp, byte(a>>16))
		tmp = append(tmp, byte(a>>24))
	}
	// b_i_arrow , c_i
	for i := 0; i < len(cmts); i++ {
		for j := 0; j < len(cmts[i].b.polyNTTs); j++ {
			appendPolyNTTToBytes(cmts[i].b.polyNTTs[j])
		}
		appendPolyNTTToBytes(cmts[i].c)
	}
	// b_hat
	for i := 0; i < pp.paramKC; i++ {
		appendPolyNTTToBytes(b_hat.polyNTTs[i])
	}
	// c_i_hat
	for i := 0; i < n2; i++ {
		appendPolyNTTToBytes(c_hats[i])
	}
	// n1
	appendInt32ToBytes(int32(n1))
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
			for k := 0; k < len(cmt_ws[i][j].polyNTTs); k++ {
				appendPolyNTTToBytes(cmt_ws[i][j].polyNTTs[k])
			}
		}
	}
	// omega^i
	for i := 0; i < len(ws); i++ {
		for j := 0; j < len(ws[i].polyNTTs); j++ {
			appendPolyNTTToBytes(ws[i].polyNTTs[j])
		}
	}
	//c_hat[n2+1]
	appendPolyNTTToBytes(c_hat_g)
	return tmp
}

// collectBytesForRPULP2 is an auxiliary function for rpulpProve and rpulpVerify to collect some information into a byte slice
func (pp *PublicParameterv2) collectBytesForRPULP2(
	tmp []byte, delta_waves [][]*PolyNTTv2, delta_hats [][]*PolyNTTv2,
	psi *PolyNTTv2, psip *PolyNTTv2, phi *PolyNTTv2, phips []*PolyNTTv2) []byte {
	appendPolyNTTToBytes := func(a *PolyNTTv2) {
		for k := 0; k < pp.paramDC; k++ {
			tmp = append(tmp, byte(a.coeffs1[k]>>0))
			tmp = append(tmp, byte(a.coeffs1[k]>>8))
			tmp = append(tmp, byte(a.coeffs1[k]>>16))
			tmp = append(tmp, byte(a.coeffs1[k]>>24))
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

func (pp *PublicParameterv2) expandUniformRandomnessInRqZqC(seed []byte, n1 int, m int) (alphas []*PolyNTTv2, betas []*PolyNTTv2, gammas [][][]int32, err error) {
	alphas = make([]*PolyNTTv2, n1)
	betas = make([]*PolyNTTv2, pp.paramK)
	gammas = make([][][]int32, pp.paramK)
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
		alphas[i] = NewPolyNTTv2(R_QC, pp.paramDC)
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
			alphas[i].coeffs1[k] = got[k]
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
		betas[i] = NewPolyNTTv2(R_QC, pp.paramDC)
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
			betas[i].coeffs1[k] = got[k]
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
		gammas[i] = make([][]int32, m)
		_, err = XOF.Read(buf)
		for j := 0; j < m; j++ {
			gammas[i][j] = make([]int32, pp.paramDC)
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
func (pp *PublicParameterv2) sigmaInvPolyNTT(polyNTT *PolyNTTv2, rtp reduceType, t int) (r *PolyNTTv2) {
	if rtp != R_QC {
		log.Fatalln("sigmaInvPolyNTT() just can be called by Qc")
	}
	coeffs := make([]int32, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		coeffs[i] = polyNTT.coeffs1[pp.paramSigmaPermutations[(pp.paramK-t)%pp.paramK][i]]
	}
	return &PolyNTTv2{coeffs1: coeffs}
}

func (pp *PublicParameterv2) genUlpPolyNTTs(rpulpType RpUlpType, binMatrixB [][]byte, I int, J int, gammas [][][]int32) (ps [][]*PolyNTTv2) {
	p := make([][]*PolyNTTv2, pp.paramK)

	switch rpulpType {
	case RpUlpTypeCbTx1:
		break
	case RpUlpTypeCbTx2:
		n := J
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyNTTv2, n2)
			for j := 0; j < n; j++ {
				p[t][j] = &PolyNTTv2{coeffs1: gammas[t][0]}
			}
			//	p[t][n] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int32, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				// F^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)
				if i == 0 {
					//coeffs[i] = pp.reduce(int64(coeffs[i] + gammas[t][1][i] + gammas[t][0][i]))
					coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + int64(gammas[t][0][i]))
				} else if i < (pp.paramN - 1) {
					//coeffs[i] = reduceToQc()(int64(coeffs[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					coeffs[i] = reduceToQc(int64(coeffs[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				} else { // i in [N-1, d-1]
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				}
			}
			p[t][n] = &PolyNTTv2{coeffs1: coeffs}

			p[t][n+1] = &PolyNTTv2{coeffs1: gammas[t][2]}
		}
	case RpUlpTypeTrTx1:
		n := I + J
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyNTTv2, n2)

			p[t][0] = &PolyNTTv2{coeffs1: gammas[t][0]}

			minuscoeffs := make([]int32, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				minuscoeffs[i] = -gammas[t][0][i]
			}
			for j := 1; j < n; j++ {
				p[t][j] = &PolyNTTv2{coeffs1: minuscoeffs}
			}

			//	p[t][n] = NTT^{-1}((-F)^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int32, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//(-F)^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)
				if i == 0 {
					//coeffs[i] = pp.reduce(int64(coeffs[i] + gammas[t][1][i] - gammas[t][0][i]))
					coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - int64(gammas[t][0][i]))
				} else if i < (pp.paramN - 1) {
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
					coeffs[i] = reduceToQc(int64(coeffs[i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
				} else { // i in [N-1, d-1]
					//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
					coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
				}
			}
			p[t][n] = &PolyNTTv2{coeffs1: coeffs}

			p[t][n+1] = &PolyNTTv2{coeffs1: gammas[t][2]}
		}
	case RpUlpTypeTrTx2:
		n := I + J
		n2 := n + 4
		//	B : d rows 2d columns
		//	m = 5
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyNTTv2, n2)

			for j := 0; j < I; j++ {
				p[t][j] = &PolyNTTv2{coeffs1: gammas[t][0]}
			}
			for j := I; j < I+J; j++ {
				p[t][j] = &PolyNTTv2{coeffs1: gammas[t][1]}
			}

			coeffs_n := make([]int32, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				coeffs_n[i] = reduceToQc(int64(-gammas[t][0][i]) + int64(-gammas[t][1][i]))
			}
			p[t][n] = &PolyNTTv2{coeffs1: coeffs_n}

			//	p[t][n+1] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][2] + B_1^T gamma[t][4])
			coeffs_np1 := make([]int32, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][0] + F_1^T[i] gamma[t][2] + B^T[i] gamma[t][4]
				coeffs_np1[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][4], pp.paramDC)
				if i == 0 {
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] + gammas[t][0][i]))
					coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) + int64(gammas[t][0][i]))
				} else if i < (pp.paramN - 1) {
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				} else { // i in [N-1, d-1]
					//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
					coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				}
			}
			p[t][n+1] = &PolyNTTv2{coeffs1: coeffs_np1}

			//	p[t][n+2] = NTT^{-1}(F^T gamma[t][1] + F_1^T gamma[t][3] + B_2^T gamma[t][4])
			coeffs_np2 := make([]int32, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][1] + F_1^T[i] gamma[t][3] + B_2^T[i] gamma[t][4]
				coeffs_np2[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramDC, pp.paramDC+i), gammas[t][4], pp.paramDC)
				if i == 0 {
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] + gammas[t][1][i]))
					coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) + int64(gammas[t][1][i]))
				} else if i < (pp.paramN - 1) {
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
					coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
				} else { // i in [N-1, d-1]
					//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
					coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
				}
			}
			p[t][n+2] = &PolyNTTv2{coeffs1: coeffs_np2}

			p[t][n+3] = &PolyNTTv2{coeffs1: gammas[t][4]}
		}
	}

	return p
}
func (pp *PublicParameterv2) intVecInnerProduct(a []int32, b []int32, vecLen int) (r int32) {
	rst := int64(0)
	for i := 0; i < vecLen; i++ {
		rst = pp.reduceInt64(rst + pp.reduceInt64(int64(a[i])*int64(b[i])))
	}

	return int32(rst)
}
func (pp *PublicParameterv2) intMatrixInnerProduct(a [][]int32, b [][]int32, rowNum int, colNum int) (r int32) {
	rst := int64(0)
	for i := 0; i < rowNum; i++ {
		for j := 0; j < colNum; j++ {
			rst = pp.reduceInt64(rst + pp.reduceInt64(int64(a[i][j])*int64(b[i][j])))
		}
	}

	return int32(rst)
}
func (pp *PublicParameterv2) expandChallenge(seed []byte) (r *Polyv2, err error) {
	// extend seed via sha3.Shake128
	ret := NewPolyv2(R_QC, pp.paramDC)
	buf := make([]byte, pp.paramDC/4)
	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err = XOF.Write(append(seed, byte('C'), byte('h')))
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}
	got, err := randomnessFromChallengeSpace(seed, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		ret.coeffs1[i] = got[i]
	}
	return ret, nil
}
