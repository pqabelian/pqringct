package pqringct

// rpulpProve generates balance proof
type RpUlpType uint8

const (
	RpUlpTypeCbTx1 RpUlpType = 0
	RpUlpTypeCbTx2 RpUlpType = 1
	RpUlpTypeTrTx1 RpUlpType = 2
	RpUlpTypeTrTx2 RpUlpType = 3
)

/**
cmt_bs []*PolyNTTVec, cmt_cs []*PolyNTT, cmt_rs []*PolyNTTVec: cmt_bs[i] = matrixB * cmt_rs[i], cmt_cs[i] =<matrixC[0], cmt_rs[i]> + (msg_hats[i])_NTT, where msg_hats[i] is viewd as a PolyNTT
h_hat *PolyNTTVec, r_hat *PolyNTTVec, c_hats []*PolyNTT
n >= 2 && n <= n1 && n1 <= n2 && n <= pp.paramI+pp.paramJ && n2 <= pp.paramI+pp.paramJ+4
*/
func (pp PublicParameter) rpulpProve(cmt_bs []*PolyNTTVec, cmt_cs []*PolyNTT, cmt_rs []*PolyNTTVec, n int,
	b_hat *PolyNTTVec, r_hat *PolyNTTVec, c_hats []*PolyNTT, msg_hats [][]int32, n2 int,
	n1 int, rpulpType RpUlpType, B [][]int32, I int, J int, m int, u_hats [][]int32) (ret_c_waves []*PolyNTT, ret_c_hat_g *PolyNTT, ret_psi *PolyNTT, ret_phi *PolyNTT, ret_ch *PolyNTT, est_cmt_zs [][]*PolyNTTVec, rest_zs []*PolyNTTVec, err error) {

	c_waves := make([]*PolyNTT, n)
	for i := 0; i < n; i++ {
		c_waves[i] = pp.PolyNTTAdd(pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], cmt_rs[i], pp.paramLc), &PolyNTT{msg_hats[i]})
	}

rpUlpProveRestart:

	cmt_ys := make([][]*PolyNTTVec, pp.paramK)
	ys := make([]*PolyNTTVec, pp.paramK)
	cmt_ws := make([][]*PolyNTTVec, pp.paramK)
	ws := make([]*PolyNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_ys[t] = make([]*PolyNTTVec, n)
		cmt_ws[t] = make([]*PolyNTTVec, n)
		for i := 0; i < n; i++ {
			cmt_ys[t][i] = pp.NTTVec(pp.sampleMaskC())
			cmt_ws[t][i] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_ys[t][i], pp.paramKc, pp.paramLc)
		}

		ys[t] = pp.NTTVec(pp.sampleMaskC())
		ws[t] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKc, pp.paramLc)
	}

	g := pp.NTT(pp.sampleUniformPloyWithLowZeros())
	c_hat_g := pp.PolyNTTAdd(pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+5], r_hat, pp.paramLc), g)

	seed1 := []byte{} // todo
	alphas, betas, gammas := pp.expandUniformRandomnessInRqZq(seed1, n1)

	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyNTT, pp.paramK)
	delta_hats := make([][]*PolyNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyNTT, n)
		delta_hats[t] = make([]*PolyNTT, n)
		for i := 0; i < n; i++ {
			delta_waves[t][i] = pp.PolyNTTVecInnerProduct(pp.PolyNTTVecSub(pp.paramMatrixC[i+1], pp.paramMatrixC[0], pp.paramLc), cmt_ys[t][i], pp.paramLc)
			delta_hats[t][i] = pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], pp.PolyNTTVecSub(ys[t], cmt_ys[t][i], pp.paramLc), pp.paramLc)
		}
	}

	//	psi, psi'
	psi := pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+6], r_hat, pp.paramLc)
	psip := pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+6], ys[0], pp.paramLc)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := NewZeroPolyNTT()
		tmp2 := NewZeroPolyNTT()

		for i := 0; i < n1; i++ {
			tmp := pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], ys[t], pp.paramLc)

			tmp1 = pp.PolyNTTAdd(
				tmp1,
				pp.PolyNTTMul(
					alphas[i],
					pp.PolyNTTMul(
						pp.PolyNTTSub(
							pp.PolyNTTAdd(&PolyNTT{msg_hats[i]}, &PolyNTT{msg_hats[i]}),
							&PolyNTT{pp.paramMu}), tmp)))

			tmp2 = pp.PolyNTTAdd(
				tmp2,
				pp.PolyNTTMul(alphas[i],
					pp.PolyNTTMul(tmp, tmp)))
		}

		psi = pp.PolyNTTSub(psi, pp.PolyNTTMul(betas[t], pp.PolyNTTSigma(tmp1, -t)))
		psip = pp.PolyNTTAdd(psip, pp.PolyNTTMul(betas[t], pp.PolyNTTSigma(tmp2, -t)))
	}

	//	p^(t)_j:
	p := make([][]*PolyNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		p[t] = make([]*PolyNTT, n2)

		for j := 0; j < n2; j++ {

			pcoeffs := []int32{0}
			// todo
			p[t][j] = &PolyNTT{coeffs: pcoeffs}
		}
	}

	//	phi
	phi := NewZeroPolyNTT()
	for t := 0; t < pp.paramK; t++ {
		tmp1 := NewZeroPolyNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := NewZeroPolyNTT()
			for j := 0; j < n2; j++ {
				tmp = pp.PolyNTTAdd(tmp, pp.PolyNTTMul(p[t][j], &PolyNTT{msg_hats[j]}))
			}

			constPoly := NewZeroPoly()
			constPoly.coeffs[0] = pp.reduce(int64(pp.intVecInnerProduct(u_hats, gammas[t], m, pp.paramD)) * int64(pp.paramDInv))

			tmp = pp.PolyNTTSub(tmp, pp.NTT(constPoly))

			tmp1 = pp.PolyNTTAdd(tmp1, pp.PolyNTTSigma(tmp, tau))
		}

		xt := NewZeroPoly()
		xt.coeffs[t] = pp.paramKInv

		phi = pp.PolyNTTMul(pp.NTT(xt), tmp1)
	}

	phi = pp.PolyNTTAdd(phi, g)

	//	phi'^(\xi)
	phips := make([]*PolyNTT, pp.paramK)
	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = NewZeroPolyNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := NewZeroPolyNTT()
			for tau := 0; tau < pp.paramK; tau++ {
				tmp := NewZeroPolyNTTVec(pp.paramLc)
				for j := 0; j < n2; j++ {
					tmp = pp.PolyNTTVecAdd(tmp, pp.PolyNTTVecScaleMul(p[t][j], pp.paramMatrixC[j+1], pp.paramLc), pp.paramKc)
				}

				tmp1 = pp.PolyNTTAdd(tmp1, pp.PolyNTTSigma(pp.PolyNTTVecInnerProduct(tmp, ys[(xi-tau)%pp.paramK], pp.paramLc), tau))

			}

			xt := NewZeroPoly()
			xt.coeffs[t] = pp.paramKInv

			phips[xi] = pp.PolyNTTAdd(phips[xi], pp.PolyNTTMul(pp.NTT(xt), tmp1))
		}

		phips[xi] = pp.PolyNTTAdd(phips[xi], pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+5], ys[xi], pp.paramLc))
	}

	//	seed_ch and ch
	seed_ch := []byte{} // todo
	ch := pp.NTT(pp.expandChallenge(seed_ch))

	// z
	cmt_zs := make([][]*PolyNTTVec, pp.paramK)
	zs := make([]*PolyNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		sigma_t_ch := pp.PolyNTTSigma(ch, t)
		for i := 0; i < n; i++ {
			cmt_zs[t][i] = pp.PolyNTTVecAdd(cmt_ys[t][i], pp.PolyNTTVecScaleMul(sigma_t_ch, cmt_rs[i], pp.paramLc), pp.paramLc)

			if pp.NTTInvVec(cmt_zs[t][i]).PolyInfNorm() > pp.paramEtaC-pp.paramBetaC {
				goto rpUlpProveRestart
			}
		}

		zs[t] = pp.PolyNTTVecAdd(ys[t], pp.PolyNTTVecScaleMul(sigma_t_ch, r_hat, pp.paramLc), pp.paramLc)

		if pp.NTTInvVec(zs[t]).PolyInfNorm() > pp.paramEtaC-pp.paramBetaC {
			goto rpUlpProveRestart
		}
	}

	return c_waves, c_hat_g, psi, phi, ch, cmt_zs, zs, nil

}

// rpulpVerify verify the proof generated by rpulpProve
func rpulpVerify() (valid bool) {
	//TODO: add inputs
	return false
}

// elrsSign genarates authorizing and authentication proof
func elrsSign() (*Signature, *Image) {
	//TODO: add inputs
	return nil, nil
}

// elrsVerify verify the authorizing and authentication proof generated by elrsSign
func elrsVerify() (valid bool) {
	// TODO: add inputs
	return false
}

/**
todo: generate MatrixA from pp.Cstr
*/
func (pp *PublicParameter) ExpandPubMatrixA() (matrixA []*PolyNTTVec) {
	matrix := make([]*PolyNTTVec, pp.paramKa)

	for i := 0; i < pp.paramKa; i++ {
		matrix[i].polyNTTs = make([]*PolyNTT, pp.paramLa)
		// todo
	}

	return matrixA
}

/**
todo: generate MatrixB from pp.Cstr
todo: store the matrices in PP or generate them each time they are generated
*/
func (pp *PublicParameter) ExpandPubMatrixB() (matrixB []*PolyNTTVec) {
	matrix := make([]*PolyNTTVec, pp.paramKc)

	for i := 0; i < pp.paramKa; i++ {
		matrix[i].polyNTTs = make([]*PolyNTT, pp.paramLc)
		// todo
	}

	return matrix
}

func (pp *PublicParameter) ExpandPubMatrixC() (matrixC []*PolyNTTVec) {
	matrix := make([]*PolyNTTVec, pp.paramI+pp.paramJ+7)

	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
		matrix[i].polyNTTs = make([]*PolyNTT, pp.paramLc)
		// todo
	}

	return matrix
}

/*
todo: expand a seed to a PolyVec with length l_a from (S_r)^d
*/
func (pp *PublicParameter) ExpandRandomnessA(seed []byte) (sp *PolyVec) {

	polys := make([]*Poly, pp.paramLa)
	//	todo
	r := &PolyVec{
		polys: polys,
	}
	return r
}

func (pp *PublicParameter) ExpandRandomnessC(seed []byte) (r *PolyVec) {

	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleRandomnessC() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleMaskC() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleUniformPloyWithLowZeros() (r *Poly) {
	rst := &Poly{} // todo

	return rst
}

func (pp PublicParameter) expandUniformRandomnessInRqZq(seed []byte, n1 int) (alphas []*PolyNTT, betas []*PolyNTT, gammas [][][]int32) {
	//	todo
	return
}

/*
todo:
*/
func (pp PublicParameter) expandChallenge(seed []byte) (r *Poly) {
	return
}

func (pp PublicParameter) PolyNTTSigma(polyNTT *PolyNTT, i int) (r *PolyNTT) {
	// todo
	return
}

/**
This method allow the vectors to be 2D, i.e. matrix
*/
func (pp PublicParameter) intVecInnerProduct(a [][]int32, b [][]int32, rowNum int, colNum int) (r int32) {
	rst := int32(0)
	for i := 0; i < rowNum; i++ {
		for j := 0; j < colNum; j++ {
			rst = pp.reduce(int64(rst) + int64(pp.reduce(int64(a[i][j])*int64(b[i][j]))))
		}
	}

	return rst
}

func intToBinary(v uint64, bitNum int) (bits []int32) {
	rstbits := make([]int32, bitNum)
	for i := 0; i < bitNum; i++ {
		rstbits[i] = int32((v >> i) & 1)
	}
	return rstbits
}

func expandBinaryMatrix(seed []byte, rownum int, colnum int) (binM [][]int32) {
	// todo: in randomness, we need a method to expandUniformBits()
	//	todo: for binaryMatrxi we may do some optimoztion, e.g. use []byte to denote the matrix directly
	//	so that for a 128*128 matrix, we just need 16*16 bytes rather than 128*128 int32's.

	return
}
