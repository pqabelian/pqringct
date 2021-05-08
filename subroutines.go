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
	n1 int, rpulpType RpUlpType, B [][]int32, I int, J int, m int, u_hats [][]int32) (ret_c_waves []*PolyNTT, ret_c_hat_g *PolyNTT, ret_psi *PolyNTT, ret_phi *PolyNTT, ret_chseed []byte, ret_cmt_zs [][]*PolyNTTVec, ret_zs []*PolyNTTVec, err error) {

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

	seed_rand := []byte{} // todo
	alphas, betas, gammas := pp.expandUniformRandomnessInRqZq(seed_rand, n1, m)

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
		tmp1 := pp.NewZeroPolyNTT()
		tmp2 := pp.NewZeroPolyNTT()

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

		psi = pp.PolyNTTSub(psi, pp.PolyNTTMul(betas[t], pp.sigmaPolyNTT(tmp1, -t)))
		psip = pp.PolyNTTAdd(psip, pp.PolyNTTMul(betas[t], pp.sigmaPolyNTT(tmp2, -t)))
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
	phi := pp.NewZeroPolyNTT()
	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyNTT()
			for j := 0; j < n2; j++ {
				tmp = pp.PolyNTTAdd(tmp, pp.PolyNTTMul(p[t][j], &PolyNTT{msg_hats[j]}))
			}

			constPoly := pp.NewZeroPoly()
			constPoly.coeffs[0] = pp.reduce(int64(pp.intVecInnerProduct(u_hats, gammas[t], m, pp.paramD)) * int64(pp.paramDInv))

			tmp = pp.PolyNTTSub(tmp, pp.NTT(constPoly))

			tmp1 = pp.PolyNTTAdd(tmp1, pp.sigmaPolyNTT(tmp, tau))
		}

		xt := pp.NewZeroPoly()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)

		phi = pp.PolyNTTAdd(phi, tmp1)
	}

	phi = pp.PolyNTTAdd(phi, g)

	//	phi'^(\xi)
	phips := make([]*PolyNTT, pp.paramK)
	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyNTT()
			for tau := 0; tau < pp.paramK; tau++ {
				tmp := pp.NewZeroPolyNTTVec(pp.paramLc)
				for j := 0; j < n2; j++ {
					tmp = pp.PolyNTTVecAdd(tmp, pp.PolyNTTVecScaleMul(p[t][j], pp.paramMatrixC[j+1], pp.paramLc), pp.paramKc)
				}

				tmp1 = pp.PolyNTTAdd(
					tmp1,
					pp.sigmaPolyNTT(
						pp.PolyNTTVecInnerProduct(tmp, ys[(xi-tau)%pp.paramK], pp.paramLc),
						tau))
			}

			xt := pp.NewZeroPoly()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)

			phips[xi] = pp.PolyNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyNTTAdd(
			phips[xi],
			pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+5], ys[xi], pp.paramLc))
	}

	//	seed_ch and ch
	chseed := []byte{} // todo
	ch := pp.NTT(pp.expandChallenge(chseed))

	// z
	cmt_zs := make([][]*PolyNTTVec, pp.paramK)
	zs := make([]*PolyNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		sigma_t_ch := pp.sigmaPolyNTT(ch, t)
		for i := 0; i < n; i++ {
			cmt_zs[t][i] = pp.PolyNTTVecAdd(
				cmt_ys[t][i],
				pp.PolyNTTVecScaleMul(sigma_t_ch, cmt_rs[i], pp.paramLc),
				pp.paramLc)

			if pp.NTTInvVec(cmt_zs[t][i]).infNorm() > pp.paramEtaC-pp.paramBetaC {
				goto rpUlpProveRestart
			}
		}

		zs[t] = pp.PolyNTTVecAdd(ys[t], pp.PolyNTTVecScaleMul(sigma_t_ch, r_hat, pp.paramLc), pp.paramLc)

		if pp.NTTInvVec(zs[t]).infNorm() > pp.paramEtaC-pp.paramBetaC {
			goto rpUlpProveRestart
		}
	}

	return c_waves, c_hat_g, psi, phi, chseed, cmt_zs, zs, nil
}

func (pp PublicParameter) rpulpVerify(cmt_bs []*PolyNTTVec, cmt_cs []*PolyNTT, n int,
	b_hat *PolyNTTVec, c_hats []*PolyNTT, n2 int,
	n1 int, rpulpType RpUlpType, B [][]int32, I int, J int, m int, u_hats [][]int32,
	c_waves []*PolyNTT, c_hat_g *PolyNTT, psi *PolyNTT, phi *PolyNTT, chseed []byte, cmt_zs [][]*PolyNTTVec, zs []*PolyNTTVec) (valid bool) {

	if !(n >= 2 && n <= n1 && n1 <= n2 && n <= pp.paramI+pp.paramJ && n2 <= pp.paramI+pp.paramJ+4) {
		return false
	}

	if len(cmt_bs) != n || len(cmt_cs) != n {
		return false
	}

	if b_hat == nil {
		return false
	}

	if len(c_hats) != n2 {
		return false
	}

	// todo
	// check the matrix and u_hats

	// todo
	// check the well-formness of the \pi
	if len(c_waves) != n {
		return false
	}

	if c_hat_g == nil || psi == nil || phi == nil || chseed == nil {
		return false
	}

	if cmt_zs == nil || len(cmt_zs) != pp.paramK || zs == nil || len(zs) != pp.paramK {
		return false
	}

	for t := 0; t < pp.paramK; t++ {
		if cmt_zs[t] == nil || len(cmt_zs[t]) != n {
			return false
		}
	}

	//	(phi_t[0] ... phi_t[k-1] = 0)
	phiPoly := pp.NTTInv(phi)
	for t := 0; t < pp.paramK; t++ {
		if phiPoly.coeffs[t] != 0 {
			return false
		}
	}

	// infNorm of z^t_i and z^t
	for t := 0; t < pp.paramK; t++ {

		for i := 0; i < n; i++ {
			if pp.NTTInvVec(cmt_zs[t][i]).infNorm() > pp.paramEtaC-pp.paramBetaC {
				return false
			}
		}

		if pp.NTTInvVec(zs[t]).infNorm() > pp.paramEtaC-pp.paramBetaC {
			return false
		}

	}

	ch := pp.NTT(pp.expandChallenge(chseed))

	sigma_chs := make([]*PolyNTT, pp.paramK)
	//	w^t_i, w_t
	cmt_ws := make([][]*PolyNTTVec, pp.paramK)
	ws := make([]*PolyNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		sigma_chs[t] = pp.sigmaPolyNTT(ch, t)

		cmt_ws[t] = make([]*PolyNTTVec, n)
		for i := 0; i < n; i++ {
			cmt_ws[t][i] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_zs[t][i], pp.paramKc, pp.paramLc),
				pp.PolyNTTVecScaleMul(sigma_chs[t], cmt_bs[i], pp.paramKc),
				pp.paramKc)
		}
		ws[t] = pp.PolyNTTVecSub(
			pp.PolyNTTMatrixMulVector(pp.paramMatrixB, zs[t], pp.paramKc, pp.paramLc),
			pp.PolyNTTVecScaleMul(sigma_chs[t], b_hat, pp.paramKc),
			pp.paramKc)
	}

	seed_rand := []byte{} // todo
	alphas, betas, gammas := pp.expandUniformRandomnessInRqZq(seed_rand, n1, m)

	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyNTT, pp.paramK)
	delta_hats := make([][]*PolyNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyNTT, n)
		delta_hats[t] = make([]*PolyNTT, n)

		for i := 0; i < n; i++ {
			delta_waves[t][i] = pp.PolyNTTSub(
				pp.PolyNTTVecInnerProduct(
					pp.PolyNTTVecSub(pp.paramMatrixC[i+1], pp.paramMatrixC[0], pp.paramLc),
					cmt_zs[t][i],
					pp.paramLc),
				pp.PolyNTTMul(sigma_chs[t], pp.PolyNTTSub(c_waves[i], cmt_cs[i])))

			delta_hats[t][i] = pp.PolyNTTSub(
				pp.PolyNTTVecInnerProduct(
					pp.paramMatrixC[i+1],
					pp.PolyNTTVecSub(zs[t], cmt_zs[t][i], pp.paramLc),
					pp.paramLc),
				pp.PolyNTTMul(sigma_chs[t], pp.PolyNTTSub(c_hats[i], c_waves[i])))
		}
	}

	// psi'
	psip := pp.NewZeroPolyNTT()
	mu := &PolyNTT{pp.paramMu}
	for t := 0; t < pp.paramK; t++ {

		tmp1 := pp.NewZeroPolyNTT()
		tmp2 := pp.NewZeroPolyNTT()
		for i := 0; i < n1; i++ {
			f_t_i := pp.PolyNTTSub(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], zs[t], pp.paramLc),
				pp.PolyNTTMul(sigma_chs[t], c_hats[i]))

			tmp := pp.PolyNTTMul(alphas[i], f_t_i)

			tmp1 = pp.PolyNTTAdd(
				tmp1,
				pp.PolyNTTMul(tmp, f_t_i))

			tmp2 = pp.PolyNTTAdd(
				tmp2,
				tmp)
		}
		tmp2 = pp.PolyNTTMul(tmp2, mu)
		tmp2 = pp.PolyNTTMul(tmp2, sigma_chs[t])

		tmp1 = pp.PolyNTTAdd(tmp1, tmp2)
		tmp1 = pp.sigmaPolyNTT(tmp1, -t)
		tmp1 = pp.PolyNTTMul(betas[t], tmp1)

		psip = pp.PolyNTTAdd(psip, tmp1)
	}

	psip = pp.PolyNTTSub(psip, pp.PolyNTTMul(ch, psi))
	psip = pp.PolyNTTAdd(psip,
		pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+6], zs[0], pp.paramLc))

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

	//	phip
	phip := pp.NewZeroPolyNTT()
	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyNTT()
			for j := 0; j < n2; j++ {
				tmp = pp.PolyNTTAdd(tmp, pp.PolyNTTMul(p[t][j], c_hats[j]))
			}

			constPoly := pp.NewZeroPoly()
			constPoly.coeffs[0] = pp.reduce(int64(pp.intVecInnerProduct(u_hats, gammas[t], m, pp.paramD)) * int64(pp.paramDInv))

			tmp = pp.PolyNTTSub(tmp, pp.NTT(constPoly))

			tmp1 = pp.PolyNTTAdd(tmp1, pp.sigmaPolyNTT(tmp, tau))
		}

		xt := pp.NewZeroPoly()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)

		phip = pp.PolyNTTAdd(phip, tmp1)
	}

	//	phi'^(\xi)
	phips := make([]*PolyNTT, pp.paramK)
	constterm := pp.PolyNTTSub(pp.PolyNTTAdd(phip, c_hat_g), phi)

	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyNTT()
			for tau := 0; tau < pp.paramK; tau++ {
				tmp := pp.NewZeroPolyNTTVec(pp.paramLc)
				for j := 0; j < n2; j++ {
					tmp = pp.PolyNTTVecAdd(
						tmp,
						pp.PolyNTTVecScaleMul(p[t][j], pp.paramMatrixC[j+1], pp.paramLc),
						pp.paramKc)
				}

				tmp1 = pp.PolyNTTAdd(
					tmp1,
					pp.sigmaPolyNTT(
						pp.PolyNTTVecInnerProduct(tmp, zs[(xi-tau)%pp.paramK], pp.paramLc),
						tau))
			}

			xt := pp.NewZeroPoly()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)

			phips[xi] = pp.PolyNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyNTTAdd(
			phips[xi],
			pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+5], zs[xi], pp.paramLc))

		phips[xi] = pp.PolyNTTSub(
			phips[xi],
			pp.PolyNTTMul(sigma_chs[xi], constterm))
	}

	//	seed_ch and ch
	//	seed_ch := []byte{} // todo
	// todo If seed_ch != chseed , return false.

	return true
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
func (pp *PublicParameter) expandPubMatrixA() (matrixA []*PolyNTTVec) {
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
func (pp *PublicParameter) expandPubMatrixB() (matrixB []*PolyNTTVec) {
	matrix := make([]*PolyNTTVec, pp.paramKc)

	for i := 0; i < pp.paramKa; i++ {
		matrix[i].polyNTTs = make([]*PolyNTT, pp.paramLc)
		// todo
	}

	return matrix
}

func (pp *PublicParameter) expandPubMatrixC() (matrixC []*PolyNTTVec) {
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
func (pp *PublicParameter) expandRandomnessA(seed []byte) (sp *PolyVec) {

	polys := make([]*Poly, pp.paramLa)
	//	todo
	r := &PolyVec{
		polys: polys,
	}
	return r
}

func (pp *PublicParameter) expandRandomnessC(seed []byte) (r *PolyVec) {

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

func (pp PublicParameter) expandUniformRandomnessInRqZq(seed []byte, n1 int, m int) (alphas []*PolyNTT, betas []*PolyNTT, gammas [][][]int32) {
	//	todo
	return
}

/*
todo:
*/
func (pp PublicParameter) expandChallenge(seed []byte) (r *Poly) {
	return
}

func (pp PublicParameter) sigmaPolyNTT(polyNTT *PolyNTT, i int) (r *PolyNTT) {
	// todo
	return
}

/**
This method allow the vectors to be 2D, i.e. matrix
*/
func (pp *PublicParameter) intVecInnerProduct(a [][]int32, b [][]int32, rowNum int, colNum int) (r int32) {
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
