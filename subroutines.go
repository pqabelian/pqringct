package pqringct

import (
	"bytes"
)

// rpulpProve generates balance proof
type RpUlpType uint8

const (
	RpUlpTypeCbTx1 RpUlpType = 0
	RpUlpTypeCbTx2 RpUlpType = 1
	RpUlpTypeTrTx1 RpUlpType = 2
	RpUlpTypeTrTx2 RpUlpType = 3
)

/**
cmts []*Commitment, cmt_rs []*PolyNTTVec: cmt_bs[i] = matrixB * cmt_rs[i], cmt_cs[i] =<matrixC[0], cmt_rs[i]> + (msg_hats[i])_NTT, where msg_hats[i] is viewd as a PolyNTT
h_hat *PolyNTTVec, r_hat *PolyNTTVec, c_hats []*PolyNTT
n >= 2 && n <= n1 && n1 <= n2 && n <= pp.paramI+pp.paramJ && n2 <= pp.paramI+pp.paramJ+4
*/
func (pp PublicParameter) rpulpProve(cmts []*Commitment, cmt_rs []*PolyNTTVec, n int,
	b_hat *PolyNTTVec, r_hat *PolyNTTVec, c_hats []*PolyNTT, msg_hats [][]int32, n2 int,
	n1 int, rpulpType RpUlpType, B [][]int32, I int, J int, m int, u_hats [][]int32) (rpulppi *rpulpProof, err error) {

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
							pp.PolyNTTAdd(
								&PolyNTT{msg_hats[i]},
								&PolyNTT{msg_hats[i]}),
							&PolyNTT{pp.paramMu}),
						tmp)))

			tmp2 = pp.PolyNTTAdd(
				tmp2,
				pp.PolyNTTMul(alphas[i],
					pp.PolyNTTMul(tmp, tmp)))
		}

		psi = pp.PolyNTTSub(psi, pp.PolyNTTMul(betas[t], pp.sigmaInvPolyNTT(tmp1, t)))
		psip = pp.PolyNTTAdd(psip, pp.PolyNTTMul(betas[t], pp.sigmaInvPolyNTT(tmp2, t)))
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

			tmp1 = pp.PolyNTTAdd(tmp1, pp.sigmaPowerPolyNTT(tmp, tau))
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
					pp.sigmaPowerPolyNTT(
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
		sigma_t_ch := pp.sigmaPowerPolyNTT(ch, t)
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

	retrpulppi := &rpulpProof{
		c_waves: c_waves,
		c_hat_g: c_hat_g,
		psi:     psi,
		phi:     phi,
		chseed:  chseed,
		cmt_zs:  cmt_zs,
		zs:      zs,
	}

	return retrpulppi, nil
}

func (pp PublicParameter) rpulpVerify(cmts []*Commitment, n int,
	b_hat *PolyNTTVec, c_hats []*PolyNTT, n2 int,
	n1 int, rpulpType RpUlpType, B [][]int32, I int, J int, m int, u_hats [][]int32,
	rpulppi *rpulpProof) (valid bool) {

	if !(n >= 2 && n <= n1 && n1 <= n2 && n <= pp.paramI+pp.paramJ && n2 <= pp.paramI+pp.paramJ+4) {
		return false
	}

	if len(cmts) != n {
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
	if rpulppi == nil {
		return false
	}
	if len(rpulppi.c_waves) != n {
		return false
	}

	if rpulppi.c_hat_g == nil || rpulppi.psi == nil || rpulppi.phi == nil || rpulppi.chseed == nil {
		return false
	}

	if rpulppi.cmt_zs == nil || len(rpulppi.cmt_zs) != pp.paramK || rpulppi.zs == nil || len(rpulppi.zs) != pp.paramK {
		return false
	}

	for t := 0; t < pp.paramK; t++ {
		if rpulppi.cmt_zs[t] == nil || len(rpulppi.cmt_zs[t]) != n {
			return false
		}
	}

	//	(phi_t[0] ... phi_t[k-1] = 0)
	phiPoly := pp.NTTInv(rpulppi.phi)
	for t := 0; t < pp.paramK; t++ {
		if phiPoly.coeffs[t] != 0 {
			return false
		}
	}

	// infNorm of z^t_i and z^t
	for t := 0; t < pp.paramK; t++ {

		for i := 0; i < n; i++ {
			if pp.NTTInvVec(rpulppi.cmt_zs[t][i]).infNorm() > pp.paramEtaC-pp.paramBetaC {
				return false
			}
		}

		if pp.NTTInvVec(rpulppi.zs[t]).infNorm() > pp.paramEtaC-pp.paramBetaC {
			return false
		}

	}

	ch := pp.NTT(pp.expandChallenge(rpulppi.chseed))

	sigma_chs := make([]*PolyNTT, pp.paramK)
	//	w^t_i, w_t
	cmt_ws := make([][]*PolyNTTVec, pp.paramK)
	ws := make([]*PolyNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		sigma_chs[t] = pp.sigmaPowerPolyNTT(ch, t)

		cmt_ws[t] = make([]*PolyNTTVec, n)
		for i := 0; i < n; i++ {
			cmt_ws[t][i] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(pp.paramMatrixB, rpulppi.cmt_zs[t][i], pp.paramKc, pp.paramLc),
				pp.PolyNTTVecScaleMul(sigma_chs[t], cmts[i].b, pp.paramKc),
				pp.paramKc)
		}
		ws[t] = pp.PolyNTTVecSub(
			pp.PolyNTTMatrixMulVector(pp.paramMatrixB, rpulppi.zs[t], pp.paramKc, pp.paramLc),
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
					rpulppi.cmt_zs[t][i],
					pp.paramLc),
				pp.PolyNTTMul(sigma_chs[t], pp.PolyNTTSub(rpulppi.c_waves[i], cmts[i].c)))

			delta_hats[t][i] = pp.PolyNTTSub(
				pp.PolyNTTVecInnerProduct(
					pp.paramMatrixC[i+1],
					pp.PolyNTTVecSub(rpulppi.zs[t], rpulppi.cmt_zs[t][i], pp.paramLc),
					pp.paramLc),
				pp.PolyNTTMul(sigma_chs[t], pp.PolyNTTSub(c_hats[i], rpulppi.c_waves[i])))
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
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], rpulppi.zs[t], pp.paramLc),
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
		tmp1 = pp.sigmaInvPolyNTT(tmp1, t)
		tmp1 = pp.PolyNTTMul(betas[t], tmp1)

		psip = pp.PolyNTTAdd(psip, tmp1)
	}

	psip = pp.PolyNTTSub(psip, pp.PolyNTTMul(ch, rpulppi.psi))
	psip = pp.PolyNTTAdd(psip,
		pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+6], rpulppi.zs[0], pp.paramLc))

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

			tmp1 = pp.PolyNTTAdd(tmp1, pp.sigmaPowerPolyNTT(tmp, tau))
		}

		xt := pp.NewZeroPoly()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)

		phip = pp.PolyNTTAdd(phip, tmp1)
	}

	//	phi'^(\xi)
	phips := make([]*PolyNTT, pp.paramK)
	constterm := pp.PolyNTTSub(pp.PolyNTTAdd(phip, rpulppi.c_hat_g), rpulppi.phi)

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
					pp.sigmaPowerPolyNTT(
						pp.PolyNTTVecInnerProduct(tmp, rpulppi.zs[(xi-tau)%pp.paramK], pp.paramLc),
						tau))
			}

			xt := pp.NewZeroPoly()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)

			phips[xi] = pp.PolyNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyNTTAdd(
			phips[xi],
			pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+5], rpulppi.zs[xi], pp.paramLc))

		phips[xi] = pp.PolyNTTSub(
			phips[xi],
			pp.PolyNTTMul(sigma_chs[xi], constterm))
	}

	//	seed_ch and ch
	seed_ch := []byte{} // todo
	if bytes.Compare(seed_ch, rpulppi.chseed) != 0 {
		return false
	}

	return true
}

// elrsSign genarates authorizing and authentication proof
func (pp PublicParameter) elrsSign(t_as []*PolyNTTVec, t_cs []*PolyNTTVec, msg []byte, sidx int, s_a *PolyNTTVec, s_c *PolyNTTVec) (elrssig *elrsSignature, err error) {
	//	check the well-formness of inputs
	if t_as == nil || t_cs == nil || msg == nil || s_a == nil || s_c == nil {
		return nil, nil // todo: error
	}

	if len(t_as) == 0 || len(t_cs) == 0 || len(msg) == 0 {
		return nil, nil // todo: error
	}

	if len(t_as) != len(t_cs) {
		return nil, nil // todo: error
	}

	ringSize := len(t_as)

	if sidx < 0 || sidx >= ringSize {
		return nil, nil // todo: error
	}

	for j := 0; j < ringSize; j++ {
		if len(t_as[j].polyNTTs) != pp.paramKa {
			return nil, nil // todo: error
		}
		if len(t_cs[j].polyNTTs) != pp.paramKc+1 {
			return nil, nil // todo: error
		}
	}

	if len(s_a.polyNTTs) != pp.paramLa || len(s_c.polyNTTs) != pp.paramLc {
		return nil, nil // todo: error
	}

	if pp.NTTInvVec(s_a).infNorm() > 2 {
		return nil, nil // todo: error
	}
	if pp.NTTInvVec(s_c).infNorm() > 2 {
		return nil, nil // todo: error
	}

	if pp.PolyNTTVecEqualCheck(t_as[sidx], pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s_a, pp.paramKa, pp.paramLa)) != true {
		return nil, nil // todo: error
	}

	matrixBExt := make([]*PolyNTTVec, pp.paramKc+1)
	for i := 0; i < pp.paramKc; i++ {
		matrixBExt[i] = pp.paramMatrixB[i]
	}
	matrixBExt[pp.paramKc] = pp.paramMatrixC[0]

	if pp.PolyNTTVecEqualCheck(t_cs[sidx], pp.PolyNTTMatrixMulVector(matrixBExt, s_c, pp.paramKc+1, pp.paramLc)) != true {
		return nil, nil // todo: error
	}

	//	keyImgMatrices
	imgMatrixs := make([][]*PolyNTTVec, ringSize)
	for j := 0; j < ringSize; j++ {
		imgMatrixs[j] = pp.expandKeyImgMatrix(t_as[j])
	}

	//	keyImage I
	retkeyImg := pp.PolyNTTMatrixMulVector(imgMatrixs[sidx], s_a, pp.paramMa, pp.paramLa)

	retz_as := make([][]*PolyNTTVec, pp.paramK)
	retz_cs := make([][]*PolyNTTVec, pp.paramK)
	for j := 0; j < ringSize; j++ {
		retz_as[j] = make([]*PolyNTTVec, pp.paramLa)
		retz_cs[j] = make([]*PolyNTTVec, pp.paramLc)
	}
	var retchseed []byte

	y_as := make([]*PolyNTTVec, pp.paramK)
	y_cs := make([]*PolyNTTVec, pp.paramK)

	w_as := make([]*PolyNTTVec, pp.paramK)
	w_cs := make([]*PolyNTTVec, pp.paramK)
	w_hat_as := make([]*PolyNTTVec, pp.paramK)

elrsSignRestart:

	for tau := 0; tau < pp.paramK; tau++ {
		y_as[tau] = pp.NTTVec(pp.sampleMaskA())
		y_cs[tau] = pp.NTTVec(pp.sampleMaskC2())

		w_as[tau] = pp.PolyNTTMatrixMulVector(pp.paramMatrixA, y_as[tau], pp.paramKa, pp.paramLa)
		w_cs[tau] = pp.PolyNTTMatrixMulVector(matrixBExt, y_cs[tau], pp.paramKc+1, pp.paramLc)
		w_hat_as[tau] = pp.PolyNTTMatrixMulVector(imgMatrixs[sidx], y_as[tau], pp.paramMa, pp.paramLa)
	}

	var seedj []byte
	var chj *PolyNTT
	var sigma_tau_ch *PolyNTT

	for j := (sidx + 1) % ringSize; ; {
		seedj = []byte{} // todo
		chj = pp.NTT(pp.expandChallenge(seedj))

		for tau := 0; tau < pp.paramK; tau++ {
			retz_as[tau][j] = pp.NTTVec(pp.sampleZetaA())
			retz_cs[tau][j] = pp.NTTVec(pp.sampleZetaC2())

			sigma_tau_ch = pp.sigmaPowerPolyNTT(chj, tau)

			w_as[tau] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(pp.paramMatrixA, retz_as[tau][j], pp.paramKa, pp.paramLa),
				pp.PolyNTTVecScaleMul(sigma_tau_ch, t_as[j], pp.paramKa),
				pp.paramKa)

			w_cs[tau] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(matrixBExt, retz_cs[tau][j], pp.paramKc+1, pp.paramLc),
				pp.PolyNTTVecScaleMul(sigma_tau_ch, t_cs[j], pp.paramKc+1),
				pp.paramKc+1)

			w_hat_as[tau] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(imgMatrixs[j], retz_as[tau][j], pp.paramMa, pp.paramLa),
				pp.PolyNTTVecScaleMul(sigma_tau_ch, retkeyImg, pp.paramMa),
				pp.paramMa)
		}

		if j == 0 {
			retchseed = seedj
		}

		j = (j + 1) % ringSize
		if j == sidx {
			break
		}
	}

	seedj = []byte{} // todo
	chj = pp.NTT(pp.expandChallenge(seedj))

	for tau := 0; tau < pp.paramK; tau++ {
		sigma_tau_ch = pp.sigmaPowerPolyNTT(chj, tau)

		retz_as[tau][sidx] = pp.PolyNTTVecAdd(y_as[tau], pp.PolyNTTVecScaleMul(sigma_tau_ch, s_a, pp.paramLa), pp.paramLa)
		if pp.NTTInvVec(retz_as[tau][sidx]).infNorm() > pp.paramEtaA-pp.paramBetaA {
			goto elrsSignRestart
		}

		retz_cs[tau][sidx] = pp.PolyNTTVecAdd(y_cs[tau], pp.PolyNTTVecScaleMul(sigma_tau_ch, s_c, pp.paramLc), pp.paramLc)
		if pp.NTTInvVec(retz_cs[tau][sidx]).infNorm() > pp.paramEtaC2-pp.paramBetaC2 {
			goto elrsSignRestart
		}
	}

	retelrssig := &elrsSignature{
		retchseed,
		retz_as,
		retz_cs,
		retkeyImg}
	return retelrssig, nil
}

// elrsVerify verify the authorizing and authentication proof generated by elrsSign
func (pp *PublicParameter) elrsVerify(t_as []*PolyNTTVec, t_cs []*PolyNTTVec, msg []byte, elrssig *elrsSignature) (valid bool) {
	//	check the well-formness of inputs
	if t_as == nil || t_cs == nil || msg == nil {
		return false
	}

	if len(t_as) == 0 || len(t_cs) == 0 || len(msg) == 0 {
		return false
	}

	if len(t_as) != len(t_cs) {
		return false
	}

	ringSize := len(t_as)

	for j := 0; j < ringSize; j++ {
		if len(t_as[j].polyNTTs) != pp.paramKa {
			return false
		}
		if len(t_cs[j].polyNTTs) != pp.paramKc+1 {
			return false
		}
	}

	if elrssig.chseed == nil || elrssig.z_as == nil || elrssig.z_cs == nil || elrssig.keyImg == nil {
		return false
	}
	if len(elrssig.z_as) != pp.paramK || len(elrssig.z_cs) != pp.paramK {
		return false
	}

	for tau := 0; tau < pp.paramK; tau++ {
		if len(elrssig.z_as[tau]) != ringSize || len(elrssig.z_cs[tau]) != ringSize {
			return false
		}
	}

	for tau := 0; tau < pp.paramK; tau++ {
		for j := 0; j < ringSize; j++ {
			if pp.NTTInvVec(elrssig.z_as[tau][j]).infNorm() > pp.paramEtaA-pp.paramBetaA {
				return false
			}

			if pp.NTTInvVec(elrssig.z_cs[tau][j]).infNorm() > pp.paramEtaC2-pp.paramBetaC2 {
				return false
			}
		}
	}

	matrixBExt := make([]*PolyNTTVec, pp.paramKc+1)
	for i := 0; i < pp.paramKc; i++ {
		matrixBExt[i] = pp.paramMatrixB[i]
	}
	matrixBExt[pp.paramKc] = pp.paramMatrixC[0]

	w_as := make([]*PolyNTTVec, pp.paramK)
	w_cs := make([]*PolyNTTVec, pp.paramK)
	w_hat_as := make([]*PolyNTTVec, pp.paramK)

	seedj := elrssig.chseed

	for j := 0; j < ringSize; j++ {
		chj := pp.NTT(pp.expandChallenge(seedj))

		imgMatrix := pp.expandKeyImgMatrix(t_as[j])

		for tau := 0; tau < pp.paramK; tau++ {
			sigma_tau_ch := pp.sigmaPowerPolyNTT(chj, tau)

			w_as[tau] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(pp.paramMatrixA, elrssig.z_as[tau][j], pp.paramKa, pp.paramLa),
				pp.PolyNTTVecScaleMul(sigma_tau_ch, t_as[j], pp.paramKa),
				pp.paramKa)

			w_cs[tau] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(matrixBExt, elrssig.z_cs[tau][j], pp.paramKc+1, pp.paramLc),
				pp.PolyNTTVecScaleMul(sigma_tau_ch, t_cs[j], pp.paramKc+1),
				pp.paramKc+1)

			w_hat_as[tau] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(imgMatrix, elrssig.z_as[tau][j], pp.paramMa, pp.paramLa),
				pp.PolyNTTVecScaleMul(sigma_tau_ch, elrssig.keyImg, pp.paramMa),
				pp.paramMa)
		}
		seedj = []byte{} // todo
	}

	if bytes.Compare(elrssig.chseed, seedj) != 0 {
		return false
	}

	return true
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

func (pp PublicParameter) expandKeyImgMatrix(t *PolyNTTVec) (matrixH []*PolyNTTVec) {
	matrix := make([]*PolyNTTVec, pp.paramMa)
	// todo

	return matrix
}

func (pp *PublicParameter) sampleRandomnessA() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLa)
	//	todo
	retr := &PolyVec{
		polys: polys,
	}
	return retr
}

/*
todo: expand a seed to a PolyVec with length l_a from (S_r)^d
*/
func (pp *PublicParameter) expandRandomnessA(seed []byte) (r *PolyVec) {

	polys := make([]*Poly, pp.paramLa)
	//	todo
	retr := &PolyVec{
		polys: polys,
	}
	return retr
}

func (pp *PublicParameter) sampleRandomnessC() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp *PublicParameter) expandRandomnessC(seed []byte) (r *PolyVec) {

	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleMaskA() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLa)
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

func (pp PublicParameter) sampleMaskC2() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleZetaA() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLa)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleZetaC() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleZetaC2() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp *PublicParameter) expandRandomBitsV(seed []byte) (r []byte) {

	// todo
	return
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
func (pp *PublicParameter) expandChallenge(seed []byte) (r *Poly) {
	return
}

/*
todo:
*/
/*func (pp *PublicParameter) sigmaPolyNTT(polyNTT *PolyNTT) (r *PolyNTT) {
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = polyNTT.coeffs[pp.paramSigmaPermutation[i]]
	}
	return &PolyNTT{coeffs}
}*/

/*
 t: 0~(d-1)
*/
func (pp *PublicParameter) sigmaPowerPolyNTT(polyNTT *PolyNTT, t int) (r *PolyNTT) {
	nttPower := pp.PolyNTTPower(polyNTT, uint(t))
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = nttPower.coeffs[pp.paramSigmaPermutations[t][i]]
	}
	return &PolyNTT{coeffs}
}

/*
todo:
*/
func (pp *PublicParameter) sigmaInvPolyNTT(polyNTT *PolyNTT, t int) (r *PolyNTT) {
	nttPower := pp.PolyNTTPower(polyNTT, uint(t))
	coeffs := make([]int32, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		coeffs[i] = nttPower.coeffs[pp.paramSigmaInvPermutations[t][i]]
	}
	return &PolyNTT{coeffs}
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

func (cmt *Commitment) toPolyNTTVec() *PolyNTTVec {
	ret := &PolyNTTVec{}
	ret.polyNTTs = make([]*PolyNTT, len(cmt.b.polyNTTs)+1)
	copy(ret.polyNTTs, cmt.b.polyNTTs)
	ret.polyNTTs[len(cmt.b.polyNTTs)] = cmt.c

	return ret
}
