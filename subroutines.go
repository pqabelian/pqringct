package pqringct

import (
	"bytes"
	"golang.org/x/crypto/sha3"
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
	n1 int, rpulpType RpUlpType, binMatrixB [][]int32, I int, J int, m int, u_hats [][]int32) (rpulppi *rpulpProof, err error) {

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
			maskC, err := pp.sampleMaskC()
			if err != nil {
				return nil, err
			}
			cmt_ys[t][i] = pp.NTTVec(maskC)
			cmt_ws[t][i] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_ys[t][i], pp.paramKc, pp.paramLc)
		}

		maskC, err := pp.sampleMaskC()
		if err != nil {
			return nil, err
		}
		ys[t] = pp.NTTVec(maskC)
		ws[t] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKc, pp.paramLc)
	}

	g := pp.NTT(pp.sampleUniformPloyWithLowZeros())
	c_hat_g := pp.PolyNTTAdd(pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+5], r_hat, pp.paramLc), g)

	// splicing the data to be processed
	tmp := make([]byte, 0,
		(pp.paramKc*pp.paramD*4+pp.paramD*4)*n+pp.paramKc*pp.paramD*4+pp.paramD*4*n2+4+m*pp.paramD*n2*pp.paramD*4+m*pp.paramD*4+pp.paramD*4*n+(pp.paramKc*pp.paramD*4)*n*pp.paramK+(pp.paramKc*pp.paramD*4)*pp.paramK+pp.paramD*4+
			pp.paramD*4*(n*pp.paramK*2+3+pp.paramK))
	appendPolyNTTToBytes := func(a *PolyNTT) {
		for k := 0; k < pp.paramD; k++ {
			tmp = append(tmp, byte(a.coeffs[k]>>0))
			tmp = append(tmp, byte(a.coeffs[k]>>8))
			tmp = append(tmp, byte(a.coeffs[k]>>16))
			tmp = append(tmp, byte(a.coeffs[k]>>24))
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
	for i := 0; i < pp.paramKc; i++ {
		appendPolyNTTToBytes(b_hat.polyNTTs[i])
	}
	// c_i_hat
	for i := 0; i < n2; i++ {
		appendPolyNTTToBytes(c_hats[i])
	}
	// n1
	appendInt32ToBytes(int32(n1))
	//TODO:A
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
	appendPolyNTTToBytes(c_hats[n2+1])

	seed_rand, err := H(tmp[:]) // todo
	if err != nil {
		return nil, err
	}
	alphas, betas, gammas, err := pp.expandUniformRandomnessInRqZq(seed_rand, n1, m)
	if err != nil {
		return nil, err
	}

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
	p := pp.genUlpPolyNTTs(rpulpType, binMatrixB, I, J, gammas)

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
			constPoly.coeffs[0] = pp.reduce(int64(pp.intMatrixInnerProduct(u_hats, gammas[t], m, pp.paramD)) * int64(pp.paramDInv))

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

	chseed, err := H(tmp) // todo
	if err != nil {
		return nil, err
	}
	ctmp, err := pp.expandChallenge(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTT(ctmp)

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
	n1 int, rpulpType RpUlpType, binMatrixB [][]int32, I int, J int, m int, u_hats [][]int32,
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
	chmp, _ := pp.expandChallenge(rpulppi.chseed) // TODO:hanle the err
	ch := pp.NTT(chmp)

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
	alphas, betas, gammas,_ := pp.expandUniformRandomnessInRqZq(seed_rand, n1, m) //TODO:handle the err

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
	p := pp.genUlpPolyNTTs(rpulpType, binMatrixB, I, J, gammas)

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
			constPoly.coeffs[0] = pp.reduce(int64(pp.intMatrixInnerProduct(u_hats, gammas[t], m, pp.paramD)) * int64(pp.paramDInv))

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
		imgMatrixs[j], err = pp.expandKeyImgMatrix(t_as[j])
		if err != nil {
			return nil, err
		}
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
		maskA, err := pp.sampleMaskA()
		if err != nil {
			return nil, err
		}
		y_as[tau] = pp.NTTVec(maskA)
		maskC2, err := pp.sampleMaskC2()
		if err != nil {
			return nil, err
		}
		y_cs[tau] = pp.NTTVec(maskC2)

		w_as[tau] = pp.PolyNTTMatrixMulVector(pp.paramMatrixA, y_as[tau], pp.paramKa, pp.paramLa)
		w_cs[tau] = pp.PolyNTTMatrixMulVector(matrixBExt, y_cs[tau], pp.paramKc+1, pp.paramLc)
		w_hat_as[tau] = pp.PolyNTTMatrixMulVector(imgMatrixs[sidx], y_as[tau], pp.paramMa, pp.paramLa)
	}

	var seedj []byte
	var chj *PolyNTT
	var sigma_tau_ch *PolyNTT

	for j := (sidx + 1) % ringSize; ; {
		seedj = []byte{} // todo
		chtmm,_:=pp.expandChallenge(seedj) //TODO:handle the err
		chj = pp.NTT(chtmm)

		for tau := 0; tau < pp.paramK; tau++ {
			zetaA, err := pp.sampleZetaA()
			if err != nil {
				return nil, err
			}
			retz_as[tau][j] = pp.NTTVec(zetaA)
			zetaC2, err := pp.sampleZetaC2()
			if err != nil {
				return nil, err
			}
			retz_cs[tau][j] = pp.NTTVec(zetaC2)

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
	chtmp, _ := pp.expandChallenge(seedj)// TODO:handle the err
	chj = pp.NTT(chtmp)

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
		chtmp,_:=pp.expandChallenge(seedj) //TODO:handle the err
		chj := pp.NTT(chtmp)

		imgMatrix, err := pp.expandKeyImgMatrix(t_as[j])
		if err != nil {
			// TODO: define Const Error Variable
			return false
		}

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
func (pp *PublicParameter) generateMatrix(seed []byte, rowLength int, colLength int) ([]*PolyVec, error) {
	var err error
	// check the length of seed
	res := make([]*PolyVec, rowLength)
	buf := make([]byte, colLength*pp.paramD*4)
	XOF := sha3.NewShake128()
	for i := 0; i < rowLength; i++ {
		res[i] = NewPolyVec(colLength, pp.paramD)
		for j := 0; j < colLength; j++ {
			XOF.Reset()
			_, err = XOF.Write(append(seed, byte(i), byte(j)))
			if err != nil {
				return nil, err
			}
			_, err = XOF.Read(buf)
			if err != nil {
				return nil, err
			}
			got := pp.rejectionUniformWithZq(buf, pp.paramD)
			if len(got) < pp.paramLc {
				newBuf := make([]byte, pp.paramD*4)
				_, err = XOF.Read(newBuf)
				if err != nil {
					return nil, err
				}
				got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramD-len(got))...)
			}
			for k := 0; k < pp.paramD; k++ {
				res[i].polys[j].coeffs[k] = got[k]
			}
		}
	}
	return res, nil
}

func (pp *PublicParameter) generateNTTMatrix(seed []byte, rowLength int, colLength int) ([]*PolyNTTVec, error) {
	var err error
	// check the length of seed
	res := make([]*PolyNTTVec, rowLength)
	buf := make([]byte, colLength*pp.paramD*4)
	XOF := sha3.NewShake128()
	for i := 0; i < rowLength; i++ {
		res[i] = NewPolyNTTVec(colLength, pp.paramD)
		for j := 0; j < colLength; j++ {
			XOF.Reset()
			_, err = XOF.Write(append(seed, byte(i), byte(j)))
			if err != nil {
				return nil, err
			}
			_, err = XOF.Read(buf)
			if err != nil {
				return nil, err
			}
			got := pp.rejectionUniformWithZq(buf, pp.paramD)
			if len(got) < pp.paramLc {
				newBuf := make([]byte, pp.paramD*4)
				_, err = XOF.Read(newBuf)
				if err != nil {
					return nil, err
				}
				got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramD-len(got))...)
			}
			for k := 0; k < pp.paramD; k++ {
				res[i].polyNTTs[j].coeffs[k] = got[k]
			}
		}
	}
	return res, nil
}

// generatePolyVecWithProbabilityDistributions generate a poly whose coefficient is in S_r named Probability Distribution
func (pp *PublicParameter) generatePolyVecWithProbabilityDistributions(seed []byte, length int) (*PolyVec, error) {
	var err error
	// check the length of seed
	res := NewPolyVec(length, pp.paramD)
	buf := make([]byte, pp.paramD*4)
	XOF := sha3.NewShake128()
	for i := 0; i < length; i++ {
		XOF.Reset()
		_, err = XOF.Write(append(seed, byte(i)))
		if err != nil {
			return nil, err
		}
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, err
		}
		got, err := randomnessFromProbabilityDistributions(buf, pp.paramD)
		if len(got) < pp.paramLc {
			newBuf := make([]byte, pp.paramD)
			_, err = XOF.Read(newBuf)
			if err != nil {
				return nil, err
			}
			newGot, err := randomnessFromProbabilityDistributions(newBuf, pp.paramD-len(got))
			if err != nil {
				return nil, err
			}
			got = append(got, newGot...)
		}
		for k := 0; k < pp.paramD; k++ {
			res.polys[i].coeffs[k] = got[k]
		}
	}
	return res, nil
}
func (pp *PublicParameter) generateBits(seed []byte, length int) ([]byte, error) {
	var err error
	// check the length of seed
	res := make([]byte, (length+7)/8*8)
	buf := make([]byte, 8)
	XOF := sha3.NewShake128()
	for i := 0; i < (length+7)/8; i++ {
		XOF.Reset()
		_, err = XOF.Write(append(seed, byte(i)))
		if err != nil {
			return nil, err
		}
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, err
		}
		res[8*i+0] = buf[i] & (1 << 0) >> 0
		res[8*i+1] = buf[i] & (1 << 1) >> 1
		res[8*i+2] = buf[i] & (1 << 2) >> 2
		res[8*i+3] = buf[i] & (1 << 3) >> 3
		res[8*i+4] = buf[i] & (1 << 4) >> 4
		res[8*i+5] = buf[i] & (1 << 5) >> 5
		res[8*i+6] = buf[i] & (1 << 6) >> 6
		res[8*i+7] = buf[i] & (1 << 7) >> 7
	}
	return res[:length], nil
}

//TODO: uniform sample a element in Z_q from buf as many as possible
func (pp *PublicParameter) rejectionUniformWithZq(buf []byte, length int) []int32 {
	res := make([]int32, 0, length)
	var pos int
	var t uint32
	//q=1111_1111_1111_1111_1110_1110_0000_0001
	for pos < len(buf) {
		// 从buf中读取32个bit（4byte）
		t = uint32(buf[pos])
		t |= uint32(buf[pos+1]) << 8
		t |= uint32(buf[pos+2]) << 16
		t |= uint32(buf[pos+3]) << 24
		if t < pp.paramQ {
			res = append(res, int32(t-pp.paramQ))
		}
	}
	return res
}

/**
todo: generate MatrixA from pp.Cstr
*/
func (pp *PublicParameter) expandPubMatrixA(seed []byte, i byte, j byte) (matrixA []*PolyNTTVec, err error) {
	matrix, err := pp.generateNTTMatrix(append(seed, i, j), pp.paramKa, pp.paramLa)
	if err != nil {
		return nil, err
	}
	return matrix, nil
}

/**
todo: generate MatrixB from pp.Cstr
todo: store the matrices in PP or generate them each time they are generated
*/
func (pp *PublicParameter) expandPubMatrixB(seed []byte, i byte, j byte) (matrixB []*PolyNTTVec, err error) {
	matrix, err := pp.generateNTTMatrix(append(seed, i, j), pp.paramKc, pp.paramLc)
	if err != nil {
		return nil, err
	}
	return matrix, nil
}

func (pp *PublicParameter) expandPubMatrixC(seed []byte, i byte, j byte) (matrixC []*PolyNTTVec, err error) {
	matrix, err := pp.generateNTTMatrix(append(seed, i, j), pp.paramI+pp.paramJ+7, pp.paramLc)
	if err != nil {
		return nil, err
	}
	return matrix, nil
}

// TODO:Why is input a poltNTTVec?
//func (pp PublicParameter) expandKeyImgMatrix(t *PolyNTTVec) (matrixH []*PolyNTTVec) {
func (pp PublicParameter) expandKeyImgMatrix(seed []byte, i byte, j byte) (matrixH []*PolyNTTVec, err error) {
	matrix, err := pp.generateNTTMatrix(append(seed, i, j), pp.paramMa, pp.paramLa)
	if err != nil {
		return nil, err
	}
	return matrix, nil
}

func (pp *PublicParameter) sampleRandomnessA() (r *PolyVec, err error) {
	polys := make([]*Poly, pp.paramLa)
	for i := 0; i < pp.paramLa; i++ {
		tmp, err := randomnessFromProbabilityDistributions(nil, pp.paramD)
		if err != nil {
			return nil, err
		}
		polys[i] = &Poly{coeffs: tmp}
	}

	retr := &PolyVec{
		polys: polys,
	}
	return retr, nil
}

/*
todo: expand a seed to a PolyVec with length l_a from (S_r)^d
*/
func (pp *PublicParameter) expandRandomnessA(seed []byte) (r *PolyVec, err error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}
	seed = append(seed, 'A')
	r, err = pp.generatePolyVecWithProbabilityDistributions(seed, pp.paramLa)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (pp *PublicParameter) sampleRandomnessC() (r *PolyVec, err error) {
	polys := make([]*Poly, pp.paramLc)

	for i := 0; i < pp.paramLc; i++ {
		tmp, err := randomnessFromProbabilityDistributions(nil, pp.paramD)
		if err != nil {
			return nil, err
		}
		polys[i] = &Poly{coeffs: tmp}
	}
	rst := &PolyVec{
		polys: polys,
	}
	return rst, nil
}

func (pp *PublicParameter) expandRandomnessC(seed []byte) (r *PolyVec, err error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}
	seed = append(seed, 'C')
	r, err = pp.generatePolyVecWithProbabilityDistributions(seed, pp.paramLc)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (pp PublicParameter) sampleMaskA() (r *PolyVec, err error) {
	polys := make([]*Poly, pp.paramLa)

	for i := 0; i < pp.paramLa; i++ {
		tmp, err := randomnessFromChallengeSpace(nil, pp.paramD)
		if err != nil {
			return nil, err
		}
		polys[i] = &Poly{coeffs: tmp}
	}
	rst := &PolyVec{
		polys: polys,
	}
	return rst, nil
}

func (pp PublicParameter) sampleMaskC() (r *PolyVec, err error) {
	polys := make([]*Poly, pp.paramLc)

	for i := 0; i < pp.paramLc; i++ {
		tmp, err := randomnessFromChallengeSpace(nil, pp.paramD)
		if err != nil {
			return nil, err
		}
		polys[i] = &Poly{coeffs: tmp}
	}
	rst := &PolyVec{
		polys: polys,
	}
	return rst, nil
}

func (pp PublicParameter) sampleMaskC2() (r *PolyVec, err error) {
	polys := make([]*Poly, pp.paramLc)

	for i := 0; i < pp.paramLc; i++ {
		tmp, err := randomnessFromChallengeSpace(nil, pp.paramD)
		if err != nil {
			return nil, err
		}
		polys[i] = &Poly{coeffs: tmp}
	}
	rst := &PolyVec{
		polys: polys,
	}
	return rst, nil
}

func (pp PublicParameter) sampleZetaA() (r *PolyVec, err error) {
	polys := make([]*Poly, pp.paramLa)

	for i := 0; i < pp.paramLa; i++ {
		tmp, err := randomnessFromChallengeSpace(nil, pp.paramD)
		if err != nil {
			return nil, err
		}
		polys[i] = &Poly{coeffs: tmp}
	}
	rst := &PolyVec{
		polys: polys,
	}
	return rst, nil
}

func (pp PublicParameter) sampleZetaC() (r *PolyVec, err error) {
	polys := make([]*Poly, pp.paramLc)

	for i := 0; i < pp.paramLc; i++ {
		tmp, err := randomnessFromChallengeSpace(nil, pp.paramD)
		if err != nil {
			return nil, err
		}
		polys[i] = &Poly{coeffs: tmp}
	}
	rst := &PolyVec{
		polys: polys,
	}
	return rst, nil
}

func (pp PublicParameter) sampleZetaC2() (r *PolyVec, err error) {
	polys := make([]*Poly, pp.paramLc)

	for i := 0; i < pp.paramLc; i++ {
		tmp, err := randomnessFromChallengeSpace(nil, pp.paramD)
		if err != nil {
			return nil, err
		}
		polys[i] = &Poly{coeffs: tmp}
	}
	rst := &PolyVec{
		polys: polys,
	}
	return rst, nil
}

func (pp *PublicParameter) expandRandomBitsV(seed []byte) (r []byte, err error) {
	if len(seed) == 0 {
		return nil, ErrLength
	}
	seed = append(seed, 'V')
	r, err = pp.generateBits(seed, pp.paramD)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (pp PublicParameter) sampleUniformPloyWithLowZeros() (r *Poly) {
	res := NewPoly(pp.paramD)
	seed := randomBytes(pp.paramSysBytes)
	tmp := pp.rejectionUniformWithZq(seed, pp.paramD-pp.paramK)
	for i := pp.paramK; i < pp.paramD; i++ {
		res.coeffs[i] = tmp[i]
	}
	return res
}

func (pp PublicParameter) expandUniformRandomnessInRqZq(seed []byte, n1 int, m int) (alphas []*PolyNTT, betas []*PolyNTT, gammas [][][]int32, err error) {
	alphas = make([]*PolyNTT, n1)
	betas = make([]*PolyNTT, pp.paramK)
	gammas = make([][][]int32, pp.paramK)
	// check the length of seed

	XOF := sha3.NewShake128()
	// alpha
	XOF.Reset()
	_, err = XOF.Write(append(seed, 0))
	if err != nil {
		return nil, nil, nil, err
	}
	buf := make([]byte, n1*pp.paramD*4)
	for i := 0; i < n1; i++ {
		alphas[i] = NewPolyNTT(pp.paramD)
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, nil, nil, err
		}
		got := pp.rejectionUniformWithZq(buf, pp.paramD)
		if len(got) < pp.paramLc {
			newBuf := make([]byte, pp.paramD*4)
			_, err = XOF.Read(newBuf)
			if err != nil {
				return nil, nil, nil, err
			}
			got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramD-len(got))...)
		}
		for k := 0; k < pp.paramD; k++ {
			alphas[i].coeffs[k] = got[k]
		}
	}
	// betas
	XOF.Reset()
	_, err = XOF.Write(append(seed, 1))
	if err != nil {
		return nil, nil, nil, err
	}
	buf = make([]byte, pp.paramK*pp.paramD*4)
	for i := 0; i < pp.paramK; i++ {
		betas[i] = NewPolyNTT(pp.paramD)
		_, err = XOF.Read(buf)
		if err != nil {
			return nil, nil, nil, err
		}
		got := pp.rejectionUniformWithZq(buf, pp.paramD)
		if len(got) < pp.paramLc {
			newBuf := make([]byte, pp.paramD*4)
			_, err = XOF.Read(newBuf)
			if err != nil {
				return nil, nil, nil, err
			}
			got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramD-len(got))...)
		}
		for k := 0; k < pp.paramD; k++ {
			betas[i].coeffs[k] = got[k]
		}
	}
	// gammas
	XOF.Reset()
	_, err = XOF.Write(append(seed, 2))
	if err != nil {
		return nil, nil, nil, err
	}
	buf = make([]byte, m*pp.paramD*4)
	for i := 0; i < pp.paramK; i++ {
		gammas[i] = make([][]int32, m)
		_, err = XOF.Read(buf)
		for j := 0; j < m; j++ {
			gammas[i][j] = make([]int32, m)
			got := pp.rejectionUniformWithZq(buf, pp.paramD)
			if len(got) < pp.paramLc {
				newBuf := make([]byte, pp.paramD*4)
				_, err = XOF.Read(newBuf)
				if err != nil {
					return nil, nil, nil, err
				}
				got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramD-len(got))...)
			}
			for k := 0; k < pp.paramD; k++ {
				gammas[i][j][k] = got[k]
			}
		}
	}
	return alphas, betas, gammas, nil
}

/*
todo:
*/
func (pp *PublicParameter) expandChallenge(seed []byte) (r *Poly, err error) {
	// extend seed via sha3.Shake128
	res := NewPoly(pp.paramD)
	buf := make([]byte, pp.paramD/4)
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
	got, err := randomnessFromChallengeSpace(seed, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		res.coeffs[i] = got[i]
	}
	return res, nil
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
 t: 0~(k-1)
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
func (pp *PublicParameter) intMatrixInnerProduct(a [][]int32, b [][]int32, rowNum int, colNum int) (r int32) {
	rst := int32(0)
	for i := 0; i < rowNum; i++ {
		for j := 0; j < colNum; j++ {
			rst = pp.reduce(int64(rst) + int64(pp.reduce(int64(a[i][j])*int64(b[i][j]))))
		}
	}

	return rst
}

func (pp *PublicParameter) intVecInnerProduct(a []int32, b []int32, vecLen int) (r int32) {
	rst := int32(0)
	for i := 0; i < vecLen; i++ {
		rst = pp.reduce(int64(rst) + int64(pp.reduce(int64(a[i])*int64(b[i]))))
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

/*func transposeMatrix(matrix [][]int32, rowNum int, colNum int) (transM [][]int32) {
	rettransMatrix := make([][]int32, colNum)
	for i := 0; i < colNum; i++ {
		rettransMatrix[i] = make([]int32, rowNum)
		for j := 0; j < rowNum; j++ {
			rettransMatrix[i][j] = matrix[j][i]
		}
	}

	return rettransMatrix
}*/

func getMatrixColumn(matrix [][]int32, rowNum int, j int) (col []int32) {
	retcol := make([]int32, rowNum)
	for i := 0; i < rowNum; i++ {
		retcol[i] = matrix[i][j]
	}

	return retcol
}

func (pp *PublicParameter) genUlpPolyNTTs(rpulpType RpUlpType, binMatrixB [][]int32, I int, J int, gammas [][][]int32) (ps [][]*PolyNTT) {
	p := make([][]*PolyNTT, pp.paramK)

	switch rpulpType {
	case RpUlpTypeCbTx1:

	case RpUlpTypeCbTx2:
		n := J
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyNTT, n2)
			for j := 0; j < n; j++ {
				p[t][j] = &PolyNTT{gammas[t][0]}
			}
			//	p[t][n] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int32, pp.paramD)
			for i := 0; i < pp.paramD; i++ {
				// F^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramD, i), gammas[t][2], pp.paramD)
				if i == 0 {
					coeffs[i] = pp.reduce(int64(coeffs[i] + gammas[t][1][i] + gammas[t][0][i]))
				} else if i < (pp.paramN - 1) {
					coeffs[i] = pp.reduce(int64(coeffs[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				} else { // i in [N-1, d-1]
					coeffs[i] = pp.reduce(int64(coeffs[i] + gammas[t][1][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				}
			}
			p[t][n] = &PolyNTT{coeffs}

			p[t][n+1] = &PolyNTT{gammas[t][2]}
		}
	case RpUlpTypeTrTx1:
		n := I + J
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyNTT, n2)

			p[t][0] = &PolyNTT{gammas[t][0]}

			minuscoeffs := make([]int32, pp.paramD)
			for i := 0; i < pp.paramD; i++ {
				minuscoeffs[i] = -gammas[t][0][i]
			}
			for j := 1; j < n; j++ {
				p[t][j] = &PolyNTT{minuscoeffs}
			}

			//	p[t][n] = NTT^{-1}((-F)^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs := make([]int32, pp.paramD)
			for i := 0; i < pp.paramD; i++ {
				//(-F)^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramD, i), gammas[t][2], pp.paramD)
				if i == 0 {
					coeffs[i] = pp.reduce(int64(coeffs[i] + gammas[t][1][i] - gammas[t][0][i]))
				} else if i < (pp.paramN - 1) {
					coeffs[i] = pp.reduce(int64(coeffs[i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
				} else { // i in [N-1, d-1]
					coeffs[i] = pp.reduce(int64(coeffs[i] + gammas[t][1][i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
				}
			}
			p[t][n] = &PolyNTT{coeffs}

			p[t][n+1] = &PolyNTT{gammas[t][2]}
		}
	case RpUlpTypeTrTx2:
		n := I + J
		n2 := n + 4
		//	B : d rows 2d columns
		//	m = 5
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyNTT, n2)

			for j := 0; j < I; j++ {
				p[t][j] = &PolyNTT{gammas[t][0]}
			}
			for j := I; j < I+J; j++ {
				p[t][j] = &PolyNTT{gammas[t][1]}
			}

			coeffs_n := make([]int32, pp.paramD)
			for i := 0; i < pp.paramD; i++ {
				coeffs_n[i] = -gammas[t][0][i] - gammas[t][1][i]
			}
			p[t][n] = &PolyNTT{coeffs_n}

			//	p[t][n+1] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][2] + B_1^T gamma[t][4])
			coeffs_np1 := make([]int32, pp.paramD)
			for i := 0; i < pp.paramD; i++ {
				//F^T[i] gamma[t][0] + F_1^T[i] gamma[t][2] + B^T[i] gamma[t][4]
				coeffs_np1[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramD, i), gammas[t][4], pp.paramD)
				if i == 0 {
					coeffs_np1[i] = pp.reduce(int64(coeffs_np1[i] + gammas[t][2][i] + gammas[t][0][i]))
				} else if i < (pp.paramN - 1) {
					coeffs_np1[i] = pp.reduce(int64(coeffs_np1[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				} else { // i in [N-1, d-1]
					coeffs_np1[i] = pp.reduce(int64(coeffs_np1[i] + gammas[t][2][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				}
			}
			p[t][n+1] = &PolyNTT{coeffs_np1}

			//	p[t][n+2] = NTT^{-1}(F^T gamma[t][1] + F_1^T gamma[t][3] + B_2^T gamma[t][4])
			coeffs_np2 := make([]int32, pp.paramD)
			for i := 0; i < pp.paramD; i++ {
				//F^T[i] gamma[t][1] + F_1^T[i] gamma[t][3] + B_2^T[i] gamma[t][4]
				coeffs_np2[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramD, pp.paramD+i), gammas[t][4], pp.paramD)
				if i == 0 {
					coeffs_np2[i] = pp.reduce(int64(coeffs_np2[i] + gammas[t][3][i] + gammas[t][1][i]))
				} else if i < (pp.paramN - 1) {
					coeffs_np2[i] = pp.reduce(int64(coeffs_np2[i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
				} else { // i in [N-1, d-1]
					coeffs_np2[i] = pp.reduce(int64(coeffs_np2[i] + gammas[t][3][i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
				}
			}
			p[t][n+2] = &PolyNTT{coeffs_np2}

			p[t][n+3] = &PolyNTT{gammas[t][4]}
		}
	}

	return p
}
