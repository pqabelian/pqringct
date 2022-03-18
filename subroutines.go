package pqringct

// rpulpProve generates balance proof

// RpUlpType is the type for difference transaction
//type RpUlpType uint8
//
//const (
//	RpUlpTypeCbTx1 RpUlpType = 0
//	RpUlpTypeCbTx2 RpUlpType = 1
//	RpUlpTypeTrTx1 RpUlpType = 2
//	RpUlpTypeTrTx2 RpUlpType = 3
//)
//
//// collectBytesForRPULP1 is an auxiliary function for rpulpProve and rpulpVerify to collect some information into a byte slice
//func (pp PublicParameter) collectBytesForRPULP1(n int, n1 int, n2 int, binMatrixB [][]byte, m int, cmts []*Commitment, b_hat *PolyNTTVec, c_hats []*PolyNTT, rpulpType RpUlpType, I int, J int, u_hats [][]int32, c_waves []*PolyNTT, cmt_ws [][]*PolyNTTVec, ws []*PolyNTTVec, c_hat_g *PolyNTT) []byte {
//	tmp := make([]byte, 0,
//		(pp.paramKC*pp.paramDC*4+pp.paramDC*4)*n+pp.paramKC*pp.paramDC*4+pp.paramDC*4*n2+4+1+len(binMatrixB)*len(binMatrixB[0])+1+1+m*pp.paramDC*4+pp.paramDC*4*n+(pp.paramKC*pp.paramDC*4)*n*pp.paramK+(pp.paramKC*pp.paramDC*4)*pp.paramK+pp.paramDC*4+
//			pp.paramDC*4*(n*pp.paramK*2+3+pp.paramK))
//	appendPolyNTTToBytes := func(a *PolyNTT) {
//		for k := 0; k < pp.paramDC; k++ {
//			tmp = append(tmp, byte(a.coeffs[k]>>0))
//			tmp = append(tmp, byte(a.coeffs[k]>>8))
//			tmp = append(tmp, byte(a.coeffs[k]>>16))
//			tmp = append(tmp, byte(a.coeffs[k]>>24))
//		}
//	}
//	appendInt32ToBytes := func(a int32) {
//		tmp = append(tmp, byte(a>>0))
//		tmp = append(tmp, byte(a>>8))
//		tmp = append(tmp, byte(a>>16))
//		tmp = append(tmp, byte(a>>24))
//	}
//	// b_i_arrow , c_i
//	for i := 0; i < len(cmts); i++ {
//		for j := 0; j < len(cmts[i].b.polyNTTs); j++ {
//			appendPolyNTTToBytes(cmts[i].b.polyNTTs[j])
//		}
//		appendPolyNTTToBytes(cmts[i].c)
//	}
//	// b_hat
//	for i := 0; i < pp.paramKC; i++ {
//		appendPolyNTTToBytes(b_hat.polyNTTs[i])
//	}
//	// c_i_hat
//	for i := 0; i < n2; i++ {
//		appendPolyNTTToBytes(c_hats[i])
//	}
//	// n1
//	appendInt32ToBytes(int32(n1))
//	//TODO_DONE:A = ulpType B I J
//	tmp = append(tmp, byte(rpulpType))
//	// B
//	appendBinaryMartix := func(data [][]byte) {
//		for i := 0; i < len(data); i++ {
//			tmp = append(tmp, data[i]...)
//		}
//	}
//	appendBinaryMartix(binMatrixB)
//	// I
//	tmp = append(tmp, byte(I))
//	// J
//	tmp = append(tmp, byte(J))
//	//u_hats
//	for i := 0; i < len(u_hats); i++ {
//		for j := 0; j < len(u_hats[i]); j++ {
//			appendInt32ToBytes(u_hats[i][j])
//		}
//	}
//	//c_waves
//	for i := 0; i < len(c_waves); i++ {
//		appendPolyNTTToBytes(c_waves[i])
//	}
//	// omega_i^j
//	for i := 0; i < len(cmt_ws); i++ {
//		for j := 0; j < len(cmt_ws[i]); j++ {
//			for k := 0; k < len(cmt_ws[i][j].polyNTTs); k++ {
//				appendPolyNTTToBytes(cmt_ws[i][j].polyNTTs[k])
//			}
//		}
//	}
//	// omega^i
//	for i := 0; i < len(ws); i++ {
//		for j := 0; j < len(ws[i].polyNTTs); j++ {
//			appendPolyNTTToBytes(ws[i].polyNTTs[j])
//		}
//	}
//	//c_hat[n2+1]
//	appendPolyNTTToBytes(c_hat_g)
//	return tmp
//}
//
//// collectBytesForRPULP2 is an auxiliary function for rpulpProve and rpulpVerify to collect some information into a byte slice
//func (pp PublicParameter) collectBytesForRPULP2(tmp []byte, delta_waves [][]*PolyNTT, delta_hats [][]*PolyNTT, psi *PolyNTT, psip *PolyNTT, phi *PolyNTT, phips []*PolyNTT) []byte {
//	appendPolyNTTToBytes := func(a *PolyNTT) {
//		for k := 0; k < pp.paramDC; k++ {
//			tmp = append(tmp, byte(a.coeffs[k]>>0))
//			tmp = append(tmp, byte(a.coeffs[k]>>8))
//			tmp = append(tmp, byte(a.coeffs[k]>>16))
//			tmp = append(tmp, byte(a.coeffs[k]>>24))
//		}
//	}
//	// delta_waves_i^j
//	for i := 0; i < len(delta_waves); i++ {
//		for j := 0; j < len(delta_waves[i]); j++ {
//			appendPolyNTTToBytes(delta_waves[i][j])
//		}
//	}
//	// delta_hat_i^j
//	for i := 0; i < len(delta_hats); i++ {
//		for j := 0; j < len(delta_hats[i]); j++ {
//			appendPolyNTTToBytes(delta_hats[i][j])
//
//		}
//	}
//	// psi
//	appendPolyNTTToBytes(psi)
//
//	// psip
//	appendPolyNTTToBytes(psip)
//
//	// phi
//	appendPolyNTTToBytes(phi)
//	// phips
//	for i := 0; i < len(phips); i++ {
//		appendPolyNTTToBytes(phips[i])
//	}
//	return tmp
//}
//
///**
//cmts []*Commitment, cmt_rs []*PolyNTTVec: cmt_bs[i] = matrixB * cmt_rs[i], cmt_cs[i] =<matrixC[0], cmt_rs[i]> + (msg_hats[i])_NTT, where msg_hats[i] is viewd as a PolyNTT
//h_hat *PolyNTTVec, r_hat *PolyNTTVec, c_hats []*PolyNTT
//n >= 2 && n <= n1 && n1 <= n2 && n <= pp.paramI+pp.paramJ && n2 <= pp.paramI+pp.paramJ+4
//*/
//// rpulpProve generate the balance proof among the message committed Commitment,
//// including the range proof for m_i ( i is [1,n1]), and the unstructured linear relation proof among m_j ( j is [1,n2]).
//func (pp PublicParameter) rpulpProve(cmts []*Commitment, cmt_rs []*PolyNTTVec, n int,
//	b_hat *PolyNTTVec, r_hat *PolyNTTVec, c_hats []*PolyNTT, msg_hats [][]int32, n2 int,
//	n1 int, rpulpType RpUlpType, binMatrixB [][]byte, I int, J int, m int, u_hats [][]int32) (rpulppi *rpulpProof, err error) {
//	// c_waves[i] = <h_i, r_i> + m_i
//	c_waves := make([]*PolyNTT, n)
//	for i := 0; i < n; i++ {
//		c_waves[i] = pp.PolyNTTAdd(pp.PolyNTTVecInnerProduct(pp.paramMatrixH[i+1], cmt_rs[i], pp.paramLC), &PolyNTT{msg_hats[i]})
//	}
//
//rpUlpProveRestart:
//
//	cmt_ys := make([][]*PolyNTTVec, pp.paramK)
//	ys := make([]*PolyNTTVec, pp.paramK)
//	cmt_ws := make([][]*PolyNTTVec, pp.paramK)
//	ws := make([]*PolyNTTVec, pp.paramK)
//	for t := 0; t < pp.paramK; t++ {
//		cmt_ys[t] = make([]*PolyNTTVec, n)
//		cmt_ws[t] = make([]*PolyNTTVec, n)
//		for i := 0; i < n; i++ {
//			// random some element in the {s_etaC}^Lc space
//			maskC, err := pp.sampleMaskC()
//			if err != nil {
//				return nil, err
//			}
//			cmt_ys[t][i] = pp.NTTVec(maskC)
//			cmt_ws[t][i] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_ys[t][i], pp.paramKC, pp.paramLC)
//		}
//
//		maskC, err := pp.sampleMaskC()
//		if err != nil {
//			return nil, err
//		}
//		ys[t] = pp.NTTVec(maskC)
//		ws[t] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
//	}
//
//	tmpg := pp.sampleUniformPloyWithLowZeros()
//	g := pp.NTT(tmpg)
//	// c_hat(n2+1)
//	c_hat_g := pp.PolyNTTAdd(pp.PolyNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], r_hat, pp.paramLC), g)
//
//	// splicing the data to be processed
//	tmp := pp.collectBytesForRPULP1(n, n1, n2, binMatrixB, m, cmts, b_hat, c_hats, rpulpType, I, J, u_hats, c_waves, cmt_ws, ws, c_hat_g)
//	seed_rand, err := Hash(tmp) // todo_DONE
//	if err != nil {
//		return nil, err
//	}
//	//fmt.Println("seed_rand=", seed_rand)
//	alphas, betas, gammas, err := pp.expandUniformRandomnessInRqZq(seed_rand, n1, m)
//	if err != nil {
//		return nil, err
//	}
//	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
//	delta_waves := make([][]*PolyNTT, pp.paramK)
//	delta_hats := make([][]*PolyNTT, pp.paramK)
//	for t := 0; t < pp.paramK; t++ {
//		delta_waves[t] = make([]*PolyNTT, n)
//		delta_hats[t] = make([]*PolyNTT, n)
//		for i := 0; i < n; i++ {
//			delta_waves[t][i] = pp.PolyNTTVecInnerProduct(pp.PolyNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC), cmt_ys[t][i], pp.paramLC)
//			delta_hats[t][i] = pp.PolyNTTVecInnerProduct(pp.paramMatrixH[i+1], pp.PolyNTTVecSub(ys[t], cmt_ys[t][i], pp.paramLC), pp.paramLC)
//		}
//	}
//	//fmt.Printf("delta_waves =\n")
//	//for i := 0; i < pp.paramK; i++ {
//	//	for j := 0; j < n; j++ {
//	//		fmt.Printf("delta_waves[%d][%d] = %v\n",i,j,delta_waves[i][j])
//	//
//	//	}
//	//}
//	//fmt.Printf("delta_hats =\n")
//	//for i := 0; i < pp.paramK; i++ {
//	//	for j := 0; j < n; j++ {
//	//		fmt.Printf("delta_hats[%d][%d] = %v\n",i,j,delta_hats[i][j])
//	//
//	//	}
//	//}
//
//	//	psi, psi'
//	psi := pp.PolyNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], r_hat, pp.paramLC)
//	psip := pp.PolyNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], ys[0], pp.paramLC)
//
//	for t := 0; t < pp.paramK; t++ {
//		tmp1 := pp.NewZeroPolyNTT()
//		tmp2 := pp.NewZeroPolyNTT()
//		// sum(0->n1-1)
//		for i := 0; i < n1; i++ {
//			// <h_i , y_t>
//			tmp := pp.PolyNTTVecInnerProduct(pp.paramMatrixH[i+1], ys[t], pp.paramLC)
//
//			tmp1 = pp.PolyNTTAdd(
//				tmp1,
//				// alpha[i] * (2 * m_i - mu) <h_i , y_t>
//				pp.PolyNTTMul(
//					alphas[i],
//					// (2 * m_i - mu) <h_i , y_t>
//					pp.PolyNTTMul(
//						// 2 * m_i - mu
//						pp.PolyNTTSub(
//							//  m_i+m_i
//							pp.PolyNTTAdd(
//								&PolyNTT{msg_hats[i]}, &PolyNTT{msg_hats[i]},
//							),
//							&PolyNTT{pp.paramMu},
//						),
//						tmp,
//					),
//				),
//			)
//			tmp2 = pp.PolyNTTAdd(
//				tmp2,
//				// alpha[i] * <h_i , y_t> * <h_i , y_t>
//				pp.PolyNTTMul(alphas[i],
//					pp.PolyNTTMul(tmp, tmp)))
//		}
//
//		psi = pp.PolyNTTSub(psi, pp.PolyNTTMul(betas[t], pp.sigmaInvPolyNTT(tmp1, t)))
//		psip = pp.PolyNTTAdd(psip, pp.PolyNTTMul(betas[t], pp.sigmaInvPolyNTT(tmp2, t)))
//	}
//	/*	fmt.Printf("Prove\n")
//		fmt.Printf("psip = %v\n", psip)*/
//	//	p^(t)_j:
//	p := pp.genUlpPolyNTTs(rpulpType, binMatrixB, I, J, gammas)
//
//	//	phi
//	phi := pp.NewZeroPolyNTT()
//	for t := 0; t < pp.paramK; t++ {
//		tmp1 := pp.NewZeroPolyNTT()
//		for tau := 0; tau < pp.paramK; tau++ {
//
//			tmp := pp.NewZeroPolyNTT()
//			for j := 0; j < n2; j++ {
//				tmp = pp.PolyNTTAdd(tmp, pp.PolyNTTMul(p[t][j], &PolyNTT{msg_hats[j]}))
//			}
//
//			/*			nttsumL := int64(0)
//						for i := 0; i < pp.paramDC; i++ {
//							nttsumL = pp.reduceInt64( int64(nttsumL) + int64(tmp.coeffs[i]) )
//						}*/
//
//			constPoly := pp.NewZeroPoly()
//			constPoly.coeffs[0] = pp.reduce(int64(pp.intMatrixInnerProduct(u_hats, gammas[t], m, pp.paramDC)) * int64(pp.paramDCInv))
//
//			/*			constPolyNTT := pp.NTT(constPoly)
//						nttsumR := int64(0)
//						for i := 0; i < pp.paramDC; i++ {
//							nttsumR = pp.reduceInt64( int64(nttsumR) + int64(constPolyNTT.coeffs[i]) )
//						}*/
//
//			tmp = pp.PolyNTTSub(tmp, pp.NTT(constPoly))
//
//			/*			nttsumF := int64(0)
//						for i := 0; i < pp.paramDC; i++ {
//							nttsumF = pp.reduceInt64( int64(nttsumF) + int64(tmp.coeffs[i]) )
//						}
//						fmt.Println("sumL:", nttsumL)
//						fmt.Println("sumR:", nttsumR)
//						fmt.Println("sumF:", nttsumF)*/
//
//			tmp1 = pp.PolyNTTAdd(tmp1, pp.sigmaPowerPolyNTT(tmp, tau))
//		}
//
//		xt := pp.NewZeroPoly()
//		xt.coeffs[t] = pp.paramKInv
//
//		tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)
//
//		phi = pp.PolyNTTAdd(phi, tmp1)
//	}
//
//	phi = pp.PolyNTTAdd(phi, g)
//	//phiinv := pp.NTTInv(phi)
//	//fmt.Println(phiinv)
//	//fmt.Printf("phi = %v\n",phi)
//	//	phi'^(\xi)
//	phips := make([]*PolyNTT, pp.paramK)
//	for xi := 0; xi < pp.paramK; xi++ {
//		phips[xi] = pp.NewZeroPolyNTT()
//
//		for t := 0; t < pp.paramK; t++ {
//
//			tmp1 := pp.NewZeroPolyNTT()
//			for tau := 0; tau < pp.paramK; tau++ {
//
//				tmp := pp.NewZeroPolyNTTVec(pp.paramLC)
//
//				for j := 0; j < n2; j++ {
//					tmp = pp.PolyNTTVecAdd(
//						tmp,
//						pp.PolyNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
//						pp.paramLC)
//				}
//
//				tmp1 = pp.PolyNTTAdd(
//					tmp1,
//					pp.sigmaPowerPolyNTT(
//						pp.PolyNTTVecInnerProduct(tmp, ys[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
//						tau))
//			}
//
//			xt := pp.NewZeroPoly()
//			xt.coeffs[t] = pp.paramKInv
//
//			tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)
//
//			phips[xi] = pp.PolyNTTAdd(phips[xi], tmp1)
//		}
//
//		phips[xi] = pp.PolyNTTAdd(
//			phips[xi],
//			pp.PolyNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], ys[xi], pp.paramLC))
//	}
//
//	//fmt.Printf("phips = \n")
//	//for i := 0; i < pp.paramK; i++ {
//	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
//	//}
//
//	//	seed_ch and ch
//	chseed, err := Hash(pp.collectBytesForRPULP2(tmp, delta_waves, delta_hats, psi, psip, phi, phips))
//	if err != nil {
//		return nil, err
//	}
//	ctmp, err := pp.expandChallenge(chseed)
//	if err != nil {
//		return nil, err
//	}
//	ch := pp.NTT(ctmp)
//
//	// z = y + sigma^t(c) * r
//	cmt_zs := make([][]*PolyNTTVec, pp.paramK)
//	zs := make([]*PolyNTTVec, pp.paramK)
//	for t := 0; t < pp.paramK; t++ {
//		cmt_zs[t] = make([]*PolyNTTVec, n)
//		sigma_t_ch := pp.sigmaPowerPolyNTT(ch, t)
//		for i := 0; i < n; i++ {
//			cmt_zs[t][i] = pp.PolyNTTVecAdd(
//				cmt_ys[t][i],
//				pp.PolyNTTVecScaleMul(sigma_t_ch, cmt_rs[i], pp.paramLC),
//				pp.paramLC)
//			if pp.NTTInvVec(cmt_zs[t][i]).infNorm() > pp.paramEtaC-pp.paramBetaC {
//				goto rpUlpProveRestart
//			}
//		}
//
//		zs[t] = pp.PolyNTTVecAdd(ys[t], pp.PolyNTTVecScaleMul(sigma_t_ch, r_hat, pp.paramLC), pp.paramLC)
//
//		if pp.NTTInvVec(zs[t]).infNorm() > pp.paramEtaC-pp.paramBetaC {
//			goto rpUlpProveRestart
//		}
//	}
//
//	retrpulppi := &rpulpProof{
//		c_waves: c_waves,
//		c_hat_g: c_hat_g,
//		psi:     psi,
//		phi:     phi,
//		chseed:  chseed,
//		cmt_zs:  cmt_zs,
//		zs:      zs,
//	}
//
//	return retrpulppi, nil
//}
//
//func (pp PublicParameter) rpulpVerify(cmts []*Commitment, n int,
//	b_hat *PolyNTTVec, c_hats []*PolyNTT, n2 int,
//	n1 int, rpulpType RpUlpType, binMatrixB [][]byte, I int, J int, m int, u_hats [][]int32,
//	rpulppi *rpulpProof) (valid bool) {
//
//	if !(n >= 2 && n <= n1 && n1 <= n2 && n <= pp.paramI+pp.paramJ && n2 <= pp.paramI+pp.paramJ+4) {
//		return false
//	}
//
//	if len(cmts) != n {
//		return false
//	}
//
//	if b_hat == nil {
//		return false
//	}
//
//	if len(c_hats) != n2 {
//		return false
//	}
//
//	// check the matrix and u_hats
//	if len(binMatrixB) != pp.paramDC {
//		return false
//	} else {
//		for i := 0; i < len(binMatrixB); i++ {
//			if len(binMatrixB[0]) != pp.paramDC/8 {
//				//	todo: sometimes 2*pp.paramDC/8
//				//return false
//			}
//		}
//	}
//	if len(u_hats) != m {
//		return false
//	} else {
//		for i := 0; i < len(u_hats); i++ {
//			if len(u_hats[0]) != pp.paramDC {
//				return false
//			}
//		}
//
//	}
//	// check the well-formness of the \pi
//	if len(rpulppi.c_waves) != n || len(rpulppi.c_hat_g.coeffs) != pp.paramDC || len(rpulppi.psi.coeffs) != pp.paramDC || len(rpulppi.phi.coeffs) != pp.paramDC || len(rpulppi.zs) != pp.paramK || len(rpulppi.zs[0].polyNTTs) != pp.paramLC {
//		return false
//	}
//	if rpulppi == nil {
//		return false
//	}
//	if len(rpulppi.c_waves) != n {
//		return false
//	}
//
//	if rpulppi.c_hat_g == nil || rpulppi.psi == nil || rpulppi.phi == nil || rpulppi.chseed == nil {
//		return false
//	}
//
//	if rpulppi.cmt_zs == nil || len(rpulppi.cmt_zs) != pp.paramK || rpulppi.zs == nil || len(rpulppi.zs) != pp.paramK {
//		return false
//	}
//
//	for t := 0; t < pp.paramK; t++ {
//		if rpulppi.cmt_zs[t] == nil || len(rpulppi.cmt_zs[t]) != n {
//			return false
//		}
//	}
//
//	//	(phi_t[0] ... phi_t[k-1] = 0)
//	phiPoly := pp.NTTInv(rpulppi.phi)
//	//	fmt.Println("phiPoly", phiPoly.coeffs)
//	for t := 0; t < pp.paramK; t++ {
//		if phiPoly.coeffs[t] != 0 {
//			// TODO 20210609 exist something theoretical error
//			return false
//		}
//	}
//
//	// infNorm of z^t_i and z^t
//	for t := 0; t < pp.paramK; t++ {
//
//		for i := 0; i < n; i++ {
//			if pp.NTTInvVec(rpulppi.cmt_zs[t][i]).infNorm() > pp.paramEtaC-pp.paramBetaC {
//				return false
//			}
//		}
//
//		if pp.NTTInvVec(rpulppi.zs[t]).infNorm() > pp.paramEtaC-pp.paramBetaC {
//			return false
//		}
//
//	}
//	chmp, err := pp.expandChallenge(rpulppi.chseed)
//	if err != nil {
//		return false
//	}
//	ch := pp.NTT(chmp)
//
//	sigma_chs := make([]*PolyNTT, pp.paramK)
//	//	w^t_i, w_t
//	cmt_ws := make([][]*PolyNTTVec, pp.paramK)
//	ws := make([]*PolyNTTVec, pp.paramK)
//	for t := 0; t < pp.paramK; t++ {
//		sigma_chs[t] = pp.sigmaPowerPolyNTT(ch, t)
//
//		cmt_ws[t] = make([]*PolyNTTVec, n)
//		for i := 0; i < n; i++ {
//			cmt_ws[t][i] = pp.PolyNTTVecSub(
//				pp.PolyNTTMatrixMulVector(pp.paramMatrixB, rpulppi.cmt_zs[t][i], pp.paramKC, pp.paramLC),
//				pp.PolyNTTVecScaleMul(sigma_chs[t], cmts[i].b, pp.paramKC),
//				pp.paramKC)
//		}
//		ws[t] = pp.PolyNTTVecSub(
//			pp.PolyNTTMatrixMulVector(pp.paramMatrixB, rpulppi.zs[t], pp.paramKC, pp.paramLC),
//			pp.PolyNTTVecScaleMul(sigma_chs[t], b_hat, pp.paramKC),
//			pp.paramKC)
//	}
//
//	// splicing the data to be processed
//
//	tmp := pp.collectBytesForRPULP1(n, n1, n2, binMatrixB, m, cmts, b_hat, c_hats, rpulpType, I, J, u_hats, rpulppi.c_waves, cmt_ws, ws, rpulppi.c_hat_g)
//	seed_rand, err := Hash(tmp)
//	if err != nil {
//		return false
//	}
//	//	fmt.Println("seed_rand=", seed_rand)
//	alphas, betas, gammas, err := pp.expandUniformRandomnessInRqZq(seed_rand, n1, m)
//	if err != nil {
//		return false
//	}
//
//	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
//	delta_waves := make([][]*PolyNTT, pp.paramK)
//	delta_hats := make([][]*PolyNTT, pp.paramK)
//	for t := 0; t < pp.paramK; t++ {
//		delta_waves[t] = make([]*PolyNTT, n)
//		delta_hats[t] = make([]*PolyNTT, n)
//
//		for i := 0; i < n; i++ {
//			delta_waves[t][i] = pp.PolyNTTSub(
//				pp.PolyNTTVecInnerProduct(
//					pp.PolyNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC),
//					rpulppi.cmt_zs[t][i],
//					pp.paramLC),
//				pp.PolyNTTMul(sigma_chs[t], pp.PolyNTTSub(rpulppi.c_waves[i], cmts[i].c)))
//
//			delta_hats[t][i] = pp.PolyNTTSub(
//				pp.PolyNTTVecInnerProduct(
//					pp.paramMatrixH[i+1],
//					pp.PolyNTTVecSub(rpulppi.zs[t], rpulppi.cmt_zs[t][i], pp.paramLC),
//					pp.paramLC),
//				pp.PolyNTTMul(sigma_chs[t], pp.PolyNTTSub(c_hats[i], rpulppi.c_waves[i])))
//		}
//	}
//	//fmt.Printf("delta_waves =\n")
//	//for i := 0; i < pp.paramK; i++ {
//	//	for j := 0; j < n; j++ {
//	//		fmt.Printf("delta_waves[%d][%d] = %v\n",i,j,delta_waves[i][j])
//	//
//	//	}
//	//}
//	//fmt.Printf("delta_hats =\n")
//	//for i := 0; i < pp.paramK; i++ {
//	//	for j := 0; j < n; j++ {
//	//		fmt.Printf("delta_hats[%d][%d] = %v\n",i,j,delta_hats[i][j])
//	//
//	//	}
//	//}
//
//	// psi'
//	psip := pp.NewZeroPolyNTT()
//	mu := &PolyNTT{pp.paramMu}
//	for t := 0; t < pp.paramK; t++ {
//
//		tmp1 := pp.NewZeroPolyNTT()
//		tmp2 := pp.NewZeroPolyNTT()
//
//		for i := 0; i < n1; i++ {
//			f_t_i := pp.PolyNTTSub(
//				//<h_i,z_t>
//				pp.PolyNTTVecInnerProduct(pp.paramMatrixH[i+1], rpulppi.zs[t], pp.paramLC),
//				// sigma_c_t
//				pp.PolyNTTMul(sigma_chs[t], c_hats[i]))
//
//			tmp := pp.PolyNTTMul(alphas[i], f_t_i)
//
//			tmp1 = pp.PolyNTTAdd(
//				tmp1,
//				pp.PolyNTTMul(tmp, f_t_i))
//
//			tmp2 = pp.PolyNTTAdd(
//				tmp2,
//				tmp)
//		}
//		tmp2 = pp.PolyNTTMul(tmp2, mu)
//		tmp2 = pp.PolyNTTMul(tmp2, sigma_chs[t])
//
//		tmp1 = pp.PolyNTTAdd(tmp1, tmp2)
//		tmp1 = pp.sigmaInvPolyNTT(tmp1, t)
//		tmp1 = pp.PolyNTTMul(betas[t], tmp1)
//
//		psip = pp.PolyNTTAdd(psip, tmp1)
//	}
//
//	psip = pp.PolyNTTSub(psip, pp.PolyNTTMul(ch, rpulppi.psi))
//	psip = pp.PolyNTTAdd(psip,
//		pp.PolyNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], rpulppi.zs[0], pp.paramLC))
//	/*	fmt.Printf("Verify\n")
//		fmt.Printf("psip = %v\n", psip)*/
//	//	p^(t)_j:
//	p := pp.genUlpPolyNTTs(rpulpType, binMatrixB, I, J, gammas)
//
//	//	phip
//	phip := pp.NewZeroPolyNTT()
//	for t := 0; t < pp.paramK; t++ {
//		tmp1 := pp.NewZeroPolyNTT()
//		for tau := 0; tau < pp.paramK; tau++ {
//
//			tmp := pp.NewZeroPolyNTT()
//			for j := 0; j < n2; j++ {
//				tmp = pp.PolyNTTAdd(tmp, pp.PolyNTTMul(p[t][j], c_hats[j]))
//			}
//
//			constPoly := pp.NewZeroPoly()
//			constPoly.coeffs[0] = pp.reduce(int64(pp.intMatrixInnerProduct(u_hats, gammas[t], m, pp.paramDC)) * int64(pp.paramDCInv))
//
//			tmp = pp.PolyNTTSub(tmp, pp.NTT(constPoly))
//
//			tmp1 = pp.PolyNTTAdd(tmp1, pp.sigmaPowerPolyNTT(tmp, tau))
//		}
//
//		xt := pp.NewZeroPoly()
//		xt.coeffs[t] = pp.paramKInv
//
//		tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)
//
//		phip = pp.PolyNTTAdd(phip, tmp1)
//	}
//
//	//	phi'^(\xi)
//	phips := make([]*PolyNTT, pp.paramK)
//	constterm := pp.PolyNTTSub(pp.PolyNTTAdd(phip, rpulppi.c_hat_g), rpulppi.phi)
//
//	for xi := 0; xi < pp.paramK; xi++ {
//		phips[xi] = pp.NewZeroPolyNTT()
//
//		for t := 0; t < pp.paramK; t++ {
//
//			tmp1 := pp.NewZeroPolyNTT()
//			for tau := 0; tau < pp.paramK; tau++ {
//
//				tmp := pp.NewZeroPolyNTTVec(pp.paramLC)
//
//				for j := 0; j < n2; j++ {
//					tmp = pp.PolyNTTVecAdd(
//						tmp,
//						pp.PolyNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
//						pp.paramLC)
//				}
//
//				tmp1 = pp.PolyNTTAdd(
//					tmp1,
//					pp.sigmaPowerPolyNTT(
//						pp.PolyNTTVecInnerProduct(tmp, rpulppi.zs[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
//						tau))
//			}
//
//			xt := pp.NewZeroPoly()
//			xt.coeffs[t] = pp.paramKInv
//
//			tmp1 = pp.PolyNTTMul(pp.NTT(xt), tmp1)
//
//			phips[xi] = pp.PolyNTTAdd(phips[xi], tmp1)
//		}
//
//		phips[xi] = pp.PolyNTTAdd(
//			phips[xi],
//			pp.PolyNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], rpulppi.zs[xi], pp.paramLC))
//
//		phips[xi] = pp.PolyNTTSub(
//			phips[xi],
//			pp.PolyNTTMul(sigma_chs[xi], constterm))
//	}
//	/*	fmt.Printf("phips = \n")
//		for i := 0; i < pp.paramK; i++ {
//			fmt.Printf("phips[%d] = %v \n", i, phips[i])
//		}*/
//	//	seed_ch and ch
//
//	seed_ch, err := Hash(pp.collectBytesForRPULP2(tmp, delta_waves, delta_hats, rpulppi.psi, psip, rpulppi.phi, phips))
//	if err != nil {
//		return false
//	}
//	if bytes.Compare(seed_ch, rpulppi.chseed) != 0 {
//		return false
//	}
//
//	return true
//}
//
//// collectBytesForRPULP1 is an auxiliary function for rpulpProve and rpulpVerify to collect some information into a byte slice
//func (pp PublicParameter) collectBytesForELR(msg []byte, ringSize int, t_as []*PolyNTTVec, w_as []*PolyNTTVec, w_cs []*PolyNTTVec, w_hat_as []*PolyNTTVec, retkeyImg *PolyNTTVec) []byte {
//	seedj_tmp := make([]byte, 0, len(msg)+ringSize*pp.paramKA*pp.paramDC*4+pp.paramK*pp.paramKA*pp.paramDC*4+pp.paramK*pp.paramKC*pp.paramDC*4+pp.paramKA*pp.paramDC*4+pp.paramMa*pp.paramDC*4)
//	appendPolyNTTToBytes := func(a *PolyNTT) {
//		for k := 0; k < pp.paramDC; k++ {
//			seedj_tmp = append(seedj_tmp, byte(a.coeffs[k]>>0))
//			seedj_tmp = append(seedj_tmp, byte(a.coeffs[k]>>8))
//			seedj_tmp = append(seedj_tmp, byte(a.coeffs[k]>>16))
//			seedj_tmp = append(seedj_tmp, byte(a.coeffs[k]>>24))
//		}
//	}
//	// M
//	for i := 0; i < len(msg); i++ {
//		seedj_tmp = append(seedj_tmp, msg...)
//	}
//	// List
//	for i := 0; i < ringSize; i++ {
//		for ii := 0; ii < pp.paramKA; ii++ {
//			appendPolyNTTToBytes(t_as[i].polyNTTs[ii])
//		}
//	}
//	// w_(a,j-1)^(t)   w_(c,j-1)^(t)
//	for i := 0; i < pp.paramK; i++ {
//		for ii := 0; ii < pp.paramKA; ii++ {
//			appendPolyNTTToBytes(w_as[i].polyNTTs[ii])
//		}
//		for ii := 0; ii < pp.paramKC+1; ii++ {
//			appendPolyNTTToBytes(w_cs[i].polyNTTs[ii])
//		}
//	}
//	// w_hat_(a,j-1)^(k-1)
//	for i := 0; i < pp.paramMa; i++ {
//		appendPolyNTTToBytes(w_hat_as[pp.paramK-1].polyNTTs[i])
//	}
//	// I
//	for i := 0; i < pp.paramMa; i++ {
//		appendPolyNTTToBytes(retkeyImg.polyNTTs[i])
//	}
//	return seedj_tmp
//}
//
//// elrsSign genarates authorizing and authentication proof
//func (pp PublicParameter) elrsSign(t_as []*PolyNTTVec, t_cs []*PolyNTTVec, msg []byte, sidx int, s_a *PolyNTTVec, s_c *PolyNTTVec) (elrssig *elrsSignature, err error) {
//	//	check the well-formness of inputs
//	if t_as == nil || t_cs == nil || msg == nil || s_a == nil || s_c == nil {
//		return nil, errors.New("lack some information")
//	}
//
//	if len(t_as) == 0 || len(t_cs) == 0 || len(msg) == 0 {
//		return nil, errors.New("lack some information")
//	}
//
//	if len(t_as) != len(t_cs) {
//		return nil, errors.New("the length of t_as is not equal to the t_cs")
//	}
//
//	ringSize := len(t_as)
//
//	if sidx < 0 || sidx >= ringSize {
//		return nil, errors.New("the index is not in [0,ringSize)")
//	}
//
//	for j := 0; j < ringSize; j++ {
//		if len(t_as[j].polyNTTs) != pp.paramKA {
//			return nil, errors.New("the length of t_as is not accurate")
//		}
//		if len(t_cs[j].polyNTTs) != pp.paramKC+1 {
//			return nil, errors.New("the length of t_cs is not accurate")
//		}
//	}
//
//	if len(s_a.polyNTTs) != pp.paramLA || len(s_c.polyNTTs) != pp.paramLC {
//		return nil, errors.New("the length of s_a or s_c is not accurate")
//	}
//
//	if pp.NTTInvVec(s_a).infNorm() > 2 {
//		return nil, errors.New("the norm of s_a is not right")
//	}
//	if pp.NTTInvVec(s_c).infNorm() > 2 {
//		return nil, errors.New("the norm of s_c is not right")
//	}
//
//	if pp.PolyNTTVecEqualCheck(t_as[sidx], pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s_a, pp.paramKA, pp.paramLA)) != true {
//		return nil, errors.New("t_as not equal")
//	}
//
//	matrixBExt := make([]*PolyNTTVec, pp.paramKC+1)
//	for i := 0; i < pp.paramKC; i++ {
//		matrixBExt[i] = pp.paramMatrixB[i]
//	}
//	matrixBExt[pp.paramKC] = pp.paramMatrixH[0]
//
//	if pp.PolyNTTVecEqualCheck(t_cs[sidx], pp.PolyNTTMatrixMulVector(matrixBExt, s_c, pp.paramKC+1, pp.paramLC)) != true {
//		return nil, errors.New("t_cs not equal")
//	}
//
//	//	keyImgMatrices
//	imgMatrixs := make([][]*PolyNTTVec, ringSize)
//	for j := 0; j < ringSize; j++ {
//		tmp := make([]byte, 0, pp.paramKA*pp.paramDC*4)
//		for ii := 0; ii < pp.paramKA; ii++ {
//			for jj := 0; jj < pp.paramDC; jj++ {
//				tmp = append(tmp, byte(t_as[j].polyNTTs[ii].coeffs[jj]>>0))
//				tmp = append(tmp, byte(t_as[j].polyNTTs[ii].coeffs[jj]>>8))
//				tmp = append(tmp, byte(t_as[j].polyNTTs[ii].coeffs[jj]>>16))
//				tmp = append(tmp, byte(t_as[j].polyNTTs[ii].coeffs[jj]>>24))
//			}
//		}
//		imgMatrixs[j], err = pp.expandKeyImgMatrix(tmp)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	//	keyImage I
//	retkeyImg := pp.PolyNTTMatrixMulVector(imgMatrixs[sidx], s_a, pp.paramMa, pp.paramLA)
//
//	retz_as := make([][]*PolyNTTVec, pp.paramK)
//	retz_cs := make([][]*PolyNTTVec, pp.paramK)
//	for j := 0; j < pp.paramK; j++ { //TODO
//		retz_as[j] = make([]*PolyNTTVec, pp.paramLA)
//		retz_cs[j] = make([]*PolyNTTVec, pp.paramLC)
//	}
//	var retchseed []byte
//
//	y_as := make([]*PolyNTTVec, pp.paramK)
//	y_cs := make([]*PolyNTTVec, pp.paramK)
//
//	w_as := make([]*PolyNTTVec, pp.paramK)
//	w_cs := make([]*PolyNTTVec, pp.paramK)
//	w_hat_as := make([]*PolyNTTVec, pp.paramK)
//
//elrsSignRestart:
//
//	for tau := 0; tau < pp.paramK; tau++ {
//		maskA, err := pp.sampleMaskA()
//		if err != nil {
//			return nil, err
//		}
//		y_as[tau] = pp.NTTVec(maskA)
//		maskC2, err := pp.sampleMaskC2()
//		if err != nil {
//			return nil, err
//		}
//		y_cs[tau] = pp.NTTVec(maskC2)
//
//		w_as[tau] = pp.PolyNTTMatrixMulVector(pp.paramMatrixA, y_as[tau], pp.paramKA, pp.paramLA)
//		w_cs[tau] = pp.PolyNTTMatrixMulVector(matrixBExt, y_cs[tau], pp.paramKC+1, pp.paramLC)
//		w_hat_as[tau] = pp.PolyNTTMatrixMulVector(imgMatrixs[sidx], y_as[tau], pp.paramMa, pp.paramLA)
//	}
//
//	var seedj []byte
//	var chj *PolyNTT
//	var sigma_tau_ch *PolyNTT
//
//	for j := (sidx + 1) % ringSize; ; {
//
//		seedj, err = Hash(pp.collectBytesForELR(msg, ringSize, t_as, w_as, w_cs, w_hat_as, retkeyImg))
//		if err != nil {
//			return nil, err
//		}
//
//		chtmm, err := pp.expandChallenge(seedj)
//		if err != nil {
//			return nil, err
//		}
//		chj = pp.NTT(chtmm)
//
//		for tau := 0; tau < pp.paramK; tau++ {
//			zetaA, err := pp.sampleZetaA()
//			if err != nil {
//				return nil, err
//			}
//			retz_as[tau][j] = pp.NTTVec(zetaA)
//			zetaC2, err := pp.sampleZetaC2()
//			if err != nil {
//				return nil, err
//			}
//			retz_cs[tau][j] = pp.NTTVec(zetaC2)
//
//			sigma_tau_ch = pp.sigmaPowerPolyNTT(chj, tau)
//
//			w_as[tau] = pp.PolyNTTVecSub(
//				pp.PolyNTTMatrixMulVector(pp.paramMatrixA, retz_as[tau][j], pp.paramKA, pp.paramLA),
//				pp.PolyNTTVecScaleMul(sigma_tau_ch, t_as[j], pp.paramKA),
//				pp.paramKA)
//
//			w_cs[tau] = pp.PolyNTTVecSub(
//				pp.PolyNTTMatrixMulVector(matrixBExt, retz_cs[tau][j], pp.paramKC+1, pp.paramLC),
//				pp.PolyNTTVecScaleMul(sigma_tau_ch, t_cs[j], pp.paramKC+1),
//				pp.paramKC+1)
//
//			w_hat_as[tau] = pp.PolyNTTVecSub(
//				pp.PolyNTTMatrixMulVector(imgMatrixs[j], retz_as[tau][j], pp.paramMa, pp.paramLA),
//				pp.PolyNTTVecScaleMul(sigma_tau_ch, retkeyImg, pp.paramMa),
//				pp.paramMa)
//		}
//
//		if j == 0 {
//			retchseed = seedj
//		}
//
//		j = (j + 1) % ringSize
//		if j == sidx {
//			break
//		}
//	}
//
//	seedj, err = Hash(pp.collectBytesForELR(msg, ringSize, t_as, w_as, w_cs, w_hat_as, retkeyImg))
//	if err != nil {
//		return nil, err
//	}
//	if sidx == 0 {
//		retchseed = seedj
//	}
//	chtmp, err := pp.expandChallenge(seedj)
//	if err != nil {
//		return nil, err
//	}
//	chj = pp.NTT(chtmp)
//
//	for tau := 0; tau < pp.paramK; tau++ {
//		sigma_tau_ch = pp.sigmaPowerPolyNTT(chj, tau)
//
//		retz_as[tau][sidx] = pp.PolyNTTVecAdd(y_as[tau], pp.PolyNTTVecScaleMul(sigma_tau_ch, s_a, pp.paramLA), pp.paramLA)
//		if pp.NTTInvVec(retz_as[tau][sidx]).infNorm() > pp.paramEtaA-pp.paramBetaA {
//			goto elrsSignRestart
//		}
//
//		retz_cs[tau][sidx] = pp.PolyNTTVecAdd(y_cs[tau], pp.PolyNTTVecScaleMul(sigma_tau_ch, s_c, pp.paramLC), pp.paramLC)
//		if pp.NTTInvVec(retz_cs[tau][sidx]).infNorm() > pp.paramEtaC2-pp.paramBetaC2 {
//			goto elrsSignRestart
//		}
//	}
//	// slice the z_as and z_cs
//	for i := 0; i < pp.paramK; i++ {
//		retz_as[i] = retz_as[i][:ringSize]
//		retz_cs[i] = retz_cs[i][:ringSize]
//	}
//
//	retelrssig := &elrsSignature{
//		retchseed,
//		retz_as,
//		retz_cs,
//		retkeyImg}
//	return retelrssig, nil
//}
//
//// elrsVerify verify the authorizing and authentication proof generated by elrsSign
//func (pp *PublicParameter) elrsVerify(t_as []*PolyNTTVec, t_cs []*PolyNTTVec, msg []byte, elrssig *elrsSignature) (valid bool) {
//	if t_as == nil || t_cs == nil || msg == nil {
//		//	check the well-formness of inputs
//		return false
//	}
//
//	if len(t_as) == 0 || len(t_cs) == 0 || len(msg) == 0 {
//		return false
//	}
//
//	if len(t_as) != len(t_cs) {
//		return false
//	}
//
//	ringSize := len(t_as)
//
//	for j := 0; j < ringSize; j++ {
//		if len(t_as[j].polyNTTs) != pp.paramKA {
//			return false
//		}
//		if len(t_cs[j].polyNTTs) != pp.paramKC+1 {
//			return false
//		}
//	}
//
//	if elrssig.chseed == nil || elrssig.z_as == nil || elrssig.z_cs == nil || elrssig.keyImg == nil {
//		return false
//	}
//	if len(elrssig.z_as) != pp.paramK || len(elrssig.z_cs) != pp.paramK {
//		return false
//	}
//
//	for tau := 0; tau < pp.paramK; tau++ {
//		if len(elrssig.z_as[tau]) != ringSize || len(elrssig.z_cs[tau]) != ringSize {
//			return false
//		}
//	}
//
//	for tau := 0; tau < pp.paramK; tau++ {
//		for j := 0; j < ringSize; j++ {
//			if pp.NTTInvVec(elrssig.z_as[tau][j]).infNorm() > pp.paramEtaA-pp.paramBetaA {
//				return false
//			}
//
//			if pp.NTTInvVec(elrssig.z_cs[tau][j]).infNorm() > pp.paramEtaC2-pp.paramBetaC2 {
//				return false
//			}
//		}
//	}
//
//	matrixBExt := make([]*PolyNTTVec, pp.paramKC+1)
//	for i := 0; i < pp.paramKC; i++ {
//		matrixBExt[i] = pp.paramMatrixB[i]
//	}
//	matrixBExt[pp.paramKC] = pp.paramMatrixH[0]
//
//	w_as := make([]*PolyNTTVec, pp.paramK)
//	w_cs := make([]*PolyNTTVec, pp.paramK)
//	w_hat_as := make([]*PolyNTTVec, pp.paramK)
//
//	seedj := elrssig.chseed
//
//	for j := 0; j < ringSize; j++ {
//		chtmp, err := pp.expandChallenge(seedj) //TODO_DONE:handle the err
//		if err != nil {
//			return false
//		}
//		chj := pp.NTT(chtmp)
//
//		tmp := make([]byte, 0, pp.paramKA*pp.paramDC*4)
//		for ii := 0; ii < pp.paramKA; ii++ {
//			for jj := 0; jj < pp.paramDC; jj++ {
//				tmp = append(tmp, byte(t_as[j].polyNTTs[ii].coeffs[jj]>>0))
//				tmp = append(tmp, byte(t_as[j].polyNTTs[ii].coeffs[jj]>>8))
//				tmp = append(tmp, byte(t_as[j].polyNTTs[ii].coeffs[jj]>>16))
//				tmp = append(tmp, byte(t_as[j].polyNTTs[ii].coeffs[jj]>>24))
//			}
//		}
//		imgMatrix, err := pp.expandKeyImgMatrix(tmp)
//		if err != nil {
//			return false
//		}
//
//		for tau := 0; tau < pp.paramK; tau++ {
//			sigma_tau_ch := pp.sigmaPowerPolyNTT(chj, tau)
//
//			w_as[tau] = pp.PolyNTTVecSub(
//				pp.PolyNTTMatrixMulVector(pp.paramMatrixA, elrssig.z_as[tau][j], pp.paramKA, pp.paramLA),
//				pp.PolyNTTVecScaleMul(sigma_tau_ch, t_as[j], pp.paramKA),
//				pp.paramKA)
//
//			w_cs[tau] = pp.PolyNTTVecSub(
//				pp.PolyNTTMatrixMulVector(matrixBExt, elrssig.z_cs[tau][j], pp.paramKC+1, pp.paramLC),
//				pp.PolyNTTVecScaleMul(sigma_tau_ch, t_cs[j], pp.paramKC+1),
//				pp.paramKC+1)
//
//			w_hat_as[tau] = pp.PolyNTTVecSub(
//				pp.PolyNTTMatrixMulVector(imgMatrix, elrssig.z_as[tau][j], pp.paramMa, pp.paramLA),
//				pp.PolyNTTVecScaleMul(sigma_tau_ch, elrssig.keyImg, pp.paramMa),
//				pp.paramMa)
//		}
//
//		//seedj_tmp := make([]byte, 0, len(msg)+ringSize*pp.paramKA*pp.paramDC*4+pp.paramK*pp.paramKA*pp.paramDC*4+pp.paramK*pp.paramKC*pp.paramDC*4+pp.paramKA*pp.paramDC*4+pp.paramMa*pp.paramDC*4)
//		//appendPolyNTTToBytes := func(a *PolyNTT) {
//		//	for k := 0; k < pp.paramDC; k++ {
//		//		seedj_tmp = append(seedj_tmp, byte(a.coeffs[k]>>0))
//		//		seedj_tmp = append(seedj_tmp, byte(a.coeffs[k]>>8))
//		//		seedj_tmp = append(seedj_tmp, byte(a.coeffs[k]>>16))
//		//		seedj_tmp = append(seedj_tmp, byte(a.coeffs[k]>>24))
//		//	}
//		//}
//		//// M
//		//for i := 0; i < len(msg); i++ {
//		//	seedj_tmp = append(seedj_tmp, msg...)
//		//}
//		//// List
//		//for i := 0; i < ringSize; i++ {
//		//	for ii := 0; ii < pp.paramKA; ii++ {
//		//		appendPolyNTTToBytes(t_as[i].polyNTTs[ii])
//		//	}
//		//}
//		//// w_(a,j-1)^(t)   w_(c,j-1)^(t)
//		//for i := 0; i < pp.paramK; i++ {
//		//	for ii := 0; ii < pp.paramKA; ii++ {
//		//		appendPolyNTTToBytes(w_as[i].polyNTTs[ii])
//		//	}
//		//	for ii := 0; ii < pp.paramKC+1; ii++ {
//		//		appendPolyNTTToBytes(w_cs[i].polyNTTs[ii])
//		//	}
//		//}
//		//// w_hat_(a,j-1)^(k-1)
//		//for i := 0; i < pp.paramKA; i++ {
//		//	appendPolyNTTToBytes(w_hat_as[pp.paramK-1].polyNTTs[i])
//		//}
//		//// I
//		//for i := 0; i < pp.paramMa; i++ {
//		//	appendPolyNTTToBytes(elrssig.keyImg.polyNTTs[i])
//		//}
//		seedj_tmp := pp.collectBytesForELR(msg, ringSize, t_as, w_as, w_cs, w_hat_as, elrssig.keyImg)
//		seedj, err = Hash(seedj_tmp) // todo_DONE
//		if err != nil {
//			return false
//		}
//	}
//
//	if bytes.Compare(elrssig.chseed, seedj) != 0 {
//		return false
//	}
//
//	return true
//}
//
//func (pp *PublicParameter) generateMatrix(seed []byte, rowLength int, colLength int) ([]*PolyVec, error) {
//	var err error
//	// check the length of seed
//	ret := make([]*PolyVec, rowLength)
//	buf := make([]byte, colLength*pp.paramDC*4)
//	XOF := sha3.NewShake128()
//	for i := 0; i < rowLength; i++ {
//		ret[i] = pp.NewZeroPolyVec(colLength)
//		for j := 0; j < colLength; j++ {
//			XOF.Reset()
//			_, err = XOF.Write(append(seed, byte(i), byte(j)))
//			if err != nil {
//				return nil, err
//			}
//			_, err = XOF.Read(buf)
//			if err != nil {
//				return nil, err
//			}
//			got := pp.rejectionUniformWithZq(buf, pp.paramDC)
//			if len(got) < pp.paramDC {
//				newBuf := make([]byte, pp.paramDC*4)
//				_, err = XOF.Read(newBuf)
//				if err != nil {
//					return nil, err
//				}
//				got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramDC-len(got))...)
//			}
//			for k := 0; k < pp.paramDC; k++ {
//				ret[i].polys[j].coeffs[k] = got[k]
//			}
//		}
//	}
//	return ret, nil
//}
//
//func (pp *PublicParameter) generateNTTMatrix(seed []byte, rowLength int, colLength int) ([]*PolyNTTVec, error) {
//	var err error
//	// check the length of seed
//	res := make([]*PolyNTTVec, rowLength)
//	buf := make([]byte, colLength*pp.paramDC*4)
//	XOF := sha3.NewShake128()
//	for i := 0; i < rowLength; i++ {
//		res[i] = pp.NewZeroPolyNTTVec(colLength)
//		//		res[i] = NewPolyNTTVec(colLength, pp.paramDC)
//		for j := 0; j < colLength; j++ {
//			XOF.Reset()
//			_, err = XOF.Write(seed)
//			if err != nil {
//				return nil, err
//			}
//			_, err = XOF.Write([]byte{byte(i), byte(j)})
//			if err != nil {
//				return nil, err
//			}
//			_, err = XOF.Read(buf)
//			if err != nil {
//				return nil, err
//			}
//			got := pp.rejectionUniformWithZq(buf, pp.paramDC)
//			if len(got) < pp.paramLC {
//				newBuf := make([]byte, pp.paramDC*4)
//				_, err = XOF.Read(newBuf)
//				if err != nil {
//					return nil, err
//				}
//				got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramDC-len(got))...)
//			}
//			for k := 0; k < pp.paramDC; k++ {
//				res[i].polyNTTs[j].coeffs[k] = got[k]
//			}
//		}
//	}
//	return res, nil
//}
//
//// generatePolyVecWithProbabilityDistributions generate a poly whose coefficient is in S_r named Probability Distribution
//func (pp *PublicParameter) generatePolyVecWithProbabilityDistributions(seed []byte, vecLen int) (*PolyVec, error) {
//	var err error
//	// check the length of seed
//	ret := pp.NewPolyVec(vecLen)
//	buf := make([]byte, pp.paramDC*4)
//	XOF := sha3.NewShake128()
//	for i := 0; i < vecLen; i++ {
//		XOF.Reset()
//		_, err = XOF.Write(seed)
//		if err != nil {
//			return nil, err
//		}
//		_, err = XOF.Write([]byte{byte(i)})
//		if err != nil {
//			return nil, err
//		}
//		_, err = XOF.Read(buf)
//		if err != nil {
//			return nil, err
//		}
//		_, got, err := randomnessFromProbabilityDistributions(buf, pp.paramDC)
//		if len(got) < pp.paramLC {
//			newBuf := make([]byte, pp.paramDC)
//			_, err = XOF.Read(newBuf)
//			if err != nil {
//				return nil, err
//			}
//			_, newGot, err := randomnessFromProbabilityDistributions(newBuf, pp.paramDC-len(got))
//			if err != nil {
//				return nil, err
//			}
//			got = append(got, newGot...)
//		}
//		for k := 0; k < pp.paramDC; k++ {
//			ret.polys[i].coeffs[k] = got[k]
//		}
//	}
//	return ret, nil
//}
//func (pp *PublicParameter) generateBits(seed []byte, length int) ([]byte, error) {
//	var err error
//	// check the length of seed
//	res := make([]byte, length)
//	buf := make([]byte, (length+7)/8)
//	XOF := sha3.NewShake128()
//	for i := 0; i < (length+7)/8; i++ {
//		XOF.Reset()
//		_, err = XOF.Write(append(seed, byte(i)))
//		if err != nil {
//			return nil, err
//		}
//		_, err = XOF.Read(buf)
//		if err != nil {
//			return nil, err
//		}
//		for j := 0; j < 8 && 8*i+j < length; j++ {
//			res[8*i+j] = buf[i] & (1 << j) >> j
//		}
//	}
//	return res[:length], nil
//}
//
////TODO_DONE: uniform sample a element in Z_q from buf as many as possible
//// rejectionUniformWithZq uniform sample some element in Z_q from buf as many as possible
//func (pp *PublicParameter) rejectionUniformWithZq(seed []byte, length int) []int32 {
//	res := make([]int32, 0, length)
//	var curr int
//	var pos int
//	var t uint32
//	//q=1111_1111_1111_1111_1110_1110_0000_0001
//	xof := sha3.NewShake128()
//	cnt := 1
//	for len(res) < length {
//		buf := make([]byte, (length-len(res))*4)
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
//		for pos < len(buf) {
//			// 从buf中读取32个bit（4byte）
//			t = uint32(buf[pos])
//			t |= uint32(buf[pos+1]) << 8
//			t |= uint32(buf[pos+2]) << 16
//			t |= uint32(buf[pos+3]) << 24
//			if t < pp.paramQC {
//				res = append(res, int32(t-pp.paramQC))
//				curr += 1
//				if curr >= length {
//					break
//				}
//			}
//			pos += 4
//		}
//		cnt++
//	}
//
//	return res
//}
//func (pp *PublicParameter) rejUniformWithZQa(seed []byte, length int) []int64 {
//	res := make([]int64, 0, length)
//	//q=1000_0000_0000_0000_0001_0000_0000_0001_0001
//	xof := sha3.NewShake128()
//	cnt := 1
//	var pos int
//	var t int64
//	for len(res) < length {
//		buf := make([]byte, (length-len(res))*4)
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
//		for pos+8 < len(buf) {
//			t = int64(buf[pos+0])
//			pos++
//			t |= int64(buf[pos+1]) << 8
//			pos++
//			t |= int64(buf[pos+2]) << 16
//			pos++
//			t |= int64(buf[pos+3]) << 24
//			pos++
//			t |= (int64(buf[pos]+4) >> 4) << 32
//			pos++
//			t &= 0xFFFFFFFFF
//			if t < pp.paramQA {
//				res = append(res, t-(pp.paramQA-1)/2)
//			}
//			t = int64(buf[pos+4]&0xF0) >> 4
//			pos++
//			t |= int64(buf[pos+5]) << 4
//			pos++
//			t |= int64(buf[pos+6]) << 12
//			pos++
//			t |= int64(buf[pos+7]) << 20
//			pos++
//			t |= int64(buf[pos+8]) << 28
//			pos++
//			t &= 0xFFFFFFFFF
//			if t < pp.paramQA {
//				res = append(res, t-(pp.paramQA-1)/2)
//			}
//		}
//		cnt++
//	}
//	return res
//}
//
///**
//todo_DONE: generate MatrixA from pp.Cstr
//*/
//// expandPubMatrixA generate the a matrix according to the given seed
//func (pp *PublicParameter) expandPubMatrixA(seed []byte) (matrixA []*PolyNTTVec, err error) {
//	res := make([]*PolyNTTVec, pp.paramKA)
//	for i := 0; i < pp.paramKA; i++ {
//		res[i] = pp.NewZeroPolyNTTVec(pp.paramLA)
//		for j := 0; j < pp.paramKA; j++ {
//			for k := 0; k < pp.paramDC; k++ {
//				res[i].polyNTTs[j].coeffs[k] = 1
//			}
//		}
//	}
//	// generate the remained sub-matrix
//	matrix, err := pp.generateNTTMatrix(seed, pp.paramKA, 1+pp.paramLambdaA)
//	if err != nil {
//		return nil, err
//	}
//	for i := 0; i < len(matrix); i++ {
//		for j := 0; j < len(matrix[i].polyNTTs); j++ {
//			for k := 0; k < pp.paramDC; k++ {
//				res[i].polyNTTs[j+pp.paramKA].coeffs[k] = matrix[i].polyNTTs[j].coeffs[k]
//			}
//		}
//	}
//	return res, nil
//}
//
//func (pp *PublicParameter) expandPubVecA(seed []byte) (matrixA *PolyNTTVec, err error) {
//	res := pp.NewZeroPolyNTTVec(pp.paramLA)
//	for i := 0; i < pp.paramDC; i++ {
//		res.polyNTTs[pp.paramKA].coeffs[i] = 1
//	}
//	// generate the remained sub-matrix
//	matrix, err := pp.generateNTTMatrix(seed, 1, 1+pp.paramLambdaA)
//	if err != nil {
//		return nil, err
//	}
//	for i := 0; i < len(matrix); i++ {
//		res.polyNTTs[i+pp.paramKA+1] = matrix[0].polyNTTs[i]
//	}
//	return res, nil
//}
//
///**
//todo_DONE: generate MatrixB from pp.Cstr
//todo_DONE: store the matrices in PP or generate them each time they are generated
//*/
//// expandPubMatrixA generate the a matrix according to the given seed
//func (pp *PublicParameter) expandPubMatrixB(seed []byte) (matrixB []*PolyNTTVec, err error) {
//	res := make([]*PolyNTTVec, pp.paramKC)
//	for i := 0; i < pp.paramKC; i++ {
//		res[i] = pp.NewZeroPolyNTTVec(pp.paramLC)
//		for j := 0; j < pp.paramKC; j++ {
//			for k := 0; k < pp.paramDC; k++ {
//				res[i].polyNTTs[j].coeffs[k] = 1
//			}
//		}
//	}
//	// generate the remained sub-matrix
//	matrix, err := pp.generateNTTMatrix(seed, pp.paramKC, 1+pp.paramLambdaC)
//	if err != nil {
//		return nil, err
//	}
//	for i := 0; i < len(matrix); i++ {
//		for j := 0; j < len(matrix[i].polyNTTs); j++ {
//			for k := 0; k < pp.paramDC; k++ {
//				res[i].polyNTTs[j+pp.paramKC].coeffs[k] = matrix[i].polyNTTs[j].coeffs[k]
//			}
//		}
//	}
//	return res, nil
//}
//
//// expandPubMatrixA generate the a matrix according to the given seed
//func (pp *PublicParameter) expandPubMatrixC(seed []byte) (matrixC []*PolyNTTVec, err error) {
//	matrix, err := pp.generateNTTMatrix(seed, pp.paramI+pp.paramJ+7, pp.paramLC)
//	if err != nil {
//		return nil, err
//	}
//	return matrix, nil
//}
//
//func (pp *PublicParameter) expandPubMatrixH(seed []byte) (matrixH []*PolyNTTVec, err error) {
//	res := make([]*PolyNTTVec, pp.paramI+pp.paramJ+7)
//
//	unitPoly := pp.NewPoly()
//	var tmp *PolyNTT
//	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
//		res[i] = pp.NewZeroPolyNTTVec(pp.paramLC)
//		unitPoly.coeffs[i] = 1
//		tmp = pp.NTT(unitPoly)
//		for j := 0; j < pp.paramDC; j++ {
//			res[i].polyNTTs[pp.paramKC].coeffs[j] = tmp.coeffs[j]
//		}
//		unitPoly.coeffs[i] = 0
//	}
//
//	// generate the remained sub-matrix
//	matrix, err := pp.generateNTTMatrix(seed, pp.paramI+pp.paramJ+7, pp.paramLC-pp.paramKC-pp.paramI-pp.paramJ-7)
//	if err != nil {
//		return nil, err
//	}
//	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
//		for j := 0; j < pp.paramLA-pp.paramKA-pp.paramI-pp.paramJ-7; j++ {
//			for k := 0; k < pp.paramDC; k++ {
//				res[i].polyNTTs[pp.paramKC+pp.paramI+pp.paramJ+7+j].coeffs[k] = matrix[i].polyNTTs[j].coeffs[k]
//			}
//		}
//	}
//	return res, nil
//}
//
//func (pp PublicParameter) expandBalCh(seed []byte) (*PolyNTT, error) {
//	length := pp.paramDC
//	// check the length of seed, make sure the randomness is enough
//	if seed == nil {
//		return nil, ErrLength
//	}
//	buf := make([]byte, length/4)
//	// handle the seed using sha3.shake128
//	xof := sha3.NewShake128()
//	xof.Reset()
//	_, err := xof.Write(seed)
//	if err != nil {
//		return nil, err
//	}
//	_, err = xof.Read(buf)
//	if err != nil {
//		return nil, err
//	}
//	res := make([]int32, pp.paramDC)
//	var a1, a2, a3, a4, b1, b2, b3, b4 int32
//	for i := 0; i < length/4; i++ {
//		a1 = int32((seed[i] & (1 << 0)) >> 0)
//		b1 = int32((seed[i] & (1 << 1)) >> 1)
//		a2 = int32((seed[i] & (1 << 2)) >> 2)
//		b2 = int32((seed[i] & (1 << 3)) >> 3)
//		a3 = int32((seed[i] & (1 << 4)) >> 4)
//		b3 = int32((seed[i] & (1 << 5)) >> 5)
//		a4 = int32((seed[i] & (1 << 6)) >> 6)
//		b4 = int32((seed[i] & (1 << 7)) >> 7)
//		res[2*i+0] = a1 - b1
//		res[2*i+1] = a2 - b2
//		res[2*i+2] = a3 - b3
//		res[2*i+3] = a4 - b4
//	}
//	return &PolyNTT{coeffs: res}, nil
//}
//
////func (pp PublicParameter) expandRand(seed []byte) (*PolyNTTVec, *PolyNTTVec, error) {
////
////}
//
//// expandKeyImgMatrix enerate the a matrix according to the given seed and a const string "IM"
//func (pp PublicParameter) expandKeyImgMatrix(seed []byte) (matrixH []*PolyNTTVec, err error) {
//	matrix, err := pp.generateNTTMatrix(append(seed, 'I', 'M'), pp.paramMa, pp.paramLA)
//	if err != nil {
//		return nil, err
//	}
//	return matrix, nil
//}
//
//// Deprecated: Before calling the function expandRandomnessA, you should got the random bytes
//func (pp *PublicParameter) sampleRandomnessA() (seed []byte, r *PolyVec, err error) {
//	polys := make([]*Poly, pp.paramLA)
//	for i := 0; i < pp.paramLA; i++ {
//		var tmp []int32
//		seed, tmp, err = randomnessFromProbabilityDistributions(nil, pp.paramDC)
//		if err != nil {
//			return nil, nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//
//	retr := &PolyVec{
//		polys: polys,
//	}
//	return seed, retr, nil
//}
//
///*
//todo_DONE: expand a seed to a PolyVec with length l_a from (S_r)^d
//*/
//// expandRandomnessA expand a bytes slice to a PolyVec with length l_a from (S_r)^d.
//// And before calling, you should have got the seed.
//func (pp *PublicParameter) expandRandomnessA(seed []byte) (r *PolyVec, err error) {
//	if len(seed) == 0 {
//		return nil, ErrLength
//	}
//	seed = append(seed, 'A')
//	r, err = pp.generatePolyVecWithProbabilityDistributions(seed, pp.paramLA)
//	if err != nil {
//		return nil, err
//	}
//	return r, nil
//}
//
//// sampleRandomnessC sample a bytes slice to a PolyVec with length l_c from (S_r)^d.
//// And before calling, you should have got the seed.
//func (pp *PublicParameter) sampleRandomnessC() (r *PolyVec, err error) {
//	polys := make([]*Poly, pp.paramLC)
//
//	for i := 0; i < pp.paramLC; i++ {
//		var tmp []int32
//		_, tmp, err = randomnessFromProbabilityDistributions(nil, pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//	rst := &PolyVec{
//		polys: polys,
//	}
//	return rst, nil
//}
//
//// sampleRandomnessR sample the ramdoness r for ComGen
//func (pp *PublicParameter) sampleRandomnessR() (r *PolyVec, err error) {
//	polys := make([]*Poly, pp.paramLC)
//
//	for i := 0; i < pp.paramLC; i++ {
//		var tmp []int32
//		_, tmp, err = randomnessFromProbabilityDistributions(nil, pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//	rst := &PolyVec{
//		polys: polys,
//	}
//	return rst, nil
//}
//
//// expandRandomnessC expand a bytes slice with given bytes slice to a PolyVec with length l_c from (S_r)^d.
//// And before calling, you should have got the seed.
//func (pp *PublicParameter) expandRandomnessC(seed []byte) (r *PolyVec, err error) {
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
//
//// sampleMaskA sample a bytes slice with given bytes slice to a PolyVec with length l_a from (S_etaA)^d.
//// And before calling, you should have got the seed.
//func (pp PublicParameter) sampleMaskA() (r *PolyVec, err error) {
//	polys := make([]*Poly, pp.paramLA)
//
//	for i := 0; i < pp.paramLA; i++ {
//		tmp, err := randomnessFromEtaA(nil, pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//	rst := &PolyVec{
//		polys: polys,
//	}
//	return rst, nil
//}
//
//func (pp PublicParameter) sampleMaskC() (r *PolyVec, err error) {
//	// etaC
//	polys := make([]*Poly, pp.paramLC)
//
//	for i := 0; i < pp.paramLC; i++ {
//		tmp, err := randomnessFromEtaC(RandomBytes(pp.paramSysBytes), pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//	rst := &PolyVec{
//		polys: polys,
//	}
//	return rst, nil
//}
//
//func (pp PublicParameter) sampleMaskC2() (r *PolyVec, err error) {
//	polys := make([]*Poly, pp.paramLC)
//
//	for i := 0; i < pp.paramLC; i++ {
//		tmp, err := randomnessFromEtaC2(nil, pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//	rst := &PolyVec{
//		polys: polys,
//	}
//	return rst, nil
//}
//
//func (pp PublicParameter) sampleZetaA() (r *PolyVec, err error) {
//	polys := make([]*Poly, pp.paramLA)
//
//	for i := 0; i < pp.paramLA; i++ {
//		tmp, err := randomnessFromZetaA(nil, pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//	rst := &PolyVec{
//		polys: polys,
//	}
//	return rst, nil
//}
//
//func (pp PublicParameter) sampleZetaC() (r *PolyVec, err error) {
//	polys := make([]*Poly, pp.paramLC)
//
//	for i := 0; i < pp.paramLC; i++ {
//		tmp, err := randomnessFromChallengeSpace(nil, pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//	rst := &PolyVec{
//		polys: polys,
//	}
//	return rst, nil
//}
//
//func (pp PublicParameter) sampleZetaC2() (r *PolyVec, err error) {
//
//	polys := make([]*Poly, pp.paramLC)
//
//	for i := 0; i < pp.paramLC; i++ {
//		tmp, err := randomnessFromZetaC2(nil, pp.paramDC)
//		if err != nil {
//			return nil, err
//		}
//		polys[i] = &Poly{coeffs: tmp}
//	}
//	rst := &PolyVec{
//		polys: polys,
//	}
//	return rst, nil
//}
//
//func (pp *PublicParameter) expandRandomBitsV(seed []byte) (r []byte, err error) {
//	if len(seed) == 0 {
//		return nil, ErrLength
//	}
//	seed = append(seed, 'V')
//	r, err = pp.generateBits(seed, pp.paramDC)
//	if err != nil {
//		return nil, err
//	}
//	return r, nil
//}
//
//func (pp *PublicParameter) sampleUniformPloyWithLowZeros() (r *Poly) {
//	ret := pp.NewZeroPoly()
//	seed := RandomBytes(pp.paramSysBytes)
//	tmp := pp.rejectionUniformWithZq(seed, pp.paramDC-pp.paramK)
//	for i := pp.paramK; i < pp.paramDC; i++ {
//		ret.coeffs[i] = tmp[i-pp.paramK]
//	}
//	return ret
//}
//
//func (pp *PublicParameter) expandUniformRandomnessInRqZq(seed []byte, n1 int, m int) (alphas []*PolyNTT, betas []*PolyNTT, gammas [][][]int32, err error) {
//	alphas = make([]*PolyNTT, n1)
//	betas = make([]*PolyNTT, pp.paramK)
//	gammas = make([][][]int32, pp.paramK)
//	// check the length of seed
//
//	XOF := sha3.NewShake128()
//	// alpha
//	XOF.Reset()
//	_, err = XOF.Write(append(seed, 0))
//	if err != nil {
//		return nil, nil, nil, err
//	}
//	buf := make([]byte, n1*pp.paramDC*4)
//	for i := 0; i < n1; i++ {
//		alphas[i] = pp.NewZeroPolyNTT()
//		_, err = XOF.Read(buf)
//		if err != nil {
//			return nil, nil, nil, err
//		}
//		got := pp.rejectionUniformWithZq(buf, pp.paramDC)
//		if len(got) < pp.paramLC {
//			newBuf := make([]byte, pp.paramDC*4)
//			_, err = XOF.Read(newBuf)
//			if err != nil {
//				return nil, nil, nil, err
//			}
//			got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramDC-len(got))...)
//		}
//		for k := 0; k < pp.paramDC; k++ {
//			alphas[i].coeffs[k] = got[k]
//		}
//	}
//	// betas
//	XOF.Reset()
//	_, err = XOF.Write(append(seed, 1))
//	if err != nil {
//		return nil, nil, nil, err
//	}
//	buf = make([]byte, pp.paramK*pp.paramDC*4)
//	for i := 0; i < pp.paramK; i++ {
//		betas[i] = pp.NewZeroPolyNTT()
//		_, err = XOF.Read(buf)
//		if err != nil {
//			return nil, nil, nil, err
//		}
//		got := pp.rejectionUniformWithZq(buf, pp.paramDC)
//		if len(got) < pp.paramLC {
//			newBuf := make([]byte, pp.paramDC*4)
//			_, err = XOF.Read(newBuf)
//			if err != nil {
//				return nil, nil, nil, err
//			}
//			got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramDC-len(got))...)
//		}
//		for k := 0; k < pp.paramDC; k++ {
//			betas[i].coeffs[k] = got[k]
//		}
//	}
//	// gammas
//	XOF.Reset()
//	_, err = XOF.Write(append(seed, 2))
//	if err != nil {
//		return nil, nil, nil, err
//	}
//	buf = make([]byte, m*pp.paramDC*4)
//	for i := 0; i < pp.paramK; i++ {
//		gammas[i] = make([][]int32, m)
//		_, err = XOF.Read(buf)
//		for j := 0; j < m; j++ {
//			gammas[i][j] = make([]int32, pp.paramDC)
//			got := pp.rejectionUniformWithZq(buf, pp.paramDC)
//			if len(got) < pp.paramLC {
//				newBuf := make([]byte, pp.paramDC*4)
//				_, err = XOF.Read(newBuf)
//				if err != nil {
//					return nil, nil, nil, err
//				}
//				got = append(got, pp.rejectionUniformWithZq(newBuf, pp.paramDC-len(got))...)
//			}
//			for k := 0; k < pp.paramDC; k++ {
//				gammas[i][j][k] = got[k]
//			}
//		}
//	}
//	return alphas, betas, gammas, nil
//}
//
//func (pp *PublicParameter) sampleUniformWithinEtaF() ([]int32, error) {
//	// 1<<28-1
//	return rejectionUniformWithinEtaF(RandomBytes(pp.paramSysBytes), pp.paramDC)
//}
//
//func rejectionUniformWithinEtaF(seed []byte, length int) ([]int32, error) {
//	// [-1<<28+1,1<<28-1] 29bit = 28bit + 1bit
//	// 1<<18 -1
//	buf := make([]byte, (29*length+7)/8)
//	xof := sha3.NewShake128()
//	xof.Reset()
//	_, err := xof.Write(seed)
//	if err != nil {
//		return nil, err
//	}
//	_, err = xof.Read(buf)
//
//	if err != nil {
//		return nil, err
//	}
//	res := make([]int32, length)
//	pos := 0
//	for pos/7*2+1 < length {
//		res[pos/7*2+0] = int32(buf[pos+0]&0xFF)<<20 | int32(buf[pos+1])<<12 | int32(buf[pos+2])<<4 | int32(buf[pos+3]&0xF0)>>4
//		res[pos/7*2+1] = int32(buf[pos+3]&0x0F)<<24 | int32(buf[pos+4])<<16 | int32(buf[pos+5])<<8 | int32(buf[pos+6]&0xFF)>>0
//		pos += 7
//	}
//	for i := 0; i < length; i += 8 {
//		for j := 0; j < 8 && i+j < length; j++ {
//			if (buf[pos]>>j)&1 == 0 {
//				res[i+j] = -res[i+j]
//			}
//		}
//		pos++
//	}
//	return res[:length], nil
//}
//
//func (pp *PublicParameter) expandChallenge(seed []byte) (r *Poly, err error) {
//	// extend seed via sha3.Shake128
//	ret := pp.NewZeroPoly()
//	buf := make([]byte, pp.paramDC/4)
//	XOF := sha3.NewShake128()
//	XOF.Reset()
//	_, err = XOF.Write(append(seed, byte('C'), byte('h')))
//	if err != nil {
//		return nil, err
//	}
//	_, err = XOF.Read(buf)
//	if err != nil {
//		return nil, err
//	}
//	got, err := randomnessFromChallengeSpace(seed, pp.paramDC)
//	for i := 0; i < pp.paramDC; i++ {
//		ret.coeffs[i] = got[i]
//	}
//	return ret, nil
//}
//
///*func (pp *PublicParameter) sigmaPolyNTT(polyNTT *PolyNTT) (r *PolyNTT) {
//	coeffs := make([]int32, pp.paramDC)
//	for i := 0; i < pp.paramDC; i++ {
//		coeffs[i] = polyNTT.coeffs[pp.paramSigmaPermutation[i]]
//	}
//	return &PolyNTT{coeffs}
//}*/
//
///*
// t: 0~(k-1)
//*/
//func (pp *PublicParameter) sigmaPowerPolyNTT(polyNTT *PolyNTT, t int) (r *PolyNTT) {
//	coeffs := make([]int32, pp.paramDC)
//	for i := 0; i < pp.paramDC; i++ {
//		coeffs[i] = polyNTT.coeffs[pp.paramSigmaPermutations[t][i]]
//	}
//	return &PolyNTT{coeffs}
//}
//
//// sigmaInvPolyNTT performances the sigma transformation where the sigma is defined as sigma_65 in {Z_256}^*
//func (pp *PublicParameter) sigmaInvPolyNTT(polyNTT *PolyNTT, t int) (r *PolyNTT) {
//	coeffs := make([]int32, pp.paramDC)
//	for i := 0; i < pp.paramDC; i++ {
//		//coeffs[i] = polyNTT.coeffs[pp.paramSigmaInvPermutations[t][i]]
//		coeffs[i] = polyNTT.coeffs[pp.paramSigmaPermutations[(pp.paramK-t)%pp.paramK][i]]
//	}
//	return &PolyNTT{coeffs}
//}
//
///**
//This method allow the vectors to be 2D, i.e. matrix
//*/
//func (pp *PublicParameter) intMatrixInnerProduct(a [][]int32, b [][]int32, rowNum int, colNum int) (r int32) {
//	rst := int64(0)
//	for i := 0; i < rowNum; i++ {
//		for j := 0; j < colNum; j++ {
//			rst = pp.reduceInt64(rst + pp.reduceInt64(int64(a[i][j])*int64(b[i][j])))
//		}
//	}
//
//	return int32(rst)
//}
//
//func (pp *PublicParameter) intVecInnerProduct(a []int32, b []int32, vecLen int) (r int32) {
//	rst := int64(0)
//	for i := 0; i < vecLen; i++ {
//		rst = pp.reduceInt64(rst + pp.reduceInt64(int64(a[i])*int64(b[i])))
//	}
//
//	return int32(rst)
//}
//
//func intToBinary(v uint64, bitNum int) (bits []int64) {
//	rstbits := make([]int64, bitNum)
//	for i := 0; i < bitNum; i++ {
//		rstbits[i] = int64((v >> i) & 1)
//	}
//	return rstbits
//}
//
//func expandBinaryMatrix(seed []byte, rownum int, colnum int) (binM [][]byte, err error) {
//	binM = make([][]byte, rownum)
//	XOF := sha3.NewShake128()
//	for i := 0; i < rownum; i++ {
//		buf := make([]byte, (colnum+7)/8)
//		binM[i] = make([]byte, (colnum+7)/8)
//		XOF.Reset()
//		_, err = XOF.Write(append(seed, byte(i)))
//		if err != nil {
//			return nil, err
//		}
//		_, err = XOF.Read(buf)
//		if err != nil {
//			return nil, err
//		}
//		binM[i] = buf
//	}
//	return binM, nil
//}
//
//func (cmt *Commitment) toPolyNTTVec() *PolyNTTVec {
//	ret := &PolyNTTVec{}
//	ret.polyNTTs = make([]*PolyNTT, len(cmt.b.polyNTTs)+1)
//	copy(ret.polyNTTs, cmt.b.polyNTTs)
//	ret.polyNTTs[len(cmt.b.polyNTTs)] = cmt.c
//
//	return ret
//}
//
///*func transposeMatrix(matrix [][]int32, rowNum int, colNum int) (transM [][]int32) {
//	rettransMatrix := make([][]int32, colNum)
//	for i := 0; i < colNum; i++ {
//		rettransMatrix[i] = make([]int32, rowNum)
//		for j := 0; j < rowNum; j++ {
//			rettransMatrix[i][j] = matrix[j][i]
//		}
//	}
//
//	return rettransMatrix
//}*/
//
//func getMatrixColumn(matrix [][]byte, rowNum int, j int) (col []int64) {
//	retcol := make([]int64, rowNum)
//	for i := 0; i < rowNum; i++ {
//		retcol[i] = int64((matrix[i][j/8] >> (j % 8)) & 1)
//	}
//	return retcol
//}
//
//func (pp *PublicParameter) genUlpPolyNTTs(rpulpType RpUlpType, binMatrixB [][]byte, I int, J int, gammas [][][]int32) (ps [][]*PolyNTT) {
//	p := make([][]*PolyNTT, pp.paramK)
//
//	switch rpulpType {
//	case RpUlpTypeCbTx1:
//		break
//	case RpUlpTypeCbTx2:
//		n := J
//		n2 := n + 2
//		// m = 3
//		for t := 0; t < pp.paramK; t++ {
//			p[t] = make([]*PolyNTT, n2)
//			for j := 0; j < n; j++ {
//				p[t][j] = &PolyNTT{gammas[t][0]}
//			}
//			//	p[t][n] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
//			coeffs := make([]int32, pp.paramDC)
//			for i := 0; i < pp.paramDC; i++ {
//				// F^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
//				// B^T[i]: ith-col of B
//				coeffs[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)
//				if i == 0 {
//					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] + gammas[t][0][i]))
//					coeffs[i] = pp.reduce(int64(coeffs[i]) + int64(gammas[t][1][i]) + int64(gammas[t][0][i]))
//				} else if i < (pp.paramN - 1) {
//					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
//					coeffs[i] = pp.reduce(int64(coeffs[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
//				} else { // i in [N-1, d-1]
//					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
//					coeffs[i] = pp.reduce(int64(coeffs[i]) + int64(gammas[t][1][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
//				}
//			}
//			p[t][n] = &PolyNTT{coeffs}
//
//			p[t][n+1] = &PolyNTT{gammas[t][2]}
//		}
//	case RpUlpTypeTrTx1:
//		n := I + J
//		n2 := n + 2
//		// m = 3
//		for t := 0; t < pp.paramK; t++ {
//			p[t] = make([]*PolyNTT, n2)
//
//			p[t][0] = &PolyNTT{gammas[t][0]}
//
//			minuscoeffs := make([]int32, pp.paramDC)
//			for i := 0; i < pp.paramDC; i++ {
//				minuscoeffs[i] = -gammas[t][0][i]
//			}
//			for j := 1; j < n; j++ {
//				p[t][j] = &PolyNTT{minuscoeffs}
//			}
//
//			//	p[t][n] = NTT^{-1}((-F)^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
//			coeffs := make([]int32, pp.paramDC)
//			for i := 0; i < pp.paramDC; i++ {
//				//(-F)^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
//				// B^T[i]: ith-col of B
//				coeffs[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)
//				if i == 0 {
//					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] - gammas[t][0][i]))
//					coeffs[i] = pp.reduce(int64(coeffs[i]) + int64(gammas[t][1][i]) - int64(gammas[t][0][i]))
//				} else if i < (pp.paramN - 1) {
//					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
//					coeffs[i] = pp.reduce(int64(coeffs[i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
//				} else { // i in [N-1, d-1]
//					//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
//					coeffs[i] = pp.reduce(int64(coeffs[i]) + int64(gammas[t][1][i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
//				}
//			}
//			p[t][n] = &PolyNTT{coeffs}
//
//			p[t][n+1] = &PolyNTT{gammas[t][2]}
//		}
//	case RpUlpTypeTrTx2:
//		n := I + J
//		n2 := n + 4
//		//	B : d rows 2d columns
//		//	m = 5
//		for t := 0; t < pp.paramK; t++ {
//			p[t] = make([]*PolyNTT, n2)
//
//			for j := 0; j < I; j++ {
//				p[t][j] = &PolyNTT{gammas[t][0]}
//			}
//			for j := I; j < I+J; j++ {
//				p[t][j] = &PolyNTT{gammas[t][1]}
//			}
//
//			coeffs_n := make([]int32, pp.paramDC)
//			for i := 0; i < pp.paramDC; i++ {
//				coeffs_n[i] = pp.reduce(int64(-gammas[t][0][i]) + int64(-gammas[t][1][i]))
//			}
//			p[t][n] = &PolyNTT{coeffs_n}
//
//			//	p[t][n+1] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][2] + B_1^T gamma[t][4])
//			coeffs_np1 := make([]int32, pp.paramDC)
//			for i := 0; i < pp.paramDC; i++ {
//				//F^T[i] gamma[t][0] + F_1^T[i] gamma[t][2] + B^T[i] gamma[t][4]
//				coeffs_np1[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][4], pp.paramDC)
//				if i == 0 {
//					//coeffs_np1[i] = pp.reduceBigInt(int64(coeffs_np1[i] + gammas[t][2][i] + gammas[t][0][i]))
//					coeffs_np1[i] = pp.reduce(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) + int64(gammas[t][0][i]))
//				} else if i < (pp.paramN - 1) {
//					//coeffs_np1[i] = pp.reduceBigInt(int64(coeffs_np1[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
//					coeffs_np1[i] = pp.reduce(int64(coeffs_np1[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
//				} else { // i in [N-1, d-1]
//					//coeffs_np1[i] = pp.reduceBigInt(int64(coeffs_np1[i] + gammas[t][2][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
//					coeffs_np1[i] = pp.reduce(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
//				}
//			}
//			p[t][n+1] = &PolyNTT{coeffs_np1}
//
//			//	p[t][n+2] = NTT^{-1}(F^T gamma[t][1] + F_1^T gamma[t][3] + B_2^T gamma[t][4])
//			coeffs_np2 := make([]int32, pp.paramDC)
//			for i := 0; i < pp.paramDC; i++ {
//				//F^T[i] gamma[t][1] + F_1^T[i] gamma[t][3] + B_2^T[i] gamma[t][4]
//				coeffs_np2[i] = pp.intVecInnerProduct(getMatrixColumn(binMatrixB, pp.paramDC, pp.paramDC+i), gammas[t][4], pp.paramDC)
//				if i == 0 {
//					//coeffs_np2[i] = pp.reduceBigInt(int64(coeffs_np2[i] + gammas[t][3][i] + gammas[t][1][i]))
//					coeffs_np2[i] = pp.reduce(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) + int64(gammas[t][1][i]))
//				} else if i < (pp.paramN - 1) {
//					//coeffs_np2[i] = pp.reduceBigInt(int64(coeffs_np2[i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
//					coeffs_np2[i] = pp.reduce(int64(coeffs_np2[i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
//				} else { // i in [N-1, d-1]
//					//coeffs_np2[i] = pp.reduceBigInt(int64(coeffs_np2[i] + gammas[t][3][i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
//					coeffs_np2[i] = pp.reduce(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
//				}
//			}
//			p[t][n+2] = &PolyNTT{coeffs_np2}
//
//			p[t][n+3] = &PolyNTT{gammas[t][4]}
//		}
//	}
//
//	return p
//}
