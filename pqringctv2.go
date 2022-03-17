package pqringct

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
	"hash"
	"math/big"
)


type AddressPublicKey struct {
	t     *PolyANTTVec // directly in NTT form
	e     *PolyANTT
}

type AddressSecretKey struct {
	s     *PolyANTTVec
	ma    *PolyANTT
}

type ValuePublicKey struct {
	pkkem *kyber.PublicKey
}

type ValueSecretKey struct {
	skkem *kyber.SecretKey
}

func (apk *AddressPublicKey) WellformCheck(pp *PublicParameterv2) bool {
	// todo
	return true
}

func (ask *AddressSecretKey) WellformCheck(pp *PublicParameterv2) bool {
	// todo
	return true
}

type Txo struct {
	*AddressPublicKey
	*ValueCommitment
	Vct []byte
	CkemSerialzed []byte
}
type LgrTxo struct {
	Txo
	Id []byte
}
type ValueCommitment struct {
	b *PolyCNTTVec
	c *PolyCNTT
}

type rpulpProofv2 struct {
	c_waves []*PolyCNTT
	c_hat_g *PolyCNTT
	psi     *PolyCNTT
	phi     *PolyCNTT
	chseed  []byte
	cmt_zs  [][]*PolyCNTTVec
	zs      []*PolyCNTTVec
}

type CoinbaseTxv2 struct {
	Vin        uint64
	OutputTxos []*Txo
	TxWitness  *CbTxWitnessv2
}

type CbTxWitnessv2 struct {
	b_hat      *PolyCNTTVec
	c_hats     []*PolyCNTT
	u_p        []int32
	rpulpproof *rpulpProofv2
}

type TxInputDescv2 struct {
	txoList []*LgrTxo
	sidx	int
	ask		*AddressSecretKey
	value	uint64
	crand	*PolyCNTTVec
}
type TxOutputDescv2 struct {
	apk	*AddressPublicKey
	vpk	*ValuePublicKey
	value uint64
}

type TransferTxv2 struct {
	//	Version uint32
	Inputs     []*TrTxInputv2
	OutputTxos []*Txo
	Fee        uint64

	TxMemo []byte

	TxWitness *TrTxWitnessv2
}

type TrTxInputv2 struct {
	TxoList	[]*LgrTxo
	//SerialNumber []byte
	SerialNumber *SerialNumber //	todo_DONE: change to a hash value
}

type TrTxWitnessv2 struct {
	ma_ps		[]*PolyANTT
	cmt_ps      []*ValueCommitment
	elrsSigs	[]*elrsSignaturev2
	b_hat		*PolyCNTT
	c_hats		[]*PolyCNTT
	u_p			[]int64
	rpulpproof	*rpulpProofv2
}

type SerialNumber *PolyANTT

type elrsSignaturev2 struct {
	seeds  [][]byte
	z_as   []*PolyANTTVec
	z_cs   [][]*PolyCNTTVec
	z_cs_p [][]*PolyCNTTVec
}


/**
This method does not return seed.
Seed is genrated by the caller.
 */
func (pp *PublicParameterv2) AddressKeyGen(seed []byte) (apk *AddressPublicKey, ask *AddressSecretKey, err error) {
	var s *PolyANTTVec

	// check the validity of the length of seed
	if seed != nil && len(seed) != pp.paramSeedBytesLen {
		return nil, nil, errors.New("the length of seed is invalid")
	}
	if seed == nil {
		seed = randomBytes(pp.paramSeedBytesLen)
	}

	// this temporary byte slice is for protect seed unmodified
	tmp := make([]byte, pp.paramSeedBytesLen)
	for i := 0; i < pp.paramSeedBytesLen; i++ {
		tmp[i] = seed[i]
	}
	s, err = pp.expandRandomnessAv2(tmp)
	if err != nil {
		return nil, nil, err
	}

	tmp = make([]byte, pp.paramSeedBytesLen+2)
	for i := 0; i < pp.paramSeedBytesLen; i++ {
		tmp[i] = seed[i]
	}

	//	todo: put the tag in ahead
	mat := rejectionUniformWithQa(append(tmp, 'M', 'A'), pp.paramDA)
	ma := &PolyANTT{coeffs: mat}

	// t = A * s, will be as a part of public key
	t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s, pp.paramKA, pp.paramLA)

	// e = <a,s>+ma
	e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVecA, s, pp.paramLA), ma )

	apk = &AddressPublicKey{
		t:     t,
		e:     e,
	}
	ask = &AddressSecretKey{
		s:     s,
		ma:    ma,
	}
	return apk, ask, nil
}


func (pp *PublicParameterv2) ValueKeyGen(seed []byte) (vpk *ValuePublicKey, vsk *ValueSecretKey, err error) {

	// check the validity of the length of seed
	if seed != nil && len(seed) != pp.paramSeedBytesLen {
		return nil, nil, errors.New("the length of seed is invalid")
	}
	if seed == nil {
		seed = randomBytes(pp.paramSeedBytesLen)
	}

	// this temporary byte slice is for protect seed unmodified
	tmp := make([]byte, pp.paramSeedBytesLen)
	for i := 0; i < pp.paramSeedBytesLen; i++ {
		tmp[i] = seed[i]
	}


	kemPK, kemSK, err := pp.paramKem.CryptoKemKeyPair(tmp)
	if err != nil {
		return nil, nil, err
	}

	//	todo: shall we add kemVersion in type ValuePublicKey and ValueSecretKey
	vpk = &ValuePublicKey{
		pkkem: kemPK,
	}
	vsk = &ValueSecretKey{
		skkem: kemSK,
	}

	return vpk, vsk, nil
}

// txoGen returns an transaction output and a random polynomial related to the corresponding transaction output with the master public key and value
func (pp *PublicParameterv2) txoGen(apk *AddressPublicKey, vpk *ValuePublicKey, vin uint64) (txo *Txo, cmtr *PolyCNTTVec, err error) {
	//	got (C, kappa) from key encapsulate mechanism
	CkemSerialzed, kappa, err := vpk.pkkem.CryptoKemEnc() // todo: rename to Encaps, interface to kem

	//	expand the kappa to PolyCVec with length Lc
/*	rctmp, err := pp.expandRandomnessC(kappa)
	if err != nil {
		return nil, nil, err
	}*/
	var rctmp *PolyCVec //	todo
	cmtr = pp.NTTPolyCVec(rctmp)

	mtmp := intToBinary(vin, pp.paramDC)
	m := &PolyCNTT{coeffs: mtmp}
	// [b c]^T = C*r + [0 m]^T
	cmt := &ValueCommitment{}
	cmt.b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKC, pp.paramLC)
	cmt.c = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr, pp.paramLC),
		m,
	)

	//	vc = m ^ sk
	//	todo: the vc should have length only N, to prevent the unused D-N bits of leaking information
/*	sk, err := pp.expandRandomBitsV(kappa) // todo:
	if err != nil {
		return nil, nil, err
	}*/
	var sk []byte
	kappa = kappa
	vct := make([]byte, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		vct[i] = sk[i] ^ byte(mtmp[i])
	}

	rettxo := &Txo{
		apk,
		cmt,
		vct,
		CkemSerialzed,
	}

	return rettxo, cmtr, nil
}


func (pp *PublicParameterv2) rpulpProve(message []byte, cmts []*ValueCommitment, cmt_rs []*PolyCNTTVec, n int,
	b_hat *PolyCNTTVec, r_hat *PolyCNTTVec, c_hats []*PolyCNTT, msg_hats [][]int64, n2 int,
	n1 int, rpulpType RpUlpType, binMatrixB [][]byte,
	I int, J int, m int, u_hats [][]int64) (rpulppi *rpulpProofv2, err error) {
	// c_waves[i] = <h_i, r_i> + m_i
	c_waves := make([]*PolyCNTT, n)
	for i := 0; i < n; i++ {
		t := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], cmt_rs[i], pp.paramLC)
		c_waves[i] = pp.PolyCNTTAdd(t, &PolyCNTT{coeffs: msg_hats[i]})
	}

rpUlpProveRestart:

	cmt_ys := make([][]*PolyCNTTVec, pp.paramK)
	ys := make([]*PolyCNTTVec, pp.paramK)
	cmt_ws := make([][]*PolyCNTTVec, pp.paramK)
	ws := make([]*PolyCNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_ys[t] = make([]*PolyCNTTVec, n)
		cmt_ws[t] = make([]*PolyCNTTVec, n)
		for i := 0; i < n; i++ {
			// random some element in the {s_etaC}^Lc space
			maskCi, err := pp.sampleMaskCv2() // todo
			if err != nil {
				return nil, err
			}
			cmt_ys[t][i] = pp.NTTPolyCVec(maskCi)
			cmt_ws[t][i] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmt_ys[t][i], pp.paramKC, pp.paramLC)
		}

		maskC, err := pp.sampleMaskCv2()
		if err != nil {
			return nil, err
		}
		ys[t] = pp.NTTPolyCVec(maskC)
		ws[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
	}

	tmpg := pp.sampleUniformPloyWithLowZeros()
	g := pp.NTTPolyC(tmpg)
	// c_hat(n2+1)
	c_hat_g := pp.PolyCNTTAdd(pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], r_hat, pp.paramLC), g)

	// splicing the data to be processed
	// todo
	tmp := pp.collectBytesForRPULP1(message, n, n1, n2, binMatrixB, m, cmts, b_hat, c_hats, rpulpType, I, J, u_hats, c_waves, cmt_ws, ws, c_hat_g)
	seed_rand, err := Hash(tmp) // todo_DONE
	if err != nil {
		return nil, err
	}
	//fmt.Println("prove seed_rand=", seed_rand)
	alphas, betas, gammas, err := pp.expandUniformRandomnessInRqZqC(seed_rand, n1, m)
	if err != nil {
		return nil, err
	}
	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyCNTT, pp.paramK)
	delta_hats := make([][]*PolyCNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyCNTT, n)
		delta_hats[t] = make([]*PolyCNTT, n)
		for i := 0; i < n; i++ {
			delta_waves[t][i] = pp.PolyCNTTVecInnerProduct(pp.PolyCNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC), cmt_ys[t][i], pp.paramLC)
			delta_hats[t][i] = pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], pp.PolyCNTTVecSub(ys[t], cmt_ys[t][i], pp.paramLC), pp.paramLC)
		}
	}
	//	psi, psi'
	psi := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], r_hat, pp.paramLC)
	psip := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], ys[0],pp.paramLC)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewPolyCNTT()
		tmp2 := pp.NewPolyCNTT()
		// sum(0->n1-1)
		for i := 0; i < n1; i++ {
			// <h_i , y_t>
			tmp := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], ys[t], pp.paramLC)

			tmp1 = pp.PolyCNTTAdd(
				tmp1,
				// alpha[i] * (2 * m_i - mu) <h_i , y_t>
				pp.PolyCNTTMul(
					alphas[i],
					// (2 * m_i - mu) <h_i , y_t>
					pp.PolyCNTTMul(
						// 2 * m_i - mu
						pp.PolyCNTTSub(
							//  m_i+m_i
							pp.PolyCNTTAdd(
								&PolyCNTT{coeffs: msg_hats[i]},
								&PolyCNTT{coeffs: msg_hats[i]},
							),
							&PolyCNTT{coeffs: pp.paramMu},
						),
						tmp,
					),
				),
			)
			tmp2 = pp.PolyCNTTAdd(
				tmp2,
				// alpha[i] * <h_i , y_t> * <h_i , y_t>
				pp.PolyCNTTMul(alphas[i],
					pp.PolyCNTTMul(tmp, tmp),
					),
				)
		}

		psi = pp.PolyCNTTSub(psi, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp1, t)))
		psip = pp.PolyCNTTAdd(psip, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp2, t)))
	}
	//fmt.Printf("Prove\n")
	//fmt.Printf("psip = %v\n", psip)
	//	p^(t)_j:
	p := pp.genUlpPolyCNTTs(rpulpType, binMatrixB, I, J, gammas)

	//	phi
	phi := pp.NewZeroPolyCNTT()

	var inprd, dcInv big.Int
	dcInv.SetInt64(pp.paramDCInv)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyCNTT()
			for j := 0; j < n2; j++ {
				tmp = pp.PolyCNTTAdd(tmp, pp.PolyCNTTMul(p[t][j], &PolyCNTT{coeffs: msg_hats[j]}))
			}

			constPoly := pp.NewZeroPolyC()
			//constPoly.coeffs[0] = reduceToQc(intMatrixInnerProductWithReduction(u_hats, gammas[t], m, pp.paramDC, pp.paramQC) * int64(pp.paramDCInv))
			inprd.SetInt64(intMatrixInnerProductWithReduction(u_hats, gammas[t], m, pp.paramDC, pp.paramQC))
			inprd.Mul(&inprd, &dcInv)
			constPoly.coeffs[0] = reduceBigInt(&inprd, pp.paramQC)

			tmp = pp.PolyCNTTSub(tmp, pp.NTTPolyC(constPoly))
			tmp1 = pp.PolyCNTTAdd(tmp1, pp.sigmaPowerPolyCNTT(tmp, tau))
		}

		xt := pp.NewZeroPolyC()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

		phi = pp.PolyCNTTAdd(phi, tmp1)
	}

	phi = pp.PolyCNTTAdd(phi, g)
	//phiinv := pp.NTTInv(phi)
	//fmt.Println(phiinv)
	//fmt.Printf("Prove\n")
	//fmt.Printf("phi = %v\n", phi)
	//	phi'^(\xi)
	phips := make([]*PolyCNTT, pp.paramK)
	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyCNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyCNTT()
			for tau := 0; tau < pp.paramK; tau++ {

				tmp := pp.NewZeroPolyCNTTVec(pp.paramLC)

				for j := 0; j < n2; j++ {
					tmp = pp.PolyCNTTVecAdd(
						tmp,
						pp.PolyCNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
						pp.paramLC)
				}

				tmp1 = pp.PolyCNTTAdd(
					tmp1,
					pp.sigmaPowerPolyCNTT(
						pp.PolyCNTTVecInnerProduct(tmp, ys[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
						tau),
					)
			}

			xt := pp.NewZeroPolyC()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

			phips[xi] = pp.PolyCNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyCNTTAdd(
			phips[xi],
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], ys[xi], pp.paramLC))
	}
	//fmt.Println("phips = ")
	//for i := 0; i < pp.paramK; i++ {
	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
	//}
	//fmt.Println("Prove")
	//fmt.Printf("rpulppi.phi =\n")
	//for i := 0; i < len(delta_hats); i++ {
	//	fmt.Printf("delta_hats[%d] = %v\n", i, phips[i])
	//}
	//	seed_ch and ch
	t := pp.collectBytesForRPULP2(tmp, delta_waves, delta_hats, psi, psip, phi, phips)
	chseed, err := Hash(t)
	if err != nil {
		return nil, err
	}
	ctmp, err := pp.expandChallenge(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyC(ctmp)
	// z = y + sigma^t(c) * r
	cmt_zs := make([][]*PolyCNTTVec, pp.paramK)
	zs := make([]*PolyCNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_zs[t] = make([]*PolyCNTTVec, n)
		sigma_t_ch := pp.sigmaPowerPolyCNTT(ch, t)
		for i := 0; i < n; i++ {
			cmt_zs[t][i] = pp.PolyCNTTVecAdd(
				cmt_ys[t][i],
				pp.PolyCNTTVecScaleMul(sigma_t_ch, cmt_rs[i], pp.paramLC),
				pp.paramLC)
			if pp.NTTInvPolyCVec(cmt_zs[t][i]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				goto rpUlpProveRestart
			}
		}

		zs[t] = pp.PolyCNTTVecAdd(ys[t], pp.PolyCNTTVecScaleMul(sigma_t_ch, r_hat, pp.paramLC), pp.paramLC)

		if pp.NTTInvPolyCVec(zs[t]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			goto rpUlpProveRestart
		}
	}

	retrpulppi := &rpulpProofv2{
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

func (pp PublicParameterv2) rpulpVerify(message []byte,
	cmts []*ValueCommitment, n int,
	b_hat *PolyCNTTVec, c_hats []*PolyCNTT, n2 int,
	n1 int, rpulpType RpUlpType, binMatrixB [][]byte, I int, J int, m int, u_hats [][]int64,
	rpulppi *rpulpProofv2) (valid bool) {

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

	// check the matrix and u_hats
	if len(binMatrixB) != pp.paramDC {
		return false
	} else {
		for i := 0; i < len(binMatrixB); i++ {
			if len(binMatrixB[0]) != pp.paramDC/8 {
				//	todo: sometimes 2*pp.paramDC/8
				//return false
			}
		}
	}
	if len(u_hats) != m {
		return false
	} else {
		for i := 0; i < len(u_hats); i++ {
			if len(u_hats[0]) != pp.paramDC {
				return false
			}
		}

	}
	// check the well-formness of the \pi
	if len(rpulppi.c_waves) != n || len(rpulppi.c_hat_g.coeffs) != pp.paramDC || len(rpulppi.psi.coeffs) != pp.paramDC || len(rpulppi.phi.coeffs1) != pp.paramDC || len(rpulppi.zs) != pp.paramK || len(rpulppi.zs[0].polyNTTs) != pp.paramLC {
		return false
	}
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
	phiPoly := pp.NTTInvPolyC(rpulppi.phi)
	//fmt.Println("phiPoly", phiPoly.coeffs1)
	for t := 0; t < pp.paramK; t++ {
		if phiPoly.coeffs[t] != 0 {
			// TODO 20210609 exist something theoretical error
			return false
		}
	}

	// infNorm of z^t_i and z^t
	for t := 0; t < pp.paramK; t++ {

		for i := 0; i < n; i++ {
			if pp.NTTInvPolyCVec(rpulppi.cmt_zs[t][i]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				return false
			}
		}

		if pp.NTTInvPolyCVec(rpulppi.zs[t]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			return false
		}

	}
	chmp, err := pp.expandChallenge(rpulppi.chseed)
	if err != nil {
		return false
	}
	ch := pp.NTTPolyC(chmp)

	sigma_chs := make([]*PolyCNTT, pp.paramK)
	//	w^t_i, w_t
	cmt_ws := make([][]*PolyCNTTVec, pp.paramK)
	ws := make([]*PolyCNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		sigma_chs[t] = pp.sigmaPowerPolyCNTT(ch, t)

		cmt_ws[t] = make([]*PolyCNTTVec, n)
		for i := 0; i < n; i++ {
			cmt_ws[t][i] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, rpulppi.cmt_zs[t][i], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(sigma_chs[t], cmts[i].b, pp.paramKC),
				pp.paramKC)
		}
		ws[t] = pp.PolyCNTTVecSub(
			pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, rpulppi.zs[t], pp.paramKC, pp.paramLC),
			pp.PolyCNTTVecScaleMul(sigma_chs[t], b_hat, pp.paramKC),
			pp.paramKC)
	}

	// splicing the data to be processed

	tmp := pp.collectBytesForRPULP1(message, n, n1, n2, binMatrixB, m, cmts, b_hat, c_hats, rpulpType, I, J, u_hats, rpulppi.c_waves, cmt_ws, ws, rpulppi.c_hat_g)
	seed_rand, err := Hash(tmp)
	if err != nil {
		return false
	}
	//fmt.Println("verify seed_rand=", seed_rand)
	alphas, betas, gammas, err := pp.expandUniformRandomnessInRqZqC(seed_rand, n1, m)
	if err != nil {
		return false
	}

	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyCNTT, pp.paramK)
	delta_hats := make([][]*PolyCNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyCNTT, n)
		delta_hats[t] = make([]*PolyCNTT, n)

		for i := 0; i < n; i++ {
			delta_waves[t][i] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.PolyCNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC),
					rpulppi.cmt_zs[t][i],
					pp.paramLC),
				pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(rpulppi.c_waves[i], cmts[i].c)),
				)

			delta_hats[t][i] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[i+1],
					pp.PolyCNTTVecSub(rpulppi.zs[t], rpulppi.cmt_zs[t][i], pp.paramLC),
					pp.paramLC),
				pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(c_hats[i], rpulppi.c_waves[i])),
				)
		}
	}
	// psi'
	psip := pp.NewZeroPolyCNTT()
	mu := &PolyCNTT{coeffs: pp.paramMu}
	for t := 0; t < pp.paramK; t++ {

		tmp1 := pp.NewZeroPolyCNTT()
		tmp2 := pp.NewZeroPolyCNTT()

		for i := 0; i < n1; i++ {
			f_t_i := pp.PolyCNTTSub(
				//<h_i,z_t>
				pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], rpulppi.zs[t], pp.paramLC),
				// sigma_c_t
				pp.PolyCNTTMul(sigma_chs[t], c_hats[i]),
				)

			tmp := pp.PolyCNTTMul(alphas[i], f_t_i)

			tmp1 = pp.PolyCNTTAdd(
				tmp1,
				pp.PolyCNTTMul(tmp, f_t_i),
				)

			tmp2 = pp.PolyCNTTAdd(
				tmp2,
				tmp,
				)
		}
		tmp2 = pp.PolyCNTTMul(tmp2, mu)
		tmp2 = pp.PolyCNTTMul(tmp2, sigma_chs[t])

		tmp1 = pp.PolyCNTTAdd(tmp1, tmp2)
		tmp1 = pp.sigmaInvPolyCNTT(tmp1, t)
		tmp1 = pp.PolyCNTTMul(betas[t], tmp1)

		psip = pp.PolyCNTTAdd(psip, tmp1)
	}

	psip = pp.PolyCNTTSub(psip, pp.PolyCNTTMul(ch, rpulppi.psi))
	psip = pp.PolyCNTTAdd(psip,
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], rpulppi.zs[0], pp.paramLC))
	//fmt.Printf("Verify\n")
	//fmt.Printf("psip = %v\n", psip)
	//	p^(t)_j:
	p := pp.genUlpPolyCNTTs(rpulpType, binMatrixB, I, J, gammas)

	//	phip
	phip := pp.NewZeroPolyCNTT()
	var inprd, dcInv big.Int
	dcInv.SetInt64(pp.paramDCInv)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyCNTT()
			for j := 0; j < n2; j++ {
				tmp = pp.PolyCNTTAdd(tmp, pp.PolyCNTTMul(p[t][j], c_hats[j]))
			}

			constPoly := pp.NewZeroPolyC()
			inprd.SetInt64(intMatrixInnerProductWithReduction(u_hats, gammas[t], m, pp.paramDC, pp.paramQC))
			inprd.Mul(&inprd, &dcInv)
			constPoly.coeffs[0] = reduceBigInt(&inprd, pp.paramQC)

			tmp = pp.PolyCNTTSub(tmp, pp.NTTPolyC(constPoly))

			tmp1 = pp.PolyCNTTAdd(tmp1, pp.sigmaPowerPolyCNTT(tmp, tau))
		}

		xt := pp.NewZeroPolyC()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

		phip = pp.PolyCNTTAdd(phip, tmp1)
	}

	//	phi'^(\xi)
	phips := make([]*PolyCNTT, pp.paramK)
	constterm := pp.PolyCNTTSub(pp.PolyCNTTAdd(phip, rpulppi.c_hat_g), rpulppi.phi)

	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyCNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyCNTT()
			for tau := 0; tau < pp.paramK; tau++ {

				tmp := pp.NewZeroPolyCNTTVec(pp.paramLC)

				for j := 0; j < n2; j++ {
					tmp = pp.PolyCNTTVecAdd(
						tmp,
						pp.PolyCNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
						pp.paramLC)
				}

				tmp1 = pp.PolyCNTTAdd(
					tmp1,
					pp.sigmaPowerPolyCNTT(
						pp.PolyCNTTVecInnerProduct(tmp, rpulppi.zs[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
						tau),
					)
			}

			xt := pp.NewZeroPolyC()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

			phips[xi] = pp.PolyCNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyCNTTAdd(
			phips[xi],
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], rpulppi.zs[xi], pp.paramLC))

		phips[xi] = pp.PolyCNTTSub(
			phips[xi],
			pp.PolyCNTTMul(sigma_chs[xi], constterm))
	}
	//fmt.Printf("Verify\n")
	//
	//fmt.Printf("phips = \n")
	//for i := 0; i < pp.paramK; i++ {
	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
	//}
	//fmt.Println("Verify")
	//fmt.Printf("rpulppi.phi =\n")
	//for i := 0; i < len(delta_hats); i++ {
	//	for j := 0; j < len(delta_hats[i]); j++ {
	//		fmt.Printf("delta_hats[%d][%d] = %v\n", i, j, delta_hats[i][j])
	//	}
	//}
	//	seed_ch and ch
	t := pp.collectBytesForRPULP2(tmp, delta_waves, delta_hats, rpulppi.psi, psip, rpulppi.phi, phips)
	seed_ch, err := Hash(t)
	if err != nil {
		return false
	}
	if bytes.Compare(seed_ch, rpulppi.chseed) != 0 {
		return false
	}

	return true
}

//	todo: this method directly samples and returns a PloyANTT
func (pp *PublicParameterv2) ExpandKIDR(lgtxo *LgrTxo) *PolyANTT {
	//	todo: directly the serialize of Txo and Id
	buf := make([]byte, 0, 1000)
	w := bytes.NewBuffer(buf)
	var err error
	err = WritePublicKey(w, lgtxo.AddressPublicKey)
	if err != nil {
		return nil
	}
	err = WriteCommitmentv2(w, lgtxo.ValueCommitment)
	if err != nil {
		return nil
	}
	err = writeElement(w, lgtxo.Id)
	if err != nil {
		return nil
	}
	seed, err := Hash(w.Bytes())
	if err != nil {
		return nil
	}
	got := rejectionUniformWithQa(seed, pp.paramDA)
	return &PolyANTT{coeffs: got}
}

//	todo: (ringHash, index) shall be ok?
func (pp *PublicParameterv2) LedgerTxoSerialNumberGen(blockHases []hash.Hash, txo *Txo, index int) []byte {
	buf := make([]byte, 1000)
	w := bytes.NewBuffer(buf)
	var err error
	// block hash_1 ... block hash_n
	for i := 0; i < len(blockHases); i++ {
		err = writeElement(w, blockHases[i])
		if err != nil {
			return nil
		}
	}
	// txo serialize
	err = txo.Serialize0(w) // todo:
	if err != nil {
		return nil
	}
	// index
	err = writeElement(w, index)
	if err != nil {
		return nil
	}
	ret, err := Hash(w.Bytes())
	if err != nil {
		return nil
	}
	return ret[:]
}

func (pp *PublicParameterv2) ELRSSign(
	lgrTxoList []*LgrTxo, ma_p *PolyANTT, cmt_p *ValueCommitment,
	msg []byte, sindex int, sa *PolyANTTVec, rc *PolyCNTTVec, rc_p *PolyCNTTVec) (*elrsSignaturev2, error) {
	var err error
	ringLen := len(lgrTxoList)
	if ringLen == 0 {
		return nil, errors.New("ELRSSign is called on input empty ring")
	}
	if sindex >= ringLen {
		return nil, errors.New("The signer index is not in the scope")
	}


	d_a_js := make([]*PolyANTT, ringLen)
	d_c_js := make([]*PolyCNTT, ringLen)

	z_a_js := make([]*PolyANTTVec, ringLen)
	w_a_js := make([]*PolyANTTVec, ringLen)
	delta_a_js := make([]*PolyANTT, ringLen)
	// j -> t
	z_c_j_ts := make([][]*PolyANTTVec, ringLen)
	z_cp_j_ts := make([][]*PolyNTTVecv2, ringLen)
	w_c_j_ts := make([][]*PolyNTTVecv2, ringLen)
	w_cp_j_ts := make([][]*PolyNTTVecv2, ringLen)
	theta_c_j_ts := make([][]*PolyNTTv2, ringLen)

	seeds := make([][]byte, ringLen)
	z_as := make([]*PolyANTTVec, ringLen)

	w_as := make([]*PolyANTTVec, ringLen)
	delta_as := make([]*PolyANTT, ringLen)

	z_cs := make([][]*PolyCNTTVec, ringLen)
	z_cps := make([][]*PolyCNTTVec, ringLen)

	w_cs := make([][]*PolyCNTTVec, ringLen)
	w_cps := make([][]*PolyCNTTVec, ringLen)
	delta_cs := make([][]*PolyCNTT, ringLen)

	for j := 0; j < ringLen; j++ {
		if j == sindex {
			continue
		}
		seeds[j] = randomBytes(pp.paramSeedBytesLen)

		tmpA, err := pp.expandSigAChv2(seeds[j])
		if err != nil {
			return nil, err
		}
		da := pp.NTTPolyA(tmpA)

		tmpC, err := pp.expandSigCChv2(seeds[j])
		if err != nil {
			return nil, err
		}
		dc := pp.NTTPolyC(tmpC)


		// sample randomness for z_a_j
		tmpZa, err := pp.sampleZetaAv2()
		if err != nil {
			return nil, err
		}
		z_as[j] = pp.NTTPolyAVec(tmpZa)

		// w_a_j = A*z_a_j - d_a_j*t_j
		w_as[j] = pp.PolyANTTVecSub(
			pp.PolyANTTMatrixMulVector(pp.paramMatrixA, z_as[j], pp.paramKA, pp.paramLA),
			pp.PolyANTTVecScaleMul(da, lgrTxoList[j].Txo.AddressPublicKey.t, pp.paramKA),
			pp.paramKA,
			)
		// theta_a_j = <a,z_a_j> - d_a_j * (e_j + ExpandKIDR(txo[j]) - m_a_p)
		delta_as[j] = pp.PolyANTTSub(
			pp.PolyANTTVecInnerProduct(pp.paramVecA, z_as[j], pp.paramLA),
			pp.PolyANTTMul(
				da,
				pp.PolyANTTSub(
					pp.PolyANTTAdd(
						lgrTxoList[j].Txo.AddressPublicKey.e,
						pp.ExpandKIDR(lgrTxoList[j]),
						),
						ma_p,
					),
				),
			)

		z_cs[j] = make([]*PolyCNTTVec, pp.paramK)
		z_cps[j] = make([]*PolyCNTTVec, pp.paramK)
		delta_cs[j] = make([]*PolyCNTT, pp.paramK)
		for tao := 0; tao < pp.paramK; tao++ {
			tmpZc, err := pp.sampleZetaC2v2()
			if err != nil {
				return nil, err
			}
			tmpZcp, err := pp.sampleZetaC2v2()
			if err != nil {
				return nil, err
			}
			z_cs[j][tao] = pp.NTTPolyCVec(tmpZc)
			z_cps[j][tao] = pp.NTTPolyCVec(tmpZcp)
			sigmatao := pp.sigmaPowerPolyCNTT(dc, tao)
			w_cs[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cs[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmatao,
					lgrTxoList[j].Txo.ValueCommitment.b,
					pp.paramKC,
					),
				pp.paramKC,
				)
			w_cps[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cps[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmatao,
					cmt_p.b,
					pp.paramKC,
					),
				pp.paramKC,
				)
			delta_cs[j][tao] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[0],
					pp.PolyCNTTVecSub(z_cs[j][tao],z_cps[j][tao], pp.paramLC),
					pp.paramLC,
					),
				pp.PolyCNTTMul(
					sigmatao,
					pp.PolyCNTTSub(lgrTxoList[j].Txo.ValueCommitment.c, cmt_p.c),
					),
				)
		}
	}

	z_cs[sindex] = make([]*PolyCNTTVec, pp.paramK)
	z_cps[sindex] = make([]*PolyCNTTVec, pp.paramK)
	delta_cs[sindex] = make([]*PolyCNTT, pp.paramK)
ELRSSignRestartv2:
	// randomness y_a_j_bar
	tmpYa, err := pp.sampleMaskAv2()
	if err != nil {
		return nil, err
	}
	y_a := pp.NTTPolyAVec(tmpYa)
	w_as[sindex] = pp.PolyANTTMatrixMulVector(pp.paramMatrixA, y_a, pp.paramKA, pp.paramLA)
	delta_as[sindex] = pp.PolyANTTVecInnerProduct(pp.paramVecA, y_a, pp.paramLA)

	for tao := 0; tao < pp.paramK; tao++ {
		tmpYc, err := pp.sampleMaskCv2()
		if err != nil {
			return nil, err
		}
		tmpYcp, err := pp.sampleMaskCv2()
		if err != nil {
			return nil, err
		}

		y_c := pp.NTTPolyCVec(tmpYc)
		y_cp := pp.NTTPolyCVec(tmpYcp)
		w_cs[sindex][tao] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y_c, pp.paramKC, pp.paramLC)
		w_cps[sindex][tao] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y_cp, pp.paramKC, pp.paramLC)
		delta_cs[sindex][tao] = pp.PolyCNTTVecInnerProduct(
			pp.paramMatrixH[0],
			pp.PolyCNTTVecSub(y_c,y_cp, pp.paramLC),
			pp.paramLC,
		)
	}

	seed_ch := pp.collectBytesForELRv2(lgrTxoList, ma_p, cmt_p, msg, w_as, delta_as, w_cs, w_cps, delta_cs)
/*	seeds[sindex] = make([]byte, len(seed_ch))
	for i := 0; i < len(seed_ch); i++ {
		seeds[sindex][i] = seed_ch[i]
	}*/
	seeds[sindex] = seed_ch
	for i := 0; i < len(lgrTxoList); i++ {
		if i == sindex {
			continue
		}
		for j := 0; j < len(seeds[i]); j++ {
			seeds[sindex][j] ^= seeds[i][j]
		}
	}

	tmpA, err := pp.expandSigAChv2(seeds[sindex])
	if err != nil {
		return nil, err
	}
	tmpC, err := pp.expandSigCChv2(seeds[sindex])
	if err != nil {
		return nil, err
	}
	dA := pp.NTTPolyA(tmpA)
	dC := pp.NTTPolyC(tmpC)

	z_as[sindex] = pp.PolyANTTAdd(y_a, pp.PolyANTTVecScaleMul(dA, rc))

	// z_a_j_bar = y_a_j_bar + d_a_j_bar * s_a
	z_a_js[index] = PolyVecAdd(y_a_j_bar, pp.PolyVecScaleMul(d_a_js[index], sa, R_QA, pp.paramLA), R_QA, pp.paramLA)
	// z_c_j_bar_t = y_c_j_bar_t + simga_t(d_c_j_bar)*rc
	z_c_j_ts[index] = make([]*PolyNTTVecv2, pp.paramK)
	// z_c_j_bar_tp = y_c_j_bar_tp + simga_t(d_c_j_bar)*rcp
	z_cp_j_ts[index] = make([]*PolyNTTVecv2, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		z_c_j_ts[index][i] = PolyNTTVecScaleMul(pp.sigmaPowerPolyNTT(d_c_js[index], R_QC, i), rc, R_QC, pp.paramLC)
		z_c_j_ts[index][i] = PolyNTTVecAdd(z_c_j_ts[index][i], y_c_j_bar_ts[index], R_QC, pp.paramLC)

		z_cp_j_ts[index][i] = PolyNTTVecScaleMul(pp.sigmaPowerPolyNTT(d_c_js[index], R_QC, i), rcp, R_QC, pp.paramLC)
		z_cp_j_ts[index][i] = PolyNTTVecAdd(z_cp_j_ts[index][i], y_c_j_bar_tps[index], R_QC, pp.paramLC)
	}

	if z_a_js[index].infNormQa() > int64(pp.paramEtaA-pp.paramThetaA*pp.paramGammaA) {
		goto ELRSSignRestartv2
	}
	for i := 0; i < pp.paramK; i++ {
		t1 := pp.NTTInvVecInRQc(z_c_j_ts[index][i]).infNormQc()
		t2 := pp.NTTInvVecInRQc(z_cp_j_ts[index][i]).infNormQc()
		bound := pp.paramEtaC - pp.paramBetaC
		if t1 > bound && t2 > bound {
			goto ELRSSignRestartv2
		}
	}
	return &elrsSignaturev2{
		seeds:  seeds,
		z_as:   z_a_js,
		z_cs:   z_c_j_ts,
		z_cs_p: z_cp_j_ts,
	}, nil
}

// todo: the paper is not accurate, use the following params
func (pp *PublicParameterv2) collectBytesForELRv2(
	lgxTxoList []*LgrTxo, ma_p *PolyANTT, cmt_p *ValueCommitment, msg []byte,
	w_as []*PolyANTTVec, delta_as []*PolyANTT,
	w_cs [][]*PolyCNTTVec, w_cps [][]*PolyCNTTVec, delta_cs[][]*PolyCNTT) []byte {
	tt := make([]byte, 0, len(msg)+pp.paramDC*4*
		(len(txoList)*(pp.paramKA+1+pp.paramKC+1+pp.paramKA+1+pp.paramK*pp.paramKC*2)+
			1+pp.paramKC+1))
	appendPolyNTTToBytes := func(a *PolyNTTv2, rtp reduceType) {
		switch rtp {
		case R_QC:
			for k := 0; k < pp.paramDC; k++ {
				tt = append(tt, byte(a.coeffs1[k]>>0))
				tt = append(tt, byte(a.coeffs1[k]>>8))
				tt = append(tt, byte(a.coeffs1[k]>>16))
				tt = append(tt, byte(a.coeffs1[k]>>24))
			}
		case R_QA:
			for k := 0; k < pp.paramDA; k++ {
				tt = append(tt, byte(a.coeffs2[k]>>0))
				tt = append(tt, byte(a.coeffs2[k]>>8))
				tt = append(tt, byte(a.coeffs2[k]>>16))
				tt = append(tt, byte(a.coeffs2[k]>>24))
				tt = append(tt, byte(a.coeffs2[k]>>32))
				tt = append(tt, byte(a.coeffs2[k]>>40))
				tt = append(tt, byte(a.coeffs2[k]>>48))
				tt = append(tt, byte(a.coeffs2[k]>>56))
			}
		default:
			panic("Unsupported type")
		}
	}
	appendPolyToBytes := func(a *Polyv2, rtp reduceType) {
		switch rtp {
		case R_QC:
			for k := 0; k < pp.paramDC; k++ {
				tt = append(tt, byte(a.coeffs1[k]>>0))
				tt = append(tt, byte(a.coeffs1[k]>>8))
				tt = append(tt, byte(a.coeffs1[k]>>16))
				tt = append(tt, byte(a.coeffs1[k]>>24))
			}
		case R_QA:
			for k := 0; k < pp.paramDA; k++ {
				tt = append(tt, byte(a.coeffs2[k]>>0))
				tt = append(tt, byte(a.coeffs2[k]>>8))
				tt = append(tt, byte(a.coeffs2[k]>>16))
				tt = append(tt, byte(a.coeffs2[k]>>24))
				tt = append(tt, byte(a.coeffs2[k]>>32))
				tt = append(tt, byte(a.coeffs2[k]>>40))
				tt = append(tt, byte(a.coeffs2[k]>>48))
				tt = append(tt, byte(a.coeffs2[k]>>56))
			}
		default:
			panic("Unsupported type")
		}
	}
	// msg
	for i := 0; i < len(msg); i++ {
		tt = append(tt, msg...)
	}
	// txoList=[(pk,cmt)]
	for i := 0; i < len(txoList); i++ {
		// pk
		appendPolyToBytes(txoList[i].e, R_QA)
		for j := 0; j < len(txoList[i].t.polys); j++ {
			appendPolyToBytes(txoList[i].t.polys[j], R_QA)
		}
		// cmt
		for j := 0; j < len(txoList[i].b.polyNTTs); j++ {
			appendPolyNTTToBytes(txoList[i].b.polyNTTs[j], R_QC)
		}
		appendPolyNTTToBytes(txoList[i].c, R_QC)
	}
	// ma
	appendPolyToBytes(ma, R_QA)
	// cmt
	for i := 0; i < len(cmt.b.polyNTTs); i++ {
		appendPolyNTTToBytes(cmt.b.polyNTTs[i], R_QC)
	}
	appendPolyNTTToBytes(cmt.c, R_QC)
	// w_a_js
	for i := 0; i < len(w_a_js); i++ {
		for j := 0; j < len(w_a_js[i].polys); j++ {
			appendPolyToBytes(w_a_js[i].polys[j], R_QA)
		}
	}
	// theta_a_js
	for i := 0; i < len(theta_a_js); i++ {
		appendPolyToBytes(theta_a_js[i], R_QA)
	}
	// w_c_j_ts
	for i := 0; i < len(w_c_j_ts); i++ {
		for j := 0; j < len(w_c_j_ts[i]); j++ {
			for k := 0; k < len(w_c_j_ts[i][j].polyNTTs); k++ {
				appendPolyNTTToBytes(w_c_j_ts[i][j].polyNTTs[k], R_QC)
			}
		}
	}
	// w_c_j_tps
	for i := 0; i < len(w_c_j_tps); i++ {
		for j := 0; j < len(w_c_j_tps[i]); j++ {
			for k := 0; k < len(w_c_j_tps[i][j].polyNTTs); k++ {
				appendPolyNTTToBytes(w_c_j_tps[i][j].polyNTTs[k], R_QC)
			}
		}
	}
	hash := sha256.New()
	hash.Reset()
	res := hash.Sum(tt)
	return res[:]
}

func (pp *PublicParameterv2) ELRSVerify(lTXOList []*LGRTXO, ma *Polyv2, cmt *Commitmentv2, msg []byte, sig *elrsSignaturev2) bool {
	for i := 0; i < len(lTXOList); i++ {
		if sig.z_as[i].infNormQa() > int64(pp.paramEtaA-pp.paramThetaA*pp.paramGammaA) {
			return false
		}
		for j := 0; j < pp.paramK; j++ {
			t1 := pp.NTTInvVecInRQc(sig.z_cs[i][j]).infNormQc()
			t2 := pp.NTTInvVecInRQc(sig.z_cs_p[i][j]).infNormQc()
			bound := pp.paramEtaC - pp.paramBetaC
			if t1 > bound && t2 > bound {
				return false
			}
		}
	}

	d_a_js := make([]*Polyv2, len(lTXOList))
	d_c_js := make([]*PolyNTTv2, len(lTXOList))

	w_a_js := make([]*PolyVecv2, len(lTXOList))
	theta_a_js := make([]*Polyv2, len(lTXOList))

	w_c_j_ts := make([][]*PolyNTTVecv2, len(lTXOList))
	w_c_j_tps := make([][]*PolyNTTVecv2, len(lTXOList))
	theta_c_j_ts := make([][]*PolyNTTv2, len(lTXOList))

	var tmp *Polyv2
	for i := 0; i < len(lTXOList); i++ {
		d_a_js[i], _ = pp.expandSigAChv2(sig.seeds[i])
		tmp, _ = pp.expandSigCChv2(sig.seeds[i])
		d_c_js[i] = pp.NTTInRQc(tmp)
		// w_a_j = A*z_a_j - d_a_j*t_j
		w_a_js[i] = pp.PolyMatrixMulVector(pp.paramMatrixA, sig.z_as[i], R_QA, pp.paramKA, pp.paramLA)
		w_a_js[i] = PolyVecSub(w_a_js[i], pp.PolyVecScaleMul(d_a_js[i], lTXOList[i].t, R_QA, pp.paramKA), R_QA, pp.paramKA)
		// theta_a_j = <a,z_a_j> - d_a_j * (e_j + ExpandKIDR(txo[j]) - m_a_p)
		theta_a_js[i] = pp.PolyVecInnerProduct(pp.paramVecA, sig.z_as[i], R_QA, pp.paramLA)
		tmp_theta_j := pp.Mul(d_a_js[i], PolySub(PolyAdd(lTXOList[i].e, pp.ExpandKIDR(lTXOList[i]), R_QA), ma, R_QA))
		theta_a_js[i] = PolySub(theta_a_js[i], tmp_theta_j, R_QA)

		w_c_j_ts[i] = make([]*PolyNTTVecv2, pp.paramK)
		w_c_j_tps[i] = make([]*PolyNTTVecv2, pp.paramK)
		theta_c_j_ts[i] = make([]*PolyNTTv2, pp.paramK)
		for j := 0; j < pp.paramK; j++ {
			// w_c_j_t = B*z_c_j_t - simga_t(d_c_j) * b_j
			w_c_j_ts[i][j] = PolyNTTMatrixMulVector(pp.paramMatrixB, sig.z_cs[i][j], R_QC, pp.paramKC, pp.paramLC)
			tmp_w_j_t := PolyNTTVecScaleMul(pp.sigmaPowerPolyNTT(d_c_js[i], R_QC, j), lTXOList[i].b, R_QC, pp.paramKC)
			w_c_j_ts[i][j] = PolyNTTVecSub(w_c_j_ts[i][j], tmp_w_j_t, R_QC, pp.paramKC)
			// w_c_j_tp = B*z_c_j_tp - simg_t(d_c_j) * b_p
			w_c_j_tps[i][j] = PolyNTTMatrixMulVector(pp.paramMatrixB, sig.z_cs_p[i][j], R_QC, pp.paramKC, pp.paramLC)
			tmp_w_j_tp := PolyNTTVecScaleMul(pp.sigmaPowerPolyNTT(d_c_js[i], R_QC, j), cmt.b, R_QC, pp.paramKC)
			w_c_j_tps[i][j] = PolyNTTVecSub(w_c_j_tps[i][j], tmp_w_j_tp, R_QC, pp.paramKC)
			// theta_a_j_t
			theta_c_j_ts[i][j] = PolyNTTVecInnerProduct(pp.paramMatrixH[0], PolyNTTVecSub(sig.z_cs[i][j], sig.z_cs_p[i][j], R_QC, pp.paramLC), R_QC, pp.paramLC)
			tmp_theta_c_t := PolyNTTMul(pp.sigmaPowerPolyNTT(d_c_js[i], R_QC, j), PolyNTTSub(lTXOList[i].c, cmt.c, R_QC), R_QC)
			theta_c_j_ts[i][j] = PolyNTTSub(theta_c_j_ts[i][j], tmp_theta_c_t, R_QC)
		}
	}

	txoList := make([]*TXOv2, len(lTXOList))
	for i := 0; i < len(lTXOList); i++ {
		txoList[i] = &lTXOList[i].TXOv2
	}
	seed_ch := pp.collectBytesForELRv2(txoList, ma, cmt, msg, w_a_js, theta_a_js, w_c_j_ts, w_c_j_tps)
	for i := 0; i < len(lTXOList); i++ {
		for j := 0; j < len(sig.seeds[i]); j++ {
			seed_ch[j] ^= sig.seeds[i][j]
		}
	}
	for i := 0; i < len(lTXOList); i++ {
		if seed_ch[i] != 0 {
			return false
		}
	}
	return true
}

func (pp *PublicParameterv2) CoinbaseTxGen(vin uint64, txOutputDescs []*TxOutputDescv2) (cbTx *CoinbaseTxv2, err error) {
	V := uint64(1)<<pp.paramN - 1

	if vin >= V {
		return nil, errors.New("vin is not in [0, V]") // todo: more accurate info
	}

	if len(txOutputDescs) == 0 || len(txOutputDescs) > pp.paramJ {
		return nil, errors.New("the number of outputs is not in [1, I_max]") // todo: more accurate info
	}

	J := len(txOutputDescs)

	retcbTx := &CoinbaseTxv2{}
	//	retcbTx.Version = 0 // todo: how to set and how to use the version? The bpf just care the content of cbTx?
	retcbTx.Vin = vin
	retcbTx.OutputTxos = make([]*TXOv2, J)

	cmts := make([]*Commitmentv2, J)
	cmt_rs := make([]*PolyNTTVecv2, J)

	vout := uint64(0)
	// generate the output using txoGen
	for j, txOutputDesc := range txOutputDescs {
		if txOutputDesc.value > V {
			return nil, errors.New("value is not in [0, V]") // todo: more accurate info, including the i
		}
		vout += txOutputDesc.value
		if vout > V {
			return nil, errors.New("the output value is not in [0, V]") // todo: more accurate info, including the i
		}

		cmts[j], cmt_rs[j], err = pp.ComGen(txOutputDesc.value)
		if err != nil {
			return nil, err
		}
		retcbTx.OutputTxos[j] = &TXOv2{
			PublicKey:    txOutputDesc.pk,
			Commitmentv2: cmts[j],
		}
	}
	if vout > vin {
		return nil, errors.New("the output value exceeds the input value") // todo: more accurate info
	}

	if J == 1 {
		// random from S_etaC^lc
		ys := make([]*PolyNTTVecv2, pp.paramK)
		// w^t = B * y^t
		ws := make([]*PolyNTTVecv2, pp.paramK)
		// delta = <h,y^t>
		deltas := make([]*PolyNTTv2, pp.paramK)
		// z^t = y^t + sigma^t(c) * r_(out,j), r_(out,j) is from txoGen, in there, r_(out,j) is cmt_rs_j
		zs := make([]*PolyNTTVecv2, pp.paramK)

	cbTxGenJ1Restart:
		for t := 0; t < pp.paramK; t++ {
			// random y
			maskC, err := pp.sampleMaskCv2()
			if err != nil {
				return nil, err
			}
			ys[t] = pp.NTTVecInRQc(maskC)

			ws[t] = PolyNTTMatrixMulVector(pp.paramMatrixB, ys[t], R_QC, pp.paramKC, pp.paramLC)
			deltas[t] = PolyNTTVecInnerProduct(pp.paramMatrixH[0], ys[t], R_QC, pp.paramLC)
		}

		chseed, err := Hash(pp.collectBytesForCoinbase1(vin, cmts, ws, deltas))
		if err != nil {
			return nil, err
		}
		chtmp, err := pp.expandChallenge(chseed)
		if err != nil {
			return nil, err
		}
		ch := pp.NTTInRQc(chtmp)

		for t := 0; t < pp.paramK; t++ {
			zs[t] = PolyNTTVecAdd(
				ys[t],
				PolyNTTVecScaleMul(pp.sigmaPowerPolyNTT(ch, R_QC, t), cmt_rs[0], R_QC, pp.paramLC),
				R_QC,
				pp.paramLC)
			// check the norm
			tmp := pp.NTTInvVecInRQc(zs[t])
			norm := tmp.infNormQc()
			if norm > pp.paramEtaC-pp.paramBetaC {
				goto cbTxGenJ1Restart
			}
		}

		retcbTx.TxWitness = &CbTxWitnessv2{
			rpulpproof: &rpulpProofv2{
				chseed: chseed,
				zs:     zs,
			},
			cmt_rs: cmt_rs,
		}
	} else {
		//	J >= 2
		n := J
		n2 := n + 2

		c_hats := make([]*PolyNTTv2, n2)

		msg_hats := make([][]int32, n2)

		u_hats := make([][]int32, 3)
		u_hats[0] = intToBinary(vin, pp.paramDC)

		for j := 0; j < J; j++ {
			msg_hats[j] = intToBinary(txOutputDescs[j].value, pp.paramDC)
		}

		u := intToBinary(vin, pp.paramDC)

		//	f is the carry vector, such that, u = m_0 + m_1 + ... + m_{J-1}
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1] + 2 f[i],
		//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1]
		f := make([]int32, pp.paramDC)
		f[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int32(0)
			for j := 0; j < J; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			//f[i] = (tmp + f[i-1] - u[i-1]) >> 1
			f[i] = (tmp + f[i-1] - u[i-1]) / 2
		}
		msg_hats[J] = f

	cbTxGenJ2Restart:
		e := make([]int32, pp.paramDC)
		e, err := pp.sampleUniformWithinEtaFv2()
		if err != nil {
			return nil, err
		}
		msg_hats[J+1] = e

		randomnessC, err := pp.sampleRandomnessRv2()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVecInRQc(randomnessC)

		// b_hat =B * r_hat
		b_hat := PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, R_QC, pp.paramKC, pp.paramLC)

		for i := 0; i < n2; i++ { // n2 = J+2
			c_hats[i] = PolyNTTAdd(
				PolyNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, R_QC, pp.paramLC),
				&PolyNTTv2{coeffs1: msg_hats[i]},
				R_QC)
		}

		//	todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramDC) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		u_p_tmp := make([]int64, pp.paramDC)

		seed_binM, err := Hash(pp.collectBytesForCoinbase2(b_hat, c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return nil, err
		}
		// todo: check B f + e
		for i := 0; i < pp.paramDC; i++ {
			u_p_tmp[i] = int64(e[i])
			for j := 0; j < pp.paramDC; j++ {
				if (binM[i][j/8]>>(j%8))&1 == 1 {
					u_p_tmp[i] = u_p_tmp[i] + int64(f[j])
				}
			}

			infNorm := u_p_tmp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > int64(pp.paramEtaF-int32(J-1)) {
				goto cbTxGenJ2Restart
			}

			u_p[i] = reduceToQc(u_p_tmp[i])
		}

		u_hats[1] = make([]int32, pp.paramDC)
		u_hats[2] = u_p

		n1 := n
		rprlppi, pi_err := pp.rpulpProve(cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		retcbTx.TxWitness = &CbTxWitnessv2{
			b_hat:      b_hat,
			c_hats:     c_hats,
			u_p:        u_p,
			rpulpproof: rprlppi,
			cmt_rs:     cmt_rs,
		}
	}

	return retcbTx, nil
}

// CoinbaseTxVerify reports whether a coinbase transaction is legal.
func (pp *PublicParameterv2) CoinbaseTxVerify(cbTx *CoinbaseTxv2) bool {
	if cbTx == nil {
		return false
	}

	V := uint64(1)<<pp.paramN - 1

	if cbTx.Vin > V {
		return false
	}

	if cbTx.OutputTxos == nil || len(cbTx.OutputTxos) == 0 {
		return false
	}

	if cbTx.TxWitness == nil {
		return false
	}

	J := len(cbTx.OutputTxos)
	if J > pp.paramJ {
		return false
	}

	// todo_DONE: check no repeated dpk in cbTx.OutputTxos
	dpkMap := make(map[*PublicKey]struct{})
	for i := 0; i < len(cbTx.OutputTxos); i++ {
		if _, ok := dpkMap[cbTx.OutputTxos[i].PublicKey]; !ok {
			dpkMap[cbTx.OutputTxos[i].PublicKey] = struct{}{}
		} else {
			return false
		}
	}
	// todo: check cbTx.OutputTxos[j].cmt is well-formed

	if J == 1 {
		if cbTx.TxWitness.b_hat != nil || cbTx.TxWitness.c_hats != nil || cbTx.TxWitness.u_p != nil {
			return false
		}
		if cbTx.TxWitness.rpulpproof == nil {
			return false
		}
		if cbTx.TxWitness.rpulpproof.c_waves != nil || cbTx.TxWitness.rpulpproof.c_hat_g != nil ||
			cbTx.TxWitness.rpulpproof.psi != nil || cbTx.TxWitness.rpulpproof.phi != nil ||
			cbTx.TxWitness.rpulpproof.cmt_zs != nil {
			return false
		}
		if cbTx.TxWitness.rpulpproof.chseed == nil || cbTx.TxWitness.rpulpproof.zs == nil {
			return false
		}
		// todo check the well-form of chseed

		// check the well-formof zs
		if len(cbTx.TxWitness.rpulpproof.zs) != pp.paramK {
			return false
		}
		// infNorm of z^t
		for t := 0; t < pp.paramK; t++ {
			if pp.NTTInvVecInRQc(cbTx.TxWitness.rpulpproof.zs[t]).infNormQc() > pp.paramEtaC-pp.paramBetaC {
				return false
			}
		}

		ws := make([]*PolyNTTVecv2, pp.paramK)
		deltas := make([]*PolyNTTv2, pp.paramK)

		chtmp, err := pp.expandChallenge(cbTx.TxWitness.rpulpproof.chseed)
		if err != nil {
			return false
		}
		ch := pp.NTTInRQc(chtmp)
		mtmp := intToBinary(cbTx.Vin, pp.paramDC)
		//msg := pp.NTTInRQc(&Polyv2{coeffs1: mtmp})
		msg := &PolyNTTv2{coeffs1: mtmp}
		for t := 0; t < pp.paramK; t++ {
			sigma_t_ch := pp.sigmaPowerPolyNTT(ch, R_QC, t)

			ws[t] = PolyNTTVecSub(
				PolyNTTMatrixMulVector(pp.paramMatrixB, cbTx.TxWitness.rpulpproof.zs[t], R_QC, pp.paramKC, pp.paramLC),
				PolyNTTVecScaleMul(sigma_t_ch, cbTx.OutputTxos[0].b, R_QC, pp.paramKC),
				R_QC,
				pp.paramKC)
			deltas[t] = PolyNTTSub(
				PolyNTTVecInnerProduct(pp.paramMatrixH[0], cbTx.TxWitness.rpulpproof.zs[t], R_QC, pp.paramLC),
				PolyNTTMul(
					sigma_t_ch,
					PolyNTTSub(cbTx.OutputTxos[0].c, msg, R_QC), R_QC), // Modified?
				R_QC)
		}

		seed_ch, err := Hash(pp.collectBytesForCoinbase1(cbTx.Vin, []*Commitmentv2{cbTx.OutputTxos[0].Commitmentv2}, ws, deltas))
		if err != nil {
			return false
		}
		if bytes.Compare(seed_ch, cbTx.TxWitness.rpulpproof.chseed) != 0 {
			return false
		}
	} else {
		// check the well-formness of cbTx.TxWitness
		if cbTx.TxWitness.b_hat == nil || cbTx.TxWitness.c_hats == nil || cbTx.TxWitness.u_p == nil || cbTx.TxWitness.rpulpproof == nil {
			return false
		}

		n := J
		n2 := J + 2

		if len(cbTx.TxWitness.c_hats) != n2 {
			return false
		}

		//	infNorm of u'
		infNorm := int32(0)
		if len(cbTx.TxWitness.u_p) != pp.paramDC {
			return false
		}
		for i := 0; i < pp.paramDC; i++ {
			infNorm = cbTx.TxWitness.u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm >= (pp.paramEtaF - int32(J-1)) { // todo: q/12 or eta_f - (J-1)
				return false
			}
		}

		seed_binM, err := Hash(pp.collectBytesForCoinbase2(cbTx.TxWitness.b_hat, cbTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return false
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = intToBinary(cbTx.Vin, pp.paramDC)
		u_hats[1] = make([]int32, pp.paramDC)
		u_hats[2] = cbTx.TxWitness.u_p

		cmts := make([]*Commitmentv2, n)
		for i := 0; i < n; i++ {
			cmts[i] = cbTx.OutputTxos[i].Commitmentv2
		}

		n1 := n
		flag := pp.rpulpVerify(cmts, n, cbTx.TxWitness.b_hat, cbTx.TxWitness.c_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats, cbTx.TxWitness.rpulpproof)
		return flag
	}

	return true
}

func (pp *PublicParameterv2) collectBytesForCoinbase1(vin uint64, cmts []*Commitmentv2, ws []*PolyNTTVecv2, deltas []*PolyNTTv2) []byte {
	tmp := make([]byte, pp.paramDC*4+(pp.paramKC+1)*pp.paramDC*4+(pp.paramKC+1)*pp.paramDC*4)
	appendPolyNTTToBytes := func(a *PolyNTTv2) {
		for k := 0; k < pp.paramDC; k++ {
			tmp = append(tmp, byte(a.coeffs1[k]>>0))
			tmp = append(tmp, byte(a.coeffs1[k]>>8))
			tmp = append(tmp, byte(a.coeffs1[k]>>16))
			tmp = append(tmp, byte(a.coeffs1[k]>>24))
		}
	}

	mtmp := intToBinary(vin, pp.paramDC)
	m := &PolyNTTv2{coeffs1: mtmp}
	appendPolyNTTToBytes(m)

	for i := 0; i < len(cmts[0].b.polyNTTs); i++ {
		appendPolyNTTToBytes(cmts[0].b.polyNTTs[i])
	}
	appendPolyNTTToBytes(cmts[0].c)

	for i := 0; i < pp.paramK; i++ {
		for j := 0; j < pp.paramKC; j++ {
			appendPolyNTTToBytes(ws[i].polyNTTs[j])
		}
		appendPolyNTTToBytes(deltas[i])
	}
	return tmp
}

// collectBytesForCoinbase2 is an auxiliary function for CoinbaseTxGen and CoinbaseTxVerify to collect some information into a byte slice
func (pp *PublicParameterv2) collectBytesForCoinbase2(b_hat *PolyNTTVecv2, c_hats []*PolyNTTv2) []byte {
	res := make([]byte, pp.paramKC*pp.paramDC*4+pp.paramDC*4*len(c_hats))
	appendPolyNTTToBytes := func(a *PolyNTTv2) {
		for k := 0; k < pp.paramDC; k++ {
			res = append(res, byte(a.coeffs1[k]>>0))
			res = append(res, byte(a.coeffs1[k]>>8))
			res = append(res, byte(a.coeffs1[k]>>16))
			res = append(res, byte(a.coeffs1[k]>>24))
		}
	}
	for i := 0; i < pp.paramKC; i++ {
		appendPolyNTTToBytes(b_hat.polyNTTs[i])
	}
	for i := 0; i < len(c_hats); i++ {
		appendPolyNTTToBytes(c_hats[i])
	}
	return res
}

func (pp *PublicParameterv2) TransferTxGen(inputDescs []*TxInputDescv2, outputDescs []*TxOutputDescv2, fee uint64, txMemo []byte) (trTx *TransferTxv2, err error) {
	//	check the well-formness of the inputs and outputs
	if len(inputDescs) == 0 || len(outputDescs) == 0 {
		return nil, errors.New("some information is empty")
	}

	if len(inputDescs) > pp.paramI {
		return nil, errors.New("too many inputs") //Todo: may define a new error type?
	}
	if len(outputDescs) > pp.paramJ {
		return nil, errors.New("too many outputs")
	}

	V := uint64(1)<<pp.paramN - 1

	if fee > V {
		return nil, errors.New("the transaction fee is more than V")
	}

	//	check on the outputDesc is simple, so check it first
	outputTotal := fee
	for _, outputDescItem := range outputDescs {
		if outputDescItem.value > V {
			return nil, errors.New("the value is more than max value")
		}
		outputTotal = outputTotal + outputDescItem.value
		if outputTotal > V {
			return nil, errors.New("the value is more than max value")
		}

		if outputDescItem.pk == nil {
			return nil, errors.New("the master public key is nil")
		}
		if !outputDescItem.pk.WellformCheck(pp) {
			return nil, errors.New("the pk is not well-form")
		}
	}

	inputTotal := uint64(0)
	//dpkMap := make(map[*PublicKey]struct{})
	for _, inputDescItem := range inputDescs {
		if inputDescItem.value > V {
			return nil, errors.New("the value is more than max value")
		}
		inputTotal = inputTotal + inputDescItem.value
		if inputTotal > V {
			return nil, errors.New("the value is more than max value")
		}

		if len(inputDescItem.txoList) == 0 {
			return nil, errors.New("the transaction output list is empty")
		}
		if inputDescItem.sidx < 0 || inputDescItem.sidx >= len(inputDescItem.txoList) {
			return nil, errors.New("the index is not suitable")
		}
		if inputDescItem.txoList[inputDescItem.sidx].PublicKey == nil || inputDescItem.sk == nil {
			return nil, errors.New("some information is empty")
		}

		if inputDescItem.sk.WellformCheck(pp) == false {
			return nil, errors.New("the master view key is not well-formed")
		}

		b := pp.ComVerify(inputDescItem.txoList[inputDescItem.sidx].Commitmentv2, inputDescItem.r, inputDescItem.value)
		if b == false {
			return nil, errors.New("fail to receive some transaction output")
		}
	}

	if outputTotal != inputTotal {
		return nil, errors.New("the total coin value is not balance")
	}

	I := len(inputDescs)
	J := len(outputDescs)

	cmt_out_js := make([]*Commitmentv2, J)
	cmt_r_out_js := make([]*PolyNTTVecv2, J)
	txo_out_js := make([]*TXOv2, J)

	rettrTx := &TransferTxv2{}
	rettrTx.Inputs = make([]*TrTxInputv2, I)
	//rettrTx.OutputTxos = make([]*TXOv2, J)
	//rettrTx.Fee = fee
	//rettrTx.TxMemo = txMemo

	for j := 0; j < J; j++ {
		cmt_out_js[j], cmt_r_out_js[j], err = pp.ComGen(outputDescs[j].value)
		if err != nil {
			return nil, errors.New("fail to generate the transaction output")
		}
		txo_out_js[j] = &TXOv2{
			PublicKey:    outputDescs[j].pk,
			Commitmentv2: cmt_out_js[j],
		}
	}
	m_r_in_is := make([]*Polyv2, I)
	sns := make([]*Polyv2, I)
	for i := 0; i < I; i++ {
		m_r_in_is[i] = pp.ExpandKIDR(inputDescs[i].txoList[inputDescs[i].sidx])
		sns[i] = PolyAdd(inputDescs[i].sk.ma, m_r_in_is[i], R_QA)

		rettrTx.Inputs[i] = &TrTxInputv2{
			TxoList:      inputDescs[i].txoList,
			SerialNumber: sns[i],
		}
	}
	rettrTx.OutputTxos = txo_out_js
	rettrTx.Fee = fee
	rettrTx.TxMemo = txMemo

	cmt_in_ips := make([]*Commitmentv2, I)
	r_in_ips := make([]*PolyNTTVecv2, I)
	m_in_is := make([]*PolyNTTv2, I)
	m_ins := make([][]int32, I)
	for i := 0; i < I; i++ {
		m_ins[i] = intToBinary(inputDescs[i].value, pp.paramDC)
		m_in_is[i] = pp.NTTInRQc(&Polyv2{coeffs1: m_ins[i]})
		cmt_in_ips[i], r_in_ips[i], err = pp.ComGen(inputDescs[i].value)
		if err != nil {
			return nil, errors.New("error for ComGen")
		}
	}
	rettrTx.TxWitness = &TrTxWitnessv2{
		b_hat:      nil,
		c_hats:     nil,
		u_p:        nil,
		rpulpproof: nil,
		cmtps:      cmt_in_ips,
		elrsSigs:   nil,
	}

	msgTrTxCon := rettrTx.Serialize(false)
	if msgTrTxCon == nil {
		return nil, errors.New("error in rettrTx.Serialize ")
	}
	msgTrTxConHash, err := Hash(msgTrTxCon)
	if err != nil {
		return nil, err
	}

	elrsSigs := make([]*elrsSignaturev2, I)
	m_a_in_ips := make([]*Polyv2, I)
	for i := 0; i < I; i++ {
		m_a_in_ips[i] = sns[i]
		elrsSigs[i], err = pp.ELRSSign(
			inputDescs[i].txoList, m_a_in_ips[i], cmt_in_ips[i], msgTrTxConHash,
			inputDescs[i].sidx, inputDescs[i].sk.s, inputDescs[i].r,
			r_in_ips[i], m_in_is[i])
		if err != nil {
			return nil, errors.New("fail to generate the extend linkable signature")
		}
	}

	n := I + J
	n2 := I + J + 2
	if I > 1 {
		n2 = I + J + 4
	}
	m_is := make([]*PolyNTTv2, n)
	r_is := make([]*PolyNTTVecv2, n)
	ms := make([][]int32, n2)
	for i := 0; i < I; i++ {
		m_is[i] = m_in_is[i]
		r_is[i] = r_in_ips[i]
		ms[i] = m_ins[i]
	}
	for j := 0; j < J; j++ {
		ms[I+j] = intToBinary(outputDescs[j].value, pp.paramDC)
		m_is[I+j] = pp.NTTInRQc(&Polyv2{coeffs1: ms[I+j]})
		r_is[I+j] = cmt_r_out_js[j]

	}
	//	fee
	u := intToBinary(fee, pp.paramDC)

	if I == 1 {
		c_hats := make([]*PolyNTTv2, n2) //	n2 = n+2

		//	f is the carry vector, such that, m_1 = m_2+ ... + m_n + u
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + 2 f[i] = m_1[i-1] + .. + m_{n-1}[i-1] + u[i-1] + f[i-1],
		//	m_0[d-1] 		  = m_1[d-1] + .. + m_{n-1}[d-1] + f[d-1],
		f := make([]int32, pp.paramDC)
		f[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int32(0)
			for j := 1; j < n; j++ {
				tmp = tmp + ms[j][i-1]
			}
			f[i] = (tmp + u[i-1] + f[i-1] - ms[0][i-1]) >> 1
		}
		ms[n] = f

	trTxGenI1Restart:
		e, err := pp.sampleUniformWithinEtaFv2()
		if err != nil {
			return nil, err
		}
		ms[n+1] = e

		randomnessC, err := pp.sampleRandomnessRv2()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVecInRQc(randomnessC)
		b_hat := PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, R_QC, pp.paramKC, pp.paramLC)
		for i := 0; i < n2; i++ { // n2 = I+J+4 = n+4
			c_hats[i] = PolyNTTAdd(
				PolyNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, R_QC, pp.paramLC),
				&PolyNTTv2{coeffs1: ms[i]},
				R_QC)
		}

		// todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramDC)
		u_p_temp := make([]int64, pp.paramDC) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM, err := Hash(pp.collectBytesForTransfer(b_hat, c_hats))
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return nil, err
		}
		// todo: check B f + e
		// up = B * f + e
		for i := 0; i < pp.paramDC; i++ {
			u_p_temp[i] = int64(e[i])
			for j := 0; j < pp.paramDC; j++ {
				if (binM[i][j/8]>>(j%8))&1 == 1 {
					u_p_temp[i] += int64(f[j])
				}
			}

			infNorm := u_p_temp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm > int64(pp.paramEtaF-int32(J)) {
				goto trTxGenI1Restart
			}

			u_p[i] = reduceToQc(u_p_temp[i])
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = u
		u_hats[1] = make([]int32, pp.paramDC)
		u_hats[2] = u_p

		n1 := n
		cmts := make([]*Commitmentv2, 0, I+J)
		for i := 0; i < I; i++ {
			cmts = append(cmts, cmt_in_ips[i])
		}
		for i := 0; i < J; i++ {
			cmts = append(cmts, cmt_out_js[i])
		}
		rprlppi, pi_err := pp.rpulpProve(cmts, r_is, n, b_hat, r_hat, c_hats, ms, n2, n1, RpUlpTypeTrTx1, binM, I, J, 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness.b_hat = b_hat
		rettrTx.TxWitness.c_hats = c_hats
		rettrTx.TxWitness.u_p = u_p
		rettrTx.TxWitness.rpulpproof = rprlppi
		rettrTx.TxWitness.elrsSigs = elrsSigs
	} else {

		c_hats := make([]*PolyNTTv2, n2) //	n2 = n+4

		ms[n] = intToBinary(inputTotal, pp.paramDC) //	v_in

		//	f1 is the carry vector, such that, m_0 + m_1+ ... + m_{I-1} = m_{n}
		//	f1[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + .. + m_{I-1}[i-1] + f1[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_0[d-1] + .. + m_{I-1}[d-1] + f1[d-1] = m_n[d-1] ,
		f1 := make([]int32, pp.paramDC)
		f1[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int32(0)
			for j := 0; j < I; j++ {
				tmp = tmp + ms[j][i-1]
			}
			f1[i] = (tmp + f1[i-1] - ms[n][i-1]) >> 1
		}
		ms[n+1] = f1

		//	f2 is the carry vector, such that, m_I + m_{I+1}+ ... + m_{(I+J)-1} + u = m_{n}
		//	f2[0] = 0, and for i=1 to d-1,
		//	m_I[i-1] + .. + m_{I+J-1}[i-1] + u[i-1] + f2[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_I[d-1] + .. + m_{I+J-1}[d-1] + u[d-1] + f2[d-1] = m_n[d-1] ,
		f2 := make([]int32, pp.paramDC)
		f2[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int32(0)
			for j := 0; j < J; j++ {
				tmp = tmp + ms[I+j][i-1]
			}
			f2[i] = (tmp + u[i-1] + f2[i-1] - ms[n][i-1]) >> 1
		}
		ms[n+2] = f2

	trTxGenI2Restart:
		e, err := pp.sampleUniformWithinEtaFv2()
		if err != nil {
			return nil, err
		}
		ms[n+3] = e

		randomnessC, err := pp.sampleRandomnessRv2()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVecInRQc(randomnessC)

		b_hat := PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, R_QC, pp.paramKC, pp.paramLC)

		for i := 0; i < n2; i++ { // n2 = I+J+4 = n+4
			c_hats[i] = PolyNTTAdd(
				PolyNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, R_QC, pp.paramLC),
				&PolyNTTv2{coeffs1: ms[i]},
				R_QC)
		}

		// todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramDC)
		u_p_temp := make([]int64, pp.paramDC) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM, err := Hash(pp.collectBytesForTransfer(b_hat, c_hats))
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, 2*pp.paramDC)
		if err != nil {
			return nil, err
		}
		// todo: check B (f_1 || f_2) + e
		betaF := I
		if J+1 > betaF {
			betaF = J + 1
		}
		betaF = betaF - 1

		for i := 0; i < pp.paramDC; i++ {
			u_p_temp[i] = int64(e[i])
			for j := 0; j < pp.paramDC; j++ {
				//	u_p_temp[i] = u_p_temp[i] + int64(e[j])

				if (binM[i][j/8]>>(j%8))&1 == 1 {
					u_p_temp[i] += int64(f1[j])
				}
				if (binM[i][(pp.paramDC+j)/8]>>((pp.paramDC+j)%8))&1 == 1 {
					u_p_temp[i] += int64(f2[j])
				}
			}

			infNorm := u_p_temp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm > int64(pp.paramEtaF-int32(betaF)) {
				goto trTxGenI2Restart
			}

			u_p[i] = reduceToQc(u_p_temp[i])
		}

		u_hats := make([][]int32, 5)
		u_hats[0] = make([]int32, pp.paramDC)
		// todo_DONE: -u
		u_hats[1] = make([]int32, pp.paramDC)
		for i := 0; i < len(u_hats[1]); i++ {
			u_hats[1][i] = -u[i]
		}
		u_hats[2] = make([]int32, pp.paramDC)
		u_hats[3] = make([]int32, pp.paramDC)
		u_hats[4] = u_p

		n1 := n + 1
		cmts := make([]*Commitmentv2, 0, I+J)
		for i := 0; i < I; i++ {
			cmts = append(cmts, cmt_in_ips[i])
		}
		for i := 0; i < J; i++ {
			cmts = append(cmts, cmt_out_js[i])
		}
		rprlppi, pi_err := pp.rpulpProve(cmts, r_is, n, b_hat, r_hat, c_hats, ms, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness.b_hat = b_hat
		rettrTx.TxWitness.c_hats = c_hats
		rettrTx.TxWitness.u_p = u_p
		rettrTx.TxWitness.rpulpproof = rprlppi
		rettrTx.TxWitness.elrsSigs = elrsSigs
	}
	rettrTx.TxWitness.m_a_inps = m_a_in_ips
	return rettrTx, err
}

// TransferTxVerify reports whether a transfer transaction is legal.
func (pp *PublicParameterv2) TransferTxVerify(trTx *TransferTxv2) bool {
	if trTx == nil {
		return false
	}

	I := len(trTx.Inputs)
	J := len(trTx.OutputTxos)

	if I <= 0 || I > pp.paramI {
		return false
	}
	if J <= 0 || J > pp.paramJ {
		return false
	}

	//	todo: check the well-form of TxWitness

	//	check the ring signatures
	msgTrTxCon := trTx.Serialize(false)
	if msgTrTxCon == nil {
		return false
	}
	msgTrTxConHash, err := Hash(msgTrTxCon)
	if err != nil {
		return false
	}
	for i := 0; i < I; i++ {
		//	check the validity of sigma_{lrs,i}
		if !pp.PolyEqualCheck(trTx.Inputs[i].SerialNumber, trTx.TxWitness.m_a_inps[i], R_QA) {
			return false
		}

		if !pp.ELRSVerify(trTx.Inputs[i].TxoList, trTx.TxWitness.m_a_inps[i], trTx.TxWitness.cmtps[i], msgTrTxConHash, trTx.TxWitness.elrsSigs[i]) {
			return false
		}
	}

	// check the balance proof
	n := I + J
	cmts := make([]*Commitmentv2, n)
	for i := 0; i < I; i++ {
		cmts[i] = trTx.TxWitness.cmtps[i]
	}
	for j := 0; j < J; j++ {
		cmts[I+j] = trTx.OutputTxos[j].Commitmentv2
	}

	u := intToBinary(trTx.Fee, pp.paramDC)

	if I == 1 {
		n2 := n + 2
		n1 := n

		betaF := J

		//	todo: consider with TransferTxGen
		for i := 0; i < len(trTx.TxWitness.u_p); i++ {
			infNorm := trTx.TxWitness.u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > (pp.paramEtaF - int32(betaF)) {
				return false
			}
		}

		seed_binM, err := Hash(pp.collectBytesForTransfer(trTx.TxWitness.b_hat, trTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return false
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = u
		u_hats[1] = make([]int32, pp.paramDC)
		u_hats[2] = trTx.TxWitness.u_p

		flag := pp.rpulpVerify(cmts, n, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats, n2, n1, RpUlpTypeTrTx1, binM, I, J, 3, u_hats, trTx.TxWitness.rpulpproof)
		if !flag {
			return false
		}
	} else {
		//	I >= 2
		n2 := n + 4
		n1 := n + 1

		betaF := I
		if J+1 > betaF {
			betaF = J + 1
		}
		betaF = betaF - 1

		//	todo: consider with TransferTxGen
		for i := 0; i < len(trTx.TxWitness.u_p); i++ {
			infNorm := trTx.TxWitness.u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > (pp.paramEtaF - int32(betaF)) {
				return false
			}
		}

		seed_binM, err := Hash(pp.collectBytesForTransfer(trTx.TxWitness.b_hat, trTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, 2*pp.paramDC)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 5)
		u_hats[0] = make([]int32, pp.paramDC)
		// todo_DONE: -u
		u_hats[1] = make([]int32, pp.paramDC)
		for i := 0; i < len(u_hats[1]); i++ {
			u_hats[1][i] = -u[i]
		}
		u_hats[2] = make([]int32, pp.paramDC)
		u_hats[3] = make([]int32, pp.paramDC)
		u_hats[4] = trTx.TxWitness.u_p

		flag := pp.rpulpVerify(cmts, n, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats, trTx.TxWitness.rpulpproof)
		if !flag {
			return false
		}
	}

	return true
}

func (pp *PublicParameterv2) collectBytesForTransfer(b_hat *PolyNTTVecv2, c_hats []*PolyNTTv2) []byte {
	res := make([]byte, pp.paramKC*pp.paramDC*4+pp.paramDC*4*len(c_hats))
	appendPolyNTTToBytes := func(a *PolyNTTv2) {
		for k := 0; k < pp.paramDC; k++ {
			res = append(res, byte(a.coeffs1[k]>>0))
			res = append(res, byte(a.coeffs1[k]>>8))
			res = append(res, byte(a.coeffs1[k]>>16))
			res = append(res, byte(a.coeffs1[k]>>24))
		}
	}
	for i := 0; i < pp.paramKC; i++ {
		appendPolyNTTToBytes(b_hat.polyNTTs[i])
	}
	for i := 0; i < len(c_hats); i++ {
		appendPolyNTTToBytes(c_hats[i])
	}
	return res
}
