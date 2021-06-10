package pqringct

import (
	"bytes"
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
)

/*func NewPolyNTTVec(rowlength int, colLength int) *PolyNTTVec {
	res := make([]*PolyNTT, rowlength)
	for i := 0; i < rowlength; i++ {
		res[i] = NewPolyNTT(colLength)
	}
	return &PolyNTTVec{polyNTTs: res}
}*/

/*
This file defines all public constants and interfaces of PQRingCT.
*/

type MasterPublicKey struct {
	pkkem *kyber.PublicKey
	t     *PolyNTTVec // directly in NTT form
}

type MasterSecretViewKey struct {
	skkem *kyber.SecretKey
}

type MasterSecretSignKey struct {
	s *PolyNTTVec
}

type CoinbaseTx struct {
	//	Version uint32

	Vin        uint64
	OutputTxos []*TXO

	TxWitness *CbTxWitness
}

type CbTxWitness struct {
	b_hat      *PolyNTTVec
	c_hats     []*PolyNTT
	u_p        []int32
	rpulpproof *rpulpProof
}

type TransferTx struct {
	//	Version uint32

	Inputs     []*TrTxInput
	OutputTxos []*TXO
	Fee        uint64

	TxMemo []byte

	TxWitness *TrTxWitness
}

type TrTxInput struct {
	TxoList []*TXO
	//SerialNumber []byte
	SerialNumber []byte // todo_DONE: change to a hash value
}

type TXO struct {
	dpk *DerivedPubKey
	cmt *Commitment
	vc  []byte
}

type TrTxWitness struct {
	b_hat      *PolyNTTVec
	c_hats     []*PolyNTT
	u_p        []int32
	rpulpproof *rpulpProof
	cmtps      []*Commitment
	elrsSigs   []*elrsSignature
}

type DerivedPubKey struct {
	ckem []byte
	t    *PolyNTTVec
}

type Commitment struct {
	b *PolyNTTVec
	c *PolyNTT
}

type rpulpProof struct {
	c_waves []*PolyNTT
	c_hat_g *PolyNTT
	psi     *PolyNTT
	phi     *PolyNTT
	chseed  []byte
	cmt_zs  [][]*PolyNTTVec
	zs      []*PolyNTTVec
}

type elrsSignature struct {
	chseed []byte
	z_as   [][]*PolyNTTVec
	z_cs   [][]*PolyNTTVec
	keyImg *PolyNTTVec
}

func (pp *PublicParameter) GetMasterPublicKeyByteLen() uint32 {
	return uint32(pp.paramKem.CryptoPublicKeyBytes() + pp.paramKa*pp.paramD*4)
}

func (pp *PublicParameter) GetTxoByteLen() uint32 {
	return uint32(
		pp.paramKem.CryptoCiphertextBytes() + // dpk.ckem
			pp.paramKa*pp.paramD*4 + // dpk.t
			pp.paramKc*pp.paramD*4 + // cmt.b
			pp.paramD*4 + // cmt.c
			pp.paramD*4, // vc
	)
}
func (pp *PublicParameter) GetCbTxWitnessMaxLen() uint32 {
	return uint32(
		pp.paramKc*pp.paramD*4 + // b_hat
			(pp.paramJ+2)*pp.paramD*4 + // c_hats
			pp.paramD*4 + // u_p
			pp.paramJ*pp.paramD*4 + //rpuprf.c_waves
			pp.paramD*4 + // rpuprf.c_hat_g
			pp.paramD*4 + //rpuprf.psi
			pp.paramD*4 + //rpuprf.phi
			4 + // rpuprf.chseed
			pp.paramK*pp.paramJ*pp.paramD*4 + // rpuprf.cmt_zs
			pp.paramK*pp.paramLc*pp.paramD*4, // rpuprg.zs
	)
}
func (pp *PublicParameter) GetTrTxWitnessMaxLen() uint32 {
	return uint32(
		pp.paramKc*pp.paramD*4 + // b_hat
			(pp.paramI+pp.paramJ+4)*pp.paramD*4 + // c_hats
			pp.paramKc*pp.paramD*4 + // u_p
			(pp.paramI+pp.paramJ)*pp.paramD*4 + //rpuprf.c_waves
			pp.paramD*4 + // rpuprf.c_hat_g
			pp.paramD*4 + //rpuprf.psi
			pp.paramD*4 + //rpuprf.phi
			4 + // rpuprf.chseed
			pp.paramK*(pp.paramI+pp.paramJ)*pp.paramD*4 + // rpuprf.cmt_zs
			pp.paramK*pp.paramLc*pp.paramD*4, // rpuprg.zs
	)
}

/*type ValueCommitment struct {

}

type ValueCiphertext struct {

}*/

type TxInputDesc struct {
	txoList []*TXO
	sidx    int
	mpk     *MasterPublicKey
	msvk    *MasterSecretViewKey
	mssk    *MasterSecretSignKey
	value   uint64
}

func NewTxInputDesc(txpList []*TXO, sidx int, mpk *MasterPublicKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, value uint64) *TxInputDesc {
	return &TxInputDesc{
		txpList,
		sidx,
		mpk,
		msvk,
		mssk,
		value,
	}
}

type TxOutputDesc struct {
	mpk   *MasterPublicKey
	value uint64
}

func NewTxOutputDesc(mpk *MasterPublicKey, value uint64) *TxOutputDesc {
	return &TxOutputDesc{
		mpk,
		value,
	}
}

//	public fun	begin
func Setup() (pp *PublicParameter) {
	// todo
	return nil
}

// MasterKeyGen generates the master public key, master view key, and master sign key.
// If the seed is nil, this function will random a seed whose length is paramSysBytes.
// This function requires the length of seed is at least 2*paramSysBytes.
func (pp *PublicParameter) MasterKeyGen(seed []byte) (retSeed []byte, mpk *MasterPublicKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, err error) {
	/*	mpk := MasterPublicKey{}
		msvk := MasterSecretViewKey{}
		mssk := MasterSecretSignKey{}

		return &mpk, &msvk, &mssk, nil*/

	var s *PolyNTTVec
	var randomnessA *PolyVec
	var kemPK *kyber.PublicKey
	var kemSK *kyber.SecretKey

	// check the validity of the length of seed
	if seed != nil && len(seed) < 2*pp.paramSysBytes {
		return nil, nil, nil, nil, errors.New("the length of seed is invalid")
	}
	if seed == nil {
		seed = randomBytes(2 * pp.paramSysBytes)
	}
	// this temporary byte slice is for protect seed unmodified
	tmp := make([]byte, pp.paramSysBytes)
	for i := 0; i < pp.paramSysBytes; i++ {
		tmp[i] = seed[i]
	}
	randomnessA, err = pp.expandRandomnessA(tmp)
	if err != nil {
		return seed, nil, nil, nil, err
	}
	for i := 0; i < pp.paramSysBytes; i++ {
		tmp[i] = seed[i+pp.paramSysBytes]
	}
	kemPK, kemSK, err = pp.paramKem.CryptoKemKeyPair(tmp)
	if err != nil {
		return seed, nil, nil, nil, err
	}

	s = pp.NTTVec(randomnessA)
	// t = A * s, will be as a part of public key
	t := pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s, pp.paramKa, pp.paramLa)

	rstmpk := &MasterPublicKey{
		kemPK,
		t,
	}

	rstmsvk := &MasterSecretViewKey{
		skkem: kemSK,
	}

	rstmssk := &MasterSecretSignKey{
		s: s,
	}

	return seed, rstmpk, rstmsvk, rstmssk, nil
}

// collectBytesForCoinbase1 is an auxiliary function for CoinbaseTxGen and CoinbaseTxVerify to collect some information into a byte slice
func (pp *PublicParameter) collectBytesForCoinbase1(vin uint64, cmts []*Commitment, ws []*PolyNTTVec, deltas []*PolyNTT) []byte {
	tmp := make([]byte, pp.paramD*4+(pp.paramKc+1)*pp.paramD*4+(pp.paramKc+1)*pp.paramD*4)
	appendPolyNTTToBytes := func(a *PolyNTT) {
		for k := 0; k < pp.paramD; k++ {
			tmp = append(tmp, byte(a.coeffs[k]>>0))
			tmp = append(tmp, byte(a.coeffs[k]>>8))
			tmp = append(tmp, byte(a.coeffs[k]>>16))
			tmp = append(tmp, byte(a.coeffs[k]>>24))
		}
	}

	mbin := intToBinary(vin, pp.paramD)
	m := &PolyNTT{mbin}
	appendPolyNTTToBytes(m)

	for i := 0; i < len(cmts[0].b.polyNTTs); i++ {
		appendPolyNTTToBytes(cmts[0].b.polyNTTs[i])
	}
	appendPolyNTTToBytes(cmts[0].c)

	for i := 0; i < pp.paramK; i++ {
		for j := 0; j < pp.paramKc; j++ {
			appendPolyNTTToBytes(ws[i].polyNTTs[j])
		}
		appendPolyNTTToBytes(deltas[i])
	}
	return tmp
}

// collectBytesForCoinbase2 is an auxiliary function for CoinbaseTxGen and CoinbaseTxVerify to collect some information into a byte slice
func (pp *PublicParameter) collectBytesForCoinbase2(b_hat *PolyNTTVec, c_hats []*PolyNTT) []byte {
	res := make([]byte, pp.paramKc*pp.paramD*4+pp.paramD*4*len(c_hats))
	appendPolyNTTToBytes := func(a *PolyNTT) {
		for k := 0; k < pp.paramD; k++ {
			res = append(res, byte(a.coeffs[k]>>0))
			res = append(res, byte(a.coeffs[k]>>8))
			res = append(res, byte(a.coeffs[k]>>16))
			res = append(res, byte(a.coeffs[k]>>24))
		}
	}
	for i := 0; i < pp.paramKc; i++ {
		appendPolyNTTToBytes(b_hat.polyNTTs[i])
	}
	for i := 0; i < len(c_hats); i++ {
		appendPolyNTTToBytes(c_hats[i])
	}
	return res
}

// CoinbaseTxGen returns an coinbase transaction with the transaction outputs request
func (pp *PublicParameter) CoinbaseTxGen(vin uint64, txOutputDescs []*TxOutputDesc) (cbTx *CoinbaseTx, err error) {
	V := uint64(1)<<pp.paramN - 1

	if vin >= V {
		return nil, errors.New("vin is not in [0, V]") // todo: more accurate info
	}

	if len(txOutputDescs) == 0 || len(txOutputDescs) > pp.paramJ {
		return nil, errors.New("the number of outputs is not in [1, I_max]") // todo: more accurate info
	}

	J := len(txOutputDescs)

	retcbTx := &CoinbaseTx{}
	//	retcbTx.Version = 0 // todo: how to set and how to use the version? The bpf just care the content of cbTx?
	retcbTx.Vin = vin
	retcbTx.OutputTxos = make([]*TXO, J)

	cmts := make([]*Commitment, J)
	cmt_rs := make([]*PolyNTTVec, J)

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

		retcbTx.OutputTxos[j], cmt_rs[j], err = pp.txoGen(txOutputDesc.mpk, txOutputDesc.value)
		if err != nil {
			return nil, err
		}
		cmts[j] = retcbTx.OutputTxos[j].cmt
	}
	if vout > vin {
		return nil, errors.New("the output value exceeds the input value") // todo: more accurate info
	}

	if J == 1 {
		// random from S_etaC^lc
		ys := make([]*PolyNTTVec, pp.paramK)
		// w^t = B * y^t
		ws := make([]*PolyNTTVec, pp.paramK)
		// delta = <h,y^t>
		deltas := make([]*PolyNTT, pp.paramK)
		// z^t = y^t + sigma^t(c) * r_(out,j), r_(out,j) is from txoGen, in there, r_(out,j) is cmt_rs_j
		zs := make([]*PolyNTTVec, pp.paramK)

	cbTxGenJ1Restart:
		for t := 0; t < pp.paramK; t++ {
			// random y
			maskC, err := pp.sampleMaskC()
			if err != nil {
				return nil, err
			}
			ys[t] = pp.NTTVec(maskC)

			ws[t] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKc, pp.paramLc)
			deltas[t] = pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], ys[t], pp.paramLc)
		}

		chseed, err := Hash(pp.collectBytesForCoinbase1(vin, cmts, ws, deltas))
		if err != nil {
			return nil, err
		}
		chtmp, err := pp.expandChallenge(chseed)
		if err != nil {
			return nil, err
		}
		ch := pp.NTT(chtmp)

		for t := 0; t < pp.paramK; t++ {
			zs[t] = pp.PolyNTTVecAdd(
				ys[t],
				pp.PolyNTTVecScaleMul(pp.sigmaPowerPolyNTT(ch, t), cmt_rs[0], pp.paramLc),
				pp.paramLc)
			// check the norm
			tmp := pp.NTTInvVec(zs[t])
			norm := tmp.infNorm()
			if norm > pp.paramEtaC-pp.paramBetaC {
				goto cbTxGenJ1Restart
			}
		}

		retcbTx.TxWitness = &CbTxWitness{
			rpulpproof: &rpulpProof{
				chseed: chseed,
				zs:     zs,
			},
		}
	} else {
		//	J >= 2
		n := J
		n2 := n + 2

		c_hats := make([]*PolyNTT, n2)

		msg_hats := make([][]int32, n2)

		u_hats := make([][]int32, 3)
		u_hats[0] = intToBinary(vin, pp.paramD)

		for j := 0; j < J; j++ {
			msg_hats[j] = intToBinary(txOutputDescs[j].value, pp.paramD)
		}

		u := intToBinary(vin, pp.paramD)

		//	f is the carry vector, such that, u = m_0 + m_1 + ... + m_{J-1}
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1] + 2 f[i],
		//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1]
		f := make([]int32, pp.paramD)
		f[0] = 0
		for i := 1; i < pp.paramD; i++ {
			tmp := int32(0)
			for j := 0; j < J; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			f[i] = (tmp + f[i-1] - u[i-1]) >> 1
		}
		msg_hats[J] = f

	cbTxGenJ2Restart:
		e := make([]int32, pp.paramD)
		e, err := pp.sampleUniformWithinEtaF()
		if err != nil {
			return nil, err
		}
		msg_hats[J+1] = e

		randomnessC, err := pp.sampleRandomnessC()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVec(randomnessC)

		// b_hat =B * r_hat
		b_hat := pp.PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKc, pp.paramLc)

		for i := 0; i < n2; i++ { // n2 = J+2
			c_hats[i] = pp.PolyNTTAdd(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], r_hat, pp.paramLc),
				&PolyNTT{msg_hats[i]})
		}

		//	todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramD) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		u_p_tmp := make([]int64, pp.paramD)

		seed_binM, err := Hash(pp.collectBytesForCoinbase2(b_hat, c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		if err != nil {
			return nil, err
		}
		// todo: check B f + e
		for i := 0; i < pp.paramD; i++ {
			u_p_tmp[i] = int64(e[i])
			for j := 0; j < pp.paramD; j++ {
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

			u_p[i] = pp.reduce(u_p_tmp[i])
		}

		u_hats[1] = make([]int32, pp.paramD)
		u_hats[2] = u_p

		n1 := n
		rprlppi, pi_err := pp.rpulpProve(cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		retcbTx.TxWitness = &CbTxWitness{
			b_hat:      b_hat,
			c_hats:     c_hats,
			u_p:        u_p,
			rpulpproof: rprlppi,
		}
	}

	return retcbTx, nil
}

// CoinbaseTxVerify reports whether a coinbase transaction is legal.
func (pp *PublicParameter) CoinbaseTxVerify(cbTx *CoinbaseTx) bool {
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
	dpkMap := make(map[*DerivedPubKey]struct{})
	for i := 0; i < len(cbTx.OutputTxos); i++ {
		if _, ok := dpkMap[cbTx.OutputTxos[i].dpk]; !ok {
			dpkMap[cbTx.OutputTxos[i].dpk] = struct{}{}
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
			if pp.NTTInvVec(cbTx.TxWitness.rpulpproof.zs[t]).infNorm() > pp.paramEtaC-pp.paramBetaC {
				return false
			}
		}

		ws := make([]*PolyNTTVec, pp.paramK)
		deltas := make([]*PolyNTT, pp.paramK)

		chtmp, err := pp.expandChallenge(cbTx.TxWitness.rpulpproof.chseed)
		if err != nil {
			return false
		}
		ch := pp.NTT(chtmp)
		msg := intToBinary(cbTx.Vin, pp.paramD)
		for t := 0; t < pp.paramK; t++ {
			sigma_t_ch := pp.sigmaPowerPolyNTT(ch, t)

			ws[t] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cbTx.TxWitness.rpulpproof.zs[t], pp.paramKc, pp.paramLc),
				pp.PolyNTTVecScaleMul(sigma_t_ch, cbTx.OutputTxos[0].cmt.b, pp.paramKc),
				pp.paramKc)
			deltas[t] = pp.PolyNTTSub(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cbTx.TxWitness.rpulpproof.zs[t], pp.paramLc),
				pp.PolyNTTMul(
					sigma_t_ch,
					pp.PolyNTTSub(cbTx.OutputTxos[0].cmt.c, &PolyNTT{msg})))
		}

		seed_ch, err := Hash(pp.collectBytesForCoinbase1(cbTx.Vin, []*Commitment{cbTx.OutputTxos[0].cmt}, ws, deltas))
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
		if len(cbTx.TxWitness.u_p) != pp.paramD {
			return false
		}
		for i := 0; i < pp.paramD; i++ {
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
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = intToBinary(cbTx.Vin, pp.paramD)
		u_hats[1] = make([]int32, pp.paramD)
		u_hats[2] = cbTx.TxWitness.u_p

		cmts := make([]*Commitment, n)
		for i := 0; i < n; i++ {
			cmts[i] = cbTx.OutputTxos[i].cmt
		}

		n1 := n
		return pp.rpulpVerify(cmts, n, cbTx.TxWitness.b_hat, cbTx.TxWitness.c_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats, cbTx.TxWitness.rpulpproof)
	}

	return true
}

// TxoCoinReceive reports whether a transaction output belongs to the given master key pair
// If true, it will show the coin value, otherwise, the returned value is 0.
func (pp *PublicParameter) TxoCoinReceive(txo *TXO, mpk *MasterPublicKey, msvk *MasterSecretViewKey) (valid bool, coinvale uint64) {
	if txo == nil || mpk == nil || msvk == nil {
		return false, 0
	}

	// todo: check the well-formness of dpk
	// (C, t)

	kappa := msvk.skkem.CryptoKemDec(txo.dpk.ckem)
	sptmp, err := pp.expandRandomnessA(kappa) // TODO_DONE handle the err
	if err != nil {
		return false, 0
	}
	s_p := pp.NTTVec(sptmp)
	t_hat_p := pp.PolyNTTVecAdd(
		mpk.t,
		pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s_p, pp.paramKa, pp.paramLa),
		pp.paramKa)

	if pp.PolyNTTVecEqualCheck(txo.dpk.t, t_hat_p) != true {
		return false, 0
	}

	v := uint64(0)
	// recover value from txo.vc
	sk, err := pp.expandRandomBitsV(kappa)
	if err != nil {
		return false, 0
	}
	for i := 0; i < pp.paramD; i++ {
		v |= uint64(sk[i]^txo.vc[i]) << i
	}
	// check value
	if v > uint64(1<<pp.paramN-1) {
		return false, 0
	}
	m := intToBinary(v, pp.paramD)
	cmtrtmp, err := pp.expandRandomnessC(kappa) // TODO_DONE handle the err
	if err != nil {
		return false, 0
	}
	cmt_r := pp.NTTVec(cmtrtmp)
	cmt := &Commitment{}
	cmt.b = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_r, pp.paramKc, pp.paramLc)
	cmt.c = pp.PolyNTTAdd(
		pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cmt_r, pp.paramLc),
		&PolyNTT{m})

	if pp.PolyNTTVecEqualCheck(cmt.b, txo.cmt.b) != true {
		return false, 0
	}

	if pp.PolyNTTEqualCheck(cmt.c, txo.cmt.c) != true {
		return false, 0
	}

	return true, v
}

// collectBytesForTransfer is an auxiliary function for TransferTxGen and TransferTxVerify to collect some information into a byte slice
func (pp *PublicParameter) collectBytesForTransfer(b_hat *PolyNTTVec, c_hats []*PolyNTT) []byte {
	res := make([]byte, pp.paramKc*pp.paramD*4+pp.paramD*4*len(c_hats))
	appendPolyNTTToBytes := func(a *PolyNTT) {
		for k := 0; k < pp.paramD; k++ {
			res = append(res, byte(a.coeffs[k]>>0))
			res = append(res, byte(a.coeffs[k]>>8))
			res = append(res, byte(a.coeffs[k]>>16))
			res = append(res, byte(a.coeffs[k]>>24))
		}
	}
	for i := 0; i < pp.paramKc; i++ {
		appendPolyNTTToBytes(b_hat.polyNTTs[i])
	}
	for i := 0; i < len(c_hats); i++ {
		appendPolyNTTToBytes(c_hats[i])
	}
	return res
}

// TransferTxGen returns an transfer transaction with the inputs, the outputs, transaction fee, and some extra information packaged in txMemo.
func (pp *PublicParameter) TransferTxGen(inputDescs []*TxInputDesc, outputDescs []*TxOutputDesc, fee uint64, txMemo []byte) (trTx *TransferTx, err error) {
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

		if outputDescItem.mpk == nil {
			return nil, errors.New("the master public key is nil")
		}
		if !outputDescItem.mpk.WellformCheck(pp) {
			return nil, errors.New("the mpk is not well-form")
		}
	}

	inputTotal := uint64(0)
	dpkMap := make(map[*DerivedPubKey]struct{})
	txoListMap := make(map[int]map[*DerivedPubKey]struct{})
	for index, inputDescItem := range inputDescs {
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
		if inputDescItem.mpk == nil || inputDescItem.msvk == nil || inputDescItem.mssk == nil {
			return nil, errors.New("some information is empty")
		}

		if inputDescItem.mssk.WellformCheck(pp) == false {
			return nil, errors.New("the master view key is not well-formed")
		}

		b, v := pp.TxoCoinReceive(inputDescItem.txoList[inputDescItem.sidx], inputDescItem.mpk, inputDescItem.msvk)
		if b == false || v != inputDescItem.value {
			return nil, errors.New("fail to receive some transaction output")
		}

		//	check no repeated dpk in inputDescItem.txoList
		var mapDpk map[*DerivedPubKey]struct{}
		mapDpk = make(map[*DerivedPubKey]struct{})
		for _, txo := range inputDescItem.txoList {
			_, ok := mapDpk[txo.dpk]
			if ok {
				return nil, errors.New("there are repeated derived public key")
			}
			mapDpk[txo.dpk] = struct{}{}
		}
		txoListMap[index] = mapDpk
		// todo_DONE
		//	check inputDescItem[i].txoList[inputDescItem[i].sidx].dpk \neq inputDescItem[j].txoList[inputDescItem[j].sidx].dpk
		if _, ok := dpkMap[inputDescItem.txoList[inputDescItem.sidx].dpk]; !ok {
			dpkMap[inputDescItem.txoList[inputDescItem.sidx].dpk] = struct{}{}
		} else {
			return nil, errors.New("the same derived public key in the input")
		}
		//	TODO check (inputDescItem[i].txoList == inputDescItem[j].txoList) or (inputDescItem[i].txoList \cap inputDescItem[j].txoList = \emptyset)
		for i := 0; i < len(inputDescItem.txoList); i++ {
			for j := 0; j < index; j++ {
				if _, ok := txoListMap[j][inputDescItem.txoList[i].dpk]; ok {
					return nil, errors.New("the intersection of txo list is not empty")
				}

			}
		}
	}

	if outputTotal != inputTotal {
		return nil, errors.New("the total coin value is not balance")
	}

	I := len(inputDescs)
	J := len(outputDescs)
	n := I + J
	n2 := I + J + 2
	if I > 1 {
		n2 = I + J + 4
	}

	msg_hats := make([][]int32, n2)

	cmts := make([]*Commitment, n)
	cmt_rs := make([]*PolyNTTVec, n)

	rettrTx := &TransferTx{}
	rettrTx.Inputs = make([]*TrTxInput, I)
	rettrTx.OutputTxos = make([]*TXO, J)
	rettrTx.Fee = fee
	rettrTx.TxMemo = txMemo

	for j := 0; j < J; j++ {
		rettrTx.OutputTxos[j], cmt_rs[I+j], err = pp.txoGen(outputDescs[j].mpk, outputDescs[j].value)
		if err != nil {
			return nil, errors.New("fail to generate the transaction output")
		}

		cmts[I+j] = rettrTx.OutputTxos[j].cmt
		msg_hats[I+j] = intToBinary(outputDescs[j].value, pp.paramD)
	}

	for i := 0; i < I; i++ {
		rettrTx.Inputs[i] = new(TrTxInput)
		rettrTx.Inputs[i].TxoList = inputDescs[i].txoList
		rettrTx.Inputs[i].SerialNumber, err = pp.TxoSerialNumberGen(inputDescs[i].txoList[inputDescs[i].sidx], inputDescs[i].mpk, inputDescs[i].msvk, inputDescs[i].mssk)
		if err != nil {
			return nil, err
		}
	}

	msgTrTxCon := rettrTx.Serialize(false)
	if msgTrTxCon == nil {
		return nil, errors.New("error in rettrTx.Serialize ")
	}
	msgTrTxConHash, err := Hash(msgTrTxCon)
	if err != nil {
		return nil, err
	}

	elrsSigs := make([]*elrsSignature, I)
	cmtps := make([]*Commitment, I)

	for i := 0; i < I; i++ {
		msg_hats[i] = intToBinary(inputDescs[i].value, pp.paramD)

		//	dpk = inputDescs[i].txoList[inputDescs[i].sidx].dpk = (C, t)
		kappa := inputDescs[i].msvk.skkem.CryptoKemDec(inputDescs[i].txoList[inputDescs[i].sidx].dpk.ckem)

		satmp, err := pp.expandRandomnessA(kappa)
		if err != nil {
			return nil, err
		}
		s_a := pp.PolyNTTVecAdd(
			inputDescs[i].mssk.s,
			pp.NTTVec(satmp),
			pp.paramLa)

		randomnessC, err := pp.sampleRandomnessC()
		if err != nil {
			return nil, err
		}
		cmt_rs[i] = pp.NTTVec(randomnessC)
		cmtps[i] = &Commitment{}
		cmtps[i].b = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_rs[i], pp.paramKc, pp.paramLc)
		cmtps[i].c = pp.PolyNTTAdd(
			pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cmt_rs[i], pp.paramLc),
			&PolyNTT{msg_hats[i]})

		cmts[i] = cmtps[i]
		sctmp, err := pp.expandRandomnessC(kappa)
		if err != nil {
			return nil, err
		}
		s_c := pp.PolyNTTVecSub(
			pp.NTTVec(sctmp),
			cmt_rs[i],
			pp.paramLc)

		t_c_p := cmtps[i].toPolyNTTVec()

		ringSize := len(inputDescs[i].txoList)
		t_as := make([]*PolyNTTVec, ringSize)
		t_cs := make([]*PolyNTTVec, ringSize)
		for j := 0; j < ringSize; j++ {
			t_as[j] = inputDescs[i].txoList[j].dpk.t

			if len(inputDescs[i].txoList[j].cmt.b.polyNTTs) != pp.paramKc {
				return nil, errors.New("the length of cmt.b is not accurate")
			}
			t_cs[j] = inputDescs[i].txoList[j].cmt.toPolyNTTVec()
			t_cs[j] = pp.PolyNTTVecSub(t_cs[j], t_c_p, pp.paramKc+1)
		}

		elrsSigs[i], err = pp.elrsSign(t_as, t_cs, msgTrTxConHash, inputDescs[i].sidx, s_a, s_c)
		if err != nil {
			return nil, errors.New("fail to generate the extend linkable signature")
		}
	}

	//	u
	u := intToBinary(fee, pp.paramD)

	if I == 1 {
		c_hats := make([]*PolyNTT, n2) //	n2 = n+2

		//	f is the carry vector, such that, m_1 = m_2+ ... + m_n + u
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + 2 f[i] = m_1[i-1] + .. + m_{n-1}[i-1] + u[i-1] + f[i-1],
		//	m_0[d-1] 		  = m_1[d-1] + .. + m_{n-1}[d-1] + f[d-1],
		f := make([]int32, pp.paramD)
		f[0] = 0
		for i := 1; i < pp.paramD; i++ {
			tmp := int32(0)
			for j := 1; j < n; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			f[i] = (tmp + u[i-1] + f[i-1] - msg_hats[0][i-1]) >> 1
		}
		msg_hats[n] = f

	trTxGenI1Restart:
		e, err := pp.sampleUniformWithinEtaF()
		if err != nil {
			return nil, err
		}
		msg_hats[n+1] = e

		randomnessC, err := pp.sampleRandomnessC()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVec(randomnessC)
		b_hat := pp.PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKc, pp.paramLc)
		for i := 0; i < n2; i++ { // n2 = I+J+4 = n+4
			c_hats[i] = pp.PolyNTTAdd(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], r_hat, pp.paramLc),
				&PolyNTT{msg_hats[i]})
		}

		// todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramD)
		u_p_temp := make([]int64, pp.paramD) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM, err := Hash(pp.collectBytesForTransfer(b_hat, c_hats))
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		if err != nil {
			return nil, err
		}
		// todo: check B f + e
		for i := 0; i < pp.paramD; i++ {
			u_p_temp[i] = int64(e[i])
			for j := 0; j < pp.paramD; j++ {
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

			u_p[i] = pp.reduce(u_p_temp[i])
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = u
		u_hats[1] = make([]int32, pp.paramD)
		u_hats[2] = u_p

		n1 := n
		rprlppi, pi_err := pp.rpulpProve(cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeTrTx1, binM, I, J, 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness = &TrTxWitness{
			b_hat:      b_hat,
			c_hats:     c_hats,
			u_p:        u_p,
			rpulpproof: rprlppi,
			cmtps:      cmtps,
			elrsSigs:   elrsSigs,
		}

	} else {

		c_hats := make([]*PolyNTT, n2) //	n2 = n+4

		msg_hats[n] = intToBinary(inputTotal, pp.paramD) //	v_in

		//	f1 is the carry vector, such that, m_0 + m_1+ ... + m_{I-1} = m_{n}
		//	f1[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + .. + m_{I-1}[i-1] + f1[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_0[d-1] + .. + m_{I-1}[d-1] + f1[d-1] = m_n[d-1] ,
		f1 := make([]int32, pp.paramD)
		f1[0] = 0
		for i := 1; i < pp.paramD; i++ {
			tmp := int32(0)
			for j := 0; j < I; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			f1[i] = (tmp + f1[i-1] - msg_hats[n][i-1]) >> 1
		}
		msg_hats[n+1] = f1

		//	f2 is the carry vector, such that, m_I + m_{I+1}+ ... + m_{(I+J)-1} + u = m_{n}
		//	f2[0] = 0, and for i=1 to d-1,
		//	m_I[i-1] + .. + m_{I+J-1}[i-1] + u[i-1] + f2[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_I[d-1] + .. + m_{I+J-1}[d-1] + u[d-1] + f2[d-1] = m_n[d-1] ,
		f2 := make([]int32, pp.paramD)
		f2[0] = 0
		for i := 1; i < pp.paramD; i++ {
			tmp := int32(0)
			for j := 0; j < I; j++ {
				tmp = tmp + msg_hats[I+j][i-1]
			}
			f2[i] = (tmp + u[i-1] + f2[i-1] - msg_hats[n][i-1]) >> 1
		}
		msg_hats[n+2] = f2

	trTxGenI2Restart:
		e, err := pp.sampleUniformWithinEtaF()
		if err != nil {
			return nil, err
		}
		msg_hats[n+3] = e

		randomnessC, err := pp.sampleRandomnessC()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVec(randomnessC)

		b_hat := pp.PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKc, pp.paramLc)

		for i := 0; i < n2; i++ { // n2 = I+J+4 = n+4
			c_hats[i] = pp.PolyNTTAdd(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], r_hat, pp.paramLc),
				&PolyNTT{msg_hats[i]})
		}

		// todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramD)
		u_p_temp := make([]int64, pp.paramD) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM, err := Hash(pp.collectBytesForTransfer(b_hat, c_hats))
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, 2*pp.paramD)
		if err != nil {
			return nil, err
		}
		// todo: check B (f_1 || f_2) + e
		betaF := I
		if J+1 > betaF {
			betaF = J + 1
		}
		betaF = betaF - 1

		for i := 0; i < pp.paramD; i++ {
			u_p_temp[i] = 0
			for j := 0; j < pp.paramD; j++ {
				u_p_temp[i] = u_p_temp[i] + int64(e[j])

				if (binM[i][j/8]>>(j%8))&1 == 1 {
					u_p_temp[i] += int64(f1[j])
				}
				if (binM[i][(pp.paramD+j)/8]>>((pp.paramD+j)%8))&1 == 1 {
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

			u_p[i] = pp.reduce(u_p_temp[i])
		}

		u_hats := make([][]int32, 5)
		u_hats[0] = make([]int32, pp.paramD)
		// todo_DONE: -u
		for i := 0; i < len(u_hats[1]); i++ {
			u_hats[1][i] = pp.reduce(-int64(u[i]))
		}
		u_hats[2] = make([]int32, pp.paramD)
		u_hats[3] = make([]int32, pp.paramD)
		u_hats[4] = u_p

		n1 := n + 1
		rprlppi, pi_err := pp.rpulpProve(cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness = &TrTxWitness{
			b_hat:      b_hat,
			c_hats:     c_hats,
			u_p:        u_p,
			rpulpproof: rprlppi,
			cmtps:      cmtps,
			elrsSigs:   elrsSigs,
		}
	}

	return rettrTx, err
}

// TransferTxVerify reports whether a transfer transaction is legal.
func (pp *PublicParameter) TransferTxVerify(trTx *TransferTx) bool {
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

	txoListMap := make(map[int]map[*DerivedPubKey]struct{})
	for i := 0; i < I; i++ {
		input := trTx.Inputs[i]
		if input.TxoList == nil || input.SerialNumber == nil {
			return false
		}
		// todo_DONE: check whether there exists repeated dpk in trTx.Inputs[i]
		dpkMap := make(map[*DerivedPubKey]struct{})
		for j := 0; j < len(input.TxoList); j++ {
			if _, ok := dpkMap[input.TxoList[j].dpk]; ok {
				return false
			}
			dpkMap[input.TxoList[j].dpk] = struct{}{}
		}

		// todo: check whether there exists two txoList such that they have common Txos but are different
		// TODO: there are some wrong?
		for j := 0; j < len(input.TxoList); j++ {
			for k := 0; k < i; k++ {
				if _, ok := txoListMap[k][input.TxoList[j].dpk]; ok {
					// check whether the two list are the same
					flag := true
					for derivedPubKey, _ := range dpkMap {
						if _, ok := txoListMap[k][derivedPubKey]; !ok {
							flag = false
							break
						}
					}
					if flag {
						return false
					}
				}
			}
		}
		txoListMap[i] = dpkMap
		// todo_DONE: check whether theres exits repeated serialNumber
		for j := 0; j < i; j++ {
			if bytes.Equal(trTx.Inputs[j].SerialNumber, input.SerialNumber) {
				return false
			}
		}
	}

	txoDpkMap := make(map[*DerivedPubKey]struct{})
	for j := 0; j < J; j++ {
		//	todo: check the well-form of outputTxos

		// todo_DONE: check whether there exits repeated dpk in the outputTxos
		for k := 0; k < len(trTx.OutputTxos); k++ {
			if _, ok := txoDpkMap[trTx.OutputTxos[k].dpk]; ok {
				return false
			}
		}
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
		sn, err := pp.keyImgToSerialNumber(trTx.TxWitness.elrsSigs[i].keyImg)
		if err != nil || bytes.Compare(sn, trTx.Inputs[i].SerialNumber) != 0 {
			return false
		}

		ringSize := len(trTx.Inputs[i].TxoList)
		t_as := make([]*PolyNTTVec, ringSize)
		t_cs := make([]*PolyNTTVec, ringSize)

		t_c_p := trTx.TxWitness.cmtps[i].toPolyNTTVec()
		for j := 0; j < ringSize; j++ {
			t_as[j] = trTx.Inputs[i].TxoList[j].dpk.t

			t_cs[j] = trTx.Inputs[i].TxoList[j].cmt.toPolyNTTVec()
			t_cs[j] = pp.PolyNTTVecSub(t_cs[j], t_c_p, pp.paramKc+1)
		}
		valid := pp.elrsVerify(t_as, t_cs, msgTrTxConHash, trTx.TxWitness.elrsSigs[i])
		if !valid {
			return false
		}
	}

	// check the balance proof
	n := I + J
	cmts := make([]*Commitment, n)
	for i := 0; i < I; i++ {
		cmts[i] = trTx.TxWitness.cmtps[i]
	}
	for j := 0; j < J; j++ {
		cmts[I+j] = trTx.OutputTxos[j].cmt
	}

	u := intToBinary(trTx.Fee, pp.paramD)

	if I == 1 {
		n2 := n + 2
		n1 := n

		betaF := pp.paramEtaF - int32(J)

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
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = u
		u_hats[1] = make([]int32, pp.paramD)
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
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, 2*pp.paramD)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 5)
		u_hats[0] = make([]int32, pp.paramD)
		// todo_DONE: -u
		for i := 0; i < len(u_hats[1]); i++ {
			u_hats[1][i] = pp.reduce(-int64(u[i]))
		}
		u_hats[2] = make([]int32, pp.paramD)
		u_hats[3] = make([]int32, pp.paramD)
		u_hats[4] = trTx.TxWitness.u_p

		flag := pp.rpulpVerify(cmts, n, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats, trTx.TxWitness.rpulpproof)
		if !flag {
			return false
		}
	}

	return true

}

// txoGen returns an transaction output and a random polynomial related to the corresponding transaction output with the master public key and value
func (pp *PublicParameter) txoGen(mpk *MasterPublicKey, vin uint64) (txo *TXO, r *PolyNTTVec, err error) {
	//	got (C, kappa) from key encapsulate mechanism
	C, kappa, err := mpk.pkkem.CryptoKemEnc()
	// expand the kappa to a PolyVec
	s_prime, err := pp.expandRandomnessA(kappa)
	s_p := pp.NTTVec(s_prime)
	// t = mpk.t + A * s_p
	t := pp.PolyNTTVecAdd(mpk.t,
		pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s_p, pp.paramKa, pp.paramLa),
		pp.paramKa)
	//	dpk = (C, t)
	dpk := &DerivedPubKey{
		ckem: C,
		t:    t,
	}

	//	expand the kappa to another PolyVec
	sctmp, err := pp.expandRandomnessC(kappa)
	if err != nil {
		return nil, nil, err
	}
	cmtr := pp.NTTVec(sctmp)

	mtmp := intToBinary(vin, pp.paramD)
	m := &PolyNTT{coeffs: mtmp}
	// [b c]^T = C*r + [0 m]^T
	cmt := &Commitment{}
	cmt.b = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKc, pp.paramLc)
	cmt.c = pp.PolyNTTAdd(
		pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cmtr, pp.paramLc),
		m,
	)

	//	vc = m ^ sk
	sk, err := pp.expandRandomBitsV(kappa)
	if err != nil {
		return nil, nil, err
	}
	vc := make([]byte, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		vc[i] = sk[i] ^ byte(mtmp[i])
	}

	rettxo := &TXO{
		dpk,
		cmt,
		vc,
	}

	return rettxo, cmtr, nil
}

//	todo_DONE: serial number is a hash value
/*
As wallet may call this algorithm to generate serial numbers for the coins, this method is set to be public.
*/
// TxoSerialNumberGen generates the serial number for given transaction output when the output does belong to given key pair
func (pp *PublicParameter) TxoSerialNumberGen(txo *TXO, mpk *MasterPublicKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sn []byte, err error) {
	if txo == nil || txo.dpk == nil || mpk == nil || msvk == nil || mssk == nil {
		return nil, errors.New("nil pointer")
	}

	dpk := txo.dpk

	// todo: check the well-formness of dpk, mpk, msvk, and mssk

	kappa := msvk.skkem.CryptoKemDec(dpk.ckem)
	sptmp, err := pp.expandRandomnessA(kappa)
	if err != nil {
		return nil, err
	}
	sp := pp.NTTVec(sptmp)
	t_hat_p := pp.PolyNTTVecAdd(
		mpk.t,
		pp.PolyNTTMatrixMulVector(pp.paramMatrixA, sp, pp.paramKa, pp.paramLa),
		pp.paramKa)

	if pp.PolyNTTVecEqualCheck(dpk.t, t_hat_p) != true {
		return nil, errors.New("not equal")
	}

	//keyImgMatrix,err := pp.expandKeyImgMatrix(dpk.t)
	tmp := make([]byte, 0, pp.paramKa*pp.paramD*4)
	for ii := 0; ii < pp.paramKa; ii++ {
		for jj := 0; jj < pp.paramD; jj++ {
			tmp = append(tmp, byte(dpk.t.polyNTTs[ii].coeffs[jj]>>0))
			tmp = append(tmp, byte(dpk.t.polyNTTs[ii].coeffs[jj]>>8))
			tmp = append(tmp, byte(dpk.t.polyNTTs[ii].coeffs[jj]>>16))
			tmp = append(tmp, byte(dpk.t.polyNTTs[ii].coeffs[jj]>>24))
		}
	}
	keyImgMatrix, err := pp.expandKeyImgMatrix(tmp)
	if err != nil {
		// TODO: define Const Error Variable
		return nil, errors.New("not equal")
	}
	s_hat := pp.PolyNTTVecAdd(mssk.s, sp, pp.paramLa)

	keyImg := pp.PolyNTTMatrixMulVector(keyImgMatrix, s_hat, pp.paramMa, pp.paramLa)

	// todo_DONE: serialize keyImg and compute the corresponding hash
	return pp.keyImgToSerialNumber(keyImg)
}

// keyImgToSerialNumber generates the serial number from key image, it is a auxiliary function for TxoSerialNumberGen and TransferTxVerify
func (pp *PublicParameter) keyImgToSerialNumber(keyImg *PolyNTTVec) (sn []byte, err error) {

	seed := make([]byte, 0, pp.paramKa*pp.paramD*4)
	for i := 0; i < len(keyImg.polyNTTs); i++ {
		for j := 0; j < len(keyImg.polyNTTs[i].coeffs); j++ {
			seed = append(seed, byte(keyImg.polyNTTs[i].coeffs[j]>>0))
			seed = append(seed, byte(keyImg.polyNTTs[i].coeffs[j]>>8))
			seed = append(seed, byte(keyImg.polyNTTs[i].coeffs[j]>>16))
			seed = append(seed, byte(keyImg.polyNTTs[i].coeffs[j]>>24))
		}

	}
	imgM, err := pp.expandKeyImgMatrix(seed)
	if err != nil {
		return nil, err
	}
	tmp := make([]byte, 0, pp.paramMa*pp.paramLa*pp.paramD*4)
	for i := 0; i < len(imgM); i++ {
		for j := 0; j < len(imgM[i].polyNTTs); j++ {
			for k := 0; k < len(imgM[i].polyNTTs[j].coeffs); k++ {
				tmp = append(tmp, byte(imgM[i].polyNTTs[j].coeffs[k]>>0))
				tmp = append(tmp, byte(imgM[i].polyNTTs[j].coeffs[k]>>8))
				tmp = append(tmp, byte(imgM[i].polyNTTs[j].coeffs[k]>>16))
				tmp = append(tmp, byte(imgM[i].polyNTTs[j].coeffs[k]>>24))
			}

		}
	}
	return Hash(tmp)
}

//	public fun	end

//	well-from check 	begin
func (mpk *MasterPublicKey) WellformCheck(pp *PublicParameter) bool {
	// todo
	return true
}

func (msvk *MasterSecretViewKey) WellformCheck(pp *PublicParameter) bool {
	// todo
	return true
}

func (mssk *MasterSecretSignKey) WellformCheck(pp *PublicParameter) bool {
	// todo
	return true
}

//	well-from check 	end

//	serialize and deSeralize	begin
func (mpk *MasterPublicKey) SerializeSize() uint32 {
	return uint32(DefaultPP.paramKem.CryptoPublicKeyBytes() + 4 + len(mpk.t.polyNTTs)*len(mpk.t.polyNTTs[0].coeffs)*4)
}

func (mpk *MasterPublicKey) Serialize() []byte {
	res := make([]byte, 0, DefaultPP.paramKem.CryptoPublicKeyBytes()+4+len(mpk.t.polyNTTs)*len(mpk.t.polyNTTs[0].coeffs)*4)
	res = append(res, mpk.pkkem.Bytes()...)
	length := len(mpk.t.polyNTTs)
	res = append(res, byte((length>>24)&0xFF))
	res = append(res, byte((length>>16)&0xFF))
	res = append(res, byte((length>>8)&0xFF))
	res = append(res, byte((length>>0)&0xFF))
	for i := 0; i < length; i++ {
		for j := 0; j < len(mpk.t.polyNTTs[i].coeffs); j++ {
			res = append(res, byte((mpk.t.polyNTTs[i].coeffs[j]>>24)&0xFF))
			res = append(res, byte((mpk.t.polyNTTs[i].coeffs[j]>>16)&0xFF))
			res = append(res, byte((mpk.t.polyNTTs[i].coeffs[j]>>8)&0xFF))
			res = append(res, byte((mpk.t.polyNTTs[i].coeffs[j]>>0)&0xFF))
		}
	}
	return res
}

func (mpk *MasterPublicKey) Deserialize(mpkSer []byte) error {
	var err error
	pos := 0
	mpk.pkkem, err = DefaultPP.paramKem.PublicKeyFromBytes(mpkSer[pos : pos+DefaultPP.paramKem.CryptoPublicKeyBytes()])
	if err != nil {
		return err
	}
	pos += DefaultPP.paramKem.CryptoPublicKeyBytes()
	length := 0
	length |= int(mpkSer[pos+0]) << 24
	length |= int(mpkSer[pos+1]) << 16
	length |= int(mpkSer[pos+2]) << 8
	length |= int(mpkSer[pos+3]) << 0
	pos += 4
	tmp := make([]*PolyNTT, length)
	for i := 0; i < length; i++ {
		tmp[i] = new(PolyNTT)
		tmp[i].coeffs = make([]int32, DefaultPP.paramD)
		for j := 0; j < DefaultPP.paramD; j++ {
			tmp[i].coeffs[j] = int32(mpkSer[pos+0])<<24 | int32(mpkSer[pos+1])<<16 | int32(mpkSer[pos+2])<<8 | int32(mpkSer[pos+3])<<0
			pos += 4
		}
	}
	mpk.t = &PolyNTTVec{polyNTTs: tmp}
	return nil
}

func (msvk *MasterSecretViewKey) SerializeSize() uint32 {
	//	todo
	return 1
}

func (msvk *MasterSecretViewKey) Serialize() []byte {
	//	todo
	return nil
}

func (msvk *MasterSecretViewKey) Deserialize(msvkSer []byte) error {
	return nil
}

func (mssk *MasterSecretSignKey) SerializeSize() uint32 {
	//	todo
	return 1
}

func (mssk *MasterSecretSignKey) Serialize() []byte {
	//	todo
	return nil
}

func (mssk *MasterSecretSignKey) Deserialize(msskSer []byte) error {
	return nil
}

//	serialize and deSeralize	end
