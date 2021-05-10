package pqringct

import (
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
)

type PolyVec struct {
	// the length must be paramLa
	polys []*Poly
}

type PolyNTTVec struct {
	// the length must be paramLa
	polyNTTs []*PolyNTT
}

/*
This file defines all public constants and interfaces of PQRingCT.
*/

type MasterPubKey struct {
	pkkem *kyber.PublicKey
	t     *PolyNTTVec // directly in NTT form
}

type MasterSecretViewKey struct {
	skkem *kyber.SecretKey
}

type MasterSecretSignKey struct {
	s *PolyNTTVec
}

type CbTxWitness struct {
	b_hat   *PolyNTTVec
	c_hats  []*PolyNTT
	u_p     []int32
	c_waves []*PolyNTT
	c_hat_g *PolyNTT
	psi     *PolyNTT
	phi     *PolyNTT
	chseed  []byte
	cmt_zs  [][]*PolyNTTVec
	zs      []*PolyNTTVec
}

type CoinbaseTx struct {
	Version uint32

	Vin        uint64
	OutputTxos []*TXO
	TxWitness  *CbTxWitness
}

type TransferTx struct {
	Version uint32
}

type DerivedPubKey struct {
	//	ckem // todo
	t *PolyNTTVec
}

type Commitment struct {
	b *PolyNTTVec
	c *PolyNTT
}

type Signature struct {
}
type Image struct {
}

/*type ValueCommitment struct {

}

type ValueCiphertext struct {

}*/

type TxInputDesc struct {
}

type TxOutputDesc struct {
	mpk *MasterPubKey
	v   uint64
}

type TXO struct {
	dpk *DerivedPubKey
	cmt *Commitment
	vc  []byte
}

//	public fun	begin
func Setup() (pp *PublicParameter) {
	// todo
	return nil
}

/*
func MasterKeyGen(masterSeed []byte, parameter *PublicParameter) (mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, mseed []byte, err error) {
	// to do
	return nil, nil, nil, nil, nil
}

func CoinbaseTxGen(vin int64, txOutputDescList []*TxOutputDesc) (cbTx *CoinbaseTx, err error) {
	//	to do
	return nil, nil
}

func CoinbaseTxVerify(cbTx *CoinbaseTx) (valid bool) {
	//	to do
	return false
}

func TxoCoinReceive(txo *TXO, mpk *MasterPubKey, msvk *MasterSecretViewKey) (valid bool, v int64, err error) {
	//	to do
	return false, 0, nil
}

func TransferTxGen(txInputDescList []*TxInputDesc, txOutputDescList []*TxOutputDesc, fee int64) (transferTx *TransferTx, err error) {
	//	to do
	return nil, nil
}

func TransferTxVerify(trTx *TransferTx) (valid bool) {
	//	to do
	return false
}

func TxoSerialNumberGen(dpk *DerivedPubKey, mpk *MasterPubKey, mssk *MasterSecretSignKey, msvk *MasterSecretViewKey) (snMa []Poly) {
	panic("implement me")
}*/

func (pp *PublicParameter) MasterKeyGen(seed []byte) (mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, err error) {
	/*	mpk := MasterPubKey{}
		msvk := MasterSecretViewKey{}
		mssk := MasterSecretSignKey{}

		return &mpk, &msvk, &mssk, nil*/

	//	kappa := []byte
	s := &PolyNTTVec{}
	//len(s.polys) != pp.paramLa

	t := &PolyNTTVec{}
	t.polyNTTs = make([]*PolyNTT, pp.paramKa)

	matrixA := pp.expandPubMatrixA()
	for i := 0; i < pp.paramKa; i++ {
		t.polyNTTs[i] = pp.PolyNTTVecInnerProduct(matrixA[i], s, pp.paramLa)
	}

	rstmpk := &MasterPubKey{
		nil, // todo
		t,
	}

	rstmsvk := &MasterSecretViewKey{
		skkem: nil,
	}

	rstmssk := &MasterSecretSignKey{
		s: s,
	}

	return rstmpk, rstmsvk, rstmssk, nil
}

func (pp *PublicParameter) CoinbaseTxGen(vin uint64, txOutputDescs []*TxOutputDesc) (cbTx *CoinbaseTx, err error) {
	V := uint64(1)<<pp.paramN - 1

	if vin > V {
		return nil, errors.New("vin is not in [0, V]") // todo: more accurate info
	}

	if len(txOutputDescs) == 0 || len(txOutputDescs) > pp.paramJ {
		return nil, errors.New("the number of outputs is not in [1, I_max]") // todo: more accurate info
	}

	J := len(txOutputDescs)

	retcbTx := &CoinbaseTx{}
	retcbTx.Version = 0 // todo: how to set and how to use the version? The bpf just care the content of cbTx?
	retcbTx.Vin = vin
	retcbTx.OutputTxos = make([]*TXO, J)

	cmts := make([]*Commitment, J)
	cmt_rs := make([]*PolyNTTVec, J)

	vout := uint64(0)
	for j, txOutputDesc := range txOutputDescs {
		if txOutputDesc.v > V {
			return nil, errors.New("v is not in [0, V]") // todo: more accurate info, including the i
		}
		vout += txOutputDesc.v
		if vout > V {
			return nil, errors.New("the output value is not in [0, V]") // todo: more accurate info, including the i
		}

		retcbTx.OutputTxos[j], cmt_rs[j], err = pp.txoGen(txOutputDesc.mpk, txOutputDesc.v)
		if err != nil {
			return nil, err
		}
		cmts[j] = retcbTx.OutputTxos[j].cmt
	}
	if vout > vin {
		return nil, errors.New("the output value exceeds the input value") // todo: more accurate info
	}

	if J == 1 {
		//	J=1

	} else {
		//	J >= 2
		n := J
		n2 := n + 2

		c_hats := make([]*PolyNTT, n2)

		msg_hats := make([][]int32, n2)

		u_hats := make([][]int32, 3)

		for j := 0; j < J; j++ {
			msg_hats[j] = intToBinary(txOutputDescs[j].v, pp.paramD)
		}

		f := make([]int32, pp.paramD) // todo: compute the carry vector f
		msg_hats[J] = f

	cbTxGenJ2Restart:
		e := make([]int32, pp.paramD) //	todo: sample e from ([-eta_f, eta_f])^d
		msg_hats[J+1] = e

		r_hat := pp.NTTVec(pp.sampleRandomnessC())

		b_hat := pp.PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKc, pp.paramLc)

		for i := 0; i < n2; i++ { // n2 = J+2
			c_hats[i] = pp.PolyNTTAdd(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], r_hat, pp.paramLc),
				&PolyNTT{msg_hats[i]})
		}

		u_p := make([]int32, pp.paramD) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM := []byte{}           // todo: compute the seed using hash function on (b_hat, c_hats).
		binM := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		// todo: check B f + e
		for i := 0; i < pp.paramD; i++ {
			u_p[i] = 0
			for j := 0; j < pp.paramD; j++ {
				u_p[i] = u_p[i] + binM[i][j]*e[j]
			}

			infNorm := u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > (pp.paramEtaF - int32(J-1)) {
				goto cbTxGenJ2Restart
			}
		}

		u_hats[0] = intToBinary(vin, pp.paramD)
		u_hats[1] = make([]int32, pp.paramD) // todo: all zero
		u_hats[2] = u_p

		n1 := n
		c_waves, c_hat_g, psi, phi, chseed, cmt_zs, zs, pi_err := pp.rpulpProve(cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		cbTx.TxWitness = &CbTxWitness{
			b_hat:   b_hat,
			c_hats:  c_hats,
			u_p:     u_p,
			c_waves: c_waves,
			c_hat_g: c_hat_g,
			psi:     psi,
			phi:     phi,
			chseed:  chseed,
			cmt_zs:  cmt_zs,
			zs:      zs,
		}
	}

	return cbTx, nil
}

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

	// todo: check no repeated dpk in cbTx.OutputTxos
	// todo: check cbTx.OutputTxos[j].cmt is well-formed

	if J == 1 {
		// todo:

	} else {
		// check the well-formness of cbTx.TxWitness
		if cbTx.TxWitness.b_hat == nil || cbTx.TxWitness.c_hats == nil || cbTx.TxWitness.u_p == nil || cbTx.TxWitness.c_waves == nil ||
			cbTx.TxWitness.c_hat_g == nil || cbTx.TxWitness.psi == nil || cbTx.TxWitness.phi == nil || cbTx.TxWitness.chseed == nil ||
			cbTx.TxWitness.cmt_zs == nil || cbTx.TxWitness.zs == nil {
			return false
		}

		n := J
		n2 := J + 2

		if len(cbTx.TxWitness.c_hats) != n2 {
			return false
		}

		if len(cbTx.TxWitness.c_waves) != n {
			return false
		}

		if len(cbTx.TxWitness.cmt_zs) != pp.paramK || len(cbTx.TxWitness.zs) != pp.paramK {
			return false
		}

		for t := 0; t < pp.paramK; t++ {
			if len(cbTx.TxWitness.cmt_zs[t]) != n {
				return false
			}
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

		seed_binM := []byte{} // todo: compute the seed using hash function on (b_hat, c_hats).
		binM := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)

		u_hats := make([][]int32, 3)
		u_hats[0] = intToBinary(cbTx.Vin, pp.paramD)
		u_hats[1] = make([]int32, pp.paramD) // todo: all zero
		u_hats[2] = cbTx.TxWitness.u_p

		cmts := make([]*Commitment, n)
		for i := 0; i < n; i++ {
			cmts[i] = cbTx.OutputTxos[i].cmt
		}

		n1 := n
		return pp.rpulpVerify(cmts, n, cbTx.TxWitness.b_hat, cbTx.TxWitness.c_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats,
			cbTx.TxWitness.c_waves, cbTx.TxWitness.c_hat_g, cbTx.TxWitness.psi, cbTx.TxWitness.phi, cbTx.TxWitness.chseed, cbTx.TxWitness.cmt_zs, cbTx.TxWitness.zs)

	}

	return true
}

func (pp *PublicParameter) TxoCoinReceive(txo *TXO, mpk *MasterPubKey, msvk *MasterSecretViewKey) (bool, uint64) {
	if txo == nil || mpk == nil || msvk == nil {
		return false, 0
	}

	// todo: check the well-formness of dpk

	// todo: decaps and obtain kappa
	kappa := []byte{} // todo
	sp := pp.NTTVec(pp.expandRandomnessA(kappa))
	t_hat_p := pp.PolyNTTVecAdd(
		mpk.t,
		pp.PolyNTTMatrixMulVector(pp.paramMatrixA, sp, pp.paramKa, pp.paramLa),
		pp.paramKa)

	if pp.PolyNTTVecEqualCheck(txo.dpk.t, t_hat_p) != true {
		return false, 0
	}

	v := uint64(0) // todo: recover v from txo.vc
	// todo: check v

	m := intToBinary(v, pp.paramD)
	cmt_r := pp.NTTVec(pp.expandRandomnessC(kappa))
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

func (pp *PublicParameter) TransferTXGen(descs []*TxInputDesc, descs2 []*TxOutputDesc) *TransferTx {
	panic("implement me")
}

func (pp *PublicParameter) TransferTXVerify(tx *TransferTx) bool {
	panic("implement me")
}

func (pp *PublicParameter) txoGen(mpk *MasterPubKey, vin uint64) (txo *TXO, r *PolyNTTVec, err error) {
	//	(C, kappa)
	kappa := []byte{} // todo

	//matrixA := pp.expandPubMatrixA()

	sp := pp.NTTVec(pp.expandRandomnessA(kappa))

	//	(C, t)
	dpkt := &PolyNTTVec{}
	dpkt.polyNTTs = make([]*PolyNTT, pp.paramKa)
	for i := 0; i < pp.paramKa; i++ {
		dpkt.polyNTTs[i] = pp.PolyNTTAdd(mpk.t.polyNTTs[i], pp.PolyNTTVecInnerProduct(pp.paramMatrixA[i], sp, pp.paramLa))
	}

	dpk := &DerivedPubKey{
		t: dpkt,
	}

	//	matrixB := pp.expandPubMatrixB()
	//	matrixC := pp.expandPubMatrixC()

	//	cmt
	cmtr := pp.NTTVec(pp.expandRandomnessC(kappa))

	cmt := &Commitment{}
	cmt.b = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKc, pp.paramLc)
	cmt.c = pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cmtr, pp.paramLc)

	//	vc
	//	todo

	rettxo := &TXO{
		dpk,
		cmt,
		nil, // todo
	}

	return rettxo, cmtr, nil
}

func (pp PublicParameter) txoSerialNumberGen(dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sn *PolyNTTVec) {
	if dpk == nil || mpk == nil || msvk == nil || mssk == nil {
		return nil
	}

	// todo: check the well-formness of dpk, mpk, msvk, and mssk

	// todo: decaps and obtain kappa
	kappa := []byte{} // todo
	sp := pp.NTTVec(pp.expandRandomnessA(kappa))
	t_hat_p := pp.PolyNTTVecAdd(
		mpk.t,
		pp.PolyNTTMatrixMulVector(pp.paramMatrixA, sp, pp.paramKa, pp.paramLa),
		pp.paramKa)

	if pp.PolyNTTVecEqualCheck(dpk.t, t_hat_p) != true {
		return nil
	}

	keyImgMatrix := pp.expandKeyImgMatrix(dpk.t)
	s_hat := pp.PolyNTTVecAdd(mssk.s, sp, pp.paramKa)

	return pp.PolyNTTMatrixMulVector(keyImgMatrix, s_hat, pp.paramMa, pp.paramLa)
}

//	public fun	end
