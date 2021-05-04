package pqringct

import (
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
	"math"
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

type CoinbaseTx struct {
	Version uint32

	Vin        uint64
	OutputTxos []*TXO
	TxWitness  []byte
}

type TransferTx struct {
	Version uint32
}

type DerivedPubKey struct {
	//	ckem // todo
	t *PolyNTTVec
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
	cmt *PolyNTTVec
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

	matrixA := pp.ExpandPubMatrixA()
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
	if vin > (uint64(1)<<pp.paramN - 1) {
		return nil, errors.New("vin is not in [0, 2^N-1]") // todo: more accurate info
	}

	if len(txOutputDescs) == 0 || len(txOutputDescs) > pp.paramJ {
		return nil, errors.New("the number of outputs is not in [1, I_max]") // todo: more accurate info
	}

	J := len(txOutputDescs)

	rstcbTx := CoinbaseTx{}
	rstcbTx.Version = 0 // todo: how to set and how to use the version
	rstcbTx.Vin = vin
	rstcbTx.OutputTxos = make([]*TXO, J)
	cmtrs := make([]*PolyNTTVec, J)

	vout := uint64(0)
	for j, txOutputDesc := range txOutputDescs {
		if txOutputDesc.v > (uint64(1)<<pp.paramN - 1) {
			return nil, errors.New("v is not in [0, 2^N-1]") // todo: more accurate info, including the i
		}
		vout += txOutputDesc.v
		if vout > (uint64(1)<<pp.paramN - 1) {
			return nil, errors.New("v is not in [0, 2^N-1]") // todo: more accurate info, including the i
		}

		rstcbTx.OutputTxos[j], cmtrs[j], err = pp.txoGen(txOutputDesc.mpk, txOutputDesc.v)
		if err != nil {
			return nil, err
		}
	}
	if vout > vin {
		return nil, errors.New("the output value exceeds the input value") // todo: more accurate info
	}

	if J == 1 {
		//	J=1

	} else {
		//	J >= 2
		n := J
		n2 := J + 2

		b_hat := &PolyNTTVec{}
		b_hat.polyNTTs = make([]*PolyNTT, pp.paramKa)

		msg_hats := make([][]int32, n2)
		c_hats := make([]*PolyNTT, n2)

		u_hats := make([][]int32, 3)

		for j := 0; j < J; j++ {
			msg_hats[j] = intToBinary(txOutputDescs[j].v, pp.paramD)
		}

		f := make([]int32, pp.paramD) // todo: compute the carry vector f
		msg_hats[J] = f

	CbTxGenJ2Restart:
		e := make([]int32, pp.paramD) //	todo: sample e from ([-eta_f, eta_f])^d
		msg_hats[J+1] = e

		r := pp.NTTVec(pp.sampleRandomnessC())

		for i := 0; i < pp.paramKa; i++ {
			b_hat.polyNTTs[i] = pp.PolyNTTVecInnerProduct(pp.paramMatrixB[i], r, pp.paramLc)
		}

		for i := 0; i < n2; i++ { // n2 = J+2
			c_hats[i] = pp.PolyNTTAdd(pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], r, pp.paramLc), &PolyNTT{msg_hats[i]})
		}

		var infNorm int32
		up := make([]int32, pp.paramD) // todo: make sure that (eta_f, d) will not make the value of up[i] over int32
		seed4BinM := []byte{}          // todo: compute the seed using hash function on (b_hat, c_hats).
		binM := expandBinaryMatrix(seed4BinM, pp.paramD, pp.paramD)
		// todo: check B f + e
		for i := 0; i < pp.paramD; i++ {
			up[i] = 0
			for j := 0; j < pp.paramD; j++ {
				up[i] = up[i] + binM[i][j]*e[j]
			}

			infNorm = up[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > int32(pp.paramEtaF-uint32(J-1)) {
				goto CbTxGenJ2Restart
			}
		}

		u_hats[0] = intToBinary(vin, pp.paramD)
		u_hats[1] = make([]int32, pp.paramD) // todo: all zero
		u_hats[2] = up

		// todo
		//rpulpProve()
	}

	return nil, nil
}

func (pp *PublicParameter) CoinbaseTxVerify(tx *CoinbaseTx) bool {
	panic("implement me")
}

func (pp *PublicParameter) TXOCoinReceive(dpk *DerivedPubKey, commitment []byte, vc []byte, mpk *MasterPubKey, key *MasterSecretViewKey) (bool, int32) {
	panic("implement me")
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

	//matrixA := pp.ExpandPubMatrixA()

	sp := pp.NTTVec(pp.ExpandRandomnessA(kappa))

	//	(C, t)
	dpkt := &PolyNTTVec{}
	dpkt.polyNTTs = make([]*PolyNTT, pp.paramKa)
	for i := 0; i < pp.paramKa; i++ {
		dpkt.polyNTTs[i] = pp.PolyNTTAdd(mpk.t.polyNTTs[i], pp.PolyNTTVecInnerProduct(pp.paramMatrixA[i], sp, pp.paramLa))
	}

	dpk := &DerivedPubKey{
		t: dpkt,
	}

	//	matrixB := pp.ExpandPubMatrixB()
	//	matrixC := pp.ExpandPubMatrixC()

	//	cmt
	cmtr := pp.NTTVec(pp.ExpandRandomnessC(kappa))

	cmt := &PolyNTTVec{}
	cmt.polyNTTs = make([]*PolyNTT, pp.paramKc+1)
	for i := 0; i < pp.paramKc; i++ {
		cmt.polyNTTs[i] = pp.PolyNTTVecInnerProduct(pp.paramMatrixB[i], cmtr, pp.paramLc)
	}
	cmt.polyNTTs[pp.paramKc] = pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cmtr, pp.paramLc)

	//	vc
	//	todo

	rsttxo := &TXO{
		dpk,
		cmt,
		nil, // todo
	}

	return rsttxo, cmtr, nil
}

//	public fun	end
