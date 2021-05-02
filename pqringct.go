package pqringct

import (
	"github.com/cryptosuite/kyber-go/kyber"
)

type PolyVec struct {
	// the length must be paramLa
	vec []*Poly
}

type PolyNTTVec struct {
	// the length must be paramLa
	vec []*PolyNTT
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
}

type TransferTx struct {
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
	v   int64
}

type TXO struct {
	dpk *DerivedPubKey
	cmt *PolyNTTVec
	vc	uint32
}

//	public fun	begin
func Setup() (pp *PublicParameter){
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
	//len(s.vec) != pp.paramLa

	t := &PolyNTTVec{}
	t.vec = make([]*PolyNTT, pp.paramKa)

	matrixA := pp.ExpandPubMatrixA()
	for i := 0; i < pp.paramKa; i++ {
		t.vec[i] = pp.PolyNTTVecInnerProduct(matrixA[i], s, pp.paramLa)
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

func (pp *PublicParameter) CoinbaseTxGen(vin int32, txos []*TxOutputDesc) *CoinbaseTx {
	panic("implement me")
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

	matrixA := pp.ExpandPubMatrixA()
	sp := pp.ExpandKeyA(kappa)

	nttVec := make([]*PolyNTT, pp.paramLa)
	for i := 0; i < pp.paramLa; i++ {
		nttVec[i] = pp.NTT( sp.vec[i])
	}
	spNTT := &PolyNTTVec{
		nttVec,
	}

	t := &PolyNTTVec{}
	t.vec = make([]*PolyNTT, pp.paramKa)
	for i := 0; i < pp.paramKa; i++ {
		t.vec[i] = pp.PolyNTTAdd(mpk.t.vec[i], pp.PolyNTTVecInnerProduct(matrixA[i], spNTT, pp.paramLa))
	}
	dpk := DerivedPubKey{

	}

	txo := &TXO{
		&DerivedPubKey{
			,
		},
		cmt
	}

	return nil, spNTT, nil
}

//	public fun	end
