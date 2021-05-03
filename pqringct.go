package pqringct

import (
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
	vc	[]byte
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
	spNTT := pp.NTTVec(sp)

	//	(C, t)
	dpkt := &PolyNTTVec{}
	dpkt.polyNTTs = make([]*PolyNTT, pp.paramKa)
	for i := 0; i < pp.paramKa; i++ {
		dpkt.polyNTTs[i] = pp.PolyNTTAdd(mpk.t.polyNTTs[i], pp.PolyNTTVecInnerProduct(matrixA[i], spNTT, pp.paramLa))
	}

	dpk := &DerivedPubKey{
		t: dpkt,
	}

	matrixB := pp.ExpandPubMatrixB()
	matrixC := pp.ExpandPubMatrixC()

	//	cmt
	cmtr := pp.ExpandKeyC(kappa)
	cmtrNTT := pp.NTTVec(cmtr)

	cmt := &PolyNTTVec{}
	cmt.polyNTTs = make([]*PolyNTT, pp.paramKc + 1)
	for i := 0; i < pp.paramKc; i++ {
		cmt.polyNTTs[i] = pp.PolyNTTVecInnerProduct(matrixB[i], cmtrNTT, pp.paramLc)
	}
	cmt.polyNTTs[pp.paramKc] = pp.PolyNTTVecInnerProduct(matrixC[0], cmtrNTT, pp.paramLc)

	//	vc
	//	todo

	rtxo := &TXO{
		dpk,
		cmt,
		nil,// todo
	}

	return rtxo, cmtrNTT, nil
}

//	public fun	end
