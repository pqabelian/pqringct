package pqringct

import (
	"github.com/cryptosuite/kyber-go/kyber"
)

/*
This file defines all public constants and interfaces of PQRingCT.
*/

type MasterPubKey struct {
	kempk *kyber.PublicKey
	t     [PP_k_a]PolyVecANTT // directly in NTT form?
}

type MasterSecretViewKey struct {
	kemsk *kyber.SecretKey
}

type MasterSecretSignKey struct {
	s [PP_l_a]PolyVecANTT
}

type CoinbaseTx struct {
}

type TransferTx struct {
}

/*type DerivedPubKey struct {

}

type ValueCommitment struct {

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
}

//	public fun	begin
func Setup() {

}

func MasterKeyGen(masterSeed []byte) (mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, mseed []byte, err error) {
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

func TxoSerialNumberGen() {

}

//	public fun	end

//	private fun	begin
func expandKa(kappa []byte) (ds [PP_l_a]PolyVecA) {
	var ret = [PP_l_a]PolyVecA{}
	//	 todo:
	return ret
}
func txoGen(mpk *MasterPubKey, v int64) (txo *TXO, err error) {
	//	to do
	//	var kappa = [32]byte{}
	//	var ds = expandKa(kappa)
	for i := 0; i < PP_l_a; i++ {

	}
	return nil, nil
}

func rpulpProve() (rpulppf []byte) {
	return nil
}

func rpulpVerify() (valid bool) {
	return false
}

func elrsSign() (elrs []byte) {
	return nil
}

func elrsVerify() (valid bool) {
	return false
}

//	private fun	end
