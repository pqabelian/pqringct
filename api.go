package pqringct

import (
	"bytes"
	"github.com/cryptosuite/pqringct/pqringctkem"
	"log"
)

func AddressKeyGen(pp *PublicParameter, seed []byte) ([]byte, []byte, []byte, error) {
	apk, ask, err := pp.AddressKeyGen(seed)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedAPk, err := pp.AddressPublicKeySerialize(apk)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedASksp, err := pp.AddressSecretKeySpSerialize(ask.AddressSecretKeySp)
	if err != nil {
		return nil, nil, nil, err
	}
	serializedASksn, err := pp.AddressSecretKeySnSerialize(ask.AddressSecretKeySn)
	if err != nil {
		return nil, nil, nil, err
	}
	return serializedAPk, serializedASksp, serializedASksn, nil
}

// TODO: split the ask to two parts as asksn and asksp? but how to do this?
//	ask = (s, m_a), apk = (t = As, e = <a,s>+m_a). s is asksp, m_a is asksn
func ValueKeyGen(pp *PublicParameter, seed []byte) ([]byte, []byte, error) {
	vpk, vsk, err := pp.ValueKeyGen(seed)
	if err != nil {
		return nil, nil, err
	}
	return vpk, vsk, nil
}

func CoinbaseTxGen(pp *PublicParameter, vin uint64, txOutputDescs []*TxOutputDescv2) (cbTx *CoinbaseTxv2, err error) {
	return pp.CoinbaseTxGen(vin, txOutputDescs)
}
func CoinbaseTxVerify(pp *PublicParameter, cbTx *CoinbaseTxv2) bool {
	return pp.CoinbaseTxVerify(cbTx)
}

func TransferTxGen(pp *PublicParameter, inputDescs []*TxInputDescv2, outputDescs []*TxOutputDescv2, fee uint64, txMemo []byte) (trTx *TransferTxv2, err error) {
	return pp.TransferTxGen(inputDescs, outputDescs, fee, txMemo)
}
func TransferTxVerify(pp *PublicParameter, trTx *TransferTxv2) bool {
	return pp.TransferTxVerify(trTx)
}
func TxoCoinReceive(pp *PublicParameter, txo *Txo, address []byte, serializedVSk []byte) (valid bool, v uint64) {
	txoAddress, err := pp.AddressPublicKeySerialize(txo.AddressPublicKey)
	if err != nil {
		log.Fatalln(err)
	}
	if !bytes.Equal(txoAddress, address) {
		return false, 0
	}
	// run kem.decaps to get kappa
	version := uint32(serializedVSk[0]) << 0
	version |= uint32(serializedVSk[1]) << 8
	version |= uint32(serializedVSk[2]) << 16
	version |= uint32(serializedVSk[3]) << 24
	if pqringctkem.VersionKEM(version) != pp.paramKem.Version {
		return false, 0
	}
	kappa, err := pqringctkem.Decaps(pp.paramKem, txo.CkemSerialzed, serializedVSk[4:])
	if err != nil {
		log.Fatalln(err)
	}
	sk, err := pp.expandRandomBitsV(kappa)
	if err != nil {
		log.Fatalln(err)
	}
	mtmp := make([]byte, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		mtmp[i] = sk[i] ^ txo.Vct[i]
	}
	v = uint64(0)
	for i := 0; i < len(mtmp); i++ {
		if mtmp[i] == 1 {
			v += 1 << i
		}
	}
	return true, v
}
func SerialNumberGen(pp *PublicParameter, serializedLgrTxo []byte, serializedSksn []byte) []byte {
	txo, err := pp.LgrTxoDeserialize(serializedLgrTxo)
	if err != nil {
		return nil
	}
	tmp := pp.ExpandKIDR(txo)
	asksn, err := pp.AddressSecretKeySnDeserialize(serializedSksn)
	if err != nil {
		return nil
	}
	sn := pp.PolyANTTAdd(tmp, asksn.ma)
	return pp.SerialNumberCompute(sn)
}
func (pp *PublicParameter) GetPublicKeyByteLen() int {
	panic("GetPublicKeyByteLen implement me")
	return -1
}

func (pp *PublicParameter) GetTxoSerializeSize() int {
	panic("GetTxoSerializeSize implement me")
	return -1
}
func (pp *PublicParameter) GetCbTxWitnessMaxLen(num int) int {
	panic("GetCoinbaseTxWitnessLen implement me")
	return -1
}

func (pp *PublicParameter) GetTrTxWitnessMaxLen() int {
	panic("GetNullSerialNumber implement me")
	return -1
}

func (pp *PublicParameter) GetTrTxWitnessSerializeSize(inputRingSizes []int, outputTxoNum uint8) int {
	panic("GetNullSerialNumber implement me")
	return -1
}

func (pp *PublicParameter) GetTxMemoMaxLen() int {
	panic("GetNullSerialNumber implement me")
	return -1
}

func (pp *PublicParameter) GetTxoSerialNumberLen() int {
	panic("GetTxoSerialNumberLen implement me")
	return -1
}
func (pp *PublicParameter) GetNullSerialNumber() []byte {
	panic("GetNullSerialNumber implement me")
	return nil
}
func (pp *PublicParameter) GetValuePublicKeySerializeSize() []byte {
	panic("GetNullSerialNumber implement me")
	return nil
}
func (pp *PublicParameter) GetAddressPublicKeySerializeSize() []byte {
	panic("GetNullSerialNumber implement me")
	return nil
}
