package pqringct

import "bytes"

func AddressKeyGen(pp *PublicParameter, seed []byte) ([]byte, []byte, []byte, error) {
	apk, ask, err := pp.AddressKeyGen(seed)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedAPk, err := pp.SerializeAddressPublicKey(apk)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedASksp, err := pp.SerializeAddressSecretKeySp(ask.AddressSecretKeySp)
	if err != nil {
		return nil, nil, nil, err
	}
	serializedASksn, err := pp.SerializeAddressSecretKeySn(ask.AddressSecretKeySn)
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
func TxoCoinReceive(pp *PublicParameter, txo *Txo, address []byte, serializedSkvalue []byte) (valid bool, v uint64) {
	panic("implement me")
}
func SerialNumberGen(pp *PublicParameter, serializedLgrTxo []byte, serializedSksn []byte) []byte {
	r := bytes.NewReader(serializedLgrTxo)
	txo, err := pp.ReadLgrTxo(r)
	if err != nil {
		return nil
	}
	tmp := pp.ExpandKIDR(txo)
	r = bytes.NewReader(serializedSksn)
	ma, err := pp.ReadPolyANTT(r)
	if err != nil {
		return nil
	}
	sn := pp.PolyANTTAdd(tmp, ma)
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
