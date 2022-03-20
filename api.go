package pqringct

import "bytes"

func AddressKeyGen(pp *PublicParameter, seed []byte) ([]byte, []byte, error) {
	apk, ask, err := pp.AddressKeyGen(seed)
	if err != nil {
		return nil, nil, err
	}

	serializedAPk, err := pp.SerializeAddressPublicKey(apk)
	if err != nil {
		return nil, nil, err
	}
	serializedASk, err := pp.SerializeAddressSecretKey(ask)
	if err != nil {
		return nil, nil, err
	}
	return serializedAPk, serializedASk, nil
}

// TODO: split the ask to two parts as asksn and asksp? but how to do this?
//	ask = (s, m_a), apk = (t = As, e = <a,s>+m_a). s is asksp, m_a is asksn
func ValueKeyGen(pp *PublicParameter, seed []byte) ([]byte, []byte, []byte, error) {
	vpk, vsk, err := pp.ValueKeyGen(seed)
	if err != nil {
		return nil, nil, nil, err
	}
	return vpk, vsk[:], vsk[:], nil
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

func (pp *PublicParameter) GetTxoSerializeSize(version uint32) int {
	panic("GetTxoSerializeSize implement me")
	return -1
}
func (pp *PublicParameter) GetCbTxWitnessMaxLen(version uint32, num int) int {
	panic("GetCoinbaseTxWitnessLen implement me")
	return -1
}

func (pp *PublicParameter) GetTrTxWitnessMaxLen(version uint32) int {
	panic("GetNullSerialNumber implement me")
	return -1
}

func (pp *PublicParameter) GetTrTxWitnessSerializeSize(txVersion uint32, inputRingVersion uint32, inputRingSizes []int, outputTxoNum uint8) int {
	panic("GetNullSerialNumber implement me")
	return -1
}

func (pp *PublicParameter) GetTxMemoMaxLen(version uint32) int {
	panic("GetNullSerialNumber implement me")
	return -1
}

func (pp *PublicParameter) GetTxoSerialNumberLen(version uint32) int {
	panic("GetTxoSerialNumberLen implement me")
	return -1
}
func (pp *PublicParameter) GetNullSerialNumber(version uint32) []byte {
	panic("GetNullSerialNumber implement me")
	return nil
}
