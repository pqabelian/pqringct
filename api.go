package pqringct

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
	panic("CoinbaseTxVerify implement me")
	return true
}
func TransferTxGen(pp *PublicParameter, inputDescs []*TxInputDescv2, outputDescs []*TxOutputDescv2, fee uint64, txMemo []byte) (trTx *TransferTxv2, err error) {
	panic("TransferTxGen implement me")
	return nil, nil
}
func TransferTxVerify(pp *PublicParameter, trTx *TransferTxv2) bool {
	panic("TransferTxVerify implement me")
	return true
}
