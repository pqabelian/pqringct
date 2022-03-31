package pqringct

const (
	//	PQRingCT, 2022.03.31
	TxoSerializeSizeMaxAllowed          = 1048576 //1024*1024*1, 1M bytes
	SerialNumberSerializeSizeMaxAllowed = 128     // 128 bytes
	TxMemoSerializeSizeMaxAllowed       = 1024    // 1024 bytes
	TxWitnessSerializeSizeMaxAllowed    = 8388608 //1024*1024*8, 8M bytes
)

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

//	ask = (s, m_a), apk = (t = As, e = <a,s>+m_a). s is asksp, m_a is asksn
func ValueKeyGen(pp *PublicParameter, seed []byte) ([]byte, []byte, error) {
	vpk, vsk, err := pp.ValueKeyGen(seed)
	if err != nil {
		return nil, nil, err
	}
	return vpk, vsk, nil
}

func CoinbaseTxGen(pp *PublicParameter, vin uint64, txOutputDescs []*TxOutputDescv2, txMemo []byte) (cbTx *CoinbaseTxv2, err error) {
	return pp.CoinbaseTxGen(vin, txOutputDescs, txMemo)
}
func CoinbaseTxVerify(pp *PublicParameter, cbTx *CoinbaseTxv2) (bool, error) {
	return pp.CoinbaseTxVerify(cbTx)
}

func TransferTxGen(pp *PublicParameter, inputDescs []*TxInputDescv2, outputDescs []*TxOutputDescv2, fee uint64, txMemo []byte) (trTx *TransferTxv2, err error) {
	return pp.TransferTxGen(inputDescs, outputDescs, fee, txMemo)
}
func TransferTxVerify(pp *PublicParameter, trTx *TransferTxv2) (bool, error) {
	return pp.TransferTxVerify(trTx)
}
func TxoCoinReceive(pp *PublicParameter, txo *Txo, address []byte, serializedVPk []byte, serializedVSk []byte) (valid bool, v uint64, err error) {
	bl, value, err := pp.TxoCoinReceive(txo, address, serializedVPk, serializedVSk)

	if err != nil {
		return false, 0, err
	}
	return bl, value, nil
}

// LedgerTxoSerialNumberGen() generates the Serial Number for a LgrTxo.
func LedgerTxoSerialNumberGen(pp *PublicParameter, lgrTxo *LgrTxo, serializedAsksn []byte) ([]byte, error) {
	sn, err := pp.ledgerTXOSerialNumberGen(lgrTxo, serializedAsksn)
	if err != nil {
		return nil, err
	}
	return sn, nil
}

//func LedgerTxoIdCompute(pp *PublicParameter, identifier []byte) ([]byte, error) {
//	lgrTxoId, err := Hash(identifier)
//	if err != nil {
//		return nil, err
//	}
//	return lgrTxoId, nil
//}

//	Data structures for Transaction generation/verify	begin

func NewTxOutputDescv2(pp *PublicParameter, serializedAPk []byte, serializedVPk []byte, value uint64) *TxOutputDescv2 {
	return pp.newTxOutputDescv2(serializedAPk, serializedVPk, value)
}

func NewTxInputDescv2(pp *PublicParameter, lgrTxoList []*LgrTxo, sidx int, serializedASksp []byte, serializedASksn []byte, serializedVPk []byte, serializedVSk []byte, value uint64) *TxInputDescv2 {
	return pp.newTxInputDescv2(lgrTxoList, sidx, serializedASksn, serializedASksp, serializedVPk, serializedVSk, value)
}

//	Data structures for Transaction generation/verify	end

//	serialize APIs	begin
func SerializeTxo(pp *PublicParameter, txo *Txo) ([]byte, error) {
	serialized, err := pp.SerializeTxo(txo)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func DeserializeTxo(pp *PublicParameter, serializedTxo []byte) (*Txo, error) {
	txo, err := pp.DeserializeTxo(serializedTxo)
	if err != nil {
		return nil, err
	}
	return txo, nil
}

func SerializeCbTxWitnessJ1(pp *PublicParameter, witness *CbTxWitnessJ1) ([]byte, error) {
	serialized, err := pp.SerializeCbTxWitnessJ1(witness)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func DeserializeCbTxWitnessJ1(pp *PublicParameter, serializedWitness []byte) (*CbTxWitnessJ1, error) {
	witness, err := pp.DeserializeCbTxWitnessJ1(serializedWitness)
	if err != nil {
		return nil, err
	}
	return witness, nil
}

func SerializeCbTxWitnessJ2(pp *PublicParameter, witness *CbTxWitnessJ2) ([]byte, error) {
	serialized, err := pp.SerializeCbTxWitnessJ2(witness)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func DeserializeCbTxWitnessJ2(pp *PublicParameter, serializedWitness []byte) (*CbTxWitnessJ2, error) {
	witness, err := pp.DeserializeCbTxWitnessJ2(serializedWitness)
	if err != nil {
		return nil, err
	}
	return witness, nil
}

//	serialize APIs	end

//	sizes begin

func GetParamSeedBytesLen(pp *PublicParameter) int {
	return pp.paramSeedBytesLen
}

func GetAddressPublicKeySerializeSize(pp *PublicParameter) int {
	return pp.AddressPublicKeySerializeSize()
}

func GetTxInputMaxNum(pp *PublicParameter) int {
	return pp.paramI
}
func GetTxOutputMaxNum(pp *PublicParameter) int {
	return pp.paramJ
}

func GetSerialNumberSerializeSize(pp *PublicParameter) int {
	return pp.LedgerTxoSerialNumberSerializeSize()
}

func GetNullSerialNumber(pp *PublicParameter) []byte {
	snSize := pp.LedgerTxoSerialNumberSerializeSize()
	nullSn := make([]byte, snSize)
	for i := 0; i < snSize; i++ {
		nullSn[i] = 0
	}
	return nullSn
}

//	sizes end

//	approximate Size begin
func GetTxoSerializeSizeApprox(pp *PublicParameter) int {
	return pp.TxoSerializeSize()
}

func GetCbTxWitnessSerializeSizeApprox(pp *PublicParameter, outTxoNum int) int {
	if outTxoNum == 0 {
		return 0
	}

	if outTxoNum == 1 {
		return pp.CbTxWitnessJ1SerializeSizeApprox()
	}

	if outTxoNum > 1 {
		return pp.CbTxWitnessJ2SerializeSizeApprox(outTxoNum)
	}

	return 0
}

func GetTrTxWitnessSerializeSizeApprox(pp *PublicParameter, inputRingSizes []int, outputTxoNum int) int {
	return pp.TrTxWitnessSerializeSizeApprox(inputRingSizes, outputTxoNum)
}

//	approximate Size end
