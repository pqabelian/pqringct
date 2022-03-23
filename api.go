package pqringct

import (
	"github.com/cryptosuite/pqringct/pqringctkem"
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
	bl, value, err := pp.TxoCoinReceive(txo, address, serializedVSk)

	if err != nil {

		return false, 0
	}
	return bl, value
}

func LedgerTxoSerialNumberGen(pp *PublicParameter, serializedTxo []byte, txolid []byte, serializedSksn []byte) []byte {
	sn := pp.LedgerTXOSerialNumberGen(serializedTxo, txolid, serializedSksn)
	return sn
}

func LedgerTxoIdCompute(pp *PublicParameter, identifier []byte) ([]byte, error) {
	lgrTxoId, err := Hash(identifier)
	if err != nil {
		return nil, err
	}
	return lgrTxoId, nil
}

//func (pp *PublicParameter) GetPublicKeyByteLen() int {
//	return pp.AddressPublicKeySerializeSize() + pqringctkem.GetKemCiphertextBytesLen(pp.paramKem)
//}

func (pp *PublicParameter) GetTxoSerializeSize() int {
	return pp.TxoSerializeSize()
}
func (pp *PublicParameter) GetCbTxWitnessMaxLenApprox(txoOutNum int) int {
	if txoOutNum == 0 {
		return 0
	}

	if txoOutNum == 1 {
		return pp.challengeSeedCSerializeSizeApprox() + pp.challengeSeedCSerializeSizeApprox()
	}

	if txoOutNum > 1 {
		lenApprox := pp.boundingVecCSerializeSizeApprox() +
			1 + (txoOutNum+2)*pp.PolyCNTTSerializeSize() +
			1 + pp.paramDC*8 +
			1 + txoOutNum*pp.PolyCNTTSerializeSize() + 3*pp.PolyCNTTSerializeSize() +
			pp.challengeSeedCSerializeSizeApprox() +
			1 + (txoOutNum)*pp.responseCSerializeSizeApprox() +
			pp.responseCSerializeSizeApprox()
		return lenApprox
	}
	return -1
}
func (pp *PublicParameter) GetCbTxWitnessMaxLen() int {
	lenApprox := pp.boundingVecCSerializeSizeApprox() +
		1 + (pp.paramJ+2)*pp.PolyCNTTSerializeSize() +
		1 + pp.paramDC*8 +
		1 + pp.paramJ*pp.PolyCNTTSerializeSize() + 3*pp.PolyCNTTSerializeSize() +
		pp.challengeSeedCSerializeSizeApprox() +
		1 + (pp.paramJ)*pp.responseCSerializeSizeApprox() +
		pp.responseCSerializeSizeApprox()
	return lenApprox
}
func (pp *PublicParameter) GetTrTxWitnessMaxLen() int {
	maxOutNum := pp.paramJ
	lenApprox := pp.boundingVecCSerializeSizeApprox() +
		1 + (maxOutNum+2)*pp.PolyCNTTSerializeSize() +
		1 + pp.paramDC*8 +
		1 + maxOutNum*pp.PolyCNTTSerializeSize() + 3*pp.PolyCNTTSerializeSize() +
		pp.challengeSeedCSerializeSizeApprox() +
		1 + (maxOutNum)*pp.responseCSerializeSizeApprox() +
		pp.responseCSerializeSizeApprox()
	return lenApprox
}

// TODO(20220320) check the length right?
func (pp *PublicParameter) GetTrTxWitnessSerializeSize(inputRingSizes []int, outputTxoNum int) int {
	inputNum := len(inputRingSizes)
	length := VarIntSerializeSize2(uint64(inputNum)) + inputNum*pp.PolyANTTSerializeSize() + // ma_ps      []*PolyANTT
		VarIntSerializeSize2(uint64(inputNum)) + inputNum*pp.ValueCommitmentSerializeSize() // cmt_ps     []*ValueCommitment

	// elrsSigs   []*elrsSignaturev2
	sigLen := 0
	length += VarIntSerializeSize2(uint64(inputNum))
	for i := 0; i < inputNum; i++ {
		// sigLen := pp.ElrsSignatureSerializeSize(witness.elrsSigs[i])
		// seeds [][]byte
		length = VarIntSerializeSize2(uint64(inputRingSizes[i]))
		for j := 0; j < inputRingSizes[i]; j++ {
			length += VarIntSerializeSize2(uint64(HashBytesLen)) + HashBytesLen
		}
		//z_as  []*PolyANTTVec
		length += VarIntSerializeSize2(uint64(inputRingSizes[i]))
		for j := 0; j < inputRingSizes[i]; j++ {
			length += VarIntSerializeSize2(uint64(pp.paramLA)) + pp.paramLA*pp.PolyANTTSerializeSize()
		}
		//z_cs  [][]*PolyCNTTVec
		length += VarIntSerializeSize2(uint64(inputRingSizes[i]))
		for j := 0; j < inputRingSizes[i]; j++ {
			length += VarIntSerializeSize2(uint64(pp.paramK))
			for k := 0; k < pp.paramK; k++ {
				length += VarIntSerializeSize2(uint64(pp.paramLC)) + pp.paramLC*pp.PolyCNTTSerializeSize()
			}
		}
		//z_cps [][]*PolyCNTTVec
		length += VarIntSerializeSize2(uint64(inputRingSizes[i]))
		for j := 0; j < inputRingSizes[i]; j++ {
			length += VarIntSerializeSize2(uint64(pp.paramK))
			for k := 0; k < pp.paramK; j++ {
				length += VarIntSerializeSize2(uint64(pp.paramLC)) + pp.paramLC*pp.PolyCNTTSerializeSize()
			}
		}
		length += VarIntSerializeSize2(uint64(sigLen)) + sigLen
	}

	length += VarIntSerializeSize2(uint64(pp.paramKC)) + pp.paramKC*pp.PolyCNTTSerializeSize() + //b_hat      *PolyCNTTVec
		VarIntSerializeSize2(uint64(inputNum+outputTxoNum+2)) + (inputNum+outputTxoNum+2)*pp.PolyCNTTSerializeSize() + //c_hats     []*PolyCNTT
		VarIntSerializeSize2(uint64(pp.paramDC)) + pp.paramDC*8 //u_p        []int64

	//rpulpproof *rpulpProofv2
	rpfLen := 0
	for i := 0; i < len(inputRingSizes); i++ {
		lengthOfPolyCNTT := pp.PolyCNTTSerializeSize()
		rpfLen += VarIntSerializeSize2(uint64(inputRingSizes[i]+outputTxoNum)) + (inputRingSizes[i]+outputTxoNum)*lengthOfPolyCNTT + // c_waves []*PolyCNTT
			+3*lengthOfPolyCNTT + //c_hat_g,psi,phi  *PolyCNTT
			VarIntSerializeSize2(uint64(HashBytesLen)) + HashBytesLen //chseed  []byte
		//cmt_zs  [][]*PolyCNTTVec
		rpfLen += VarIntSerializeSize2(uint64(pp.paramK))
		for j := 0; j < pp.paramK; j++ {
			rpfLen += VarIntSerializeSize2(uint64(inputRingSizes[i] + outputTxoNum))
			for k := 0; k < (inputRingSizes[i] + outputTxoNum); k++ {
				rpfLen += VarIntSerializeSize2(uint64(pp.paramLC)) + pp.paramLC*pp.PolyCNTTSerializeSize()
			}
		}
		//zs      []*PolyCNTTVec
		rpfLen += VarIntSerializeSize2(uint64(pp.paramK))
		for j := 0; j < pp.paramK; j++ {
			rpfLen += VarIntSerializeSize2(uint64(pp.paramLC)) + pp.paramLC*pp.PolyCNTTSerializeSize()
		}
	}
	length += VarIntSerializeSize2(uint64(rpfLen)) + rpfLen

	return length
}

func (pp *PublicParameter) GetTxMemoMaxLen() int {
	return 56
}

func (pp *PublicParameter) GetTxoSerialNumberLen() int {
	return pp.GetTxoSerializeSize()
}

func (pp *PublicParameter) GetValuePublicKeySerializeSize() int {
	return pqringctkem.GetKemCiphertextBytesLen(pp.paramKem)
}
func (pp *PublicParameter) GetAddressPublicKeySerializeSize() int {
	return pp.AddressPublicKeySerializeSize()
}
