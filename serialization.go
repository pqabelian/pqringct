package pqringct

import (
	"bytes"
	"io"
)

func WriteBytes(w io.Writer, b []byte) error {
	count := len(b)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func WritePolyNTT(w io.Writer, polyNTT *PolyNTT) error {
	count := len(polyNTT.coeffs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := writeElement(w, polyNTT.coeffs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func WritePolyNTTVec(w io.Writer, polyNTTVec *PolyNTTVec) error {
	count := len(polyNTTVec.polyNTTs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := WritePolyNTT(w, polyNTTVec.polyNTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func WriteRpulpProof(w io.Writer, proof *rpulpProof) error {
	// write c_waves
	count := len(proof.c_waves)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := WritePolyNTT(w, proof.c_waves[i])
		if err != nil {
			return err
		}
	}

	// write c_hat_g
	err = WritePolyNTT(w, proof.c_hat_g)
	if err != nil {
		return err
	}

	// write psi
	err = WritePolyNTT(w, proof.psi)
	if err != nil {
		return err
	}

	// write phi
	err = WritePolyNTT(w, proof.phi)
	if err != nil {
		return err
	}

	// write chseed
	err = WriteBytes(w, proof.chseed)
	if err != nil {
		return err
	}

	// write cmt_zs
	count = len(proof.cmt_zs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		count2 := len(proof.cmt_zs[i])
		err = WriteVarInt(w, uint64(count2))
		if err != nil {
			return err
		}
		for j := 0; j < count2; j++ {
			err = WritePolyNTTVec(w, proof.cmt_zs[i][j])
			if err != nil {
				return err
			}
		}
	}

	// write zs
	count = len(proof.zs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := WritePolyNTTVec(w, proof.zs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func WriteCommitment(w io.Writer, cmt *Commitment) error {
	// write b
	err := WritePolyNTTVec(w, cmt.b)
	if err != nil {
		return err
	}

	// write c
	err = WritePolyNTT(w, cmt.c)
	if err != nil {
		return err
	}

	return nil
}

func WriteDerivedPubKey(w io.Writer, dpk *DerivedPubKey) error {
	// write ckem
	err := WriteBytes(w, dpk.ckem)
	if err != nil {
		return err
	}

	// write t
	err = WritePolyNTTVec(w, dpk.t)
	if err != nil {
		return err
	}

	return nil
}

func WriteElrsSignature(w io.Writer, elrsSig *elrsSignature) error {
	// write chseed
	err := WriteBytes(w, elrsSig.chseed)
	if err != nil {
		return err
	}

	// write z_as
	count := len(elrsSig.z_as)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		count2 := len(elrsSig.z_as[i])
		err = WriteVarInt(w, uint64(count2))
		if err != nil {
			return err
		}
		for j := 0; j < count2; j++ {
			err = WritePolyNTTVec(w, elrsSig.z_as[i][j])
			if err != nil {
				return err
			}
		}
	}

	// write z_cs
	count = len(elrsSig.z_cs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		count2 := len(elrsSig.z_cs[i])
		err = WriteVarInt(w, uint64(count2))
		if err != nil {
			return err
		}
		for j := 0; j < count2; j++ {
			err = WritePolyNTTVec(w, elrsSig.z_cs[i][j])
			if err != nil {
				return err
			}
		}
	}

	// write keyImg
	err = WritePolyNTTVec(w, elrsSig.keyImg)
	if err != nil {
		return err
	}

	return nil
}

func (coinbaseTx *CoinbaseTx) Serialize(hasWitness bool) ([]byte, error) {
	// write Vin
	w := new(bytes.Buffer)
	err := writeElement(w, coinbaseTx.Vin)
	if err != nil {
		return nil, err
	}

	// write OutputTxos
	count := len(coinbaseTx.OutputTxos)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return nil, err
	}
	for i := 0; i < count; i++ {
		err := coinbaseTx.OutputTxos[i].Serialize(w)
		if err != nil {
			return nil, err
		}
	}

	// write TxWitness
	if hasWitness {
		err := coinbaseTx.TxWitness.Serialize(w)
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (coinbaseTx *CoinbaseTx) Deserialize() ([]byte, error) {
	// todo
	return nil, nil
}

func (cbTxWitness *CbTxWitness) SerializeSize() uint32 {
	// todo
	return 1
}

func (cbTxWitness *CbTxWitness) Serialize(w io.Writer) error {
	// write b_hat
	err := WritePolyNTTVec(w, cbTxWitness.b_hat)
	if err != nil {
		 return err
	}

	// write c_hats
	count := len(cbTxWitness.c_hats)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := WritePolyNTT(w, cbTxWitness.c_hats[i])
		if err != nil {
			return err
		}
	}

	// write u_p
	count = len(cbTxWitness.u_p)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := writeElement(w, cbTxWitness.u_p[i])
		if err != nil {
			return err
		}
	}

	// write rpulpproof
	err = WriteRpulpProof(w, cbTxWitness.rpulpproof)
	if err != nil {
		return err
	}

	return nil
}

func (cbTxWitness *CbTxWitness) Deserialize(serializedTxWitness []byte) error {
	// todo
	return nil
}

func (trTx *TransferTx) Serialize(hasWitness bool) ([]byte, error) {
	w := new(bytes.Buffer)

	// write inputs
	count := len(trTx.Inputs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return nil, err
	}
	for _, input := range trTx.Inputs {
		err := input.Serialize(w)
		if err != nil {
			return nil, err
		}
	}

	// write outputs
	count = len(trTx.OutputTxos)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return nil, err
	}
	for _, output := range trTx.OutputTxos {
		err := output.Serialize(w)
		if err != nil {
			return nil, err
		}
	}

	// write txFee
	err = writeElement(w, trTx.Fee)
	if err != nil {
		return nil, err
	}

	// write txMemo
	err = WriteBytes(w, trTx.TxMemo)
	if err != nil {
		return nil, err
	}

	// write txWitness
	if hasWitness {
		err := trTx.TxWitness.Serialize(w)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

func (txo *TXO) SerializeSize() uint32 {
	// todo
	return 1
}

func (txo *TXO) Serialize(w io.Writer) error {
	err := WriteDerivedPubKey(w, txo.dpk)
	if err != nil {
		return err
	}

	// write commitment
	err = WriteCommitment(w, txo.cmt)
	if err != nil {
		return err
	}

	// write vc
	err = WriteBytes(w, txo.vc)
	if err != nil {
		return err
	}

	return nil
}

func (txo *TXO) Deserialize(serializedTxo []byte) error {
	// todo
	return nil
}

func (trTxInput *TrTxInput) Serialize(w io.Writer) error {
	// write txoList
	count := len(trTxInput.TxoList)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for _, txo := range trTxInput.TxoList {
		err := txo.Serialize(w)
		if err != nil {
			return err
		}
	}

	// write serialNumber
	err = WriteBytes(w, trTxInput.SerialNumber)
	if err != nil {
		return err
	}

	return nil
}

func (trTxWitness *TrTxWitness) SerializeSize() uint32 {
	// todo
	return 1
}

func (trTxWitness *TrTxWitness) Serialize(w io.Writer) error {
	// write b_hat
	err := WritePolyNTTVec(w, trTxWitness.b_hat)
	if err != nil {
		return err
	}

	// write c_hats
	count := len(trTxWitness.c_hats)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = WritePolyNTT(w, trTxWitness.c_hats[i])
		if err != nil {
			return err
		}
	}

	// write u_p
	count = len(trTxWitness.u_p)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := writeElement(w, trTxWitness.u_p[i])
		if err != nil {
			return err
		}
	}

	// write rpulpproof
	err = WriteRpulpProof(w, trTxWitness.rpulpproof)
	if err != nil {
		return err
	}

	// write cmtps
	count = len(trTxWitness.cmtps)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = WriteCommitment(w, trTxWitness.cmtps[i])
		if err != nil {
			return err
		}
	}

	// write elrsSigs
	count = len(trTxWitness.elrsSigs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = WriteElrsSignature(w, trTxWitness.elrsSigs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (trTxWitness *TrTxWitness) Deserialize(serializedTxWitness []byte) error {
	// todo
	return nil
}
