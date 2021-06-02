package pqringct

import (
	"bytes"
	"io"
)

func (cbTxWitness *CbTxWitness) SerializeSize() uint32 {
	// todo
	return 1
}

func (cbTxWitness *CbTxWitness) Serialize() []byte {
	// write b_hat

	// write c_hats

	// write u_p

	// write rpulpproof
	return nil
}

func (cbTxWitness *CbTxWitness) Deserialize(serializedTxWitness []byte) error {
	// todo
	return nil
}

func (trTx *TransferTx) Serialize(hasWitness bool) ([]byte, error) {
	w := new(bytes.Buffer)

	// write inputs size
	count := uint64(len(trTx.Inputs))
	err := WriteVarInt(w, count)
	if err != nil {
		return nil, err
	}
	// write inputs
	for _, input := range trTx.Inputs {
		err := input.Serialize(w)
		if err != nil {
			return nil, err
		}
	}

	// write outputs size
	count = uint64(len(trTx.OutputTxos))
	err = WriteVarInt(w, count)
	if err != nil {
		return nil, err
	}
	// write outputs
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

	// write txMemo size
	count = uint64(len(trTx.TxMemo))
	err = WriteVarInt(w, count)
	if err != nil {
		return nil, err
	}
	// write txMemo
	w.Write(trTx.TxMemo[:])

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
	// write dpk.ckem
	count := len(txo.dpk.ckem)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	_, err = w.Write(txo.dpk.ckem)
	if err != nil {
		return err
	}

	// write dpk.t
	count = len(txo.dpk.t.polyNTTs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		cnt := len(txo.dpk.t.polyNTTs[i].coeffs)
		err = WriteVarInt(w, uint64(cnt))
		if err != nil {
			return err
		}
		for j := 0; j < cnt; j++ {
			err = writeElement(w, txo.dpk.t.polyNTTs[i].coeffs[j])
			if err != nil {
				return err
			}
		}
	}

	//write cmt.b
	count = len(txo.cmt.b.polyNTTs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		cnt := len(txo.cmt.b.polyNTTs[i].coeffs)
		err = WriteVarInt(w, uint64(cnt))
		if err != nil {
			return err
		}
		for j := 0; j < cnt; j++ {
			err = writeElement(w, txo.cmt.b.polyNTTs[i].coeffs[j])
			if err != nil {
				return err
			}
		}
	}

	// write cmt.c
	count = len(txo.cmt.c.coeffs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = writeElement(w, txo.cmt.c.coeffs[i])
		if err != nil {
			return err
		}
	}

	// write vc
	count = len(txo.vc)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	_, err = w.Write(txo.vc[:])
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
	// write txoList size
	count := uint64(len(trTxInput.TxoList))
	err := WriteVarInt(w, count)
	if err != nil {
		return err
	}
	// write txoList
	for _, txo := range trTxInput.TxoList {
		err := txo.Serialize(w)
		if err != nil {
			return err
		}
	}

	// write serialNumber
	count = uint64(len(trTxInput.SerialNumber))
	err = WriteVarInt(w, count)
	if err != nil {
		return err
	}
	_, err = w.Write(trTxInput.SerialNumber)
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
	count := len(trTxWitness.b_hat.polyNTTs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		num := len(trTxWitness.b_hat.polyNTTs[i].coeffs)
		err := WriteVarInt(w, uint64(num))
		if err != nil {
			return err
		}
		for j := 0; j < num; j++ {
			err := writeElement(w, trTxWitness.b_hat.polyNTTs[i].coeffs[j])
			if err != nil {
				return err
			}
		}
	}

	// write c_hats
	count = len(trTxWitness.c_hats)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		num := len(trTxWitness.c_hats[i].coeffs)
		err := WriteVarInt(w, uint64(num))
		if err != nil {
			return err
		}
		for j := 0; j < num; j++ {
			err := writeElement(w, trTxWitness.c_hats[i].coeffs[j])
			if err != nil {
				return err
			}
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
	// write rpulpproof.c_waves
	count = len(trTxWitness.rpulpproof.c_waves)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		num := len(trTxWitness.rpulpproof.c_waves[i].coeffs)
		err := WriteVarInt(w, uint64(num))
		if err != nil {
			return err
		}
		for j := 0; j < num; j++ {
			err := writeElement(w, trTxWitness.rpulpproof.c_waves[i].coeffs[j])
			if err != nil {
				return err
			}
		}
	}

	// write rpulpproof.c_hat_g
	count = len(trTxWitness.rpulpproof.c_hat_g.coeffs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := writeElement(w, trTxWitness.rpulpproof.c_hat_g.coeffs[i])
		if err != nil {
			return err
		}
	}

	// write rpulpproof.psi
	count = len(trTxWitness.rpulpproof.psi.coeffs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := writeElement(w, trTxWitness.rpulpproof.psi.coeffs[i])
		if err != nil {
			return err
		}
	}

	// write rpulpproof.phi
	count = len(trTxWitness.rpulpproof.phi.coeffs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := writeElement(w, trTxWitness.rpulpproof.phi.coeffs[i])
		if err != nil {
			return err
		}
	}

	// write rpulpproof.chseed
	count = len(trTxWitness.rpulpproof.chseed)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	_, err = w.Write(trTxWitness.rpulpproof.chseed[:])
	if err != nil {
		return err
	}

	// write rpulpproof.cmt_zs
	count = len(trTxWitness.rpulpproof.cmt_zs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		len1 := len(trTxWitness.rpulpproof.cmt_zs[i])
		err := WriteVarInt(w, uint64(len1))
		if err != nil {
			return err
		}
		for j := 0; j < len1; j++ {
			len2 := len(trTxWitness.rpulpproof.cmt_zs[i][j].polyNTTs)
			err := WriteVarInt(w, uint64(len2))
			if err != nil {
				return err
			}
			for k := 0; k < len2; k++ {
				len3 := len(trTxWitness.rpulpproof.cmt_zs[i][j].polyNTTs[k].coeffs)
				err := WriteVarInt(w, uint64(len3))
				if err != nil {
					return err
				}
				for k2 := 0; k2 < len3; k2++ {
					err := writeElement(w, trTxWitness.rpulpproof.cmt_zs[i][j].polyNTTs[k].coeffs[k2])
					if err != nil {
						return err
					}
				}
			}
		}
	}

	// write rpulpproof.zs
	count = len(trTxWitness.rpulpproof.zs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		len1 := len(trTxWitness.rpulpproof.zs[i].polyNTTs)
		err := WriteVarInt(w, uint64(len1))
		if err != nil {
			return err
		}
		for j := 0; j < len1; j++ {
			len2 := len(trTxWitness.rpulpproof.zs[i].polyNTTs[j].coeffs)
			err := WriteVarInt(w, uint64(len2))
			if err != nil {
				return err
			}
			for k := 0; k < len2; k++ {
				err := writeElement(w, trTxWitness.rpulpproof.zs[i].polyNTTs[j].coeffs[k])
				if err != nil {
					return err
				}
			}
		}
	}

	// write cmtps
	count = len(trTxWitness.cmtps)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		// write cmtps.b
		len1 := len(trTxWitness.cmtps[i].b.polyNTTs)
		err := WriteVarInt(w, uint64(len1))
		if err != nil {
			return err
		}
		for j := 0; j < len1; j++ {
			len2 := len(trTxWitness.cmtps[i].b.polyNTTs[j].coeffs)
			err := WriteVarInt(w, uint64(len2))
			if err != nil {
				return err
			}
			for k := 0; k < len2; k++ {
				err := writeElement(w, trTxWitness.cmtps[i].b.polyNTTs[j].coeffs[k])
				if err != nil {
					return err
				}
			}
		}

		// write cmtps.c
		len3 := len(trTxWitness.cmtps[i].c.coeffs)
		err = WriteVarInt(w, uint64(len3))
		if err != nil {
			return err
		}
		for j := 0; j < len3; j++ {
			err := writeElement(w, trTxWitness.cmtps[i].c.coeffs[j])
			if err != nil {
				return err
			}
		}
	}

	// write elrsSigs
	count = len(trTxWitness.elrsSigs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		// write elrsSigs.chseed
		chseedLen := len(trTxWitness.elrsSigs[i].chseed)
		err = WriteVarInt(w, uint64(chseedLen))
		if err != nil {
			return err
		}
		_, err = w.Write(trTxWitness.elrsSigs[i].chseed[:])
		if err != nil {
			return err
		}

		// write elrsSigs.z_as
		z_asRowLen := len(trTxWitness.elrsSigs[i].z_as)
		err = WriteVarInt(w, uint64(z_asRowLen))
		if err != nil {
			return err
		}
		for k1 := 0; k1 < z_asRowLen; k1++ {
			z_asColLen := len(trTxWitness.elrsSigs[i].z_as[k1])
			err = WriteVarInt(w, uint64(z_asColLen))
			if err != nil {
				return err
			}
			for k2 := 0; k2 < z_asColLen; k2++ {
				polyNTTLen := len(trTxWitness.elrsSigs[i].z_as[k1][k2].polyNTTs)
				err = WriteVarInt(w, uint64(polyNTTLen))
				if err != nil {
					return err
				}
				for k3 := 0; k3 < polyNTTLen; k3++ {
					coeffsLen := len(trTxWitness.elrsSigs[i].z_as[k1][k2].polyNTTs[k3].coeffs)
					err = WriteVarInt(w, uint64(coeffsLen))
					if err != nil {
						return err
					}
					for k4 := 0; k4 < coeffsLen; k4++ {
						err := writeElement(w, trTxWitness.elrsSigs[i].z_as[k1][k2].polyNTTs[k3].coeffs[k4])
						if err != nil {
							return err
						}
					}
				}
			}
		}

		// write elrsSigs.z_cs
		z_csRowLen := len(trTxWitness.elrsSigs[i].z_cs)
		err = WriteVarInt(w, uint64(z_csRowLen))
		if err != nil {
			return err
		}
		for k1 := 0; k1 < z_csRowLen; k1++ {
			z_csColLen := len(trTxWitness.elrsSigs[i].z_cs[k1])
			err = WriteVarInt(w, uint64(z_csColLen))
			if err != nil {
				return err
			}
			for k2 := 0; k2 < z_csColLen; k2++ {
				polyNTTLen := len(trTxWitness.elrsSigs[i].z_cs[k1][k2].polyNTTs)
				err = WriteVarInt(w, uint64(polyNTTLen))
				if err != nil {
					return err
				}
				for k3 := 0; k3 < polyNTTLen; k3++ {
					coeffsLen := len(trTxWitness.elrsSigs[i].z_cs[k1][k2].polyNTTs[k3].coeffs)
					err = WriteVarInt(w, uint64(coeffsLen))
					if err != nil {
						return err
					}
					for k4 := 0; k4 < coeffsLen; k4++ {
						err := writeElement(w, trTxWitness.elrsSigs[i].z_cs[k1][k2].polyNTTs[k3].coeffs[k4])
						if err != nil {
							return err
						}
					}
				}
			}
		}

		// write elrsSigs.keyImg
		polyNTTsLen := len(trTxWitness.elrsSigs[i].keyImg.polyNTTs)
		err = WriteVarInt(w, uint64(polyNTTsLen))
		if err != nil {
			return err
		}
		for k1 := 0; k1 < polyNTTsLen; k1++ {
			coeffsLen := len(trTxWitness.elrsSigs[i].keyImg.polyNTTs[k1].coeffs)
			err = WriteVarInt(w, uint64(coeffsLen))
			if err != nil {
				return err
			}
			for k2 := 0; k2 < coeffsLen; k2++ {
				err := writeElement(w, trTxWitness.elrsSigs[i].keyImg.polyNTTs[k1].coeffs[k2])
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (trTxWitness *TrTxWitness) Deserialize(serializedTxWitness []byte) error {
	// todo
	return nil
}
