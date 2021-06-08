package pqringct

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	MAXALLOWED uint32 = 4294967295 // 2^32-1
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

func ReadVarBytes(r io.Reader, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(maxAllowed) {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxAllowed)
		return nil, errors.New(str)
	}

	b := make([]byte, count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
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

func ReadPolyNTT(r io.Reader) (*PolyNTT, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// todo: compare length?

	coeffs0 := make([]int32, count)
	for i := 0; i < int(count); i++ {
		err := readElement(r, &coeffs0[i])
		if err != nil {
			return nil, errors.New("error when reading polyNTT")
		}
	}
	polyNTT := &PolyNTT{
		coeffs: coeffs0,
	}
	return polyNTT, nil
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

func ReadPolyNTTVec(r io.Reader) (*PolyNTTVec, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// todo: compare length?
	polyNTTs0 := make([]*PolyNTT, count)
	for i := 0; i < int(count); i++ {
		tmp, err := ReadPolyNTT(r)
		if err != nil {
			return nil, err
		}
		polyNTTs0[i] = tmp
	}
	polyNTTVec := &PolyNTTVec{
		polyNTTs: polyNTTs0,
	}
	return polyNTTVec, nil
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

func ReadRpulpProof(r io.Reader) (*rpulpProof, error) {
	// read c_waves
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	c_waves0 := make([]*PolyNTT, count)
	for i := 0; i < int(count); i++ {
		c_waves0[i], err = ReadPolyNTT(r)
		if err != nil {
			return nil, err
		}
	}

	// read c_hat_g
	c_hat_g0, err := ReadPolyNTT(r)
	if err != nil {
		return nil, err
	}

	// read psi
	psi0, err := ReadPolyNTT(r)
	if err != nil {
		return nil, err
	}

	// read phi
	phi0, err := ReadPolyNTT(r)
	if err != nil {
		return nil, err
	}

	// read chseed
	chseed0, err := ReadVarBytes(r, MAXALLOWED, "readRpulpProof")
	if err != nil {
		return nil, err
	}

	// read cmt_zs
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	cmt_zs0 := make([][]*PolyNTTVec, count)
	for i := 0; i < int(count); i++ {
		count2, err := ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		cmt_zs0[i] = make([]*PolyNTTVec, count2)
		for j := 0; j < int(count2); j++ {
			cmt_zs0[i][j], err = ReadPolyNTTVec(r)
			if err != nil {
				return nil, err
			}
		}
	}

	// read zs
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	zs0 := make([]*PolyNTTVec, count)
	for i := 0; i < int(count); i++ {
		zs0[i], err = ReadPolyNTTVec(r)
		if err != nil {
			return nil, err
		}
	}

	ret := &rpulpProof{
		c_waves: c_waves0,
		c_hat_g: c_hat_g0,
		psi: psi0,
		phi: phi0,
		chseed: chseed0,
		cmt_zs: cmt_zs0,
		zs: zs0,
	}
	return ret, nil
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

func ReadCommitment(r io.Reader) (*Commitment, error) {
	// read b
	b0, err := ReadPolyNTTVec(r)
	if err != nil {
		return nil, err
	}

	// read c
	c0, err := ReadPolyNTT(r)
	if err != nil {
		return nil, err
	}

	commitment := &Commitment{
		b: b0,
		c: c0,
	}

	return commitment, nil
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

func ReadDerivedPubKey(r io.Reader) (*DerivedPubKey, error) {
	// read ckem
	ckem0, err := ReadVarBytes(r, MAXALLOWED, "ReadDerivedPubKey")
	if err != nil {
		return nil, err
	}

	// read t
	t0, err := ReadPolyNTTVec(r)
	if err != nil {
		return nil, err
	}

	derivedPubKey := &DerivedPubKey{
		ckem: ckem0,
		t: t0,
	}

	return derivedPubKey, nil
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

func ReadElrsSignature(r io.Reader) (*elrsSignature, error) {
	// read chseed
	chseed0, err := ReadVarBytes(r, MAXALLOWED, "ReadElrsSignature")
	if err != nil {
		return nil, err
	}

	// read z_as
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	z_as0 := make([][]*PolyNTTVec, count)
	for i := 0; i < int(count); i++ {
		count2, err := ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		z_as0[i] = make([]*PolyNTTVec, count2)
		for j := 0; j < int(count2); j++ {
			z_as0[i][j], err = ReadPolyNTTVec(r)
			if err != nil {
				return nil, err
			}
		}
	}

	// read z_cs
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	z_cs0 := make([][]*PolyNTTVec, count)
	for i := 0; i < int(count); i++ {
		count2, err := ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		z_cs0[i] = make([]*PolyNTTVec, count2)
		for j := 0; j < int(count2); j++ {
			z_cs0[i][j], err = ReadPolyNTTVec(r)
			if err != nil {
				return nil, err
			}
		}
	}

	// read keyImg
	keyImg0, err := ReadPolyNTTVec(r)
	if err != nil {
		return nil, err
	}

	ret := &elrsSignature{
		chseed: chseed0,
		z_as: z_as0,
		z_cs: z_cs0,
		keyImg: keyImg0,
	}

	return ret, nil
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

func (coinbaseTx *CoinbaseTx) Deserialize(r io.Reader) error {
	// todo
	return nil
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

func (cbTxWitness *CbTxWitness) Deserialize(r io.Reader) error {
	// read b_hat
	b_hat0, err := ReadPolyNTTVec(r)
	if err != nil {
		return err
	}

	// read c_hats
	count, err := ReadVarInt(r)
	if err != nil {
		return err
	}
	c_hats0 := make([]*PolyNTT, count)
	for i :=0; i < int(count); i++ {
		c_hats0[i], err = ReadPolyNTT(r)
		if err != nil {
			return err
		}
	}

	// read u_p
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	u_p0 := make([]int32, count)
	for i :=0; i < int(count); i++ {
		err := readElement(r, &u_p0[i])
		if err != nil {
			return err
		}
	}

	// read rpulpproof
	rpulpproof0, err := ReadRpulpProof(r)
	if err != nil {
		return err
	}

	cbTxWitness.b_hat = b_hat0
	cbTxWitness.c_hats = c_hats0
	cbTxWitness.u_p = u_p0
	cbTxWitness.rpulpproof = rpulpproof0
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

func (trTx *TransferTx) Deserialize(r io.Reader) error {
	return nil
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

func (txo *TXO) Deserialize(r io.Reader) error {
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

func (trTxInput *TrTxInput) Deserialize(r io.Reader) error {
	// todo
	return nil
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

func (trTxWitness *TrTxWitness) Deserialize(r io.Reader) error {
	// todo
	return nil
}
