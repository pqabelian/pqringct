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

// WriteBytes write byte array to io.Writer
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

// ReadVarBytes read certain number of byte from io.Reader
// the length of the byte array is decided by the initial several byte
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

func WriteNULL(w io.Writer) {
	err := WriteVarInt(w, uint64(0))
	if err != nil {
		panic(err)
	}
}

func WriteNotNULL(w io.Writer) {
	err := WriteVarInt(w, uint64(1))
	if err != nil {
		panic(err)
	}
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
	if proof.c_waves != nil {
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
	}else{
		WriteNULL(w)
	}

	// write c_hat_g
	if proof.c_hat_g != nil {
		WriteNotNULL(w)
		err := WritePolyNTT(w, proof.c_hat_g)
		if err != nil {
			return err
		}
	}else{
		WriteNULL(w)
	}

	// write psi
	if proof.psi != nil {
		WriteNotNULL(w)
		err := WritePolyNTT(w, proof.psi)
		if err != nil {
			return err
		}
	}else{
		WriteNULL(w)
	}

	// write phi
	if proof.phi != nil {
		WriteNotNULL(w)
		err := WritePolyNTT(w, proof.phi)
		if err != nil {
			return err
		}
	}else{
		WriteNULL(w)
	}

	// write chseed
	if proof.chseed != nil {
		WriteNotNULL(w)
		err := WriteBytes(w, proof.chseed)
		if err != nil {
			return err
		}
	}else{
		WriteNULL(w)
	}

	// write cmt_zs
	if proof.cmt_zs != nil {
		count := len(proof.cmt_zs)
		err := WriteVarInt(w, uint64(count))
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
	}else{
		WriteNULL(w)
	}

	// write zs
	if proof.zs != nil {
		count := len(proof.zs)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err := WritePolyNTTVec(w, proof.zs[i])
			if err != nil {
				return err
			}
		}
	}else{
		WriteNULL(w)
	}

	return nil
}

func ReadRpulpProof(r io.Reader) (*rpulpProof, error) {
	// read c_waves
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var c_waves0 []*PolyNTT = nil
	if count != 0 {
		c_waves0 = make([]*PolyNTT, count)
		for i := 0; i < int(count); i++ {
			c_waves0[i], err = ReadPolyNTT(r)
			if err != nil {
				return nil, err
			}
		}
	}

	// read c_hat_g
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var c_hat_g0 *PolyNTT = nil
	if count != 0{
		c_hat_g0, err = ReadPolyNTT(r)
		if err != nil {
			return nil, err
		}
	}

	// read psi
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var psi0 *PolyNTT = nil
	if count != 0 {
		psi0, err = ReadPolyNTT(r)
		if err != nil {
			return nil, err
		}
	}

	// read phi
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var phi0 *PolyNTT = nil
	if count != 0 {
		phi0, err = ReadPolyNTT(r)
		if err != nil {
			return nil, err
		}
	}

	// read chseed
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var chseed0 []byte = nil
	if count != 0 {
		chseed0, err = ReadVarBytes(r, MAXALLOWED, "readRpulpProof")
		if err != nil {
			return nil, err
		}
	}

	// read cmt_zs
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var cmt_zs0 [][]*PolyNTTVec = nil
	if count != 0 {
		cmt_zs0 = make([][]*PolyNTTVec, count)
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
	}

	// read zs
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var zs0 []*PolyNTTVec = nil
	if count != 0 {
		zs0 = make([]*PolyNTTVec, count)
		for i := 0; i < int(count); i++ {
			zs0[i], err = ReadPolyNTTVec(r)
			if err != nil {
				return nil, err
			}
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

func (coinbaseTx *CoinbaseTx) Serialize(hasWitness bool) []byte {
	// write Vin
	w := new(bytes.Buffer)
	err := writeElement(w, coinbaseTx.Vin)
	if err != nil {
		return nil
	}

	// write OutputTxos
	count := len(coinbaseTx.OutputTxos)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return nil
	}
	for i := 0; i < count; i++ {
		err := coinbaseTx.OutputTxos[i].Serialize0(w)
		if err != nil {
			return nil
		}
	}

	// write TxWitness
	if hasWitness {
		err := coinbaseTx.TxWitness.Serialize0(w)
		if err != nil {
			return nil
		}
	}
	return w.Bytes()
}

func (coinbaseTx *CoinbaseTx) Deserialize(r io.Reader) error {
	// read Vin
	var Vin0 uint64 = 0
	err := readElements(r, Vin0)
	if err != nil {
		return err
	}

	// read OutputTxos
	count, err := ReadVarInt(r)
	if err != nil {
		return err
	}
	OutputTxos0 := make([]*TXO, count)
	for i := 0; i < int(count); i++ {
		OutputTxos0[i] = &TXO{}
		err = OutputTxos0[i].Deserialize(r)
		if err != nil {
			return err
		}
	}

	// read TxWitness
	TxWitness0 := &CbTxWitness{}
	err = TxWitness0.Deserialize(r)
	if err != nil {
		return err
	}

	coinbaseTx.Vin = Vin0
	coinbaseTx.OutputTxos = OutputTxos0
	coinbaseTx.TxWitness = TxWitness0
	return nil
}

func (cbTxWitness *CbTxWitness) SerializeSize() uint32 {
	// todo
	return 1
}

func (cbTxWitness *CbTxWitness) Serialize() []byte {
	w := new(bytes.Buffer)
	err := cbTxWitness.Serialize0(w)
	if err != nil {
		return nil
	}
	return w.Bytes()
}

func (cbTxWitness *CbTxWitness) Serialize0(w io.Writer) error {
	// write b_hat
	if cbTxWitness.b_hat != nil {
		WriteNotNULL(w)
		err := WritePolyNTTVec(w, cbTxWitness.b_hat)
		if err != nil {
			return err
		}
	}else{
		WriteNULL(w)
	}

	// write c_hats
	if cbTxWitness.c_hats != nil {
		count := len(cbTxWitness.c_hats)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err := WritePolyNTT(w, cbTxWitness.c_hats[i])
			if err != nil {
				return err
			}
		}
	}else {
		WriteNULL(w)
	}

	// write u_p
	if cbTxWitness.u_p != nil {
		count := len(cbTxWitness.u_p)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err := writeElement(w, cbTxWitness.u_p[i])
			if err != nil {
				return err
			}
		}
	}else{
		WriteNULL(w)
	}

	// write rpulpproof
	if cbTxWitness.rpulpproof != nil {
		WriteNotNULL(w)
		err := WriteRpulpProof(w, cbTxWitness.rpulpproof)
		if err != nil {
			return err
		}
	}else{
		WriteNULL(w)
	}

	return nil
}

func (cbTxWitness *CbTxWitness) Deserialize(r io.Reader) error {
	// read b_hat
	count, err := ReadVarInt(r)
	if err != nil {
		return err
	}
	var b_hat0 *PolyNTTVec = nil
	if count != 0 {
		b_hat0, err = ReadPolyNTTVec(r)
		if err != nil {
			return err
		}
	}

	// read c_hats
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var c_hats0 []*PolyNTT = nil
	if count != 0 {
		c_hats0 = make([]*PolyNTT, count)
		for i :=0; i < int(count); i++ {
			c_hats0[i], err = ReadPolyNTT(r)
			if err != nil {
				return err
			}
		}
	}

	// read u_p
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var u_p0 []int32 = nil
	if count != 0 {
		u_p0 = make([]int32, count)
		for i :=0; i < int(count); i++ {
			err := readElement(r, &u_p0[i])
			if err != nil {
				return err
			}
		}
	}

	// read rpulpproof
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var rpulpproof0 *rpulpProof = nil
	if count != 0 {
		rpulpproof0, err = ReadRpulpProof(r)
		if err != nil {
			return err
		}
	}

	cbTxWitness.b_hat = b_hat0
	cbTxWitness.c_hats = c_hats0
	cbTxWitness.u_p = u_p0
	cbTxWitness.rpulpproof = rpulpproof0

	return nil
}

func (trTx *TransferTx) Serialize(hasWitness bool) []byte {
	w := new(bytes.Buffer)

	// write inputs
	count := len(trTx.Inputs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return nil
	}
	for _, input := range trTx.Inputs {
		err := input.Serialize0(w)
		if err != nil {
			return nil
		}
	}

	// write outputs
	count = len(trTx.OutputTxos)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return nil
	}
	for _, output := range trTx.OutputTxos {
		err := output.Serialize0(w)
		if err != nil {
			return nil
		}
	}

	// write txFee
	err = writeElement(w, trTx.Fee)
	if err != nil {
		return nil
	}

	// write txMemo
	err = WriteBytes(w, trTx.TxMemo)
	if err != nil {
		return nil
	}

	// write txWitness
	if hasWitness {
		err := trTx.TxWitness.Serialize0(w)
		if err != nil {
			return nil
		}
	}

	return w.Bytes()
}

func (trTx *TransferTx) Deserialize(r io.Reader) error {
	// read Inputs
	count, err := ReadVarInt(r)
	if err != nil {
		return err
	}
	Inputs0 := make([]*TrTxInput, count)
	for i :=0; i < int(count); i++ {
		Inputs0[i] = &TrTxInput{}
		err = Inputs0[i].Deserialize(r)
		if err != nil {
			return err
		}
	}

	// read OutputTxos
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	OutputTxos0 := make([]*TXO, count)
	for i := 0; i < int(count); i++ {
		OutputTxos0[i] = &TXO{}
		err = OutputTxos0[i].Deserialize(r)
		if err != nil {
			return err
		}
	}

	// read Fee
	var Fee0 uint64 = 0
	err = readElement(r, &Fee0)
	if err != nil {
		return err
	}

	// read TxMemo
	TxMemo0, err := ReadVarBytes(r, MAXALLOWED, "TransferTx.Deserialize")
	if err != nil {
		return err
	}

	// read TxWitness
	TxWitness0 := &TrTxWitness{}
	err = TxWitness0.Deserialize(r)
	if err != nil {
		return err
	}

	trTx.Inputs = Inputs0
	trTx.OutputTxos = OutputTxos0
	trTx.Fee = Fee0
	trTx.TxMemo = TxMemo0
	trTx.TxWitness = TxWitness0

	return nil
}

func (txo *TXO) SerializeSize() uint32 {
	// todo
	return 1
}

func (txo *TXO) Serialize() []byte {
	w := new(bytes.Buffer)
	err := txo.Serialize0(w)
	if err != nil {
		return nil
	}
	
	return w.Bytes()
}


func (txo *TXO) Serialize0(w io.Writer) error {
	// write DerivedPubKey
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
	// read DerivedPubKey
	dpk0, err := ReadDerivedPubKey(r)
	if err != nil {
		return err
	}

	// read commitment
	cmt0, err := ReadCommitment(r)
	if err != nil {
		return err
	}

	// read vc
	vc0, err := ReadVarBytes(r, MAXALLOWED, "txo.Deserialize")
	if err != nil {
		return err
	}

	txo.dpk = dpk0
	txo.cmt = cmt0
	txo.vc = vc0
	return nil
}

func (trTxInput *TrTxInput) Serialize() []byte {
	w := new(bytes.Buffer)
	err := trTxInput.Serialize0(w)
	if err != nil {
		return nil
	}

	return w.Bytes()
}

func (trTxInput *TrTxInput) Serialize0(w io.Writer) error {
	// write txoList
	count := len(trTxInput.TxoList)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for _, txo := range trTxInput.TxoList {
		err := txo.Serialize0(w)
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
	// read TxoList
	count, err := ReadVarInt(r)
	if err != nil {
		return err
	}
	txoList0 := make([]*TXO, count)
	for i := 0; i < int(count); i++ {
		txoList0[i] = &TXO{}
		err := txoList0[i].Deserialize(r)
		if err != nil {
			return err
		}
	}

	// read SerialNumber
	serialNumber0, err := ReadVarBytes(r, MAXALLOWED, "trTxInput.Deserialize")
	if err != nil {
		return err
	}

	trTxInput.TxoList = txoList0
	trTxInput.SerialNumber = serialNumber0
	return nil
}

func (trTxWitness *TrTxWitness) Serialize() []byte {
	w := new(bytes.Buffer)
	err := trTxWitness.Serialize0(w)
	if err != nil {
		return nil
	}

	return w.Bytes()
}

func (trTxWitness *TrTxWitness) Serialize0(w io.Writer) error {
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
	for i := 0; i < int(count); i++ {
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
	for i := 0; i < int(count); i++ {
		err = readElement(r, &u_p0[i])
		if err != nil {
			return err
		}
	}

	// read rpulpproof
	rpulpproof0, err := ReadRpulpProof(r)
	if err != nil {
		return err
	}

	// read cmtps
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	cmtps0 := make([]*Commitment, count)
	for i := 0; i < int(count); i++ {
		cmtps0[i], err = ReadCommitment(r)
		if err != nil {
			return err
		}
	}

	// read elrsSigs
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	elrsSigs0 := make([]*elrsSignature, count)
	for i := 0; i < int(count); i++ {
		elrsSigs0[i], err = ReadElrsSignature(r)
		if err != nil {
			return err
		}
	}

	trTxWitness.b_hat = b_hat0
	trTxWitness.c_hats = c_hats0
	trTxWitness.u_p = u_p0
	trTxWitness.rpulpproof = rpulpproof0
	trTxWitness.cmtps = cmtps0
	trTxWitness.elrsSigs = elrsSigs0

	return nil
}
