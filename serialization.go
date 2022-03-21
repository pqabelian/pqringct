package pqringct

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringct/pqringctkem/pqringctkyber"
	"io"
)

const (
	ErrInvalidLength = "invalid length"
	ErrNilPointer    = "there are nil pointer"
)

func (pp *PublicParameter) PolyANTTSerializeSize() int {
	// todo: 37-bit int64 could be serialized to 5 bytes, that is pp.paramDA * 5
	return pp.paramDA * 8
}
func (pp *PublicParameter) writePolyANTT(w io.Writer, a *PolyANTT) error {
	var err error
	/*	err = WriteVarInt(w, uint64(pp.paramDA))
		if err != nil {
			return err
		}*/
	for i := 0; i < pp.paramDA; i++ {
		err = writeElement(w, a.coeffs[i])
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyANTT(r io.Reader) (*PolyANTT, error) {
	var err error
	/*	var count uint64
		count, err = ReadVarInt(r)
		if err != nil {
			return nil, err
		}*/
	res := pp.NewPolyANTT()
	for i := 0; i < pp.paramDA; i++ {
		err = readElement(r, &res.coeffs[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (pp *PublicParameter) PolyANTTVecSerializeSize(a *PolyANTTVec) int {
	return VarIntSerializeSize2(uint64(len(a.polyANTTs))) + len(a.polyANTTs)*pp.PolyANTTSerializeSize()
}
func (pp *PublicParameter) writePolyANTTVec(w io.Writer, a *PolyANTTVec) error {
	var err error
	// length
	count := len(a.polyANTTs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = pp.writePolyANTT(w, a.polyANTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyANTTVec(r io.Reader) (*PolyANTTVec, error) {
	var err error
	var count uint64
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	res := make([]*PolyANTT, count)
	for i := uint64(0); i < count; i++ {
		res[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}
	return &PolyANTTVec{polyANTTs: res}, nil
}

func (pp *PublicParameter) PolyCNTTSerializeSize() int {
	//	todo: 53-bit int64 could be serialized to 7 bytes, that is pp.paramDA * 7
	return pp.paramDC * 8
}
func (pp *PublicParameter) writePolyCNTT(w io.Writer, c *PolyCNTT) error {
	var err error
	/*	err = WriteVarInt(w, uint64(pp.paramDC))
		if err != nil {
			return err
		}*/
	for i := 0; i < pp.paramDC; i++ {
		err = writeElement(w, c.coeffs[i])
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyCNTT(r io.Reader) (*PolyCNTT, error) {
	var err error
	/*	var count uint64
		count, err = ReadVarInt(r)
		if err != nil {
			return nil, err
		}*/
	res := pp.NewPolyCNTT()
	for i := 0; i < pp.paramDC; i++ {
		err = readElement(r, &res.coeffs[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (pp *PublicParameter) PolyCNTTVecSerializeSize(c *PolyCNTTVec) int {
	if c == nil || c.polyCNTTs == nil {
		return 0
	}
	return VarIntSerializeSize2(uint64(len(c.polyCNTTs))) + len(c.polyCNTTs)*pp.PolyCNTTSerializeSize()
}
func (pp *PublicParameter) writePolyCNTTVec(w io.Writer, c *PolyCNTTVec) error {
	if c == nil || c.polyCNTTs == nil {
		return errors.New("serialize nil PolyCNTTVec")
	}
	var err error
	// length
	count := len(c.polyCNTTs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = pp.writePolyCNTT(w, c.polyCNTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyCNTTVec(r io.Reader) (*PolyCNTTVec, error) {
	var err error
	var count uint64
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	res := make([]*PolyCNTT, count)
	for i := uint64(0); i < count; i++ {
		res[i], err = pp.readPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}
	return &PolyCNTTVec{polyCNTTs: res}, nil
}

func (pp *PublicParameter) AddressPublicKeySerializeSize() int {
	//return pp.PolyANTTVecSerializeSize(a.t) + pp.PolyANTTSerializeSize()
	return (pp.paramKA + 1) * pp.PolyANTTSerializeSize()
}
func (pp *PublicParameter) SerializeAddressPublicKey(apk *AddressPublicKey) ([]byte, error) {
	var err error
	if apk == nil || apk.t == nil || apk.e == nil {
		return nil, errors.New(ErrNilPointer)
	}
	if len(apk.t.polyANTTs) != pp.paramKA {
		return nil, errors.New("the format of AddressPublicKey does not match the design")
	}

	length := pp.AddressPublicKeySerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))
	for i := 0; i < pp.paramKA; i++ {
		err = pp.writePolyANTT(w, apk.t.polyANTTs[i])
		if err != nil {
			return nil, err
		}
	}
	err = pp.writePolyANTT(w, apk.e)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeAddressPublicKey(serialziedAPk []byte) (*AddressPublicKey, error) {
	var err error
	r := bytes.NewReader(serialziedAPk)

	t := pp.NewPolyANTTVec(pp.paramKA)
	var e *PolyANTT

	for i := 0; i < pp.paramKA; i++ {
		t.polyANTTs[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}
	e, err = pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressPublicKey{t, e}, nil
}

func (pp *PublicParameter) AddressSecretKeySpSerializeSize() int {
	//	return pp.PolyANTTVecSerializeSize(ask.s)
	return pp.paramLA * pp.PolyANTTSerializeSize()
}
func (pp *PublicParameter) SerializeAddressSecretKeySp(asksp *AddressSecretKeySp) ([]byte, error) {
	var err error
	if asksp == nil || asksp.s == nil {
		return nil, errors.New(ErrNilPointer)
	}

	if len(asksp.s.polyANTTs) != pp.paramLA {
		return nil, errors.New("the format of AddressSecretKeySp does not match the design")
	}

	spLength := pp.AddressSecretKeySpSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, spLength))
	for i := 0; i < pp.paramLA; i++ {
		err = pp.writePolyANTT(w, asksp.s.polyANTTs[i])
		if err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeAddressSecretKeySp(serialziedASkSp []byte) (*AddressSecretKeySp, error) {
	var err error
	r := bytes.NewReader(serialziedASkSp)
	s := pp.NewPolyANTTVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		s.polyANTTs[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}
	return &AddressSecretKeySp{s}, nil
}

func (pp *PublicParameter) AddressSecretKeySnSerializeSize() int {
	return pp.PolyANTTSerializeSize()
}
func (pp *PublicParameter) SerializeAddressSecretKeySn(asksn *AddressSecretKeySn) ([]byte, error) {
	var err error
	if asksn.ma == nil {
		return nil, errors.New(ErrNilPointer)
	}
	spLength := pp.AddressSecretKeySnSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, spLength))
	err = pp.writePolyANTT(w, asksn.ma)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeAddressSecretKeySn(serialziedASkSn []byte) (*AddressSecretKeySn, error) {
	var err error
	r := bytes.NewReader(serialziedASkSn)
	var ma *PolyANTT
	ma, err = pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressSecretKeySn{ma}, nil
}

//
//func (pp *PublicParameter) AddressSecretKeySize(ask *AddressSecretKey) (int, int) {
//	return pp.AddressSecretKeySpSerializeSize(ask.AddressSecretKeySp), pp.AddressSecretKeySnSerializeSize(ask.AddressSecretKeySn)
//}
//func (pp *PublicParameter) AddressSecretKeySerialize(ask *AddressSecretKey) ([]byte, []byte, error) {
//	var err error
//	if ask == nil || ask.AddressSecretKeySp == nil || ask.AddressSecretKeySn == nil {
//		return nil, nil, errors.New(ErrNilPointer)
//	}
//
//	spLength, snLength := pp.AddressSecretKeySize(ask)
//	serializedSecretKeySp := make([]byte, spLength)
//	serializedSecretKeySn := make([]byte, snLength)
//
//	serializedSecretKeySp, err = pp.SerializeAddressSecretKeySp(ask.AddressSecretKeySp)
//	if err != nil {
//		return nil, nil, err
//	}
//	serializedSecretKeySn, err = pp.SerializeAddressSecretKeySn(ask.AddressSecretKeySn)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	return serializedSecretKeySp, serializedSecretKeySn, nil
//}
//func (pp *PublicParameter) AddressSecretKeyDeserialize(serialziedASkSp []byte, serialziedASkSn []byte) (*AddressSecretKey, error) {
//	var err error
//
//	addressSecretKeySp, err := pp.DeserializeAddressSecretKeySp(serialziedASkSp)
//	if err != nil {
//		return nil, err
//	}
//	addressSecretKeySn, err := pp.DeserializeAddressSecretKeySn(serialziedASkSn)
//	if err != nil {
//		return nil, err
//	}
//
//	return &AddressSecretKey{
//		AddressSecretKeySp: addressSecretKeySp,
//		AddressSecretKeySn: addressSecretKeySn,
//	}, nil
//}

func (pp *PublicParameter) ValueCommitmentRandSerializeSize() int {
	//	return pp.PolyCNTTVecSerializeSize(v.b) + pp.PolyCNTTSerializeSize()
	return pp.paramLC * pp.PolyCNTTSerializeSize()
}
func (pp *PublicParameter) ValueCommitmentSerializeSize() int {
	//	return pp.PolyCNTTVecSerializeSize(v.b) + pp.PolyCNTTSerializeSize()
	return (pp.paramKC + 1) * pp.PolyCNTTSerializeSize()
}
func (pp *PublicParameter) SerializeValueCommitment(vcmt *ValueCommitment) ([]byte, error) {
	var err error
	if vcmt == nil || vcmt.b == nil || vcmt.c == nil {
		return nil, errors.New(ErrNilPointer)
	}
	if len(vcmt.b.polyCNTTs) != pp.paramKC {
		return nil, errors.New("the format of ValueCommitment does not match the design")
	}

	length := pp.ValueCommitmentSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))
	for i := 0; i < pp.paramKC; i++ {
		err = pp.writePolyCNTT(w, vcmt.b.polyCNTTs[i])
		if err != nil {
			return nil, err
		}
	}
	err = pp.writePolyCNTT(w, vcmt.c)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeValueCommitment(serialziedValueCommitment []byte) (*ValueCommitment, error) {
	var err error
	r := bytes.NewReader(serialziedValueCommitment)

	b := pp.NewPolyCNTTVec(pp.paramKC)
	var c *PolyCNTT

	for i := 0; i < pp.paramKC; i++ {
		b.polyCNTTs[i], err = pp.readPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}
	c, err = pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	return &ValueCommitment{b, c}, nil
}

func (pp *PublicParameter) TxoValueCiphertextSerializeSize() int {
	return pp.paramN/8 + 1
}

func (pp *PublicParameter) TxoSerializeSize() int {
	return pp.AddressPublicKeySerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		VarIntSerializeSize2(uint64(pp.TxoValueCiphertextSerializeSize())) + pp.TxoValueCiphertextSerializeSize() +
		VarIntSerializeSize2(uint64(pqringctkyber.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctkyber.GetKemCiphertextBytesLen(pp.paramKem)
	// 8 for vc: 53-bits, for simplicity, just as uint64
}

func (pp *PublicParameter) SerializeTxo(txo *Txo) ([]byte, error) {
	if txo == nil || txo.AddressPublicKey == nil || txo.ValueCommitment == nil {
		return nil, errors.New(ErrNilPointer)
	}

	var err error
	length := pp.TxoSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	serializedAddressPublicKey, err := pp.SerializeAddressPublicKey(txo.AddressPublicKey)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedAddressPublicKey)
	if err != nil {
		return nil, err
	}

	serializedValueCmt, err := pp.SerializeValueCommitment(txo.ValueCommitment)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedValueCmt)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(w, txo.Vct)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(w, txo.CkemSerialzed)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (pp *PublicParameter) DeserializeTxo(serializedTxo []byte) (*Txo, error) {
	var err error
	r := bytes.NewReader(serializedTxo)

	tmp := make([]byte, pp.AddressPublicKeySerializeSize())
	err = readElement(r, tmp)
	if err != nil {
		return nil, err
	}
	var apk *AddressPublicKey
	apk, err = pp.DeserializeAddressPublicKey(tmp)
	if err != nil {
		return nil, err
	}

	tmp = make([]byte, pp.ValueCommitmentSerializeSize())
	err = readElement(r, tmp)
	if err != nil {
		return nil, err
	}
	var cmt *ValueCommitment
	cmt, err = pp.DeserializeValueCommitment(tmp)
	if err != nil {
		return nil, err
	}

	vct, err := ReadVarBytes(r, MAXALLOWED, "txo.Vct")
	if err != nil {
		return nil, err
	}

	ckem, err := ReadVarBytes(r, MAXALLOWED, "txo.CkemSerialzed")
	if err != nil {
		return nil, err
	}

	return &Txo{apk, cmt, vct, ckem}, nil
}

func (pp *PublicParameter) LgrTxoIdSerializeSize() int {
	return HashBytesLen
}

func (pp *PublicParameter) LgrTxoSerializeSize() int {
	return pp.GetTxoSerializeSize() + VarIntSerializeSize2(uint64(pp.LgrTxoIdSerializeSize())) + pp.LgrTxoIdSerializeSize()
}
func (pp *PublicParameter) SerializeLgrTxo(lgrTxo *LgrTxo) ([]byte, error) {
	if lgrTxo.Txo == nil {
		return nil, errors.New(ErrNilPointer)
	}

	var err error
	length := pp.LgrTxoSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	serializedTxo, err := pp.SerializeTxo(lgrTxo.Txo)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedTxo)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(w, lgrTxo.Id)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeLgrTxo(serializedLgrTxo []byte) (*LgrTxo, error) {
	var err error

	r := bytes.NewReader(serializedLgrTxo)

	tmp := make([]byte, pp.TxoSerializeSize())
	err = readElement(r, tmp)
	if err != nil {
		return nil, err
	}
	var txo *Txo
	txo, err = pp.DeserializeTxo(tmp)
	if err != nil {
		return nil, err
	}

	id, err := ReadVarBytes(r, MAXALLOWED, "LgrTxo.Id")
	if err != nil {
		return nil, err
	}

	return &LgrTxo{txo, id}, nil
}

func (pp *PublicParameter) RpulpProofSerializeSize(prf *rpulpProofv2) int {
	var length int
	lengthOfPolyCNTT := pp.PolyCNTTSerializeSize()
	length = VarIntSerializeSize2(uint64(len(prf.c_waves))) + len(prf.c_waves)*lengthOfPolyCNTT + // c_waves []*PolyCNTT
		+3*lengthOfPolyCNTT + //c_hat_g,psi,phi  *PolyCNTT
		VarIntSerializeSize2(uint64(len(prf.chseed))) + len(prf.chseed) //chseed  []byte
	//cmt_zs  [][]*PolyCNTTVec
	length += VarIntSerializeSize2(uint64(len(prf.cmt_zs)))
	for i := 0; i < len(prf.cmt_zs); i++ {
		length += VarIntSerializeSize2(uint64(len(prf.cmt_zs[i])))
		for j := 0; j < len(prf.cmt_zs[i]); j++ {
			length += pp.PolyCNTTVecSerializeSize(prf.cmt_zs[i][j])
		}
	}
	//zs      []*PolyCNTTVec
	length += VarIntSerializeSize2(uint64(len(prf.zs)))
	for i := 0; i < len(prf.zs); i++ {
		length += pp.PolyCNTTVecSerializeSize(prf.zs[i])
	}
	return length
}

func (pp *PublicParameter) SerializeRpulpProof(prf *rpulpProofv2) ([]byte, error) {
	if prf == nil || prf.c_waves == nil || prf.c_hat_g == nil || prf.psi == nil ||
		prf.phi == nil || prf.cmt_zs == nil || prf.zs == nil {
		return nil, errors.New(ErrNilPointer)
	}

	var err error
	length := pp.RpulpProofSerializeSize(prf)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// c_waves []*PolyCNTT
	n := len(prf.c_waves)
	err = WriteVarInt(w, uint64(len(prf.c_waves)))
	for i := 0; i < n; i++ {
		err = pp.writePolyCNTT(w, prf.c_waves[i])
		if err != nil {
			return nil, err
		}
	}

	//c_hat_g *PolyCNTT
	err = pp.writePolyCNTT(w, prf.c_hat_g)
	if err != nil {
		return nil, err
	}

	//psi     *PolyCNTT
	err = pp.writePolyCNTT(w, prf.psi)
	if err != nil {
		return nil, err
	}

	//phi     *PolyCNTT
	err = pp.writePolyCNTT(w, prf.phi)
	if err != nil {
		return nil, err
	}

	//chseed  []byte
	err = WriteVarBytes(w, prf.chseed)
	if err != nil {
		return nil, err
	}

	//cmt_zs  [][]*PolyCNTTVec
	n = len(prf.cmt_zs)
	err = WriteVarInt(w, uint64(n))
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		n1 := len(prf.cmt_zs[i])
		err = WriteVarInt(w, uint64(n1))
		if err != nil {
			return nil, err
		}
		for j := 0; j < n1; j++ {
			pp.writePolyCNTTVec(w, prf.cmt_zs[i][j])
		}
	}

	//zs      []*PolyCNTTVec
	n = len(prf.zs)
	err = WriteVarInt(w, uint64(n))
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		err = pp.writePolyCNTTVec(w, prf.zs[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeRpulpProof(serializedRpulpProof []byte) (*rpulpProofv2, error) {

	r := bytes.NewReader(serializedRpulpProof)

	// c_waves []*PolyCNTT
	var c_waves []*PolyCNTT
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		c_waves = make([]*PolyCNTT, count)
		for i := uint64(0); i < count; i++ {
			c_waves[i], err = pp.readPolyCNTT(r)
			if err != nil {
				return nil, err
			}
		}
	}

	//c_hat_g *PolyCNTT
	c_hat_g, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//psi     *PolyCNTT
	psi, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//phi     *PolyCNTT
	phi, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//chseed  []byte
	chseed, err := ReadVarBytes(r, MAXALLOWED, "rpulpProof.chseed")
	if err != nil {
		return nil, err
	}

	//cmt_zs  [][]*PolyCNTTVec
	var cmt_zs [][]*PolyCNTTVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		cmt_zs = make([][]*PolyCNTTVec, count)
		var tcount uint64
		for i := uint64(0); i < count; i++ {
			tcount, err = ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			if tcount != 0 {
				cmt_zs[i] = make([]*PolyCNTTVec, tcount)
				for j := uint64(0); j < tcount; j++ {
					cmt_zs[i][j], err = pp.readPolyCNTTVec(r)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	//zs      []*PolyCNTTVec
	var zs []*PolyCNTTVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		zs = make([]*PolyCNTTVec, count)
		for i := uint64(0); i < count; i++ {
			zs[i], err = pp.readPolyCNTTVec(r)
			if err != nil {
				return nil, err
			}
		}
	}
	return &rpulpProofv2{
		c_waves: c_waves,
		c_hat_g: c_hat_g,
		psi:     psi,
		phi:     phi,
		chseed:  chseed,
		cmt_zs:  cmt_zs,
		zs:      zs,
	}, nil
}

func (pp *PublicParameter) CbTxWitnessJ1SerializeSize(witness *CbTxWitnessJ1) int {
	if witness == nil {
		return 0
	}
	var length int
	length = VarIntSerializeSize2(uint64(len(witness.chseed))) + len(witness.chseed)

	length += VarIntSerializeSize2(uint64(len(witness.zs)))
	for i := 0; i < len(witness.zs); i++ {
		length += pp.PolyCNTTVecSerializeSize(witness.zs[i])
	}

	return length
}

func (pp *PublicParameter) SerializeCbTxWitnessJ1(witness *CbTxWitnessJ1) ([]byte, error) {
	if witness.zs == nil {
		return nil, errors.New(ErrNilPointer)
	}

	var err error
	length := pp.CbTxWitnessJ1SerializeSize(witness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	//chseed  []byte
	err = WriteVarBytes(w, witness.chseed)
	if err != nil {
		return nil, err
	}

	//zs      []*PolyCNTTVec
	n := len(witness.zs)
	err = WriteVarInt(w, uint64(n))
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		err = pp.writePolyCNTTVec(w, witness.zs[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeCbTxWitnessJ1(serializedWitness []byte) (*CbTxWitnessJ1, error) {
	r := bytes.NewReader(serializedWitness)

	//chseed  []byte
	chseed, err := ReadVarBytes(r, MAXALLOWED, "CbTxWitnessJ1.chseed")
	if err != nil {
		return nil, err
	}

	//zs      []*PolyCNTTVec
	var zs []*PolyCNTTVec
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		zs = make([]*PolyCNTTVec, count)
		for i := uint64(0); i < count; i++ {
			zs[i], err = pp.readPolyCNTTVec(r)
			if err != nil {
				return nil, err
			}
		}
	}
	return &CbTxWitnessJ1{
		chseed: chseed,
		zs:     zs,
	}, nil
}

func (pp *PublicParameter) CbTxWitnessJ2SerializeSize(witness *CbTxWitnessJ2) int {
	if witness == nil {
		return 0
	}
	var length int
	length = pp.PolyCNTTVecSerializeSize(witness.b_hat) +
		VarIntSerializeSize2(uint64(len(witness.c_hats))) + len(witness.c_hats)*pp.PolyCNTTSerializeSize()

	length += VarIntSerializeSize2(uint64(len(witness.u_p))) + len(witness.u_p)*8
	rplPrfLen := pp.RpulpProofSerializeSize(witness.rpulpproof)
	length += VarIntSerializeSize2(uint64(rplPrfLen)) + rplPrfLen

	return length
}
func (pp *PublicParameter) SerializeCbTxWitnessJ2(witness *CbTxWitnessJ2) ([]byte, error) {
	if witness == nil || witness.b_hat == nil || witness.c_hats == nil || witness.rpulpproof == nil {
		return nil, errors.New(ErrNilPointer)
	}
	var err error
	length := pp.CbTxWitnessJ2SerializeSize(witness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// b_hat      *PolyCNTTVec
	err = pp.writePolyCNTTVec(w, witness.b_hat)
	if err != nil {
		return nil, err
	}

	// c_hats     []*PolyCNTT
	err = WriteVarInt(w, uint64(len(witness.c_hats)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.c_hats); i++ {
		err = pp.writePolyCNTT(w, witness.c_hats[i])
		if err != nil {
			return nil, err
		}
	}
	// u_p        []int64
	err = WriteVarInt(w, uint64(len(witness.u_p)))
	if err != nil {
		return nil, err
	}
	tmp := make([]byte, 8)
	for i := 0; i < len(witness.u_p); i++ {
		tmp[0] = byte(witness.u_p[i] >> 0)
		tmp[1] = byte(witness.u_p[i] >> 8)
		tmp[2] = byte(witness.u_p[i] >> 16)
		tmp[3] = byte(witness.u_p[i] >> 24)
		tmp[4] = byte(witness.u_p[i] >> 32)
		tmp[5] = byte(witness.u_p[i] >> 40)
		tmp[6] = byte(witness.u_p[i] >> 48)
		tmp[7] = byte(witness.u_p[i] >> 56)
		err = WriteVarBytes(w, tmp)
		if err != nil {
			return nil, err
		}
	}
	// rpulpproof *rpulpProofv2
	err = WriteVarInt(w, uint64(pp.RpulpProofSerializeSize(witness.rpulpproof)))
	if err != nil {
		return nil, err
	}
	serializedRpuProof, err := pp.SerializeRpulpProof(witness.rpulpproof)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedRpuProof)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeCbTxWitnessJ2(serializedCbTxWitness []byte) (*CbTxWitnessJ2, error) {
	var count uint64
	r := bytes.NewReader(serializedCbTxWitness)

	// b_hat      *PolyCNTTVec
	b_hat, err := pp.readPolyCNTTVec(r)
	if err != nil {
		return nil, err
	}

	// c_hats     []*PolyCNTT
	var c_hats []*PolyCNTT
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		c_hats = make([]*PolyCNTT, count)
		for i := uint64(0); i < count; i++ {
			c_hats[i], err = pp.readPolyCNTT(r)
			if err != nil {
				return nil, err
			}
		}
	}

	// u_p        []int64
	var u_p []int64
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		u_p = make([]int64, count)
		tmp := make([]byte, 8)
		for i := uint64(0); i < count; i++ {
			n, err := r.Read(tmp)
			if n != 8 || err != nil {
				return nil, err
			}
			u_p[i] = int64(tmp[0]) << 0
			u_p[i] |= int64(tmp[1]) << 8
			u_p[i] |= int64(tmp[2]) << 16
			u_p[i] |= int64(tmp[3]) << 24
			u_p[i] |= int64(tmp[4]) << 32
			u_p[i] |= int64(tmp[5]) << 40
			u_p[i] |= int64(tmp[6]) << 48
			u_p[i] |= int64(tmp[7]) << 56
		}
	}

	// rpulpproof *rpulpProofv2
	var rpulpproof *rpulpProofv2
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		serializedRpulpProof := make([]byte, count)
		_, err = r.Read(serializedRpulpProof)
		if err != nil {
			return nil, err
		}
		rpulpproof, err = pp.DeserializeRpulpProof(serializedRpulpProof)
		if err != nil {
			return nil, err
		}
	}

	return &CbTxWitnessJ2{
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rpulpproof,
	}, nil
}

func (pp *PublicParameter) ElrsSignatureSerializeSize(sig *elrsSignaturev2) int {
	var length int
	// seeds [][]byte
	length = VarIntSerializeSize2(uint64(len(sig.seeds)))
	for i := 0; i < len(sig.seeds); i++ {
		length += VarIntSerializeSize2(uint64(len(sig.seeds[i]))) + len(sig.seeds[i])
	}
	//z_as  []*PolyANTTVec
	length += VarIntSerializeSize2(uint64(len(sig.z_as)))
	for i := 0; i < len(sig.z_as); i++ {
		length += pp.PolyANTTVecSerializeSize(sig.z_as[i])
	}
	//z_cs  [][]*PolyCNTTVec
	length += VarIntSerializeSize2(uint64(len(sig.z_cs)))
	for i := 0; i < len(sig.z_cs); i++ {
		length += VarIntSerializeSize2(uint64(len(sig.z_cs[i])))
		for j := 0; j < len(sig.z_cs[i]); j++ {
			length += pp.PolyCNTTVecSerializeSize(sig.z_cs[i][j])
		}
	}
	//z_cps [][]*PolyCNTTVec
	length += VarIntSerializeSize2(uint64(len(sig.z_cps)))
	for i := 0; i < len(sig.z_cps); i++ {
		length += VarIntSerializeSize2(uint64(len(sig.z_cps[i])))
		for j := 0; j < len(sig.z_cps[i]); j++ {
			length += pp.PolyCNTTVecSerializeSize(sig.z_cps[i][j])
		}
	}
	return length
}
func (pp *PublicParameter) SerializeElrsSignature(sig *elrsSignaturev2) ([]byte, error) {
	if sig == nil {
		return nil, errors.New(ErrNilPointer)
	}

	var err error
	length := pp.ElrsSignatureSerializeSize(sig)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// seeds [][]byte
	err = WriteVarInt(w, uint64(len(sig.seeds)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(sig.seeds); i++ {
		err = WriteVarBytes(w, sig.seeds[i])
		if err != nil {
			return nil, err
		}
	}

	// z_as  []*PolyANTTVec
	err = WriteVarInt(w, uint64(len(sig.z_as)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(sig.z_as); i++ {
		err = pp.writePolyANTTVec(w, sig.z_as[i])
		if err != nil {
			return nil, err
		}
	}

	// z_cs  [][]*PolyCNTTVec
	err = WriteVarInt(w, uint64(len(sig.z_as)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(sig.z_as); i++ {
		tlength := len(sig.z_cs[i])
		err = WriteVarInt(w, uint64(tlength))
		if err != nil {
			return nil, err
		}
		for j := 0; j < tlength; j++ {
			err = pp.writePolyCNTTVec(w, sig.z_cs[i][j])
			if err != nil {
				return nil, err
			}
		}
	}

	// z_cps [][]*PolyCNTTVec
	err = WriteVarInt(w, uint64(len(sig.z_as)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(sig.z_as); i++ {
		tlength := len(sig.z_cps[i])
		err = WriteVarInt(w, uint64(tlength))
		if err != nil {
			return nil, err
		}
		for j := 0; j < tlength; j++ {
			err = pp.writePolyCNTTVec(w, sig.z_cps[i][j])
			if err != nil {
				return nil, err
			}
		}
	}

	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeElrsSignature(serializeElrsSignature []byte) (*elrsSignaturev2, error) {
	var err error
	var count uint64
	r := bytes.NewReader(serializeElrsSignature)

	// seeds [][]byte
	var seeds [][]byte
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		seeds = make([][]byte, count)
		for i := uint64(0); i < count; i++ {
			seeds[i], err = ReadVarBytes(r, MAXALLOWED, "cbTxWitness.seeds")
			if err != nil {
				return nil, err
			}
		}
	}
	// z_as  []*PolyANTTVec
	var z_as []*PolyANTTVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		z_as = make([]*PolyANTTVec, count)
		for i := uint64(0); i < count; i++ {
			z_as[i], err = pp.readPolyANTTVec(r)
			if err != nil {
				return nil, err
			}
		}
	}
	// z_cs  [][]*PolyCNTTVec
	var z_cs [][]*PolyCNTTVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		z_cs = make([][]*PolyCNTTVec, count)
		var tcount uint64
		for i := uint64(0); i < count; i++ {
			tcount, err = ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			z_cs[i] = make([]*PolyCNTTVec, tcount)
			for j := uint64(0); j < tcount; j++ {
				z_cs[i][j], err = pp.readPolyCNTTVec(r)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	// z_cps [][]*PolyCNTTVec
	var z_cps [][]*PolyCNTTVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		z_cps = make([][]*PolyCNTTVec, count)
		var tcount uint64
		for i := uint64(0); i < count; i++ {
			tcount, err = ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			z_cps[i] = make([]*PolyCNTTVec, tcount)
			for j := uint64(0); j < tcount; j++ {
				z_cps[i][j], err = pp.readPolyCNTTVec(r)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return &elrsSignaturev2{
		seeds: seeds,
		z_as:  z_as,
		z_cs:  z_cs,
		z_cps: z_cps,
	}, nil
}

func (pp *PublicParameter) TrTxWitnessSerializedSize(witness *TrTxWitnessv2) int {
	length := VarIntSerializeSize2(uint64(len(witness.ma_ps))) + len(witness.ma_ps)*pp.PolyANTTSerializeSize() + // ma_ps      []*PolyANTT
		VarIntSerializeSize2(uint64(len(witness.cmt_ps))) + len(witness.cmt_ps)*pp.ValueCommitmentSerializeSize() // cmt_ps     []*ValueCommitment

	// elrsSigs   []*elrsSignaturev2
	length += VarIntSerializeSize2(uint64(len(witness.elrsSigs)))
	for i := 0; i < len(witness.elrsSigs); i++ {
		sigLen := pp.ElrsSignatureSerializeSize(witness.elrsSigs[i])
		length += VarIntSerializeSize2(uint64(sigLen)) + sigLen
	}

	length += pp.PolyCNTTVecSerializeSize(witness.b_hat) + //b_hat      *PolyCNTTVec
		VarIntSerializeSize2(uint64(len(witness.c_hats))) + len(witness.c_hats)*pp.PolyCNTTSerializeSize() + //c_hats     []*PolyCNTT
		VarIntSerializeSize2(uint64(len(witness.u_p))) + len(witness.u_p)*8 //u_p        []int64

	//rpulpproof *rpulpProofv2
	rpfLen := pp.RpulpProofSerializeSize(witness.rpulpproof)
	length += VarIntSerializeSize2(uint64(rpfLen)) + rpfLen

	return length
}

func (pp *PublicParameter) SerializeTrTxWitness(witness *TrTxWitnessv2) ([]byte, error) {
	if witness == nil || witness.ma_ps == nil || witness.cmt_ps == nil ||
		witness.elrsSigs == nil || witness.b_hat == nil || witness.c_hats == nil || witness.rpulpproof == nil {
		return nil, errors.New(ErrNilPointer)
	}
	var err error
	length := pp.TrTxWitnessSerializedSize(witness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// ma_ps      []*PolyANTT
	err = WriteVarInt(w, uint64(len(witness.ma_ps)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.ma_ps); i++ {
		err = pp.writePolyANTT(w, witness.ma_ps[i])
		if err != nil {
			return nil, err
		}
	}

	// cmt_ps     []*ValueCommitment
	err = WriteVarInt(w, uint64(len(witness.cmt_ps)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.cmt_ps); i++ {
		serializedVCmt, err := pp.SerializeValueCommitment(witness.cmt_ps[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedVCmt)
		if err != nil {
			return nil, err
		}
	}

	// elrsSigs   []*elrsSignaturev2
	err = WriteVarInt(w, uint64(len(witness.elrsSigs)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.elrsSigs); i++ {
		serializedElrSig, err := pp.SerializeElrsSignature(witness.elrsSigs[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedElrSig)
		if err != nil {
			return nil, err
		}
	}
	// b_hat      *PolyCNTTVec
	err = pp.writePolyCNTTVec(w, witness.b_hat)
	if err != nil {
		return nil, err
	}
	// c_hats     []*PolyCNTT
	err = WriteVarInt(w, uint64(len(witness.c_hats)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(witness.c_hats); i++ {
		err = pp.writePolyCNTT(w, witness.c_hats[i])
		if err != nil {
			return nil, err
		}
	}
	// u_p        []int64
	err = WriteVarInt(w, uint64(len(witness.u_p)))
	if err != nil {
		return nil, err
	}
	tmp := make([]byte, 8)
	for i := 0; i < len(witness.u_p); i++ {
		tmp[0] = byte(witness.u_p[i] >> 0)
		tmp[1] = byte(witness.u_p[i] >> 8)
		tmp[2] = byte(witness.u_p[i] >> 16)
		tmp[3] = byte(witness.u_p[i] >> 24)
		tmp[4] = byte(witness.u_p[i] >> 32)
		tmp[5] = byte(witness.u_p[i] >> 40)
		tmp[6] = byte(witness.u_p[i] >> 48)
		tmp[7] = byte(witness.u_p[i] >> 56)
		err = WriteVarBytes(w, tmp)
		if err != nil {
			return nil, err
		}
	}

	// rpulpproof *rpulpProofv2
	err = WriteVarInt(w, uint64(pp.RpulpProofSerializeSize(witness.rpulpproof)))
	if err != nil {
		return nil, err
	}
	serializedRpuProof, err := pp.SerializeRpulpProof(witness.rpulpproof)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedRpuProof)
	if err != nil {
		return nil, err
	}
	return nil, nil
}
func (pp *PublicParameter) DeserializeTrTxWitness(serializedTrTxWitness []byte) (*TrTxWitnessv2, error) {
	var err error
	var count uint64
	r := bytes.NewReader(serializedTrTxWitness)

	// ma_ps     []*PolyANTT
	var ma_ps []*PolyANTT
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		ma_ps = make([]*PolyANTT, count)
		for i := uint64(0); i < count; i++ {
			ma_ps[i], err = pp.readPolyANTT(r)
			if err != nil {
				return nil, err
			}
		}
	}
	// cmt_ps     []*ValueCommitment
	var cmt_ps []*ValueCommitment
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		cmt_ps = make([]*ValueCommitment, count)
		for i := uint64(0); i < count; i++ {
			tmp := make([]byte, pp.ValueCommitmentSerializeSize())
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			cmt_ps[i], err = pp.DeserializeValueCommitment(tmp)
			if err != nil {
				return nil, err
			}
		}
	}
	// elrsSigs   []*elrsSignaturev2
	var elrsSigs []*elrsSignaturev2
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		elrsSigs = make([]*elrsSignaturev2, count)
		for i := uint64(0); i < count; i++ {
			sigLen, err := ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			tmp := make([]byte, sigLen)
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			elrsSigs[i], err = pp.DeserializeElrsSignature(tmp)
			if err != nil {
				return nil, err
			}
		}
	}
	// b_hat      *PolyCNTTVec
	var b_hat *PolyCNTTVec
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		b_hat, err = pp.readPolyCNTTVec(r)
		if err != nil {
			return nil, err
		}
	}
	// c_hats     []*PolyCNTT
	var c_hats []*PolyCNTT
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		c_hats = make([]*PolyCNTT, count)
		for i := uint64(0); i < count; i++ {
			c_hats[i], err = pp.readPolyCNTT(r)
			if err != nil {
				return nil, err
			}
		}
	}
	// u_p        []int64
	var u_p []int64
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		u_p = make([]int64, count)
		tmp := make([]byte, 8)
		for i := uint64(0); i < count; i++ {
			n, err := r.Read(tmp)
			if n != 8 || err != nil {
				return nil, err
			}
			u_p[i] = int64(tmp[0]) << 0
			u_p[i] |= int64(tmp[1]) << 8
			u_p[i] |= int64(tmp[2]) << 16
			u_p[i] |= int64(tmp[3]) << 24
			u_p[i] |= int64(tmp[4]) << 32
			u_p[i] |= int64(tmp[5]) << 40
			u_p[i] |= int64(tmp[6]) << 48
			u_p[i] |= int64(tmp[7]) << 56
		}
	}
	// rpulpproof *rpulpProofv2
	var rpulpproof *rpulpProofv2
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		count, err = ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		serializedRpulpProof := make([]byte, count)
		_, err = r.Read(serializedRpulpProof)
		if err != nil {
			return nil, err
		}
		rpulpproof, err = pp.DeserializeRpulpProof(serializedRpulpProof)
		if err != nil {
			return nil, err
		}
	}
	return &TrTxWitnessv2{
		ma_ps:      ma_ps,
		cmt_ps:     cmt_ps,
		elrsSigs:   elrsSigs,
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rpulpproof,
	}, nil
}

// todo: 20220322
func (pp *PublicParameter) TrTxInputSerializedSize(trTxIn *TrTxInputv2) int {
	var length int
	//	TxoList      []*LgrTxo
	length += VarIntSerializeSize2(1)
	if trTxIn.TxoList != nil {
		length += VarIntSerializeSize2(uint64(len(trTxIn.TxoList)))
		for i := 0; i < len(trTxIn.TxoList); i++ {
			tmp := pp.LgrTxoSerializeSize()
			length += VarIntSerializeSize2(uint64(tmp)) + tmp
		}
	}
	//	SerialNumber []byte
	length += VarIntSerializeSize2(1)
	if trTxIn.SerialNumber != nil {
		tmp := len(trTxIn.SerialNumber)
		length += VarIntSerializeSize2(uint64(tmp)) + tmp
	}
	return length
}
func (pp *PublicParameter) TrTxInputSerialize(trTxIn *TrTxInputv2) ([]byte, error) {
	if trTxIn == nil {
		return nil, errors.New(ErrNilPointer)
	}
	var err error
	length := pp.TrTxInputSerializedSize(trTxIn)
	w := bytes.NewBuffer(make([]byte, 0, length))

	//TxoList      []*LgrTxo
	if trTxIn.TxoList != nil {
		err = WriteNotNULL(w)
		if err != nil {
			return nil, err
		}
		err = WriteVarInt(w, uint64(len(trTxIn.TxoList)))
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(trTxIn.TxoList); i++ {
			size := pp.LgrTxoSerializeSize(trTxIn.TxoList[i])
			err = WriteVarInt(w, uint64(size))
			if err != nil {
				return nil, err
			}
			serializedTxo, err := pp.SerializeLgrTxo(trTxIn.TxoList[i])
			if err != nil {
				return nil, err
			}
			_, err = w.Write(serializedTxo)
			if err != nil {
				return nil, err
			}
		}
	} else {
		err = WriteNULL(w)
		if err != nil {
			return nil, err
		}
	}
	//SerialNumber []byte
	if trTxIn.SerialNumber != nil {
		err = WriteNotNULL(w)
		if err != nil {
			return nil, err
		}
		err = WriteVarBytes(w, trTxIn.SerialNumber)
		if err != nil {
			return nil, err
		}
	} else {
		err = WriteNULL(w)
		if err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) TrTxInputDeserialize(serialziedTrTxInput []byte) (*TrTxInputv2, error) {
	var err error
	var count uint64
	r := bytes.NewReader(serialziedTrTxInput)
	//TxoList      []*LgrTxo
	var TxoList []*LgrTxo
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		TxoList = make([]*LgrTxo, count)
		for i := uint64(0); i < count; i++ {
			tLength, err := ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			tmp := make([]byte, tLength)
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			TxoList[i], err = pp.DeserializeLgrTxo(tmp)
			if err != nil {
				return nil, err
			}
		}
	}
	//SerialNumber []byte
	var SerialNumber []byte
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		SerialNumber, err = ReadVarBytes(r, MAXALLOWED, "trTxInput.SerialNumber")
		if err != nil {
			return nil, err
		}
	}
	return &TrTxInputv2{
		TxoList:      TxoList,
		SerialNumber: SerialNumber,
	}, nil
}

func (pp *PublicParameter) TransferTxSerializedSize(tx *TransferTxv2, b bool) int {
	var length int
	//Inputs     []*TrTxInputv2
	length += VarIntSerializeSize2(1)
	if tx.Inputs != nil {
		length += VarIntSerializeSize2(uint64(len(tx.Inputs)))
		for i := 0; i < len(tx.Inputs); i++ {
			tmp := pp.TrTxInputSerializedSize(tx.Inputs[i])
			length += VarIntSerializeSize2(uint64(tmp)) + tmp
		}
	}

	//OutputTxos []*Txo
	length += VarIntSerializeSize2(1)
	if tx.OutputTxos != nil {
		length += VarIntSerializeSize2(uint64(len(tx.OutputTxos)))
		for i := 0; i < len(tx.OutputTxos); i++ {
			tmp := pp.TxoSerializeSize(tx.OutputTxos[i])
			length += VarIntSerializeSize2(uint64(tmp)) + tmp
		}
	}
	//Fee        uint64
	length += 8
	//TxMemo []byte
	length += VarIntSerializeSize2(1)
	if tx.TxMemo != nil {
		length += GetBytesSerializeSize2(tx.TxMemo)
	}
	if b {
		//TxWitness *TrTxWitnessv2
		length += VarIntSerializeSize2(1)
		if tx.TxWitness != nil {
			tmp := pp.TrTxWitnessSerializedSize(tx.TxWitness)
			length += VarIntSerializeSize2(uint64(tmp)) + tmp
		}
	}
	return length
}
func (pp *PublicParameter) TransferTxSerialize(tx *TransferTxv2, b bool) ([]byte, error) {
	if tx == nil {
		return nil, errors.New(ErrNilPointer)
	}
	var err error
	length := pp.TransferTxSerializedSize(tx, b)
	w := bytes.NewBuffer(make([]byte, 0, length))
	// Inputs     []*TrTxInputv2
	if tx.Inputs != nil {
		err = WriteNotNULL(w)
		if err != nil {
			return nil, err
		}
		err = WriteVarInt(w, uint64(len(tx.Inputs)))
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(tx.Inputs); i++ {
			size := pp.TrTxInputSerializedSize(tx.Inputs[i])
			err = WriteVarInt(w, uint64(size))
			if err != nil {
				return nil, err
			}
			serializedTxo, err := pp.TrTxInputSerialize(tx.Inputs[i])
			if err != nil {
				return nil, err
			}
			_, err = w.Write(serializedTxo)
			if err != nil {
				return nil, err
			}
		}
	} else {
		err = WriteNULL(w)
		if err != nil {
			return nil, err
		}
	}
	//OutputTxos []*Txo
	if tx.OutputTxos != nil {
		err = WriteNotNULL(w)
		if err != nil {
			return nil, err
		}
		err = WriteVarInt(w, uint64(len(tx.OutputTxos)))
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(tx.OutputTxos); i++ {
			size := pp.TxoSerializeSize(tx.OutputTxos[i])
			err = WriteVarInt(w, uint64(size))
			if err != nil {
				return nil, err
			}
			serializedTxo, err := pp.SerializeTxo(tx.OutputTxos[i])
			if err != nil {
				return nil, err
			}
			_, err = w.Write(serializedTxo)
			if err != nil {
				return nil, err
			}
		}
	} else {
		err = WriteNULL(w)
		if err != nil {
			return nil, err
		}
	}
	//Fee        uint64
	tmp := make([]byte, 8)
	tmp[0] = byte(tx.Fee >> 0)
	tmp[1] = byte(tx.Fee >> 8)
	tmp[2] = byte(tx.Fee >> 16)
	tmp[3] = byte(tx.Fee >> 24)
	tmp[4] = byte(tx.Fee >> 32)
	tmp[5] = byte(tx.Fee >> 40)
	tmp[6] = byte(tx.Fee >> 48)
	tmp[7] = byte(tx.Fee >> 56)
	_, err = w.Write(tmp)
	if err != nil {
		return nil, err
	}
	//TxMemo []byte
	if tx.TxMemo != nil {
		err = WriteNotNULL(w)
		if err != nil {
			return nil, err
		}
		err = WriteVarBytes(w, tx.TxMemo)
		if err != nil {
			return nil, err
		}
	} else {
		err = WriteNULL(w)
		if err != nil {
			return nil, err
		}
	}
	//TxWitness *TrTxWitnessv2
	if b {

		if tx.TxWitness != nil {
			err = WriteNotNULL(w)
			if err != nil {
				return nil, err
			}
			size := pp.TrTxWitnessSerializedSize(tx.TxWitness)
			err = WriteVarInt(w, uint64(size))
			if err != nil {
				return nil, err
			}
			serializedTxo, err := pp.SerializeTrTxWitness(tx.TxWitness)
			if err != nil {
				return nil, err
			}
			_, err = w.Write(serializedTxo)
			if err != nil {
				return nil, err
			}
		} else {
			err = WriteNULL(w)
			if err != nil {
				return nil, err
			}
		}
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) TransferTxDeserialize(serializedTrTx []byte, b bool) (*TransferTxv2, error) {
	var err error
	var count uint64
	r := bytes.NewReader(serializedTrTx)
	// Inputs     []*TrTxInputv2
	var Inputs []*TrTxInputv2
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		Inputs = make([]*TrTxInputv2, count)
		for i := uint64(0); i < count; i++ {
			tLength, err := ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			tmp := make([]byte, tLength)
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			Inputs[i], err = pp.TrTxInputDeserialize(tmp)
			if err != nil {
				return nil, err
			}
		}
	}
	// OutputTxos []*Txo
	var OutputTxos []*Txo
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		OutputTxos = make([]*Txo, count)
		for i := uint64(0); i < count; i++ {
			tLength, err := ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			tmp := make([]byte, tLength)
			_, err = r.Read(tmp)
			if err != nil {
				return nil, err
			}
			OutputTxos[i], err = pp.DeserializeTxo(tmp)
			if err != nil {
				return nil, err
			}
		}
	}
	// Fee        uint64
	tmp := make([]byte, 8)
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	Fee := uint64(tmp[0]) << 0
	Fee |= uint64(tmp[1]) << 8
	Fee |= uint64(tmp[2]) << 16
	Fee |= uint64(tmp[3]) << 24
	Fee |= uint64(tmp[4]) << 32
	Fee |= uint64(tmp[5]) << 40
	Fee |= uint64(tmp[6]) << 48
	Fee |= uint64(tmp[7]) << 56
	// TxMemo []byte
	var TxMemo []byte
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		TxMemo, err = ReadVarBytes(r, MAXALLOWED, "trTx.TxMemo")
		if err != nil {
			return nil, err
		}
	}
	var TxWitness *TrTxWitnessv2
	if b {
		// TxWitness *TrTxWitnessv2
		count, err = ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		if count != 0 {
			count, err = ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			serializedTrTxWitness := make([]byte, count)
			_, err = r.Read(serializedTrTxWitness)
			if err != nil {
				return nil, err
			}
			TxWitness, err = pp.DeserializeTrTxWitness(serializedTrTxWitness)
			if err != nil {
				return nil, err
			}
		}
	}
	return &TransferTxv2{
		Inputs:     Inputs,
		OutputTxos: OutputTxos,
		Fee:        Fee,
		TxMemo:     TxMemo,
		TxWitness:  TxWitness,
	}, nil
}

const (
	MAXALLOWED uint32 = 4294967295 // 2^32-1
)

// WriteVarBytes write byte array to io.Writer
func WriteVarBytes(w io.Writer, b []byte) error {
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

func GetBytesSerializeSize(b []byte) uint32 {
	if b == nil {
		return 0
	}
	var res uint32 = 0
	count := len(b)
	res += VarIntSerializeSize(uint64(count))
	res += uint32(count)
	return res
}
func GetBytesSerializeSize2(b []byte) int {
	if b == nil {
		return 0
	}
	var res int
	count := len(b)
	res += VarIntSerializeSize2(uint64(count))
	res += count
	return res
}

//func WritePolyNTT(w io.Writer, polyNTT *PolyNTT) error {
//	count := len(polyNTT.coeffs)
//	err := WriteVarInt(w, uint64(count))
//	if err != nil {
//		return err
//	}
//	for i := 0; i < count; i++ {
//		err := writeElement(w, polyNTT.coeffs[i])
//		if err != nil {
//			return err
//		}
//	}
//	return nil
//}

func WritePolyANTT(w io.Writer, poly *PolyANTT) error {
	count := len(poly.coeffs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := writeElement(w, poly.coeffs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadPolyANTT(r io.Reader) (*PolyANTT, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// todo: compare length?

	coeffs0 := make([]int64, count)
	for i := 0; i < int(count); i++ {
		err := readElement(r, &coeffs0[i])
		if err != nil {
			return nil, errors.New("error when reading polyNTT")
		}
	}
	polyNTT := &PolyANTT{
		coeffs: coeffs0,
	}
	return polyNTT, nil
}

func WritePolyCNTT(w io.Writer, poly *PolyCNTT) error {
	count := len(poly.coeffs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := writeElement(w, poly.coeffs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadPolyCNTT(r io.Reader) (*PolyCNTT, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// todo: compare length?

	coeffs0 := make([]int64, count)
	for i := 0; i < int(count); i++ {
		err := readElement(r, &coeffs0[i])
		if err != nil {
			return nil, errors.New("error when reading polyNTT")
		}
	}
	polyNTT := &PolyCNTT{
		coeffs: coeffs0,
	}
	return polyNTT, nil
}

//func ReadPolyNTT(r io.Reader) (*PolyNTT, error) {
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//
//	// todo: compare length?
//
//	coeffs0 := make([]int32, count)
//	for i := 0; i < int(count); i++ {
//		err := readElement(r, &coeffs0[i])
//		if err != nil {
//			return nil, errors.New("error when reading polyNTT")
//		}
//	}
//	polyNTT := &PolyNTT{
//		coeffs: coeffs0,
//	}
//	return polyNTT, nil
//}

//func GetPolyNTTSerializeSize(polyNTT *PolyNTT) uint32 {
//	var res uint32 = 0
//	if polyNTT == nil {
//		return 0
//	}
//	count := len(polyNTT.coeffs)
//	res += VarIntSerializeSize(uint64(count))
//	res += uint32(count) * 4
//	return res
//}

//func WritePolyNTTVec(w io.Writer, polyNTTVec *PolyNTTVec) error {
//	count := len(polyNTTVec.polyNTTs)
//	err := WriteVarInt(w, uint64(count))
//	if err != nil {
//		return err
//	}
//	for i := 0; i < count; i++ {
//		err := WritePolyNTT(w, polyNTTVec.polyNTTs[i])
//		if err != nil {
//			return err
//		}
//	}
//	return nil
//}

func WritePolyANTTVec(w io.Writer, polyNTTVec *PolyANTTVec) error {
	count := len(polyNTTVec.polyANTTs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := WritePolyANTT(w, polyNTTVec.polyANTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadPolyANTTVec(r io.Reader) (*PolyANTTVec, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// todo: compare length?
	polyNTTs0 := make([]*PolyANTT, count)
	for i := 0; i < int(count); i++ {
		tmp, err := ReadPolyANTT(r)
		if err != nil {
			return nil, err
		}
		polyNTTs0[i] = tmp
	}
	polyNTTVec := &PolyANTTVec{
		polyANTTs: polyNTTs0,
	}
	return polyNTTVec, nil
}

func ReadPolyCNTTVec(r io.Reader) (*PolyCNTTVec, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// todo: compare length?
	polyNTTs0 := make([]*PolyCNTT, count)
	for i := 0; i < int(count); i++ {
		tmp, err := ReadPolyCNTT(r)
		if err != nil {
			return nil, err
		}
		polyNTTs0[i] = tmp
	}
	polyNTTVec := &PolyCNTTVec{
		polyCNTTs: polyNTTs0,
	}
	return polyNTTVec, nil
}

func WritePolyCNTTVec(w io.Writer, polyNTTVec *PolyCNTTVec) error {
	count := len(polyNTTVec.polyCNTTs)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err := WritePolyCNTT(w, polyNTTVec.polyCNTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

//func WritePolyAVec(w io.Writer, polyNTTVec *PolyAVec) error {
//	count := len(polyNTTVec.polyAs)
//	err := WriteVarInt(w, uint64(count))
//	if err != nil {
//		return err
//	}
//	for i := 0; i < count; i++ {
//		err := WritePolyAv2(w, polyNTTVec.polyAs[i])
//		if err != nil {
//			return err
//		}
//	}
//	return nil
//}

//func ReadPolyNTTVec(r io.Reader) (*PolyNTTVec, error) {
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//
//	// todo: compare length?
//	polyNTTs0 := make([]*PolyNTT, count)
//	for i := 0; i < int(count); i++ {
//		tmp, err := ReadPolyNTT(r)
//		if err != nil {
//			return nil, err
//		}
//		polyNTTs0[i] = tmp
//	}
//	polyNTTVec := &PolyNTTVec{
//		polyNTTs: polyNTTs0,
//	}
//	return polyNTTVec, nil
//}

//func GetPolyNTTVecSerializeSize(polyNTTVec *PolyNTTVec) uint32 {
//	var res uint32 = 0
//	if polyNTTVec == nil {
//		return 0
//	}
//	count := len(polyNTTVec.polyNTTs)
//	res += VarIntSerializeSize(uint64(count))
//	res += uint32(count) * GetPolyNTTSerializeSize(polyNTTVec.polyNTTs[0])
//	return res
//}

//func SerializeRpulpProof(w io.Writer, proof *rpulpProof) error {
//	// write c_waves
//	if proof.c_waves != nil {
//		count := len(proof.c_waves)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			err := WritePolyNTT(w, proof.c_waves[i])
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write c_hat_g
//	if proof.c_hat_g != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTT(w, proof.c_hat_g)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write psi
//	if proof.psi != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTT(w, proof.psi)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write phi
//	if proof.phi != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTT(w, proof.phi)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write chseed
//	if proof.chseed != nil {
//		WriteNotNULL(w)
//		err := WriteVarBytes(w, proof.chseed)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write cmt_zs
//	if proof.cmt_zs != nil {
//		count := len(proof.cmt_zs)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			count2 := len(proof.cmt_zs[i])
//			err = WriteVarInt(w, uint64(count2))
//			if err != nil {
//				return err
//			}
//			for j := 0; j < count2; j++ {
//				err = WritePolyNTTVec(w, proof.cmt_zs[i][j])
//				if err != nil {
//					return err
//				}
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write zs
//	if proof.zs != nil {
//		count := len(proof.zs)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			err := WritePolyNTTVec(w, proof.zs[i])
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}

func WriteRpulpProofv2(w io.Writer, proof *rpulpProofv2) error {
	// write c_waves
	if proof.c_waves != nil {
		count := len(proof.c_waves)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err := WritePolyCNTT(w, proof.c_waves[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	// write c_hat_g
	if proof.c_hat_g != nil {
		WriteNotNULL(w)
		err := WritePolyCNTT(w, proof.c_hat_g)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write psi
	if proof.psi != nil {
		WriteNotNULL(w)
		err := WritePolyCNTT(w, proof.psi)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write phi
	if proof.phi != nil {
		WriteNotNULL(w)
		err := WritePolyCNTT(w, proof.phi)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write chseed
	if proof.chseed != nil {
		WriteNotNULL(w)
		err := WriteVarBytes(w, proof.chseed)
		if err != nil {
			return err
		}
	} else {
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
				err = WritePolyCNTTVec(w, proof.cmt_zs[i][j])
				if err != nil {
					return err
				}
			}
		}
	} else {
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
			err := WritePolyCNTTVec(w, proof.zs[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	return nil
}

func ReadRpulpProofv2(r io.Reader) (*rpulpProofv2, error) {
	// read c_waves
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var c_waves0 []*PolyCNTT = nil
	if count > 0 {
		c_waves0 = make([]*PolyCNTT, count)
		for i := 0; i < int(count); i++ {
			c_waves0[i], err = ReadPolyCNTT(r)
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
	var c_hat_g0 *PolyCNTT = nil
	if count > 0 {
		c_hat_g0, err = ReadPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}

	// read psi
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var psi0 *PolyCNTT = nil
	if count > 0 {
		psi0, err = ReadPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}

	// read phi
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var phi0 *PolyCNTT = nil
	if count > 0 {
		phi0, err = ReadPolyCNTT(r)
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
	if count > 0 {
		chseed0, err = ReadVarBytes(r, MAXALLOWED, "DeserializeRpulpProof")
		if err != nil {
			return nil, err
		}
	}

	// read cmt_zs
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var cmt_zs0 [][]*PolyCNTTVec = nil
	if count > 0 {
		cmt_zs0 = make([][]*PolyCNTTVec, count)
		for i := 0; i < int(count); i++ {
			count2, err := ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			cmt_zs0[i] = make([]*PolyCNTTVec, count2)
			for j := 0; j < int(count2); j++ {
				cmt_zs0[i][j], err = ReadPolyCNTTVec(r)
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
	var zs0 []*PolyCNTTVec = nil
	if count > 0 {
		zs0 = make([]*PolyCNTTVec, count)
		for i := 0; i < int(count); i++ {
			zs0[i], err = ReadPolyCNTTVec(r)
			if err != nil {
				return nil, err
			}
		}
	}

	ret := &rpulpProofv2{
		c_waves: c_waves0,
		c_hat_g: c_hat_g0,
		psi:     psi0,
		phi:     phi0,
		chseed:  chseed0,
		cmt_zs:  cmt_zs0,
		zs:      zs0,
	}
	return ret, nil
}

//func DeserializeRpulpProof(r io.Reader) (*rpulpProof, error) {
//	// read c_waves
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var c_waves0 []*PolyNTT = nil
//	if count > 0 {
//		c_waves0 = make([]*PolyNTT, count)
//		for i := 0; i < int(count); i++ {
//			c_waves0[i], err = ReadPolyNTT(r)
//			if err != nil {
//				return nil, err
//			}
//		}
//	}
//
//	// read c_hat_g
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var c_hat_g0 *PolyNTT = nil
//	if count > 0 {
//		c_hat_g0, err = ReadPolyNTT(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// read psi
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var psi0 *PolyNTT = nil
//	if count > 0 {
//		psi0, err = ReadPolyNTT(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// read phi
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var phi0 *PolyNTT = nil
//	if count > 0 {
//		phi0, err = ReadPolyNTT(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// read chseed
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var chseed0 []byte = nil
//	if count > 0 {
//		chseed0, err = ReadVarBytes(r, MAXALLOWED, "DeserializeRpulpProof")
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// read cmt_zs
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var cmt_zs0 [][]*PolyNTTVec = nil
//	if count > 0 {
//		cmt_zs0 = make([][]*PolyNTTVec, count)
//		for i := 0; i < int(count); i++ {
//			count2, err := ReadVarInt(r)
//			if err != nil {
//				return nil, err
//			}
//			cmt_zs0[i] = make([]*PolyNTTVec, count2)
//			for j := 0; j < int(count2); j++ {
//				cmt_zs0[i][j], err = ReadPolyNTTVec(r)
//				if err != nil {
//					return nil, err
//				}
//			}
//		}
//	}
//
//	// read zs
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var zs0 []*PolyNTTVec = nil
//	if count > 0 {
//		zs0 = make([]*PolyNTTVec, count)
//		for i := 0; i < int(count); i++ {
//			zs0[i], err = ReadPolyNTTVec(r)
//			if err != nil {
//				return nil, err
//			}
//		}
//	}
//
//	ret := &rpulpProof{
//		c_waves: c_waves0,
//		c_hat_g: c_hat_g0,
//		psi:     psi0,
//		phi:     phi0,
//		chseed:  chseed0,
//		cmt_zs:  cmt_zs0,
//		zs:      zs0,
//	}
//	return ret, nil
//}

//func GetRpulpProofSerializeSize(proof *rpulpProof) uint32 {
//	var res uint32 = 0
//
//	// c_waves
//	if proof.c_waves == nil {
//		res += 1
//	} else {
//		count := len(proof.c_waves)
//		res += VarIntSerializeSize(uint64(count))
//		res += uint32(count) * GetPolyNTTSerializeSize(proof.c_waves[0])
//	}
//
//	// c_hat_g
//	res += 1
//	res += GetPolyNTTSerializeSize(proof.c_hat_g)
//
//	// psi
//	res += 1
//	res += GetPolyNTTSerializeSize(proof.psi)
//
//	// phi
//	res += 1
//	res += GetPolyNTTSerializeSize(proof.phi)
//
//	// chseed
//	res += 1
//	res += GetBytesSerializeSize(proof.chseed)
//
//	// cmt_zs
//	if proof.cmt_zs == nil {
//		res += 1
//	} else {
//		count1 := len(proof.cmt_zs)
//		res += VarIntSerializeSize(uint64(count1))
//		count2 := len(proof.cmt_zs[0])
//		res += uint32(count1) * VarIntSerializeSize(uint64(count2))
//		res += uint32(count1) * uint32(count2) * GetPolyNTTVecSerializeSize(proof.cmt_zs[0][0])
//	}
//
//	// zs
//	if proof.zs == nil {
//		res += 1
//	} else {
//		count := len(proof.zs)
//		res += VarIntSerializeSize(uint64(count))
//		res += uint32(count) * GetPolyNTTVecSerializeSize(proof.zs[0])
//	}
//
//	return res
//}

//func WriteCommitment(w io.Writer, cmt *Commitment) error {
//	// write b
//	if cmt.b != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTTVec(w, cmt.b)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write c
//	if cmt.c != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTT(w, cmt.c)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}
func WriteCommitmentv2(w io.Writer, cmt *ValueCommitment) error {
	// write b
	if cmt.b != nil {
		WriteNotNULL(w)
		err := WritePolyCNTTVec(w, cmt.b)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write c
	if cmt.c != nil {
		WriteNotNULL(w)
		err := WritePolyCNTT(w, cmt.c)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	return nil
}

func ReadCommitmentv2(r io.Reader) (*ValueCommitment, error) {
	// read b
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var b0 *PolyCNTTVec = nil
	if count > 0 {
		b0, err = ReadPolyCNTTVec(r)
		if err != nil {
			return nil, err
		}
	}

	// read c
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var c0 *PolyCNTT = nil
	if count > 0 {
		c0, err = ReadPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}

	commitment := &ValueCommitment{
		b: b0,
		c: c0,
	}

	return commitment, nil
}

//func ReadCommitment(r io.Reader) (*Commitment, error) {
//	// read b
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var b0 *PolyNTTVec = nil
//	if count > 0 {
//		b0, err = ReadPolyNTTVec(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// read c
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var c0 *PolyNTT = nil
//	if count > 0 {
//		c0, err = ReadPolyNTT(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	commitment := &Commitment{
//		b: b0,
//		c: c0,
//	}
//
//	return commitment, nil
//}

//func GetCommitmentSerializeSize(cmt *Commitment) uint32 {
//	if cmt == nil {
//		return 0
//	}
//	var res uint32 = 0
//
//	// b
//	res += 1
//	res += GetPolyNTTVecSerializeSize(cmt.b)
//
//	// c
//	res += 10
//	res += GetPolyNTTSerializeSize(cmt.c)
//
//	return res
//}

func WritePublicKey(w io.Writer, pk *AddressPublicKey) error {
	// write t
	if pk.t != nil {
		WriteNotNULL(w)
		err := WritePolyANTTVec(w, pk.t)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write e

	if pk.e != nil {
		WriteNotNULL(w)
		err := WritePolyANTT(w, pk.e)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	return nil
}

func ReadPublicKey(r io.Reader) (*AddressPublicKey, error) {
	// read t
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var t0 *PolyANTTVec = nil
	if count > 0 {
		t0, err = ReadPolyANTTVec(r)
		if err != nil {
			return nil, err
		}
	}
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var e0 *PolyANTT = nil
	if count > 0 {
		e0, err = ReadPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}
	derivedPubKey := &AddressPublicKey{
		t: t0,
		e: e0,
	}

	return derivedPubKey, nil
}

//func WriteDerivedPubKey(w io.Writer, dpk *DerivedPubKey) error {
//	// write ckem
//	if dpk.ckem != nil {
//		WriteNotNULL(w)
//		err := WriteVarBytes(w, dpk.ckem)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write t
//	if dpk.t != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTTVec(w, dpk.t)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}
//
//func ReadDerivedPubKey(r io.Reader) (*DerivedPubKey, error) {
//	// read ckem
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var ckem0 []byte = nil
//	if count > 0 {
//		ckem0, err = ReadVarBytes(r, MAXALLOWED, "ReadDerivedPubKey")
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// read t
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var t0 *PolyNTTVec = nil
//	if count > 0 {
//		t0, err = ReadPolyNTTVec(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	derivedPubKey := &DerivedPubKey{
//		ckem: ckem0,
//		t:    t0,
//	}
//
//	return derivedPubKey, nil
//}

//func GetDerivedPubKeySerializeSize(dpk *DerivedPubKey) uint32 {
//	if dpk == nil {
//		return 0
//	}
//	var res uint32 = 0
//
//	// ckem
//	res += 1
//	res += GetBytesSerializeSize(dpk.ckem)
//
//	// t
//	res += 1
//	res += GetPolyNTTVecSerializeSize(dpk.t)
//
//	return res
//}

//func SerializeElrsSignature(w io.Writer, elrsSig *elrsSignature) error {
//	// write chseed
//	if elrsSig.chseed != nil {
//		WriteNotNULL(w)
//		err := WriteVarBytes(w, elrsSig.chseed)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write z_as
//	if elrsSig.z_as != nil {
//		count := len(elrsSig.z_as)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			count2 := len(elrsSig.z_as[i])
//			err = WriteVarInt(w, uint64(count2))
//			if err != nil {
//				return err
//			}
//			for j := 0; j < count2; j++ {
//				err = WritePolyNTTVec(w, elrsSig.z_as[i][j])
//				if err != nil {
//					return err
//				}
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write z_cs
//	if elrsSig.z_cs != nil {
//		count := len(elrsSig.z_cs)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			count2 := len(elrsSig.z_cs[i])
//			err = WriteVarInt(w, uint64(count2))
//			if err != nil {
//				return err
//			}
//			for j := 0; j < count2; j++ {
//				err = WritePolyNTTVec(w, elrsSig.z_cs[i][j])
//				if err != nil {
//					return err
//				}
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write keyImg
//	if elrsSig.keyImg != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTTVec(w, elrsSig.keyImg)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}

func WriteElrsSignaturev2(w io.Writer, elrsSig *elrsSignaturev2) error {
	// write chseed
	if len(elrsSig.seeds) != 0 {
		count := len(elrsSig.seeds)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			count2 := len(elrsSig.seeds[i])
			err = WriteVarInt(w, uint64(count2))
			if err != nil {
				return err
			}
			err := WriteVarBytes(w, elrsSig.seeds[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	// write z_as
	if elrsSig.z_as != nil {
		count := len(elrsSig.z_as)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err = WritePolyANTTVec(w, elrsSig.z_as[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	// write z_cs
	if elrsSig.z_cs != nil {
		count := len(elrsSig.z_cs)
		err := WriteVarInt(w, uint64(count))
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
				err = WritePolyCNTTVec(w, elrsSig.z_cs[i][j])
				if err != nil {
					return err
				}
			}
		}
	} else {
		WriteNULL(w)
	}

	if elrsSig.z_cps != nil {
		count := len(elrsSig.z_cps)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			count2 := len(elrsSig.z_cps[i])
			err = WriteVarInt(w, uint64(count2))
			if err != nil {
				return err
			}
			for j := 0; j < count2; j++ {
				err = WritePolyCNTTVec(w, elrsSig.z_cps[i][j])
				if err != nil {
					return err
				}
			}
		}
	} else {
		WriteNULL(w)
	}

	return nil
}

func ReadElrsSignaturev2(r io.Reader) (*elrsSignaturev2, error) {
	// read chseed
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var chseed0 [][]byte
	if count > 0 {
		chseed0 = make([][]byte, count)
		for i := 0; i < int(count); i++ {
			chseed0[i], err = ReadVarBytes(r, MAXALLOWED, "DeserializeElrsSignature")
			if err != nil {
				return nil, err
			}
		}

	}

	// read z_as
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var z_as0 []*PolyANTTVec = nil
	if count > 0 {
		z_as0 = make([]*PolyANTTVec, count)
		for i := 0; i < int(count); i++ {
			z_as0[i], err = ReadPolyANTTVec(r)
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
	var z_cs0 [][]*PolyCNTTVec = nil
	if count > 0 {
		z_cs0 = make([][]*PolyCNTTVec, count)
		for i := 0; i < int(count); i++ {
			count2, err := ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			z_cs0[i] = make([]*PolyCNTTVec, count2)
			for j := 0; j < int(count2); j++ {
				z_cs0[i][j], err = ReadPolyCNTTVec(r)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// read z_cps
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	var z_cps0 [][]*PolyCNTTVec = nil
	if count > 0 {
		z_cps0 = make([][]*PolyCNTTVec, count)
		for i := 0; i < int(count); i++ {
			count2, err := ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			z_cps0[i] = make([]*PolyCNTTVec, count2)
			for j := 0; j < int(count2); j++ {
				z_cps0[i][j], err = ReadPolyCNTTVec(r)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	ret := &elrsSignaturev2{
		seeds: chseed0,
		z_as:  z_as0,
		z_cs:  z_cs0,
		z_cps: z_cps0,
	}

	return ret, nil
}

//func DeserializeElrsSignature(r io.Reader) (*elrsSignature, error) {
//	// read chseed
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var chseed0 []byte = nil
//	if count > 0 {
//		chseed0, err = ReadVarBytes(r, MAXALLOWED, "DeserializeElrsSignature")
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// read z_as
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var z_as0 [][]*PolyNTTVec = nil
//	if count > 0 {
//		z_as0 = make([][]*PolyNTTVec, count)
//		for i := 0; i < int(count); i++ {
//			count2, err := ReadVarInt(r)
//			if err != nil {
//				return nil, err
//			}
//			z_as0[i] = make([]*PolyNTTVec, count2)
//			for j := 0; j < int(count2); j++ {
//				z_as0[i][j], err = ReadPolyNTTVec(r)
//				if err != nil {
//					return nil, err
//				}
//			}
//		}
//	}
//
//	// read z_cs
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var z_cs0 [][]*PolyNTTVec = nil
//	if count > 0 {
//		z_cs0 = make([][]*PolyNTTVec, count)
//		for i := 0; i < int(count); i++ {
//			count2, err := ReadVarInt(r)
//			if err != nil {
//				return nil, err
//			}
//			z_cs0[i] = make([]*PolyNTTVec, count2)
//			for j := 0; j < int(count2); j++ {
//				z_cs0[i][j], err = ReadPolyNTTVec(r)
//				if err != nil {
//					return nil, err
//				}
//			}
//		}
//	}
//
//	// read keyImg
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var keyImg0 *PolyNTTVec = nil
//	if count > 0 {
//		keyImg0, err = ReadPolyNTTVec(r)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	ret := &elrsSignature{
//		chseed: chseed0,
//		z_as:   z_as0,
//		z_cs:   z_cs0,
//		keyImg: keyImg0,
//	}
//
//	return ret, nil
//}

//func GetElrsSignatureSerializeSize(elrsSig *elrsSignature) uint32 {
//	if elrsSig == nil {
//		return 0
//	}
//	var res uint32 = 0
//
//	// chseed
//	res += 1
//	res += GetBytesSerializeSize(elrsSig.chseed)
//
//	// z_as
//	if elrsSig.z_as == nil {
//		res += 1
//	} else {
//		count1 := len(elrsSig.z_as)
//		res += VarIntSerializeSize(uint64(count1))
//		count2 := len(elrsSig.z_as[0])
//		res += uint32(count1) * VarIntSerializeSize(uint64(count2))
//		res += uint32(count1) * uint32(count2) * GetPolyNTTVecSerializeSize(elrsSig.z_as[0][0])
//	}
//
//	// z_cs
//	if elrsSig.z_cs == nil {
//		res += 1
//	} else {
//		count1 := len(elrsSig.z_cs)
//		res += VarIntSerializeSize(uint64(count1))
//		count2 := len(elrsSig.z_cs[0])
//		res += uint32(count1) * VarIntSerializeSize(uint64(count2))
//		res += uint32(count1) * uint32(count2) * GetPolyNTTVecSerializeSize(elrsSig.z_cs[0][0])
//	}
//
//	// keyImg
//	res += 1
//	res += GetPolyNTTVecSerializeSize(elrsSig.keyImg)
//
//	return res
//}

//func (coinbaseTx *CoinbaseTx) Serialize(hasWitness bool) []byte {
//	// write Vin
//	w := new(bytes.Buffer)
//	err := writeElement(w, coinbaseTx.Vin)
//	if err != nil {
//		return nil
//	}
//
//	// write OutputTxos
//	if coinbaseTx.OutputTxos != nil {
//		count := len(coinbaseTx.OutputTxos)
//		err = WriteVarInt(w, uint64(count))
//		if err != nil {
//			return nil
//		}
//		for i := 0; i < count; i++ {
//			err := coinbaseTx.OutputTxos[i].Serialize0(w)
//			if err != nil {
//				return nil
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write TxWitness
//	if hasWitness {
//		if coinbaseTx.TxWitness != nil {
//			WriteNotNULL(w)
//			err := coinbaseTx.TxWitness.Serialize0(w)
//			if err != nil {
//				return nil
//			}
//		} else {
//			WriteNULL(w)
//		}
//	}
//	return w.Bytes()
//}

//func (coinbaseTx *CoinbaseTx) Deserialize(r io.Reader) error {
//	// read Vin
//	var Vin0 uint64 = 0
//	err := readElements(r, Vin0)
//	if err != nil {
//		return err
//	}
//
//	// read OutputTxos
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var OutputTxos0 []*TXO = nil
//	if count > 0 {
//		OutputTxos0 = make([]*TXO, count)
//		for i := 0; i < int(count); i++ {
//			OutputTxos0[i] = &TXO{}
//			err = OutputTxos0[i].Deserialize(r)
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read TxWitness
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var TxWitness0 *CbTxWitness = nil
//	if count > 0 {
//		TxWitness0 = &CbTxWitness{}
//		err = TxWitness0.Deserialize(r)
//		if err != nil {
//			return err
//		}
//	}
//
//	coinbaseTx.Vin = Vin0
//	coinbaseTx.OutputTxos = OutputTxos0
//	coinbaseTx.TxWitness = TxWitness0
//	return nil
//}

//func (cbTxWitness *CbTxWitness) SerializeSize() uint32 {
//	if cbTxWitness == nil {
//		return 0
//	}
//	var res uint32 = 0
//
//	// b_hat
//	res += 1
//	res += GetPolyNTTVecSerializeSize(cbTxWitness.b_hat)
//
//	// c_hats
//	if cbTxWitness.c_hats == nil {
//		res += 1
//	} else {
//		count := len(cbTxWitness.c_hats)
//		res += VarIntSerializeSize(uint64(count))
//		res += uint32(count) * GetPolyNTTSerializeSize(cbTxWitness.c_hats[0])
//	}
//
//	// u_p
//	if cbTxWitness.u_p == nil {
//		res += 1
//	} else {
//		count := len(cbTxWitness.u_p)
//		res += VarIntSerializeSize(uint64(count))
//		res += 4 * uint32(count)
//	}
//
//	// rpulpproof
//	res += 1
//	res += GetRpulpProofSerializeSize(cbTxWitness.rpulpproof)
//
//	return res
//}

//func (cbTxWitness *CbTxWitness) Serialize() []byte {
//	w := new(bytes.Buffer)
//	err := cbTxWitness.Serialize0(w)
//	if err != nil {
//		return nil
//	}
//	return w.Bytes()
//}

//func (cbTxWitness *CbTxWitness) Serialize0(w io.Writer) error {
//	// write b_hat
//	if cbTxWitness.b_hat != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTTVec(w, cbTxWitness.b_hat)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write c_hats
//	if cbTxWitness.c_hats != nil {
//		count := len(cbTxWitness.c_hats)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			err := WritePolyNTT(w, cbTxWitness.c_hats[i])
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write u_p
//	if cbTxWitness.u_p != nil {
//		count := len(cbTxWitness.u_p)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			err := writeElement(w, cbTxWitness.u_p[i])
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write rpulpproof
//	if cbTxWitness.rpulpproof != nil {
//		WriteNotNULL(w)
//		err := SerializeRpulpProof(w, cbTxWitness.rpulpproof)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}

func (cbTxWitness *CbTxWitnessJ2) Serialize0(w io.Writer) error {
	// write b_hat
	if cbTxWitness.b_hat != nil {
		WriteNotNULL(w)
		err := WritePolyCNTTVec(w, cbTxWitness.b_hat)
		if err != nil {
			return err
		}
	} else {
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
			err := WritePolyCNTT(w, cbTxWitness.c_hats[i])
			if err != nil {
				return err
			}
		}
	} else {
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
	} else {
		WriteNULL(w)
	}

	// write rpulpproof
	if cbTxWitness.rpulpproof != nil {
		WriteNotNULL(w)
		err := WriteRpulpProofv2(w, cbTxWitness.rpulpproof)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	return nil
}
func (cbTxWitness *CbTxWitnessJ2) Deserialize(r io.Reader) error {
	// read b_hat
	count, err := ReadVarInt(r)
	if err != nil {
		return err
	}
	var b_hat0 *PolyCNTTVec = nil
	if count > 0 {
		b_hat0, err = ReadPolyCNTTVec(r)
		if err != nil {
			return err
		}
	}

	// read c_hats
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var c_hats0 []*PolyCNTT = nil
	if count > 0 {
		c_hats0 = make([]*PolyCNTT, count)
		for i := 0; i < int(count); i++ {
			c_hats0[i], err = ReadPolyCNTT(r)
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
	var u_p0 []int64 = nil
	if count > 0 {
		u_p0 = make([]int64, count)
		for i := 0; i < int(count); i++ {
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
	var rpulpproof0 *rpulpProofv2 = nil
	if count > 0 {
		rpulpproof0, err = ReadRpulpProofv2(r)
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

//func (cbTxWitness *CbTxWitness) Deserialize(r io.Reader) error {
//	// read b_hat
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var b_hat0 *PolyNTTVec = nil
//	if count > 0 {
//		b_hat0, err = ReadPolyNTTVec(r)
//		if err != nil {
//			return err
//		}
//	}
//
//	// read c_hats
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var c_hats0 []*PolyNTT = nil
//	if count > 0 {
//		c_hats0 = make([]*PolyNTT, count)
//		for i := 0; i < int(count); i++ {
//			c_hats0[i], err = ReadPolyNTT(r)
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read u_p
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var u_p0 []int32 = nil
//	if count > 0 {
//		u_p0 = make([]int32, count)
//		for i := 0; i < int(count); i++ {
//			err := readElement(r, &u_p0[i])
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read rpulpproof
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var rpulpproof0 *rpulpProof = nil
//	if count > 0 {
//		rpulpproof0, err = DeserializeRpulpProof(r)
//		if err != nil {
//			return err
//		}
//	}
//
//	cbTxWitness.b_hat = b_hat0
//	cbTxWitness.c_hats = c_hats0
//	cbTxWitness.u_p = u_p0
//	cbTxWitness.rpulpproof = rpulpproof0
//
//	return nil
//}

//func (trTx *TransferTx) Serialize(hasWitness bool) []byte {
//	w := new(bytes.Buffer)
//
//	// write inputs
//	if trTx.Inputs != nil {
//		count := len(trTx.Inputs)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return nil
//		}
//		for _, input := range trTx.Inputs {
//			err := input.Serialize0(w)
//			if err != nil {
//				return nil
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write outputs
//	if trTx.OutputTxos != nil {
//		count := len(trTx.OutputTxos)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return nil
//		}
//		for _, output := range trTx.OutputTxos {
//			err := output.Serialize0(w)
//			if err != nil {
//				return nil
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write txFee
//	err := writeElement(w, trTx.Fee)
//	if err != nil {
//		return nil
//	}
//
//	// write txMemo
//	if trTx.TxMemo != nil {
//		WriteNotNULL(w)
//		err := WriteVarBytes(w, trTx.TxMemo)
//		if err != nil {
//			return nil
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write txWitness
//	if hasWitness {
//		if trTx.TxWitness != nil {
//			WriteNotNULL(w)
//			err := trTx.TxWitness.Serialize0(w)
//			if err != nil {
//				return nil
//			}
//		} else {
//			WriteNULL(w)
//		}
//	}
//
//	return w.Bytes()
//}

//func (trTx *TransferTx) Deserialize(r io.Reader) error {
//	// read Inputs
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var Inputs0 []*TrTxInput = nil
//	if count > 0 {
//		Inputs0 = make([]*TrTxInput, count)
//		for i := 0; i < int(count); i++ {
//			Inputs0[i] = &TrTxInput{}
//			err = Inputs0[i].Deserialize(r)
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read OutputTxos
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var OutputTxos0 []*TXO = nil
//	if count > 0 {
//		OutputTxos0 = make([]*TXO, count)
//		for i := 0; i < int(count); i++ {
//			OutputTxos0[i] = &TXO{}
//			err = OutputTxos0[i].Deserialize(r)
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read Fee
//	var Fee0 uint64 = 0
//	err = readElement(r, &Fee0)
//	if err != nil {
//		return err
//	}
//
//	// read TxMemo
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var TxMemo0 []byte = nil
//	if count > 0 {
//		TxMemo0, err = ReadVarBytes(r, MAXALLOWED, "TransferTx.Deserialize")
//		if err != nil {
//			return err
//		}
//	}
//
//	// read TxWitness
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var TxWitness0 *TrTxWitness = nil
//	if count > 0 {
//		TxWitness0 = &TrTxWitness{}
//		err = TxWitness0.Deserialize(r)
//		if err != nil {
//			return err
//		}
//	}
//
//	trTx.Inputs = Inputs0
//	trTx.OutputTxos = OutputTxos0
//	trTx.Fee = Fee0
//	trTx.TxMemo = TxMemo0
//	trTx.TxWitness = TxWitness0
//
//	return nil
//}

//func (txo *TXO) SerializeSize() uint32 {
//	if txo == nil {
//		return 0
//	}
//	var res uint32 = 0
//
//	// dpk
//	res += 1
//	res += GetDerivedPubKeySerializeSize(txo.dpk)
//
//	// cmt
//	res += 1
//	res += GetCommitmentSerializeSize(txo.cmt)
//
//	// vc
//	res += 1
//	res += GetBytesSerializeSize(txo.vc)
//
//	return res
//}

//func (txo *TXO) Serialize() []byte {
//	w := new(bytes.Buffer)
//	err := txo.Serialize0(w)
//	if err != nil {
//		return nil
//	}
//
//	return w.Bytes()
//}

//func (txo *TXO) Serialize0(w io.Writer) error {
//	// write DerivedPubKey
//	if txo.dpk != nil {
//		WriteNotNULL(w)
//		err := WriteDerivedPubKey(w, txo.dpk)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write commitment
//	if txo.cmt != nil {
//		WriteNotNULL(w)
//		err := WriteCommitment(w, txo.cmt)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write vc
//	if txo.vc != nil {
//		WriteNotNULL(w)
//		err := WriteVarBytes(w, txo.vc)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}

func (txo *Txo) Serialize0(w io.Writer) error {
	// write DerivedPubKey
	if txo.AddressPublicKey != nil {
		WriteNotNULL(w)
		err := WritePublicKey(w, txo.AddressPublicKey)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write commitment
	if txo.ValueCommitment != nil {
		WriteNotNULL(w)
		err := WriteCommitmentv2(w, txo.ValueCommitment)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	//write vc
	if txo.Vct != nil {
		WriteNotNULL(w)
		err := WriteVarBytes(w, txo.Vct)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	//CkemSerialzed
	if txo.CkemSerialzed != nil {
		WriteNotNULL(w)
		err := WriteVarBytes(w, txo.CkemSerialzed)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	return nil
}
func (txo *Txo) Deserialize(r io.Reader) error {
	// read DerivedPubKey
	count, err := ReadVarInt(r)
	if err != nil {
		return err
	}
	var apk0 *AddressPublicKey
	if count > 0 {
		apk0, err = ReadPublicKey(r)
		if err != nil {
			return err
		}
	}

	// read commitment
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var cmt0 *ValueCommitment = nil
	if count > 0 {
		cmt0, err = ReadCommitmentv2(r)
		if err != nil {
			return err
		}
	}

	// read vc
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var vc0 []byte = nil
	if count > 0 {
		vc0, err = ReadVarBytes(r, MAXALLOWED, "txo.Deserialize")
		if err != nil {
			return err
		}
	}

	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var cs0 []byte = nil
	if count > 0 {
		cs0, err = ReadVarBytes(r, MAXALLOWED, "txo.Deserialize")
		if err != nil {
			return err
		}
	}

	txo.AddressPublicKey = apk0
	txo.ValueCommitment = cmt0
	txo.Vct = vc0
	txo.CkemSerialzed = cs0

	return nil
}

//func (txo *TXO) Deserialize(r io.Reader) error {
//	// read DerivedPubKey
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var dpk0 *DerivedPubKey = nil
//	if count > 0 {
//		dpk0, err = ReadDerivedPubKey(r)
//		if err != nil {
//			return err
//		}
//	}
//
//	// read commitment
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var cmt0 *Commitment = nil
//	if count > 0 {
//		cmt0, err = ReadCommitment(r)
//		if err != nil {
//			return err
//		}
//	}
//
//	// read vc
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var vc0 []byte = nil
//	if count > 0 {
//		vc0, err = ReadVarBytes(r, MAXALLOWED, "txo.Deserialize")
//		if err != nil {
//			return err
//		}
//	}
//
//	txo.dpk = dpk0
//	txo.cmt = cmt0
//	txo.vc = vc0
//	return nil
//}

//func (trTxInput *TrTxInput) Serialize() []byte {
//	w := new(bytes.Buffer)
//	err := trTxInput.Serialize0(w)
//	if err != nil {
//		return nil
//	}
//
//	return w.Bytes()
//}

//func (trTxInput *TrTxInput) Serialize0(w io.Writer) error {
//	// write txoList
//	if trTxInput.TxoList != nil {
//		count := len(trTxInput.TxoList)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for _, txo := range trTxInput.TxoList {
//			err := txo.Serialize0(w)
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write serialNumber
//	if trTxInput.SerialNumber != nil {
//		err := WriteVarBytes(w, trTxInput.SerialNumber)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}

//func (trTxWitness *TrTxWitness) SerializeSize() uint32 {
//	if trTxWitness == nil {
//		return 0
//	}
//	var res uint32 = 0
//
//	// b_hat
//	res += 1
//	res += GetPolyNTTVecSerializeSize(trTxWitness.b_hat)
//
//	// c_hats
//	if trTxWitness.c_hats == nil {
//		res += 1
//	} else {
//		count := len(trTxWitness.c_hats)
//		res += VarIntSerializeSize(uint64(count))
//		res += uint32(count) * GetPolyNTTSerializeSize(trTxWitness.c_hats[0])
//	}
//
//	// u_p
//	if trTxWitness.u_p == nil {
//		res += 1
//	} else {
//		count := len(trTxWitness.u_p)
//		res += VarIntSerializeSize(uint64(count))
//		res += 4 * uint32(count)
//	}
//
//	// rpulpproof
//	res += 1
//	res += GetRpulpProofSerializeSize(trTxWitness.rpulpproof)
//
//	// cmtps
//	if trTxWitness.cmtps == nil {
//		res += 1
//	} else {
//		count := len(trTxWitness.cmtps)
//		res += VarIntSerializeSize(uint64(count))
//		res += uint32(count) * GetCommitmentSerializeSize(trTxWitness.cmtps[0])
//	}
//
//	// elrsSigs
//	if trTxWitness.elrsSigs == nil {
//		res += 1
//	} else {
//		count := len(trTxWitness.elrsSigs)
//		res += VarIntSerializeSize(uint64(count))
//		res += uint32(count) * GetElrsSignatureSerializeSize(trTxWitness.elrsSigs[0])
//	}
//
//	return res
//}

//func (trTxInput *TrTxInput) Deserialize(r io.Reader) error {
//	// read TxoList
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var txoList0 []*TXO = nil
//	if count > 0 {
//		txoList0 = make([]*TXO, count)
//		for i := 0; i < int(count); i++ {
//			txoList0[i] = &TXO{}
//			err := txoList0[i].Deserialize(r)
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read SerialNumber
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var serialNumber0 []byte = nil
//	if count > 0 {
//		serialNumber0, err = ReadVarBytes(r, MAXALLOWED, "trTxInput.Deserialize")
//		if err != nil {
//			return err
//		}
//	}
//
//	trTxInput.TxoList = txoList0
//	trTxInput.SerialNumber = serialNumber0
//	return nil
//}

//func (trTxWitness *TrTxWitness) Serialize() []byte {
//	w := new(bytes.Buffer)
//	err := trTxWitness.Serialize0(w)
//	if err != nil {
//		return nil
//	}
//
//	return w.Bytes()
//}

//func (trTxWitness *TrTxWitness) Serialize0(w io.Writer) error {
//	// write b_hat
//	if trTxWitness.b_hat != nil {
//		WriteNotNULL(w)
//		err := WritePolyNTTVec(w, trTxWitness.b_hat)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write c_hats
//	if trTxWitness.c_hats != nil {
//		count := len(trTxWitness.c_hats)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			err = WritePolyNTT(w, trTxWitness.c_hats[i])
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write u_p
//	if trTxWitness.u_p != nil {
//		count := len(trTxWitness.u_p)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			err := writeElement(w, trTxWitness.u_p[i])
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write rpulpproof
//	if trTxWitness.rpulpproof != nil {
//		WriteNotNULL(w)
//		err := SerializeRpulpProof(w, trTxWitness.rpulpproof)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write cmtps
//	if trTxWitness.cmtps != nil {
//		count := len(trTxWitness.cmtps)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			err = WriteCommitment(w, trTxWitness.cmtps[i])
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	// write elrsSigs
//	if trTxWitness.elrsSigs != nil {
//		count := len(trTxWitness.elrsSigs)
//		err := WriteVarInt(w, uint64(count))
//		if err != nil {
//			return err
//		}
//		for i := 0; i < count; i++ {
//			err = SerializeElrsSignature(w, trTxWitness.elrsSigs[i])
//			if err != nil {
//				return err
//			}
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}

func (trTxWitness *TrTxWitnessv2) Serialize0(w io.Writer) error {
	// write ma_ps
	if trTxWitness.ma_ps != nil {
		count := len(trTxWitness.ma_ps)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err = WritePolyANTT(w, trTxWitness.ma_ps[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	// write cmtps
	if trTxWitness.cmt_ps != nil {
		count := len(trTxWitness.cmt_ps)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err = WriteCommitmentv2(w, trTxWitness.cmt_ps[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	// write elrsSigs
	if trTxWitness.elrsSigs != nil {
		count := len(trTxWitness.elrsSigs)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err = WriteElrsSignaturev2(w, trTxWitness.elrsSigs[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	// write b_hat
	if trTxWitness.b_hat != nil {
		WriteNotNULL(w)
		err := WritePolyCNTTVec(w, trTxWitness.b_hat)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write c_hats
	if trTxWitness.c_hats != nil {
		count := len(trTxWitness.c_hats)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err = WritePolyCNTT(w, trTxWitness.c_hats[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	// write u_p
	if trTxWitness.u_p != nil {
		count := len(trTxWitness.u_p)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			err := writeElement(w, trTxWitness.u_p[i])
			if err != nil {
				return err
			}
		}
	} else {
		WriteNULL(w)
	}

	// write rpulpproof
	if trTxWitness.rpulpproof != nil {
		WriteNotNULL(w)
		err := WriteRpulpProofv2(w, trTxWitness.rpulpproof)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	return nil
}

func (trTxWitness *TrTxWitnessv2) Deserialize(r io.Reader) error {
	count, err := ReadVarInt(r)
	if err != nil {
		return err
	}
	var ma_ps0 []*PolyANTT
	if count > 0 {
		ma_ps0 = make([]*PolyANTT, count)
		for i := 0; i < int(count); i++ {
			ma_ps0[i], err = ReadPolyANTT(r)
			if err != nil {
				return err
			}
		}
	}

	// read cmtps
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var cmtps0 []*ValueCommitment = nil
	if count > 0 {
		cmtps0 = make([]*ValueCommitment, count)
		for i := 0; i < int(count); i++ {
			cmtps0[i], err = ReadCommitmentv2(r)
			if err != nil {
				return err
			}
		}
	}

	// read elrsSigs
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var elrsSigs0 []*elrsSignaturev2 = nil
	if count > 0 {
		elrsSigs0 = make([]*elrsSignaturev2, count)
		for i := 0; i < int(count); i++ {
			elrsSigs0[i], err = ReadElrsSignaturev2(r)
			if err != nil {
				return err
			}
		}
	}

	// read b_hat
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var b_hat0 *PolyCNTTVec = nil
	if count > 0 {
		b_hat0, err = ReadPolyCNTTVec(r)
		if err != nil {
			return err
		}
	}

	// read c_hats
	count, err = ReadVarInt(r)
	if err != nil {
		return err
	}
	var c_hats0 []*PolyCNTT = nil
	if count > 0 {
		c_hats0 = make([]*PolyCNTT, count)
		for i := 0; i < int(count); i++ {
			c_hats0[i], err = ReadPolyCNTT(r)
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
	var u_p0 []int64 = nil
	if count > 0 {
		u_p0 = make([]int64, count)
		for i := 0; i < int(count); i++ {
			err = readElement(r, &u_p0[i])
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
	var rpulpproof0 *rpulpProofv2 = nil
	if count > 0 {
		rpulpproof0, err = ReadRpulpProofv2(r)
		if err != nil {
			return err
		}
	}

	trTxWitness.b_hat = b_hat0
	trTxWitness.c_hats = c_hats0
	trTxWitness.u_p = u_p0
	trTxWitness.rpulpproof = rpulpproof0
	trTxWitness.cmt_ps = cmtps0
	trTxWitness.elrsSigs = elrsSigs0

	return nil
}

//func (trTxWitness *TrTxWitness) Deserialize(r io.Reader) error {
//	// read b_hat
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var b_hat0 *PolyNTTVec = nil
//	if count > 0 {
//		b_hat0, err = ReadPolyNTTVec(r)
//		if err != nil {
//			return err
//		}
//	}
//
//	// read c_hats
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var c_hats0 []*PolyNTT = nil
//	if count > 0 {
//		c_hats0 = make([]*PolyNTT, count)
//		for i := 0; i < int(count); i++ {
//			c_hats0[i], err = ReadPolyNTT(r)
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read u_p
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var u_p0 []int32 = nil
//	if count > 0 {
//		u_p0 = make([]int32, count)
//		for i := 0; i < int(count); i++ {
//			err = readElement(r, &u_p0[i])
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read rpulpproof
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var rpulpproof0 *rpulpProof = nil
//	if count > 0 {
//		rpulpproof0, err = DeserializeRpulpProof(r)
//		if err != nil {
//			return err
//		}
//	}
//
//	// read cmtps
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var cmtps0 []*Commitment = nil
//	if count > 0 {
//		cmtps0 = make([]*Commitment, count)
//		for i := 0; i < int(count); i++ {
//			cmtps0[i], err = ReadCommitment(r)
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// read elrsSigs
//	count, err = ReadVarInt(r)
//	if err != nil {
//		return err
//	}
//	var elrsSigs0 []*elrsSignature = nil
//	if count > 0 {
//		elrsSigs0 = make([]*elrsSignature, count)
//		for i := 0; i < int(count); i++ {
//			elrsSigs0[i], err = DeserializeElrsSignature(r)
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	trTxWitness.b_hat = b_hat0
//	trTxWitness.c_hats = c_hats0
//	trTxWitness.u_p = u_p0
//	trTxWitness.rpulpproof = rpulpproof0
//	trTxWitness.cmtps = cmtps0
//	trTxWitness.elrsSigs = elrsSigs0
//
//	return nil
//}

func (txo *LgrTxo) Serialize(w io.Writer) error {
	// write PubKey
	if txo.AddressPublicKey != nil {
		WriteNotNULL(w)
		err := WritePublicKey(w, txo.AddressPublicKey)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write commitment
	if txo.ValueCommitment != nil {
		WriteNotNULL(w)
		err := WriteCommitmentv2(w, txo.ValueCommitment)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	// write vc
	err := writeElement(w, txo.Id)
	if err != nil {
		return err
	}
	//if txo.vc != nil {
	//	WriteNotNULL(w)
	//	err := WriteVarBytes(w, txo.vc)
	//	if err != nil {
	//		return err
	//	}
	//} else {
	//	WriteNULL(w)
	//}

	return nil
}
func (trTxInput *TrTxInputv2) Serialize0(w io.Writer) error {
	// write txoList
	if trTxInput.TxoList != nil {
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
	} else {
		WriteNULL(w)
	}

	// write serialNumber
	if trTxInput.SerialNumber != nil {
		err := writeElement(w, trTxInput.SerialNumber)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	return nil
}
func (trTx *TransferTxv2) Serialize(hasWitness bool) []byte {
	w := new(bytes.Buffer)

	// write inputs
	if trTx.Inputs != nil {
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
	} else {
		WriteNULL(w)
	}

	// write outputs
	if trTx.OutputTxos != nil {
		count := len(trTx.OutputTxos)
		err := WriteVarInt(w, uint64(count))
		if err != nil {
			return nil
		}
		for _, output := range trTx.OutputTxos {
			err := output.Serialize0(w)
			if err != nil {
				return nil
			}
		}
	} else {
		WriteNULL(w)
	}

	// write txFee
	err := writeElement(w, trTx.Fee)
	if err != nil {
		return nil
	}

	// write txMemo
	if trTx.TxMemo != nil {
		WriteNotNULL(w)
		err := WriteVarBytes(w, trTx.TxMemo)
		if err != nil {
			return nil
		}
	} else {
		WriteNULL(w)
	}

	// write txWitness
	if hasWitness {
		if trTx.TxWitness != nil {
			WriteNotNULL(w)
			err := trTx.TxWitness.Serialize0(w)
			if err != nil {
				return nil
			}
		} else {
			WriteNULL(w)
		}
	}

	return w.Bytes()
}
