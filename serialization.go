package pqringct

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringct/pqringctkem"
	"io"
)

const (
	ErrInvalidLength = "invalid length"
	ErrNilPointer    = "there are nil pointer"
)

func (pp *PublicParameter) IntegerASerializeSize() int {
	// todo: 37-bit int64 could be serialized to 5 bytes, that is pp.paramDA * 5
	// todo: 37-bit int64 could be precise serialized to 37-bit bytes, that is (pp.paramDA * 37 + 7) / 8
	return 5
}

func (pp *PublicParameter) writeIntegerA(w io.Writer, a int64) error {
	// a shall be in [-(q_a-1)/2, (q_a-1)/2]
	//	hardcode as q_a is 38-bit integer
	//	5 bytes, the highest bit used for +-sign
	tmp := make([]byte, 5)
	// the element in coeffs is an value with 37-bit but as int64
	// so it could be serialized to 5 bytes
	tmp[0] = byte(a >> 0)
	tmp[1] = byte(a >> 8)
	tmp[2] = byte(a >> 16)
	tmp[3] = byte(a >> 24)
	tmp[4] = byte(a >> 32)
	return writeElement(w, tmp)
}
func (pp *PublicParameter) readIntegerA(r io.Reader) (int64, error) {
	// a shall be in [-(q_a-1)/2, (q_a-1)/2]
	//	hardcode as q_a is 38-bit integer
	//	5 bytes, the highest bit used for +-sign
	//	pp.paramDA
	var res int64
	tmp := make([]byte, 5)
	_, err := r.Read(tmp)
	if err != nil {
		return -1, err
	}
	res = int64(tmp[0]) >> 0
	res |= int64(tmp[1]) << 8
	res |= int64(tmp[2]) << 16
	res |= int64(tmp[3]) << 24
	res |= int64(tmp[4]) << 32
	if tmp[4]>>7 == 1 {
		res = int64(uint64(res) | 0xFFFFFF0000000000)
	}
	return res, nil
}

func (pp *PublicParameter) PolyANTTSerializeSize() int {
	// todo: 37-bit int64 could be serialized to 5 bytes, that is pp.paramDA * 5
	return pp.paramDA * pp.IntegerASerializeSize()
}
func (pp *PublicParameter) writePolyANTT(w io.Writer, a *PolyANTT) error {
	var err error

	for i := 0; i < pp.paramDA; i++ {
		err = pp.writeIntegerA(w, a.coeffs[i])
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyANTT(r io.Reader) (*PolyANTT, error) {
	var err error
	res := pp.NewPolyANTT()
	for i := 0; i < pp.paramDA; i++ {
		res.coeffs[i], err = pp.readIntegerA(r)
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

func (pp *PublicParameter) IntegerCSerializeSize() int {
	//	todo: 53-bit int64 could be serialized to 7 bytes, that is pp.paramDA * 7
	return 7
}
func (pp *PublicParameter) writeIntegerC(w io.Writer, c int64) error {
	// a shall be in [-(q_c-1)/2, (q_c-1)/2]
	//	hardcode as q_c is 53-bit integer
	//	7 bytes, the highest bit used for +-sign
	tmp := make([]byte, 7)
	// the element in coeffs is an value with 53-bit but as int64
	// so it could be serialized to 7 bytes
	tmp[0] = byte(c >> 0)
	tmp[1] = byte(c >> 8)
	tmp[2] = byte(c >> 16)
	tmp[3] = byte(c >> 24)
	tmp[4] = byte(c >> 32)
	tmp[5] = byte(c >> 40)
	tmp[6] = byte(c >> 48)
	return writeElement(w, tmp)
}
func (pp *PublicParameter) readIntegerC(r io.Reader) (int64, error) {
	// a shall be in [-(q_c-1)/2, (q_c-1)/2]
	//	hardcode as q_c is 53-bit integer
	//	7 bytes, the highest bit used for +-sign
	var res int64
	tmp := make([]byte, 7)
	_, err := r.Read(tmp)
	if err != nil {
		return -1, err
	}
	res = int64(tmp[0]) >> 0
	res |= int64(tmp[1]) << 8
	res |= int64(tmp[2]) << 16
	res |= int64(tmp[3]) << 24
	res |= int64(tmp[4]) << 32
	res |= int64(tmp[5]) << 40
	res |= int64(tmp[6]) << 48
	if tmp[6]>>7 == 1 {
		res = int64(uint64(res) | 0xFFF0000000000000)
	}
	return res, nil
}

func (pp *PublicParameter) PolyCNTTSerializeSize() int {
	return pp.paramDC * pp.IntegerCSerializeSize()
}
func (pp *PublicParameter) writePolyCNTT(w io.Writer, c *PolyCNTT) error {
	var err error
	/*	err = WriteVarInt(w, uint64(pp.paramDC))
		if err != nil {
			return err
		}*/
	for i := 0; i < pp.paramDC; i++ {
		//err = writeElement(w, c.coeffs[i])
		err = pp.writeIntegerC(w, c.coeffs[i])
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
		//err = readElement(r, &res.coeffs[i])
		res.coeffs[i], err = pp.readIntegerC(r)
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

func (pp *PublicParameter) TxoValueBytesLen() int {
	//	N = 51, v \in [0, 2^{51}-1]
	return 7
}
func (pp *PublicParameter) encodeTxoValueToBytes(value uint64) ([]byte, error) {
	//	N = 51, v \in [0, 2^{51}-1]
	if value < 0 || value > (1<<51)-1 {
		return nil, errors.New("value is not in the scope [0, 2^N-1] for N= 51")
	}

	res := make([]byte, 7)
	for i := 0; i < 7; i++ {
		res[0] = byte(value >> 0)
		res[1] = byte(value >> 8)
		res[2] = byte(value >> 16)
		res[3] = byte(value >> 24)
		res[4] = byte(value >> 32)
		res[5] = byte(value >> 40)
		res[6] = byte(value >> 48)
	}
	return res, nil
}

func (pp *PublicParameter) decodeTxoValueFromBytes(serializedValue []byte) (uint64, error) {
	//	N = 51, v \in [0, 2^{51}-1]
	if len(serializedValue) != 7 {
		return 0, errors.New("serializedValue's length is not 7")
	}
	var res uint64
	res = uint64(serializedValue[0]) << 0
	res |= uint64(serializedValue[1]) << 8
	res |= uint64(serializedValue[2]) << 16
	res |= uint64(serializedValue[3]) << 24
	res |= uint64(serializedValue[4]) << 32
	res |= uint64(serializedValue[5]) << 40
	res |= uint64(serializedValue[6]&0x07) << 48

	return res, nil
}

func (pp *PublicParameter) TxoSerializeSize() int {
	return pp.AddressPublicKeySerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		VarIntSerializeSize2(uint64(pp.TxoValueBytesLen())) + pp.TxoValueBytesLen() +
		VarIntSerializeSize2(uint64(pqringctkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctkem.GetKemCiphertextBytesLen(pp.paramKem)
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

	//tmp := make([]byte, (pp.paramN+7)/8)
	//for i := 0; i < pp.paramN; i += 8 {
	//	for j := 0; j < 8; j++ {
	//		if i+j < pp.paramN {
	//			tmp[i/8] |= (txo.Vct[i+j] & 1) << j
	//		}
	//	}
	//}
	err = writeVarBytes(w, txo.Vct)
	if err != nil {
		return nil, err
	}

	err = writeVarBytes(w, txo.CkemSerialzed)
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

	//tmp, err = readVarBytes(r, MAXALLOWED, "txo.Vct")
	//if err != nil {
	//	return nil, err
	//}
	//vct := make([]byte, pp.paramN)
	//for i := 0; i < len(tmp); i++ {
	//	for j := 0; j < 8; j++ {
	//		if 8*i+j < pp.paramN {
	//			vct[8*i+j] = (tmp[i] & (1 << j)) >> j
	//		}
	//	}
	//}
	vct, err := readVarBytes(r, MAXALLOWED, "txo.Vct")
	if err != nil {
		return nil, err
	}

	ckem, err := readVarBytes(r, MAXALLOWED, "txo.CkemSerialzed")
	if err != nil {
		return nil, err
	}

	return &Txo{apk, cmt, vct, ckem}, nil
}

func (pp *PublicParameter) LgrTxoIdSerializeSize() int {
	return HashBytesLen
}

func (pp *PublicParameter) LgrTxoSerializeSize() int {
	return pp.TxoSerializeSize() +
		VarIntSerializeSize2(uint64(pp.LgrTxoIdSerializeSize())) + pp.LgrTxoIdSerializeSize()
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

	err = writeVarBytes(w, lgrTxo.Id)
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

	id, err := readVarBytes(r, MAXALLOWED, "LgrTxo.Id")
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
	err = writeVarBytes(w, prf.chseed)
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
	chseed, err := readVarBytes(r, MAXALLOWED, "rpulpProof.chseed")
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

func (pp *PublicParameter) challengeSeedCSerializeSizeApprox() int {
	return 1 + HashBytesLen
}
func (pp *PublicParameter) responseCSerializeSizeApprox() int {
	//	r \in \in (Ring_{q_c})^{L_c}
	//	z \in (Ring_{q_c})^{L_c}
	//	k
	return 1 + pp.paramK*(1+pp.PolyCNTTSerializeSize()*pp.paramLC)
}

func (pp *PublicParameter) CbTxWitnessJ1SerializeSizeApprox() int {
	var lenApprox int

	//	chseed []byte
	lenApprox = pp.challengeSeedCSerializeSizeApprox()

	//	zs []*PolyCNTTVec
	//	r \in \in (Ring_{q_c})^{L_c}
	//	z \in (Ring_{q_c})^{L_c}
	//	k
	lenApprox += pp.challengeSeedCSerializeSizeApprox()

	return lenApprox
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
	err = writeVarBytes(w, witness.chseed)
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
	chseed, err := readVarBytes(r, MAXALLOWED, "CbTxWitnessJ1.chseed")
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

func (pp *PublicParameter) boundingVecCSerializeSizeApprox() int {
	//	PolyCNTTVec[k_c]
	return 1 + pp.paramKC*pp.PolyCNTTSerializeSize()
}

func (pp *PublicParameter) CbTxWitnessJ2SerializeSizeApprox(outTxoNum int) int {
	var lenApprox int

	//	b_hat
	//	PolyCNTTVec[k_c]
	lenApprox = pp.boundingVecCSerializeSizeApprox()

	//	c_hats
	lenApprox += 1 + (outTxoNum+2)*pp.PolyCNTTSerializeSize()

	// u_p
	lenApprox += 1 + pp.paramDC*8

	// rpulpproof
	// c_waves []*PolyCNTT
	lenApprox += 1 + outTxoNum*pp.PolyCNTTSerializeSize()
	// c_hat_g,psi,phi  *PolyCNTT
	lenApprox += 3 * pp.PolyCNTTSerializeSize()
	// chseed  []byte
	lenApprox += pp.challengeSeedCSerializeSizeApprox()
	//cmt_zs  [][]*PolyCNTTVec
	lenApprox += 1 + (outTxoNum)*pp.responseCSerializeSizeApprox()
	//zs      []*PolyCNTTVec
	lenApprox += pp.responseCSerializeSizeApprox()

	return lenApprox
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
		err = writeVarBytes(w, tmp)
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

func (pp *PublicParameter) CoinbaseTxSerializeSize(tx *CoinbaseTxv2, withWitness bool) int {
	var length int

	// Vin uint64
	length = 8

	//OutputTxos []*Txo
	length += VarIntSerializeSize2(uint64(len(tx.OutputTxos))) + len(tx.OutputTxos)*pp.TxoSerializeSize()

	//TxMemo []byte
	length += VarIntSerializeSize2(uint64(len(tx.TxMemo))) + len(tx.TxMemo)

	// TxWitness
	if withWitness {
		if len(tx.OutputTxos) == 1 {
			witnessLen := pp.CbTxWitnessJ1SerializeSize(tx.TxWitnessJ1)
			length += VarIntSerializeSize2(uint64(witnessLen)) + witnessLen
		} else { // >= 2
			witnessLen := pp.CbTxWitnessJ2SerializeSize(tx.TxWitnessJ2)
			length += VarIntSerializeSize2(uint64(witnessLen)) + witnessLen
		}
	}
	return length
}

func (pp *PublicParameter) SerializeCoinbaseTx(tx *CoinbaseTxv2, withWitness bool) ([]byte, error) {
	if tx == nil || tx.OutputTxos == nil {
		return nil, errors.New(ErrNilPointer)
	}
	var err error
	length := pp.CoinbaseTxSerializeSize(tx, withWitness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// Vin     uint64
	binarySerializer.PutUint64(w, binary.LittleEndian, tx.Vin)

	//OutputTxos []*Txo
	err = WriteVarInt(w, uint64(len(tx.OutputTxos)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(tx.OutputTxos); i++ {
		serializedTxo, err := pp.SerializeTxo(tx.OutputTxos[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//TxMemo []byte
	err = writeVarBytes(w, tx.TxMemo)
	if err != nil {
		return nil, err
	}

	if withWitness {
		var serializedTxWitness []byte
		var err error
		if len(tx.OutputTxos) == 1 { // TxWitnessJ1
			serializedTxWitness, err = pp.SerializeCbTxWitnessJ1(tx.TxWitnessJ1)
		} else { // TxWitnessJ2
			serializedTxWitness, err = pp.SerializeCbTxWitnessJ2(tx.TxWitnessJ2)
		}
		if err != nil {
			return nil, err
		}

		txWitnessSize := len(serializedTxWitness)
		err = WriteVarInt(w, uint64(txWitnessSize))
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedTxWitness)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

func (pp *PublicParameter) DeserializeCoinbaseTx(serializedCbTx []byte, withWitness bool) (*CoinbaseTxv2, error) {
	r := bytes.NewReader(serializedCbTx)

	// Vin uint64
	vin, err := binarySerializer.Uint64(r, binary.LittleEndian)

	// OutputTxos []*Txo
	var OutputTxos []*Txo
	outTxoNum, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if outTxoNum != 0 {
		OutputTxos = make([]*Txo, outTxoNum)
		for i := uint64(0); i < outTxoNum; i++ {
			tmp := make([]byte, pp.TxoSerializeSize())
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

	// TxMemo []byte
	var TxMemo []byte
	TxMemo, err = readVarBytes(r, MaxAllowedTxMemoSize, "trTx.TxMemo")
	if err != nil {
		return nil, err
	}

	var txWitnessJ1 *CbTxWitnessJ1
	var txWitnessJ2 *CbTxWitnessJ2
	if withWitness {
		txWitnessSize, err := ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		serializedTrTxWitness := make([]byte, txWitnessSize)
		_, err = r.Read(serializedTrTxWitness)
		if err != nil {
			return nil, err
		}

		if outTxoNum == 1 { // J=1
			txWitnessJ1, err = pp.DeserializeCbTxWitnessJ1(serializedTrTxWitness)
			if err != nil {
				return nil, err
			}
			txWitnessJ2 = nil
		} else { // J >= 2
			txWitnessJ1 = nil
			txWitnessJ2, err = pp.DeserializeCbTxWitnessJ2(serializedTrTxWitness)
			if err != nil {
				return nil, err
			}
		}
	}

	return &CoinbaseTxv2{
		Vin:         vin,
		OutputTxos:  OutputTxos,
		TxMemo:      TxMemo,
		TxWitnessJ1: txWitnessJ1,
		TxWitnessJ2: txWitnessJ2,
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
		err = writeVarBytes(w, sig.seeds[i])
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
			seeds[i], err = readVarBytes(r, MAXALLOWED, "cbTxWitness.seeds")
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

func (pp *PublicParameter) TrTxWitnessSerializeSize(witness *TrTxWitnessv2) int {
	if witness == nil {
		return 0
	}

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
	length := pp.TrTxWitnessSerializeSize(witness)
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
		err = writeVarBytes(w, tmp)
		if err != nil {
			return nil, err
		}
	}

	// rpulpproof *rpulpProofv2
	serializedRpuProof, err := pp.SerializeRpulpProof(witness.rpulpproof)
	if err != nil {
		return nil, err
	}
	err = WriteVarInt(w, uint64(len(serializedRpuProof)))
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedRpuProof)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
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
	rpulpproofSize, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if rpulpproofSize != 0 {
		serializedRpulpProof := make([]byte, rpulpproofSize)
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

func (pp *PublicParameter) TrTxInputSerializeSize(trTxIn *TrTxInputv2) int {
	var length int
	//	TxoList      []*LgrTxo
	length = VarIntSerializeSize2(uint64(len(trTxIn.TxoList))) + len(trTxIn.TxoList)*pp.LgrTxoSerializeSize()

	//	SerialNumber []byte
	length += VarIntSerializeSize2(uint64(len(trTxIn.SerialNumber))) + len(trTxIn.SerialNumber)

	return length
}
func (pp *PublicParameter) TrTxInputSerialize(trTxIn *TrTxInputv2) ([]byte, error) {
	if trTxIn == nil || trTxIn.TxoList == nil {
		return nil, errors.New(ErrNilPointer)
	}

	if len(trTxIn.SerialNumber) == 0 {
		return nil, errors.New("nil serialNumber in TrTxInput")
	}

	var err error
	length := pp.TrTxInputSerializeSize(trTxIn)
	w := bytes.NewBuffer(make([]byte, 0, length))

	//TxoList      []*LgrTxo
	err = WriteVarInt(w, uint64(len(trTxIn.TxoList)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(trTxIn.TxoList); i++ {
		serializedTxo, err := pp.SerializeLgrTxo(trTxIn.TxoList[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//SerialNumber []byte
	err = writeVarBytes(w, trTxIn.SerialNumber)
	if err != nil {
		return nil, err
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
			tmp := make([]byte, pp.LgrTxoSerializeSize())
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
	SerialNumber, err = readVarBytes(r, MaxAllowedSerialNumberSize, "trTxInput.SerialNumber")
	if err != nil {
		return nil, err
	}

	return &TrTxInputv2{
		TxoList:      TxoList,
		SerialNumber: SerialNumber,
	}, nil
}

func (pp *PublicParameter) TransferTxSerializeSize(tx *TransferTxv2, withWitness bool) int {
	var length int

	//Inputs     []*TrTxInputv2
	length = VarIntSerializeSize2(uint64(len(tx.Inputs)))
	for i := 0; i < len(tx.Inputs); i++ {
		txInLen := pp.TrTxInputSerializeSize(tx.Inputs[i])
		length += VarIntSerializeSize2(uint64(txInLen)) + txInLen
	}

	//OutputTxos []*Txo
	length += VarIntSerializeSize2(uint64(len(tx.OutputTxos))) + len(tx.OutputTxos)*pp.TxoSerializeSize()

	//Fee        uint64
	length += 8

	//TxMemo []byte
	length += VarIntSerializeSize2(uint64(len(tx.TxMemo))) + len(tx.TxMemo)

	// TxWitness
	if withWitness {
		//TxWitness *TrTxWitnessv2
		witnessLen := pp.TrTxWitnessSerializeSize(tx.TxWitness)
		length += VarIntSerializeSize2(uint64(witnessLen)) + witnessLen
	}
	return length
}

func (pp *PublicParameter) SerializeTransferTx(tx *TransferTxv2, withWitness bool) ([]byte, error) {
	if tx == nil || tx.Inputs == nil || tx.OutputTxos == nil {
		return nil, errors.New(ErrNilPointer)
	}
	var err error
	length := pp.TransferTxSerializeSize(tx, withWitness)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// Inputs     []*TrTxInputv2
	err = WriteVarInt(w, uint64(len(tx.Inputs)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(tx.Inputs); i++ {
		serializedTxo, err := pp.TrTxInputSerialize(tx.Inputs[i])
		if err != nil {
			return nil, err
		}
		err = WriteVarInt(w, uint64(len(serializedTxo)))
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//OutputTxos []*Txo
	err = WriteVarInt(w, uint64(len(tx.OutputTxos)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(tx.OutputTxos); i++ {
		serializedTxo, err := pp.SerializeTxo(tx.OutputTxos[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//Fee        uint64
	//tmp := make([]byte, 8)
	//tmp[0] = byte(tx.Fee >> 0)
	//tmp[1] = byte(tx.Fee >> 8)
	//tmp[2] = byte(tx.Fee >> 16)
	//tmp[3] = byte(tx.Fee >> 24)
	//tmp[4] = byte(tx.Fee >> 32)
	//tmp[5] = byte(tx.Fee >> 40)
	//tmp[6] = byte(tx.Fee >> 48)
	//tmp[7] = byte(tx.Fee >> 56)
	//_, err = w.Write(tmp)
	err = binarySerializer.PutUint64(w, binary.LittleEndian, tx.Fee)
	if err != nil {
		return nil, err
	}

	//TxMemo []byte
	err = writeVarBytes(w, tx.TxMemo)
	if err != nil {
		return nil, err
	}

	//TxWitness *TrTxWitnessv2
	if withWitness {
		serializedWitness, err := pp.SerializeTrTxWitness(tx.TxWitness)
		if err != nil {
			return nil, err
		}

		err = WriteVarInt(w, uint64(len(serializedWitness)))
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedWitness)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeTransferTx(serializedTrTx []byte, withWitness bool) (*TransferTxv2, error) {
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
			tmp := make([]byte, pp.TxoSerializeSize())
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
	//tmp := make([]byte, 8)
	//_, err = r.Read(tmp)
	//if err != nil {
	//	return nil, err
	//}
	//Fee := uint64(tmp[0]) << 0
	//Fee |= uint64(tmp[1]) << 8
	//Fee |= uint64(tmp[2]) << 16
	//Fee |= uint64(tmp[3]) << 24
	//Fee |= uint64(tmp[4]) << 32
	//Fee |= uint64(tmp[5]) << 40
	//Fee |= uint64(tmp[6]) << 48
	//Fee |= uint64(tmp[7]) << 56

	Fee, err := binarySerializer.Uint64(r, binary.LittleEndian)
	if err != nil {
		return nil, err
	}

	// TxMemo []byte
	var TxMemo []byte
	TxMemo, err = readVarBytes(r, MaxAllowedTxMemoSize, "trTx.TxMemo")
	if err != nil {
		return nil, err
	}

	var TxWitness *TrTxWitnessv2
	if withWitness {
		// TxWitness *TrTxWitnessv2
		serializedSize, err := ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		if serializedSize != 0 {
			serializedTrTxWitness := make([]byte, serializedSize)
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
	MAXALLOWED                 uint32 = 4294967295 // 2^32-1
	MaxAllowedTxMemoSize              = 1024       // bytes
	MaxAllowedSerialNumberSize        = 64         // 512 bits = 64 bytes
	//	todo: 202203 different fields use different MaxAllowed? e.g. MaxAllowed
)

// writeVarBytes write byte array to io.Writer
func writeVarBytes(w io.Writer, b []byte) error {
	count := len(b)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	if count > 0 {
		_, err = w.Write(b)
		if err != nil {
			return err
		}
	}
	return nil
}

// readVarBytes read certain number of byte from io.Reader
// the length of the byte array is decided by the initial several byte
func readVarBytes(r io.Reader, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	if count == 0 {
		return nil, nil
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
