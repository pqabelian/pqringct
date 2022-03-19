package pqringct

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

func (pp *PublicParameter) SerializePolyCNTT(a *PolyCNTT) []byte {
	tmp := make([]byte, 0, pp.paramDC*8)
	w := bytes.NewBuffer(tmp)
	for k := 0; k < pp.paramDC; k++ {
		w.WriteByte(byte(a.coeffs[k] >> 0))
		w.WriteByte(byte(a.coeffs[k] >> 8))
		w.WriteByte(byte(a.coeffs[k] >> 16))
		w.WriteByte(byte(a.coeffs[k] >> 24))
		w.WriteByte(byte(a.coeffs[k] >> 32))
		w.WriteByte(byte(a.coeffs[k] >> 40))
		w.WriteByte(byte(a.coeffs[k] >> 48))
		w.WriteByte(byte(a.coeffs[k] >> 56))
	}
	return tmp
}
func (pp *PublicParameter) SerializePolyCNTTVec(a *PolyCNTTVec) []byte {
	tmp := make([]byte, 0, 4+len(a.polyCNTTs)*pp.paramDC*8)
	w := bytes.NewBuffer(tmp)
	length := int32(len(a.polyCNTTs))
	tmp = append(tmp, byte(length>>0))
	tmp = append(tmp, byte(length>>8))
	tmp = append(tmp, byte(length>>16))
	tmp = append(tmp, byte(length>>24))
	for i := 0; i < len(a.polyCNTTs); i++ {
		for j := 0; j < pp.paramDC; j++ {
			w.WriteByte(byte(a.polyCNTTs[i].coeffs[j] >> 0))
			w.WriteByte(byte(a.polyCNTTs[i].coeffs[j] >> 8))
			w.WriteByte(byte(a.polyCNTTs[i].coeffs[j] >> 16))
			w.WriteByte(byte(a.polyCNTTs[i].coeffs[j] >> 24))
			w.WriteByte(byte(a.polyCNTTs[i].coeffs[j] >> 32))
			w.WriteByte(byte(a.polyCNTTs[i].coeffs[j] >> 40))
			w.WriteByte(byte(a.polyCNTTs[i].coeffs[j] >> 48))
			w.WriteByte(byte(a.polyCNTTs[i].coeffs[j] >> 56))
		}
	}
	return tmp
}
func (pp *PublicParameter) SerializePolyANTT(a *PolyANTT) []byte {
	tmp := make([]byte, 0, pp.paramDA*8)
	w := bytes.NewBuffer(tmp)
	for k := 0; k < pp.paramDA; k++ {
		w.WriteByte(byte(a.coeffs[k] >> 0))
		w.WriteByte(byte(a.coeffs[k] >> 8))
		w.WriteByte(byte(a.coeffs[k] >> 16))
		w.WriteByte(byte(a.coeffs[k] >> 24))
		w.WriteByte(byte(a.coeffs[k] >> 32))
		w.WriteByte(byte(a.coeffs[k] >> 40))
		w.WriteByte(byte(a.coeffs[k] >> 48))
		w.WriteByte(byte(a.coeffs[k] >> 56))
	}
	return tmp
}
func (pp *PublicParameter) DeserializePolyANTT(a []byte) *PolyANTT {
	tmp := make([]int64, pp.paramDA)
	var r int64
	for k := 0; k < len(a); k += 8 {
		r = int64(a[k+0]) >> 0
		r |= int64(a[k+1]) >> 8
		r |= int64(a[k+2]) >> 16
		r |= int64(a[k+3]) >> 24
		r |= int64(a[k+4]) >> 32
		r |= int64(a[k+5]) >> 40
		r |= int64(a[k+6]) >> 48
		r |= int64(a[k+7]) >> 56
	}
	return &PolyANTT{coeffs: tmp}
}
func (pp *PublicParameter) SerializePolyANTTVec(a *PolyANTTVec) []byte {
	// length
	tmp := make([]byte, 0, 4+len(a.polyANTTs)*pp.paramDA*8)
	length := int32(len(a.polyANTTs))
	tmp = append(tmp, byte(length>>0))
	tmp = append(tmp, byte(length>>8))
	tmp = append(tmp, byte(length>>16))
	tmp = append(tmp, byte(length>>24))
	w := bytes.NewBuffer(tmp)
	for i := 0; i < len(a.polyANTTs); i++ {
		for j := 0; j < pp.paramDA; j++ {
			w.WriteByte(byte(a.polyANTTs[i].coeffs[j] >> 0))
			w.WriteByte(byte(a.polyANTTs[i].coeffs[j] >> 8))
			w.WriteByte(byte(a.polyANTTs[i].coeffs[j] >> 16))
			w.WriteByte(byte(a.polyANTTs[i].coeffs[j] >> 24))
			w.WriteByte(byte(a.polyANTTs[i].coeffs[j] >> 32))
			w.WriteByte(byte(a.polyANTTs[i].coeffs[j] >> 40))
			w.WriteByte(byte(a.polyANTTs[i].coeffs[j] >> 48))
			w.WriteByte(byte(a.polyANTTs[i].coeffs[j] >> 56))
		}
	}
	return tmp
}

func (pp *PublicParameter) writePolyANTT(w io.Writer, a *PolyANTT) error {
	var err error
	for i := 0; i < pp.paramDA; i++ {
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 0)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 8)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 16)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 24)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 32)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 40)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 48)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 56)})
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyANTT(r io.Reader) (*PolyANTT, error) {
	var n int
	var err error
	res := pp.NewPolyANTT()
	buf := make([]byte, 8)
	for i := 0; i < pp.paramDA; i++ {
		n, err = r.Read(buf)
		if n != 8 || err != nil {
			return nil, err
		}
		res.coeffs[i] = int64(buf[0]) << 0
		res.coeffs[i] |= int64(buf[1]) << 8
		res.coeffs[i] |= int64(buf[2]) << 16
		res.coeffs[i] |= int64(buf[3]) << 24
		res.coeffs[i] |= int64(buf[4]) << 32
		res.coeffs[i] |= int64(buf[5]) << 40
		res.coeffs[i] |= int64(buf[6]) << 48
		res.coeffs[i] |= int64(buf[7]) << 56
	}
	return res, nil
}
func (pp *PublicParameter) writePolyANTTVec(w io.Writer, a *PolyANTTVec) error {
	var err error
	length := len(a.polyANTTs)
	err = writeElement(w, int32(length))
	if err != nil {
		return err
	}
	for i := 0; i < length; i++ {
		err = pp.writePolyANTT(w, a.polyANTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyANTTVec(r io.Reader) (*PolyANTTVec, error) {
	var err error
	var lengthI32 int32
	err = readElement(r, &lengthI32)
	if err != nil {
		return nil, err
	}
	length := int(lengthI32)
	res := pp.NewPolyANTTVec(length)
	for i := 0; i < length; i++ {
		res.polyANTTs[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (pp *PublicParameter) writePolyCNTT(w io.Writer, a *PolyCNTT) error {
	var err error
	for i := 0; i < len(a.coeffs); i++ {
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 0)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 8)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 16)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 24)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 32)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 40)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 48)})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{byte(a.coeffs[i] >> 56)})
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyCNTT(r io.Reader) (*PolyCNTT, error) {
	var n int
	var err error
	res := pp.NewPolyCNTT()
	buf := make([]byte, 8)
	for i := 0; i < pp.paramDC; i++ {
		n, err = r.Read(buf)
		if n != 8 || err != nil {
			return nil, err
		}
		res.coeffs[i] = int64(buf[0]) << 0
		res.coeffs[i] |= int64(buf[1]) << 8
		res.coeffs[i] |= int64(buf[2]) << 16
		res.coeffs[i] |= int64(buf[3]) << 24
		res.coeffs[i] |= int64(buf[4]) << 32
		res.coeffs[i] |= int64(buf[5]) << 40
		res.coeffs[i] |= int64(buf[6]) << 48
		res.coeffs[i] |= int64(buf[7]) << 56
	}
	return res, nil
}
func (pp *PublicParameter) writePolyCNTTVec(w io.Writer, a *PolyCNTTVec) error {
	var err error
	length := len(a.polyCNTTs)
	err = writeElement(w, int32(length))
	if err != nil {
		return err
	}
	for i := 0; i < len(a.polyCNTTs); i++ {
		err = pp.writePolyCNTT(w, a.polyCNTTs[i])
		if err != nil {
			return err
		}
	}
	return nil
}
func (pp *PublicParameter) readPolyCNTTVec(r io.Reader) (*PolyCNTTVec, error) {
	var err error
	var lengthI32 int32
	err = readElement(r, &lengthI32)
	if err != nil {
		return nil, err
	}
	length := int(lengthI32)
	res := pp.NewPolyCNTTVec(length)
	for i := 0; i < length; i++ {
		res.polyCNTTs[i], err = pp.readPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (pp *PublicParameter) SerializeAddressPublicKey(apk *AddressPublicKey) ([]byte, error) {
	var err error
	length := (len(apk.t.polyANTTs) + 1) * pp.paramDA * 8
	buf := make([]byte, 0, 4+length)
	w := bytes.NewBuffer(buf)
	// length
	err = writeElement(w, int32(4+length))
	if err != nil {
		return nil, err
	}
	// t
	err = pp.writePolyANTTVec(w, apk.t)
	if err != nil {
		return nil, err
	}
	// e
	err = pp.writePolyANTT(w, apk.e)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeAddressPublicKey(serialziedAPk []byte) (*AddressPublicKey, error) {
	r := bytes.NewReader(serialziedAPk)
	var err error
	var lengthI32 int32
	err = readElement(r, &lengthI32)
	if err != nil {
		return nil, err
	}
	length := int(lengthI32)
	if len(serialziedAPk) != length+4 {
		return nil, err
	}
	t, err := pp.readPolyANTTVec(r)
	if err != nil {
		return nil, err
	}
	e, err := pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressPublicKey{
		t: t,
		e: e,
	}, nil
}
func (pp *PublicParameter) SerializeAddressSecretKey(ask *AddressSecretKey) ([]byte, error) {
	var err error
	length := (len(ask.s.polyANTTs) + 1) * pp.paramDA * 8
	buf := make([]byte, 0, 4+length)
	w := bytes.NewBuffer(buf)
	// length
	err = writeElement(w, int32(4+length))
	if err != nil {
		return nil, err
	}

	err = pp.writePolyANTTVec(w, ask.s)
	if err != nil {
		return nil, err
	}

	err = pp.writePolyANTT(w, ask.ma)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeAddressSecretKey(serialziedASk []byte) (*AddressSecretKey, error) {
	r := bytes.NewReader(serialziedASk)
	var err error
	var lengthI32 int32
	err = readElement(r, &lengthI32)
	if err != nil {
		return nil, err
	}
	length := int(lengthI32)
	if len(serialziedASk) != length+4 {
		return nil, err
	}
	s, err := pp.readPolyANTTVec(r)
	if err != nil {
		return nil, err
	}
	ma, err := pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressSecretKey{
		s:  s,
		ma: ma,
	}, nil
}

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

// WriteNULL write an identifier 0x00 to w,
// which means current variable is null
func WriteNULL(w io.Writer) {
	err := WriteVarInt(w, uint64(0))
	if err != nil {
		panic(err)
	}
}

// WriteNotNULL write an identifier 0x01 to w,
// which means current variable is not null
func WriteNotNULL(w io.Writer) {
	err := WriteVarInt(w, uint64(1))
	if err != nil {
		panic(err)
	}
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

//func WriteRpulpProof(w io.Writer, proof *rpulpProof) error {
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
//		err := WriteBytes(w, proof.chseed)
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
		err := WriteBytes(w, proof.chseed)
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

//func ReadRpulpProof(r io.Reader) (*rpulpProof, error) {
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
//		chseed0, err = ReadVarBytes(r, MAXALLOWED, "readRpulpProof")
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
//		err := WriteBytes(w, dpk.ckem)
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

//func WriteElrsSignature(w io.Writer, elrsSig *elrsSignature) error {
//	// write chseed
//	if elrsSig.chseed != nil {
//		WriteNotNULL(w)
//		err := WriteBytes(w, elrsSig.chseed)
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
			err := WriteBytes(w, elrsSig.seeds[i])
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

//func ReadElrsSignature(r io.Reader) (*elrsSignature, error) {
//	// read chseed
//	count, err := ReadVarInt(r)
//	if err != nil {
//		return nil, err
//	}
//	var chseed0 []byte = nil
//	if count > 0 {
//		chseed0, err = ReadVarBytes(r, MAXALLOWED, "ReadElrsSignature")
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
//		err := WriteRpulpProof(w, cbTxWitness.rpulpproof)
//		if err != nil {
//			return err
//		}
//	} else {
//		WriteNULL(w)
//	}
//
//	return nil
//}

func (cbTxWitness *CbTxWitnessv2) Serialize0(w io.Writer) error {
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
func (cbTxWitness *CbTxWitnessv2) Deserialize(r io.Reader) error {
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
//		rpulpproof0, err = ReadRpulpProof(r)
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
//		err := WriteBytes(w, trTx.TxMemo)
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
//		err := WriteBytes(w, txo.vc)
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
		err := WriteBytes(w, txo.Vct)
		if err != nil {
			return err
		}
	} else {
		WriteNULL(w)
	}

	//CkemSerialzed
	if txo.CkemSerialzed != nil {
		WriteNotNULL(w)
		err := WriteBytes(w, txo.CkemSerialzed)
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
//		err := WriteBytes(w, trTxInput.SerialNumber)
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
//		err := WriteRpulpProof(w, trTxWitness.rpulpproof)
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
//			err = WriteElrsSignature(w, trTxWitness.elrsSigs[i])
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
//		rpulpproof0, err = ReadRpulpProof(r)
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
//			elrsSigs0[i], err = ReadElrsSignature(r)
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
	//	err := WriteBytes(w, txo.vc)
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
		err := WriteBytes(w, trTx.TxMemo)
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
