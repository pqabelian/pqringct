package pqringct

import (
	"bytes"
	"fmt"
	"github.com/cryptosuite/pqringct/pqringctkem"
	"log"
	"reflect"
	"testing"
)

func TestSerializeTxoValue(t *testing.T) {
	pp := DefaultPPV2

	value := uint64(123456789)
	fmt.Println(value, "pvalue")

	seed := make([]byte, 7)
	for i := 0; i < 7; i++ {
		seed[i] = byte(i)
	}

	sk, err := pp.expandRandomBitsInBytesV(seed)

	vbytes, err := pp.encodeTxoValueToBytes(value)
	if err != nil {
		log.Fatalln(err)
	}

	rst := make([]byte, pp.TxoValueBytesLen())
	for i := 0; i < pp.TxoValueBytesLen(); i++ {
		rst[i] = vbytes[i] ^ sk[i]
	}
	cipherValue, err := pp.decodeTxoValueFromBytes(rst)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(cipherValue, "cvalue")

	skr, err := pp.expandRandomBitsInBytesV(seed)

	recover := make([]byte, pp.TxoValueBytesLen())
	for i := 0; i < pp.TxoValueBytesLen(); i++ {
		recover[i] = rst[i] ^ skr[i]
	}
	recoverValue, err := pp.decodeTxoValueFromBytes(recover)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(recoverValue, "revalue")

}

func TestPublicParameter_writePolyANTT_readPolyANTT(t *testing.T) {
	pp := DefaultPPV2
	seed := make([]byte, pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	a := &PolyANTT{coeffs: tmp}
	w := bytes.NewBuffer(make([]byte, 0, pp.paramDA*8))
	err := pp.writePolyANTT(w, a)
	if err != nil {
		log.Fatalln(err)
	}
	serializedA := w.Bytes()
	r := bytes.NewReader(serializedA)
	got, err := pp.readPolyANTT(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramDA; i++ {
		if got.coeffs[i] != a.coeffs[i] {
			t.Fatal("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", a.coeffs[i])
		}
	}
}
func TestPublicParameter_writePolyCNTT_readPolyCNTT(t *testing.T) {
	pp := DefaultPPV2
	seed := make([]byte, pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQc(seed, pp.paramDC)
	a := &PolyCNTT{coeffs: tmp}
	w := bytes.NewBuffer(make([]byte, 0, pp.paramDC*8))
	err := pp.writePolyCNTT(w, a)
	if err != nil {
		log.Fatalln(err)
	}
	serializedA := w.Bytes()
	r := bytes.NewReader(serializedA)
	got, err := pp.readPolyCNTT(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramDC; i++ {
		if got.coeffs[i] != a.coeffs[i] {
			t.Fatal("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", a.coeffs[i])
		}
	}
}

func TestPublicParameter_writePolyANTTVec_readPolyANTTVec(t *testing.T) {
	pp := DefaultPPV2
	as := pp.NewPolyANTTVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
		as.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	w := bytes.NewBuffer(make([]byte, 0, pp.PolyANTTVecSerializeSize(as)))
	err := pp.writePolyANTTVec(w, as)
	if err != nil {
		log.Fatalln(err)
	}
	serializedA := w.Bytes()
	r := bytes.NewReader(serializedA)
	got, err := pp.readPolyANTTVec(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramLA; i++ {
		for j := 0; j < pp.paramDA; j++ {
			if got.polyANTTs[i].coeffs[j] != as.polyANTTs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.polyANTTs[i].coeffs[j], " origin[i][j]=", as.polyANTTs[i].coeffs[j])
			}
		}
	}
}
func TestPublicParameter_writePolyCNTTVec_readPolyCNTTVec(t *testing.T) {
	pp := DefaultPPV2
	as := pp.NewPolyCNTTVec(pp.paramLC)
	for i := 0; i < pp.paramLC; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQc(seed, pp.paramDC)
		as.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	w := bytes.NewBuffer(make([]byte, 0, pp.PolyCNTTVecSerializeSize(as)))
	err := pp.writePolyCNTTVec(w, as)
	if err != nil {
		log.Fatalln(err)
	}
	serializedC := w.Bytes()
	r := bytes.NewReader(serializedC)
	got, err := pp.readPolyCNTTVec(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramLC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if got.polyCNTTs[i].coeffs[j] != as.polyCNTTs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.polyCNTTs[i].coeffs[j], " origin[i][j]=", as.polyCNTTs[i].coeffs[j])
			}
		}
	}
}

func TestPublicParameter_SerializeAddressSecretSpAndSnKey_DeserializeAddressSecretSpAndSnKey(t *testing.T) {
	pp := DefaultPPV2
	ts := pp.NewPolyANTTVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed := RandomBytes(pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	e = &PolyANTT{coeffs: tmp}

	asksp := &AddressSecretKeySp{ts}
	asksn := &AddressSecretKeySn{e}

	serializedAskSp, err := pp.SerializeAddressSecretKeySp(asksp)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeAddressSecretKeySp(serializedAskSp)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < len(got.s.polyANTTs); i++ {
		for j := 0; j < len(got.s.polyANTTs[i].coeffs); j++ {
			if got.s.polyANTTs[i].coeffs[j] != asksp.s.polyANTTs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.s.polyANTTs[i].coeffs[j], " origin[i][j]=", asksp.s.polyANTTs[i].coeffs[j])
			}
		}
	}

	serializedAskSn, err := pp.SerializeAddressSecretKeySn(asksn)
	if err != nil {
		log.Fatalln(err)
	}
	gotsn, err := pp.DeserializeAddressSecretKeySn(serializedAskSn)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < len(gotsn.ma.coeffs); i++ {
		if gotsn.ma.coeffs[i] != asksn.ma.coeffs[i] {
			t.Fatal("i=", i, " gotsn[i]=", gotsn.ma.coeffs[i], " origin[i]=", asksn.ma.coeffs[i])
		}
	}
}

func TestPublicParameter_SerializeValueCommitment_DeserializeValueCommitment(t *testing.T) {
	pp := DefaultPPV2
	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQc(seed, pp.paramDC)
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed := RandomBytes(pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQc(seed, pp.paramDC)
	c = &PolyCNTT{coeffs: tmp}

	vcmt := &ValueCommitment{
		b: b,
		c: c,
	}

	serializedVCmt, err := pp.SerializeValueCommitment(vcmt)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeValueCommitment(serializedVCmt)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < len(got.b.polyCNTTs); i++ {
		for j := 0; j < len(got.b.polyCNTTs[i].coeffs); j++ {
			if got.b.polyCNTTs[i].coeffs[j] != vcmt.b.polyCNTTs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.b.polyCNTTs[i].coeffs[j], " origin[i][j]=", vcmt.b.polyCNTTs[i].coeffs[j])
			}
		}
	}
	fmt.Println("------------------------------")
	for i := 0; i < len(got.c.coeffs); i++ {
		if got.c.coeffs[i] != vcmt.c.coeffs[i] {
			t.Fatal("i=", i, " got[i]=", got.c.coeffs[i], " origin[i]=", vcmt.c.coeffs[i])
		}
	}
}

func TestPublicParameter_SerializeAddressPublicKey(t *testing.T) {
	pp := DefaultPPV2
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed := RandomBytes(pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	e = &PolyANTT{coeffs: tmp}

	apk := &AddressPublicKey{
		t: ts,
		e: e,
	}

	serializedApk, err := pp.SerializeAddressPublicKey(apk)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeAddressPublicKey(serializedApk)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < len(got.t.polyANTTs); i++ {
		for j := 0; j < len(got.t.polyANTTs[i].coeffs); j++ {
			if got.t.polyANTTs[i].coeffs[j] != apk.t.polyANTTs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.t.polyANTTs[i].coeffs[j], " origin[i][j]=", apk.t.polyANTTs[i].coeffs[j])
			}
		}
	}
	for i := 0; i < len(got.e.coeffs); i++ {
		if got.e.coeffs[i] != apk.e.coeffs[i] {
			t.Fatal("i=", i, " got[i]=", got.e.coeffs[i], " origin[i]=", apk.e.coeffs[i])
		}
	}
}

func TestPublicParameter_SerializeTxo_DeserializeTxo(t *testing.T) {
	var seed []byte
	pp := DefaultPPV2
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	e = &PolyANTT{coeffs: tmp}

	apk := &AddressPublicKey{
		t: ts,
		e: e,
	}

	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQc(seed, pp.paramDC)
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp = rejectionUniformWithQc(seed, pp.paramDC)
	c = &PolyCNTT{coeffs: tmp}

	vcmt := &ValueCommitment{
		b: b,
		c: c,
	}

	vct := RandomBytes(pp.paramN)
	for i := 0; i < pp.paramN; i++ {
		vct[i] = vct[i] & 1
	}
	Ckem := RandomBytes(pqringctkem.GetKemCiphertextBytesLen(pp.paramKem))

	txo := &Txo{
		AddressPublicKey: apk,
		ValueCommitment:  vcmt,
		Vct:              vct,
		CkemSerialzed:    Ckem,
	}

	serializedTxo, err := pp.SerializeTxo(txo)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeTxo(serializedTxo)
	if err != nil {
		log.Fatalln(err)
	}
	equal := reflect.DeepEqual(got, txo)
	if !equal {
		t.Fatal("error for serialize and deserialize txo")
	}

}

func TestPublicParameter_SerializeLgrTxo_DeserializeLgrTxo(t *testing.T) {
	var seed []byte
	pp := DefaultPPV2
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	e = &PolyANTT{coeffs: tmp}

	apk := &AddressPublicKey{
		t: ts,
		e: e,
	}

	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := rejectionUniformWithQc(seed, pp.paramDC)
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp = rejectionUniformWithQc(seed, pp.paramDC)
	c = &PolyCNTT{coeffs: tmp}

	vcmt := &ValueCommitment{
		b: b,
		c: c,
	}

	length := pp.TxoValueBytesLen()
	vct := RandomBytes(length)

	Ckem := RandomBytes(pqringctkem.GetKemCiphertextBytesLen(pp.paramKem))

	txo := &Txo{
		AddressPublicKey: apk,
		ValueCommitment:  vcmt,
		Vct:              vct,
		CkemSerialzed:    Ckem,
	}

	id := RandomBytes(HashBytesLen)
	lgrTxo := &LgrTxo{
		Txo: txo,
		Id:  id,
	}
	serializedLgrTxo, err := pp.SerializeLgrTxo(lgrTxo)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeLgrTxo(serializedLgrTxo)
	if err != nil {
		log.Fatalln(err)
	}
	equal := reflect.DeepEqual(got, lgrTxo)
	if !equal {
		t.Fatal("error for serialize and deserialize lgrTxo")
	}

}

func TestPublicParameter_SerializeRpulpProof_DeserializeRpulpProof(t *testing.T) {

}
