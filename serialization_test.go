package pqringct

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringct/pqringctkem"
	"log"
	"reflect"
	"testing"
)

func Test_writePolyANTT_readPolyANTT(t *testing.T) {
	testBound := true
	//testBound := true

	var polyANTT *PolyANTT
	manualCheck := true

	pp := DefaultPP

	for t := 0; t < 1000; t++ {
		polyANTT = &PolyANTT{coeffs: pp.randomDaIntegersInQa(nil)}

		if testBound {
			polyANTT.coeffs[0] = (pp.paramQA - 1) >> 1
			polyANTT.coeffs[1] = -polyANTT.coeffs[0]
			polyANTT.coeffs[2] = 1
			polyANTT.coeffs[3] = -1
			polyANTT.coeffs[4] = 2
			polyANTT.coeffs[5] = -2
		}

		size := pp.PolyANTTSerializeSize()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err := pp.writePolyANTT(w, polyANTT)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}
		//fmt.Println("serilaizeSize of a PolyANTT:", size)

		r := bytes.NewReader(serialized)
		rePolyANTT, err := pp.readPolyANTT(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyANTT.coeffs[i] != rePolyANTT.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyANTT.coeffs[i], " read[i]=", rePolyANTT.coeffs[i])
			}

		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyANTT:", pp.PolyANTTSerializeSize())

		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyANTT.coeffs[i])
		}
	}
}

func Test_writePolyANTTVec_readPolyANTTVec(t *testing.T) {
	pp := DefaultPP

	polyANTTs := make([]*PolyANTT, pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		polyANTTs[i] = &PolyANTT{pp.randomDaIntegersInQa(nil)}
	}

	polyANTTVec := &PolyANTTVec{polyANTTs: polyANTTs}

	length := pp.PolyANTTVecSerializeSize(polyANTTVec)

	w := bytes.NewBuffer(make([]byte, 0, length))
	err := pp.writePolyANTTVec(w, polyANTTVec)
	if err != nil {
		log.Fatal(err)
	}

	serialized := w.Bytes()

	if len(serialized) != length {
		log.Fatal("size is wrong")
	}

	r := bytes.NewReader(serialized)
	recovered, err := pp.readPolyANTTVec(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramKA; i++ {
		for j := 0; j < pp.paramDA; j++ {
			if polyANTTVec.polyANTTs[i].coeffs[j] != recovered.polyANTTs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i]=", polyANTTVec.polyANTTs[i].coeffs[j], " read[i]=", recovered.polyANTTs[i].coeffs[j])
			}
		}

	}

	//	test nil
	w = bytes.NewBuffer(make([]byte, 0, pp.PolyANTTVecSerializeSize(nil)))
	err = pp.writePolyANTTVec(w, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss := w.Bytes()
	ssLen := len(ss)
	fmt.Println("serialize empty, length:", ssLen)

	r = bytes.NewReader(ss)
	recovered, err = pp.readPolyANTTVec(r)
	if err != nil {
		log.Fatal(err)
	}

	if recovered != nil {
		log.Fatal("serialize empty FAIL")
	}
}

func Test_writePolyAEta_readPolyAEta(t *testing.T) {
	pp := DefaultPP

	testBound := true
	//testBound := true

	var polyA *PolyA
	manualCheck := true

	var err error
	for t := 0; t < 10000; t++ {
		polyA, err = pp.randomPolyAinEtaA()
		if err != nil {
			log.Fatal(err)
		}

		if testBound {
			polyA.coeffs[0] = pp.paramEtaA
			polyA.coeffs[1] = -polyA.coeffs[0]
			polyA.coeffs[2] = 1
			polyA.coeffs[3] = -1
			polyA.coeffs[4] = 2
			polyA.coeffs[5] = -2
		}

		size := pp.PolyASerializeSizeEta()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err := pp.writePolyAEta(w, polyA)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}

		r := bytes.NewReader(serialized)
		rePolyA, err := pp.readPolyAEta(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyA.coeffs[i] != rePolyA.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyA.coeffs[i], " read[i]=", rePolyA.coeffs[i])
			}
		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyAEta:", pp.PolyASerializeSizeEta())

		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyA.coeffs[i])
		}
	}
}

func Test_writePolyANTTVecEta_readPolyANTTVecEta(t *testing.T) {
	pp := DefaultPP

	var err error

	polyAs := make([]*PolyA, pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		polyAs[i], err = pp.randomPolyAinEtaA()
	}

	polyAVec := &PolyAVec{polyAs: polyAs}

	length := pp.PolyAVecSerializeSizeEta(polyAVec)

	fmt.Println("serializeSize:", length)

	w := bytes.NewBuffer(make([]byte, 0, length))
	err = pp.writePolyAVecEta(w, polyAVec)
	if err != nil {
		log.Fatal(err)
	}
	serialized := w.Bytes()

	if len(serialized) != length {
		log.Fatal("size is wrong")
	}

	r := bytes.NewReader(serialized)
	recovered, err := pp.readPolyAVecEta(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramKA; i++ {
		for j := 0; j < pp.paramDA; j++ {
			if polyAVec.polyAs[i].coeffs[j] != recovered.polyAs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i]=", polyAVec.polyAs[i].coeffs[j], " read[i]=", recovered.polyAs[i].coeffs[j])
			}
		}
	}

	//	test nil
	w = bytes.NewBuffer(make([]byte, 0, pp.PolyAVecSerializeSizeEta(nil)))
	err = pp.writePolyAVecEta(w, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss := w.Bytes()
	ssLen := len(ss)
	fmt.Println("serialize empty, length:", ssLen)

	r = bytes.NewReader(ss)
	recovered, err = pp.readPolyAVecEta(r)
	if err != nil {
		log.Fatal(err)
	}

	if recovered != nil {
		log.Fatal("serialize empty FAIL")
	}
}

func Test_writePolyAGamma_readPolyAGamma(t *testing.T) {
	pp := DefaultPP

	testBound := true
	//testBound := true

	var polyA *PolyA
	manualCheck := true

	var err error
	for t := 0; t < 10000; t++ {
		polyA, err = pp.randomPolyAinGammaA5(nil)
		if err != nil {
			log.Fatal(err)
		}

		if testBound {
			polyA.coeffs[0] = int64(pp.paramGammaA)
			polyA.coeffs[1] = -polyA.coeffs[0]
			polyA.coeffs[2] = 1
			polyA.coeffs[3] = -1
			polyA.coeffs[4] = 2
			polyA.coeffs[5] = -2
		}

		size := pp.PolyASerializeSizeGamma()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err := pp.writePolyAGamma(w, polyA)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}

		r := bytes.NewReader(serialized)
		rePolyA, err := pp.readPolyAGamma(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDA; i++ {
			if polyA.coeffs[i] != rePolyA.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyA.coeffs[i], " read[i]=", rePolyA.coeffs[i])
			}
		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyAGamma:", pp.PolyASerializeSizeGamma())

		for i := 0; i < pp.paramDA; i++ {
			fmt.Println(polyA.coeffs[i])
		}
	}
}

func Test_writePolyCNTT_readPolyCNTT(t *testing.T) {
	testBound := true
	//testBound := true

	var polyCNTT *PolyCNTT
	manualCheck := true

	pp := DefaultPP

	for t := 0; t < 1000; t++ {
		polyCNTT = &PolyCNTT{coeffs: pp.randomDcIntegersInQc(nil)}

		if testBound {
			polyCNTT.coeffs[0] = (pp.paramQC - 1) >> 1
			polyCNTT.coeffs[1] = -polyCNTT.coeffs[0]
			polyCNTT.coeffs[2] = 1
			polyCNTT.coeffs[3] = -1
			polyCNTT.coeffs[4] = 2
			polyCNTT.coeffs[5] = -2
			polyCNTT.coeffs[6] = 0
		}

		size := pp.PolyCNTTSerializeSize()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err := pp.writePolyCNTT(w, polyCNTT)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}
		//fmt.Println("serilaizeSize of a PolyANTT:", size)

		r := bytes.NewReader(serialized)
		rePolyCNTT, err := pp.readPolyCNTT(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDC; i++ {
			if polyCNTT.coeffs[i] != rePolyCNTT.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyCNTT.coeffs[i], " read[i]=", rePolyCNTT.coeffs[i])
			}

		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyCNTT:", pp.PolyCNTTSerializeSize())

		for i := 0; i < pp.paramDC; i++ {
			fmt.Println(polyCNTT.coeffs[i])
		}
	}
}

func Test_writePolyCNTTVec_readPolyCNTTVec(t *testing.T) {
	pp := DefaultPP

	polyCNTTs := make([]*PolyCNTT, pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		polyCNTTs[i] = &PolyCNTT{pp.randomDcIntegersInQc(nil)}
	}

	polyCNTTVec := &PolyCNTTVec{polyCNTTs: polyCNTTs}

	length := pp.PolyCNTTVecSerializeSize(polyCNTTVec)

	w := bytes.NewBuffer(make([]byte, 0, length))
	err := pp.writePolyCNTTVec(w, polyCNTTVec)
	if err != nil {
		log.Fatal(err)
	}

	serialized := w.Bytes()

	if len(serialized) != length {
		log.Fatal("size is wrong")
	}

	r := bytes.NewReader(serialized)
	recovered, err := pp.readPolyCNTTVec(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramKC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if polyCNTTVec.polyCNTTs[i].coeffs[j] != recovered.polyCNTTs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i]=", polyCNTTVec.polyCNTTs[i].coeffs[j], " read[i]=", recovered.polyCNTTs[i].coeffs[j])
			}
		}

	}

	//	test nil
	w = bytes.NewBuffer(make([]byte, 0, pp.PolyCNTTVecSerializeSize(nil)))
	err = pp.writePolyCNTTVec(w, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss := w.Bytes()
	ssLen := len(ss)
	fmt.Println("serialize empty, length:", ssLen)

	r = bytes.NewReader(ss)
	recovered, err = pp.readPolyCNTTVec(r)
	if err != nil {
		log.Fatal(err)
	}

	if recovered != nil {
		log.Fatal("serialize empty FAIL")
	}

}

func Test_writePolyCEta_readPolyCEta(t *testing.T) {
	testBound := true
	//testBound := true

	var polyCEta *PolyC
	manualCheck := true

	pp := DefaultPP

	var err error
	for t := 0; t < 1000; t++ {
		polyCEta, err = pp.randomPolyCinEtaC()
		if err != nil {
			log.Fatal(err)
		}

		if testBound {
			polyCEta.coeffs[0] = pp.paramEtaC
			polyCEta.coeffs[1] = -polyCEta.coeffs[0]
			polyCEta.coeffs[2] = 1
			polyCEta.coeffs[3] = -1
			polyCEta.coeffs[4] = 2
			polyCEta.coeffs[5] = -2
			polyCEta.coeffs[6] = 0
		}

		size := pp.PolyCSerializeSizeEta()
		w := bytes.NewBuffer(make([]byte, 0, size))
		err = pp.writePolyCEta(w, polyCEta)
		if err != nil {
			log.Fatal(err)
		}

		serialized := w.Bytes()
		if len(serialized) != size {
			log.Fatal(errors.New("size is worng"))
		}
		//fmt.Println("serilaizeSize of a PolyANTT:", size)

		r := bytes.NewReader(serialized)
		rePolyCEta, err := pp.readPolyCEta(r)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < pp.paramDC; i++ {
			if polyCEta.coeffs[i] != rePolyCEta.coeffs[i] {
				log.Fatal("i=", i, " origin[i]=", polyCEta.coeffs[i], " read[i]=", rePolyCEta.coeffs[i])
			}

		}
	}

	if manualCheck {
		fmt.Println("SerializeSize of a PolyCEta:", pp.PolyCSerializeSizeEta())

		for i := 0; i < pp.paramDC; i++ {
			fmt.Println(polyCEta.coeffs[i])
		}
	}
}

func Test_writePolyCVecEta_readPolyCVecEta(t *testing.T) {
	pp := DefaultPP

	var err error
	polyCs := make([]*PolyC, pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		polyCs[i], err = pp.randomPolyCinEtaC()
		if err != nil {
			log.Fatal(err)
		}
	}

	polyCVecEta := &PolyCVec{polyCs: polyCs}

	length := pp.PolyCVecSerializeSizeEta(polyCVecEta)

	w := bytes.NewBuffer(make([]byte, 0, length))
	err = pp.writePolyCVecEta(w, polyCVecEta)
	if err != nil {
		log.Fatal(err)
	}

	serialized := w.Bytes()

	if len(serialized) != length {
		log.Fatal("size is wrong")
	}

	r := bytes.NewReader(serialized)
	recovered, err := pp.readPolyCVecEta(r)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < pp.paramKC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if polyCVecEta.polyCs[i].coeffs[j] != recovered.polyCs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i]=", polyCVecEta.polyCs[i].coeffs[j], " read[i]=", recovered.polyCs[i].coeffs[j])
			}
		}

	}

	//	test nil
	w = bytes.NewBuffer(make([]byte, 0, pp.PolyCVecSerializeSizeEta(nil)))
	err = pp.writePolyCVecEta(w, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss := w.Bytes()
	ssLen := len(ss)
	fmt.Println("serialize empty, length:", ssLen)

	r = bytes.NewReader(ss)
	recovered, err = pp.readPolyCVecEta(r)
	if err != nil {
		log.Fatal(err)
	}

	if recovered != nil {
		log.Fatal("serialize empty FAIL")
	}
}

func TestAddressPubicKeySerialize(t *testing.T) {
	pp := DefaultPP

	testAbnormal := false

	// normal
	apkt := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		apkt.polyANTTs[i] = &PolyANTT{coeffs: pp.randomDaIntegersInQa(nil)}
	}
	apke := &PolyANTT{pp.randomDaIntegersInQa(nil)}

	apk := &AddressPublicKey{t: apkt, e: apke}

	size := pp.AddressPublicKeySerializeSize()

	serialized, err := pp.SerializeAddressPublicKey(apk)
	if err != nil {
		log.Fatal(err)
	}

	if len(serialized) != size {
		log.Fatal("the size does not match")
	}

	recoverd, err := pp.DeserializeAddressPublicKey(serialized)

	length := len(recoverd.t.polyANTTs)
	if length != pp.paramKA {
		log.Fatal("the length of t is does not match the design")
	}
	for i := 0; i < len(recoverd.t.polyANTTs); i++ {
		for j := 0; j < pp.paramDA; j++ {
			if apk.t.polyANTTs[i].coeffs[j] != recoverd.t.polyANTTs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i,j]=", apk.t.polyANTTs[i].coeffs[j], " read[i]=", recoverd.t.polyANTTs[i].coeffs[j])
			}
		}
	}

	// abnormal
	if testAbnormal {
		apkt = pp.NewPolyANTTVec(pp.paramKA + 1)
		for i := 0; i < pp.paramKA+1; i++ {
			apkt.polyANTTs[i] = &PolyANTT{coeffs: pp.randomDaIntegersInQa(nil)}
		}
		apke = &PolyANTT{pp.randomDaIntegersInQa(nil)}

		apk = &AddressPublicKey{t: apkt, e: apke}

		size = pp.AddressPublicKeySerializeSize()

		_, err = pp.SerializeAddressPublicKey(apk)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func TestSerializeAddressSecretKeySp(t *testing.T) {
	pp := DefaultPP

	testAbnormal := true

	var err error
	s := pp.NewPolyAVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		s.polyAs[i], err = pp.randomPolyAinGammaA5(nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	asksp := &AddressSecretKeySp{
		s: s,
	}

	serializedAskSp, err := pp.SerializeAddressSecretKeySp(asksp)
	if err != nil {
		log.Fatal(err)
	}
	if len(serializedAskSp) != pp.AddressSecretKeySpSerializeSize() {
		log.Fatal("the size does not match design")
	}

	recovered, err := pp.DeserializeAddressSecretKeySp(serializedAskSp)
	if err != nil {
		log.Fatal(err)
	}

	if len(recovered.s.polyAs) != pp.paramLA {
		log.Fatal("the length does not match design")
	}

	for i := 0; i < len(recovered.s.polyAs); i++ {
		for j := 0; j < pp.paramDA; j++ {
			if asksp.s.polyAs[i].coeffs[j] != recovered.s.polyAs[i].coeffs[j] {
				log.Fatal("i=", i, "j=", j, " origin[i,j]=", asksp.s.polyAs[i].coeffs[j], " read[i]=", recovered.s.polyAs[i].coeffs[j])
			}
		}
	}

	// abnormal
	if testAbnormal {
		ask := &AddressSecretKeySp{}

		_, err = pp.SerializeAddressSecretKeySp(ask)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// new test case end

func TestSerializeTxoValue(t *testing.T) {
	pp := DefaultPP

	value := uint64(123456789)
	fmt.Println(value, "pvalue")

	seed := make([]byte, 7)
	for i := 0; i < 7; i++ {
		seed[i] = byte(i)
	}

	sk, err := pp.expandValuePadRandomness(seed)

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

	skr, err := pp.expandValuePadRandomness(seed)

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
	pp := DefaultPP
	seed := make([]byte, pp.paramSeedBytesLen)
	tmp := pp.randomDaIntegersInQa(seed)
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
	pp := DefaultPP
	seed := make([]byte, pp.paramSeedBytesLen)
	tmp := pp.randomDcIntegersInQc(seed)
	a := &PolyCNTT{coeffs: tmp}
	w := bytes.NewBuffer(make([]byte, 0, pp.paramDC*8))
	err := pp.writePolyCNTT(w, a)
	if err != nil {
		log.Fatalln(err)
	}
	//for i := 0; i < pp.paramDC; i++ {
	//	fmt.Println(a.coeffs[i])
	//}
	//fmt.Println("wait")
	serializedA := w.Bytes()
	r := bytes.NewReader(serializedA)
	got, err := pp.readPolyCNTT(r)
	if err != nil {
		log.Fatalln(err)
	}
	//for i := 0; i < pp.paramDC; i++ {
	//	fmt.Println(got.coeffs[i])
	//}
	for i := 0; i < pp.paramDC; i++ {
		if got.coeffs[i] != a.coeffs[i] {
			t.Fatal("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", a.coeffs[i])
		}
	}
}

func TestPublicParameter_writePolyANTTVec_readPolyANTTVec(t *testing.T) {
	pp := DefaultPP
	as := pp.NewPolyANTTVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDaIntegersInQa(seed)
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
	pp := DefaultPP
	as := pp.NewPolyCNTTVec(pp.paramLC)
	for i := 0; i < pp.paramLC; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDcIntegersInQc(seed)
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

func TestPublicParameter_writePolyAVecEta_readPolyAVecEta(t *testing.T) {
	pp := DefaultPP
	var err error
	as := pp.NewPolyAVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		//	seed := RandomBytes(pp.paramSeedBytesLen)
		as.polyAs[i], err = pp.randomPolyAinEtaA()
		if err != nil {
			log.Fatalln(err)
		}
	}

	w := bytes.NewBuffer(make([]byte, 0, pp.PolyAVecSerializeSizeEta(as)))
	err = pp.writePolyAVecEta(w, as)
	if err != nil {
		log.Fatalln(err)
	}

	serializedA := w.Bytes()
	r := bytes.NewReader(serializedA)
	got, err := pp.readPolyAVecEta(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramLA; i++ {
		for j := 0; j < pp.paramDA; j++ {
			if got.polyAs[i].coeffs[j] != as.polyAs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.polyAs[i].coeffs[j], " origin[i][j]=", as.polyAs[i].coeffs[j])
			}
		}
	}
}

func TestPublicParameter_writePolyAGamma_readPolyAGamma(t *testing.T) {
	pp := DefaultPP
	seed := RandomBytes(pp.paramSeedBytesLen)
	as, err := pp.randomPolyAinGammaA5(seed)
	if err != nil {
		log.Fatalln(err)
	}

	w := bytes.NewBuffer(make([]byte, 0, pp.PolyASerializeSizeGamma()))
	err = pp.writePolyAGamma(w, as)
	if err != nil {
		log.Fatalln(err)
	}

	serializedA := w.Bytes()
	r := bytes.NewReader(serializedA)
	got, err := pp.readPolyAGamma(r)
	if err != nil {
		log.Fatalln(err)
	}
	for j := 0; j < pp.paramDA; j++ {
		if got.coeffs[j] != as.coeffs[j] {
			t.Fatal("j=", j, " got[i][j]=", got.coeffs[j], " origin[i][j]=", as.coeffs[j])
		}
	}
}

//func TestPublicParameter_writePolyAVecGamma_readPolyAVecGamma(t *testing.T) {
//	pp := DefaultPP
//	as := pp.NewPolyAVec(pp.paramLA)
//	for i := 0; i < pp.paramLA; i++ {
//		seed := RandomBytes(pp.paramSeedBytesLen)
//		tmp, err := randomPolyAinGammaA5(seed, pp.paramDA)
//		if err != nil {
//			log.Fatalln(err)
//		}
//		as.polyAs[i] = &PolyA{coeffs: tmp}
//	}
//
//	w := bytes.NewBuffer(make([]byte, 0, pp.PolyAVecSerializeSizeGamma(as)))
//	err := pp.writePolyAVecGamma(w, as)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	serializedA := w.Bytes()
//	r := bytes.NewReader(serializedA)
//	got, err := pp.readPolyAVecGamma(r)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	for i := 0; i < pp.paramLA; i++ {
//		for j := 0; j < pp.paramDA; j++ {
//			if got.polyAs[i].coeffs[j] != as.polyAs[i].coeffs[j] {
//				t.Fatal("j=", j, " got[i][j]=", got.polyAs[i].coeffs[j], " origin[i][j]=", as.polyAs[i].coeffs[j])
//			}
//		}
//	}
//}

func TestPublicParameter_writePolyCVecEta_readPolyCVecEta(t *testing.T) {
	pp := DefaultPP
	var err error
	as := pp.NewPolyCVec(pp.paramLC)
	for i := 0; i < pp.paramLC; i++ {
		//seed := RandomBytes(pp.paramSeedBytesLen)
		as.polyCs[i], err = pp.randomPolyCinEtaC()
		if err != nil {
			log.Fatalln(err)
		}
	}

	w := bytes.NewBuffer(make([]byte, 0, pp.PolyCVecSerializeSizeEta(as)))
	err = pp.writePolyCVecEta(w, as)
	if err != nil {
		log.Fatalln(err)
	}

	serializedC := w.Bytes()
	r := bytes.NewReader(serializedC)
	got, err := pp.readPolyCVecEta(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramLC; i++ {
		for j := 0; j < pp.paramDC; j++ {
			if got.polyCs[i].coeffs[j] != as.polyCs[i].coeffs[j] {
				t.Fatal("i=", i, "j=", j, " got[i][j]=", got.polyCs[i].coeffs[j], " origin[i][j]=", as.polyCs[i].coeffs[j])
			}
		}
	}
}

func TestPublicParameter_SerializeAddressSecretSpAndSnKey_DeserializeAddressSecretSpAndSnKey(t *testing.T) {
	pp := DefaultPP
	ts := pp.NewPolyAVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp, err := pp.randomPolyAinGammaA5(seed)
		if err != nil {
			log.Fatalln(err)
		}
		ts.polyAs[i] = tmp
	}
	var e *PolyANTT
	seed := RandomBytes(pp.paramSeedBytesLen)
	tmp := pp.randomDaIntegersInQa(seed)
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
	for i := 0; i < len(got.s.polyAs); i++ {
		for j := 0; j < len(got.s.polyAs[i].coeffs); j++ {
			if got.s.polyAs[i].coeffs[j] != asksp.s.polyAs[i].coeffs[j] {
				t.Fatal("j=", j, " got[i][j]=", got.s.polyAs[i].coeffs[j], " origin[i][j]=", asksp.s.polyAs[i].coeffs[j])
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
	pp := DefaultPP
	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDcIntegersInQc(seed)
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed := RandomBytes(pp.paramSeedBytesLen)
	tmp := pp.randomDcIntegersInQc(seed)
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
	pp := DefaultPP
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed := RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDaIntegersInQa(seed)
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed := RandomBytes(pp.paramSeedBytesLen)
	tmp := pp.randomDaIntegersInQa(seed)
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
	pp := DefaultPP
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDaIntegersInQa(seed)
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp := pp.randomDaIntegersInQa(seed)
	e = &PolyANTT{coeffs: tmp}

	apk := &AddressPublicKey{
		t: ts,
		e: e,
	}

	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDcIntegersInQc(seed)
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp = pp.randomDcIntegersInQc(seed)
	c = &PolyCNTT{coeffs: tmp}

	vcmt := &ValueCommitment{
		b: b,
		c: c,
	}

	value := uint64(123)
	vct, err := pp.encodeTxoValueToBytes(value)
	if err != nil {
		log.Fatalln(err)
	}

	Ckem := RandomBytes(pqringctkem.GetKemCiphertextBytesLen(pp.paramKem))

	txo := &Txo{
		AddressPublicKey: apk,
		ValueCommitment:  vcmt,
		Vct:              vct,
		CtKemSerialized:  Ckem,
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
	pp := DefaultPP
	ts := pp.NewPolyANTTVec(pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDaIntegersInQa(seed)
		ts.polyANTTs[i] = &PolyANTT{coeffs: tmp}
	}
	var e *PolyANTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp := pp.randomDaIntegersInQa(seed)
	e = &PolyANTT{coeffs: tmp}

	apk := &AddressPublicKey{
		t: ts,
		e: e,
	}

	b := pp.NewPolyCNTTVec(pp.paramKC)
	for i := 0; i < pp.paramKC; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDcIntegersInQc(seed)
		b.polyCNTTs[i] = &PolyCNTT{coeffs: tmp}
	}
	var c *PolyCNTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp = pp.randomDcIntegersInQc(seed)
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
		CtKemSerialized:  Ckem,
	}

	id := RandomBytes(HashOutputBytesLen)
	lgrTxo := &LgrTxo{
		txo: txo,
		id:  id,
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
	pp := DefaultPP
	J := 2
	var seed []byte
	// c_waves []*PolyCNTT
	c_waves := make([]*PolyCNTT, J)
	for i := 0; i < J; i++ {
		seed = RandomBytes(pp.paramSeedBytesLen)
		tmp := pp.randomDcIntegersInQc(seed)
		c_waves[i] = &PolyCNTT{coeffs: tmp}
	}

	//	c_hat_g *PolyCNTT
	var c_hat_g *PolyCNTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp := pp.randomDcIntegersInQc(seed)
	c_hat_g = &PolyCNTT{coeffs: tmp}

	//	psi     *PolyCNTT
	var psi *PolyCNTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp = pp.randomDcIntegersInQc(seed)
	psi = &PolyCNTT{coeffs: tmp}

	//	phi     *PolyCNTT
	var phi *PolyCNTT
	seed = RandomBytes(pp.paramSeedBytesLen)
	tmp = pp.randomDcIntegersInQc(seed)
	phi = &PolyCNTT{coeffs: tmp}

	//	chseed  []byte
	chseed := RandomBytes(pp.paramSeedBytesLen)

	//	cmt_zs [][]*PolyCVec
	cmt_zs := make([][]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		cmt_zs[i] = make([]*PolyCVec, J)
		for j := 0; j < J; j++ {
			cmt_zs[i][j] = pp.NewPolyCVec(pp.paramLC)
			for k := 0; k < pp.paramLC; k++ {
				seed = RandomBytes(pp.paramSeedBytesLen)
				tmp, err := pp.randomPolyCForResponseZetaC()
				if err != nil {
					log.Fatal(err)
				}
				cmt_zs[i][j].polyCs[k] = tmp
			}
		}
	}

	//	zs     []*PolyCVec
	zs := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		zs[i] = pp.NewPolyCVec(pp.paramLC)
		for j := 0; j < J; j++ {
			seed = RandomBytes(pp.paramSeedBytesLen)
			tmp, err := pp.randomPolyCForResponseZetaC()
			if err != nil {
				log.Fatal(err)
			}
			zs[i].polyCs[j] = tmp
		}
	}

	rpulpProof := &rpulpProof{
		c_waves: c_waves,
		c_hat_g: c_hat_g,
		psi:     psi,
		phi:     phi,
		chseed:  chseed,
		cmt_zs:  cmt_zs,
		zs:      zs,
	}

	serializedRpulpProof, err := pp.SerializeRpulpProof(rpulpProof)
	if err != nil {
		log.Fatalln(err)
	}
	got, err := pp.DeserializeRpulpProof(serializedRpulpProof)
	if err != nil {
		log.Fatalln(err)
	}
	equal := reflect.DeepEqual(got, rpulpProof)
	if !equal {
		t.Fatal("error for serialize and deserialize lgrTxo")
	}
}
