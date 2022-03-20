package pqringct

import (
	"bytes"
	"fmt"
	"log"
	"testing"
)

func TestPublicParameter_writePolyANTT_readPolyANTT(t *testing.T) {
	pp := DefaultPPV2
	seed := make([]byte, pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	a := &PolyANTT{coeffs: tmp}
	w := bytes.NewBuffer(make([]byte, 0, pp.paramDA*8))
	err := pp.WritePolyANTT(w, a)
	if err != nil {
		log.Fatalln(err)
	}
	serializedA := w.Bytes()
	r := bytes.NewReader(serializedA)
	got, err := pp.ReadPolyANTT(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramDA; i++ {
		if got.coeffs[i] != a.coeffs[i] {
			fmt.Println("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", a.coeffs[i])
		}
	}
}
func TestPublicParameter_writePolyCNTT_readPolyCNTT(t *testing.T) {
	pp := DefaultPPV2
	seed := make([]byte, pp.paramSeedBytesLen)
	tmp := rejectionUniformWithQc(seed, pp.paramDC)
	a := &PolyCNTT{coeffs: tmp}
	w := bytes.NewBuffer(make([]byte, 0, pp.paramDC*8))
	err := pp.WritePolyCNTT(w, a)
	if err != nil {
		log.Fatalln(err)
	}
	serializedA := w.Bytes()
	r := bytes.NewReader(serializedA)
	got, err := pp.ReadPolyCNTT(r)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < pp.paramDC; i++ {
		if got.coeffs[i] != a.coeffs[i] {
			fmt.Println("i=", i, " got[i]=", got.coeffs[i], " origin[i]=", a.coeffs[i])
		}
	}
}
