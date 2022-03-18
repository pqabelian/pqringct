package pqringctkyber

import (
	"crypto/rand"
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
	"golang.org/x/crypto/sha3"
	"log"
)

// RandomBytes returns a byte array with given length from crypto/rand.Reader
func RandomBytes(length int) []byte {
	res := make([]byte, 0, length)
	for length > 0 {
		tmp := make([]byte, length)
		n, err := rand.Read(tmp)
		if err != nil {
			log.Fatalln(err)
			return nil
		}
		res = append(res, tmp[:n]...)
		length -= n
	}
	return res
}

func KeyPair(kpp *kyber.ParamSet, seed []byte, seedLen int) ([]byte, []byte, error) {
	// check the validity of the length of seed
	if seed == nil || len(seed) != seedLen {
		return nil, nil, errors.New("the length of seed is invalid")
	}
	if seed == nil {
		seed = RandomBytes(seedLen)
	}

	// this temporary byte slice is for protect seed unmodified
	// hash(seed) to meet the length required by kyber
	usedSeed := make([]byte, 2*seedLen)
	shake256 := sha3.NewShake256()
	shake256.Write(seed)
	shake256.Read(usedSeed)
	return kpp.KeyPair(usedSeed)
}
func Encaps(kpp *kyber.ParamSet, pk []byte) ([]byte, []byte, error) {
	return kpp.Encaps(pk)
}
func Decaps(kpp *kyber.ParamSet, cipher []byte, sk []byte) ([]byte, error) {
	return kpp.Decaps(cipher, sk)
}
