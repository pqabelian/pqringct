package pqringctkem

import (
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
	"github.com/cryptosuite/pqringct/pqringctkem/pqringctkyber"
	"log"
)

type VersionKEM uint32

const (
	KEM_KYBER VersionKEM = iota
)

type ParamKem struct {
	Version VersionKEM
	Kyber   *kyber.ParameterSet
}

type ValuePublicKey struct {
	Version      VersionKEM
	SerializedPK []byte
}

type ValueSecretKey struct {
	Version      VersionKEM
	SerializedSK []byte
}

func KeyGen(ppkem *ParamKem, seed []byte, seedLen int) ([]byte, []byte, error) {
	var originSerializedPK, originSerializedSK []byte
	var err error
	switch ppkem.Version {
	case KEM_KYBER:
		originSerializedPK, originSerializedSK, err = pqringctkyber.KeyPair(ppkem.Kyber, seed, seedLen)
		if err != nil {
			return nil, nil, err
		}
	default:
		log.Fatalln("Unsupported KEM version.")
	}
	retSerializedPK := make([]byte, 0, 4+len(originSerializedPK))
	retSerializedPK = append(retSerializedPK, byte(ppkem.Version>>0))
	retSerializedPK = append(retSerializedPK, byte(ppkem.Version>>8))
	retSerializedPK = append(retSerializedPK, byte(ppkem.Version>>16))
	retSerializedPK = append(retSerializedPK, byte(ppkem.Version>>24))
	retSerializedPK = append(retSerializedPK, originSerializedPK...)

	retSerializedSK := make([]byte, 0, 4+len(originSerializedSK))
	retSerializedSK = append(retSerializedSK, byte(ppkem.Version>>0))
	retSerializedSK = append(retSerializedSK, byte(ppkem.Version>>8))
	retSerializedSK = append(retSerializedSK, byte(ppkem.Version>>16))
	retSerializedSK = append(retSerializedSK, byte(ppkem.Version>>24))
	retSerializedSK = append(retSerializedSK, originSerializedSK...)

	return retSerializedPK, retSerializedSK, nil
}

func Encaps(ppkem *ParamKem, pk []byte) ([]byte, []byte, error) {
	var serializedC, kappa []byte
	var err error
	// todo: shall be encapsed into pqringctkem
	version := uint32(pk[0]) << 0
	version |= uint32(pk[1]) << 8
	version |= uint32(pk[2]) << 16
	version |= uint32(pk[3]) << 24
	if VersionKEM(version) != ppkem.Version {
		return nil, nil, errors.New("the version of kem is not matched")
	}
	switch ppkem.Version {
	case KEM_KYBER:
		serializedC, kappa, err = pqringctkyber.Encaps(ppkem.Kyber, pk[4:])
		if err != nil {
			return nil, nil, err
		}
	default:
		log.Fatalln("Unsupported KEM version.")
	}

	retSerializedC := make([]byte, 0, 4+len(serializedC))

	retSerializedC = append(retSerializedC, byte(ppkem.Version>>0))
	retSerializedC = append(retSerializedC, byte(ppkem.Version>>8))
	retSerializedC = append(retSerializedC, byte(ppkem.Version>>16))
	retSerializedC = append(retSerializedC, byte(ppkem.Version>>24))
	retSerializedC = append(retSerializedC, serializedC...)

	return retSerializedC, kappa, nil
}

func Decaps(ppkem *ParamKem, serializedC []byte, sk []byte) ([]byte, error) {
	version := uint32(sk[0]) << 0
	version |= uint32(sk[1]) << 8
	version |= uint32(sk[2]) << 16
	version |= uint32(sk[3]) << 24
	if VersionKEM(version) != ppkem.Version {
		return nil, errors.New("the version of kem is not matched")
	}
	version = uint32(serializedC[0]) << 0
	version |= uint32(serializedC[1]) << 8
	version |= uint32(serializedC[2]) << 16
	version |= uint32(serializedC[3]) << 24
	if VersionKEM(version) != ppkem.Version {
		return nil, errors.New("the version of kem is not matched")
	}
	var kappa []byte
	var err error
	switch ppkem.Version {
	case KEM_KYBER:
		kappa, err = pqringctkyber.Decaps(ppkem.Kyber, serializedC[4:], sk[4:])
		if err != nil {
			return nil, err
		}
	default:
		log.Fatalln("Unsupported KEM version.")
	}
	return kappa, nil
}

func GetKemCiphertextBytesLen(ppkem *ParamKem) int {
	return 4 + ppkem.Kyber.CryptoCiphertextBytes()
}

func (vpk *ValuePublicKey) WellformCheck() bool {
	// todo
	return true
}

func (vsk *ValueSecretKey) WellformCheck() bool {
	// todo
	return true
}

func NewParamKem(version VersionKEM, kyber *kyber.ParameterSet) *ParamKem {
	switch version {
	case KEM_KYBER:
		return &ParamKem{
			Version: version,
			Kyber:   kyber,
		}
	default:
		return nil
	}
}

var KyberKem *ParamKem

func init() {
	KyberKem = NewParamKem(KEM_KYBER, kyber.Kyber768)
}
