package pqringct

import "golang.org/x/crypto/sha3"

const HashBytesLen = 32

// Hash encapsulates a hash function to output a byte stream of arbitrary length
// TODO_DONE: Should be as a parameter not a function,in that way, it can be substitute by other function?
// this function can be changed by other hash function than sha3.NewShake256
func Hash(data []byte) ([]byte, error) {
	shake256 := sha3.NewShake256()
	_, err := shake256.Write(data)
	if err != nil {
		return nil, err
	}
	res := make([]byte, 32)
	_, err = shake256.Read(res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
