package pqringct

import (
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"log"
)

const RandSeedBytesLen = 64 // 512-bits

//	todo: review
// RandomBytes returns a byte array with given length from crypto/rand.Reader
func RandomBytes(length int) []byte {
	res := make([]byte, 0, length)
	for length > 0 {
		tmp := make([]byte, length)
		n, err := rand.Read(tmp)
		if err != nil {
			log.Fatalln(err) // todo: throw err?
			return nil
		}
		res = append(res, tmp[:n]...)
		length -= n
	}
	return res
}

//	todo: review and optimize
// 523987 = 0111_1111_1110_1101_0011
// randomPolyAForResponseZetaA() returns a PolyA, where each coefficient lies in [-(eta_a - beta_a), (eta_a - beta_a)],
// where eta_a = 2^{19}-1 and beta=300
func (pp *PublicParameter) randomPolyAForResponseZetaA() (*PolyA, error) {
	bound := int64(523987)

	// todo: use fix length = pp.paramDA, is thers any optimization
	coeffs := make([]int64, pp.paramDA)

	length := pp.paramDA
	buf := make([]byte, (length+7)/8)

	seed := RandomBytes(RandSeedBytesLen)

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(append(seed, byte(0)))
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	pos := 0
	for i := 0; i < length; i += 8 {
		for j := 0; j < 8; j++ {
			if (buf[pos]>>j)&1 == 0 {
				coeffs[i+j] = -1
			} else {
				coeffs[i+j] = 1
			}
		}
		pos++
	}
	cnt := 1
	cur := 0
	for cur < length {
		buf = make([]byte, (length+7)/8*19)
		xof.Reset()
		//	todo: seed is updated?
		_, err := xof.Write(append(seed, byte(cnt)))
		if err != nil {
			return nil, err
		}
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		pos = 0
		var t int64
		for pos+19 < len(buf) {
			t = int64(buf[pos+0])
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]&0x07) << 16
			t &= 0x0007FFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+2]&0xF8) >> 3
			t |= int64(buf[pos+3]) << 5
			t |= int64(buf[pos+4]&0x3F) << 13
			t &= 0x0007FFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+4]&0xC0) >> 6
			t |= int64(buf[pos+5]) << 2
			t |= int64(buf[pos+6]) << 10
			t |= int64(buf[pos+7]&0x01) << 18
			t &= 0x0007FFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+7]&0xFE) >> 1
			t |= int64(buf[pos+8]) << 7
			t |= int64(buf[pos+9]&0x0F) << 15
			t &= 0x0007FFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+9]&0xF0) >> 4
			t |= int64(buf[pos+10]) << 4
			t |= int64(buf[pos+11]&0x7F) << 12
			t &= 0x0007FFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+11]&0x80) >> 7
			t |= int64(buf[pos+12]) << 1
			t |= int64(buf[pos+13]) << 9
			t |= int64(buf[pos+14]&0x03) << 17
			t &= 0x0007FFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+14]&0xFC) >> 2
			t |= int64(buf[pos+15]) << 6
			t |= int64(buf[pos+16]&0x1F) << 14
			t &= 0x0007FFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+16]&0xE0) >> 5
			t |= int64(buf[pos+17]) << 3
			t |= int64(buf[pos+18]) << 11
			t &= 0x0007FFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			pos += 19
		}
	}
	return &PolyA{coeffs}, nil
}

//	todo: review and refactor, optimization
// 16777087 = 1111_1111_1111_1111_0111_1111
// randomPolyCForResponseZetaC() returns a PolyC, where each coefficient lies in [-(eta_c - beta_c), (eta_c - beta_c)],
// where eta_c = 2^{24}-1 and beta_c=128
func (pp *PublicParameter) randomPolyCForResponseZetaC() (*PolyC, error) {
	bound := int64(16777087)

	length := pp.paramDC // todo: fix the length to be pp.paramDC, will there is optimization?

	coeffs := make([]int64, length)

	buf := make([]byte, (length+7)/8)

	seed := RandomBytes(RandSeedBytesLen)

	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(append(seed, byte(0)))
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(buf)
	if err != nil {
		return nil, err
	}
	pos := 0
	for i := 0; i < length; i += 8 {
		for j := 0; j < 8; j++ {
			if (buf[pos]>>j)&1 == 0 {
				coeffs[i+j] = -1
			} else {
				coeffs[i+j] = 1
			}
		}
		pos++
	}
	cnt := 1
	cur := 0
	for cur < length {
		buf = make([]byte, length*3)
		xof.Reset()
		// todo: seed is updated?
		_, err := xof.Write(append(seed, byte(cnt)))
		if err != nil {
			return nil, err
		}
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		pos = 0
		var t int64
		for pos+3 < len(buf) {
			t = int64(buf[pos+0])
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]) << 16
			t &= 0x0FFFFFF
			if t < bound {
				coeffs[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			pos += 3
		}
	}

	return &PolyC{coeffs}, nil
}

//	todo: review
// 2^24-1= 1111_1111_1111_1111_1111_1111
//	randomPolyCinEtaC() outputs a PolyC, where each coefficient lies in [-eta_c, eta_c].
//	eta_c = 2^{24}-1, so that each coefficient needs 3 bytes (for absolute) and 1 bit (for signal)
func (pp *PublicParameter) randomPolyCinEtaC() (*PolyC, error) {
	coeffs := make([]int64, pp.paramDC)

	buf := make([]byte, pp.paramDC*3+pp.paramDC/8) //

	seed := RandomBytes(RandSeedBytesLen)

	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err := XOF.Write(seed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}

	//	the last pp.paramDC/8 bytes for signal
	signalBytes := make([]byte, pp.paramDC/8)
	for i := 0; i < pp.paramDC/8; i++ {
		signalBytes[i] = buf[pp.paramDC*3+i]
	}

	var abs uint32
	var signal byte
	t := 0
	for i := 0; i < pp.paramDC; i++ {
		abs = uint32(buf[t]) << 0
		abs |= uint32(buf[t+1]) << 8
		abs |= uint32(buf[t+2]) << 16

		signal = 0x01 << (i % 8)
		if signalBytes[i/8]&signal == signal {
			//	- signal
			coeffs[i] = (-1) * int64(abs)
		} else {
			coeffs[i] = int64(abs)
		}

		t += 3
	}

	return &PolyC{coeffs}, nil
}

//func randomPolyCinEtaC(seed []byte, length int) ([]int64, error) {
//	// 1<<22-1
//	res := make([]int64, length)
//	buf := make([]byte, (length+7)/8)
//	if seed == nil {
//		seed = RandomBytes(32)
//	}
//	xof := sha3.NewShake128()
//	xof.Reset()
//	_, err := xof.Write(append(seed, byte(0)))
//	if err != nil {
//		return nil, err
//	}
//	_, err = xof.Read(buf)
//	if err != nil {
//		return nil, err
//	}
//	pos := 0
//	for i := 0; i < length; i += 8 {
//		for j := 0; j < 8; j++ {
//			if (buf[pos]>>j)&1 == 0 {
//				res[i+j] = -1
//			} else {
//				res[i+j] = 1
//			}
//		}
//		pos++
//	}
//	cnt := 1
//	cur := 0
//	for cur < length {
//		buf = make([]byte, length*3)
//		xof.Reset()
//		_, err := xof.Write(append(seed, byte(cnt)))
//		if err != nil {
//			return nil, err
//		}
//		_, err = xof.Read(buf)
//		if err != nil {
//			return nil, err
//		}
//		pos = 0
//		var t int64
//		for pos+3 < len(buf) {
//			t = int64(buf[pos+0])
//			t |= int64(buf[pos+1]) << 8
//			t |= int64(buf[pos+2]) << 16
//			t &= 0x0FFFFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//		}
//	}
//	return res[:length], nil
//}

// todo: review
//	randomPolyAinEtaA() outputs a PolyA, where each coefficient lies in [-eta_a, eta_a].
//	eta_a = 2^{19}-1, so that each coefficient needs 20 bits to sample, say 19 bits (for absolute) and 1 bit (for signal).
//	That is, we can use 5 byets to sample 2 coefficients.
func (pp *PublicParameter) randomPolyAinEtaA() (*PolyA, error) {
	coeffs := make([]int64, pp.paramDA)

	buf := make([]byte, pp.paramDA/2*5)

	seed := RandomBytes(RandSeedBytesLen)

	XOF := sha3.NewShake128()
	XOF.Reset()
	_, err := XOF.Write(seed)
	if err != nil {
		return nil, err
	}
	_, err = XOF.Read(buf)
	if err != nil {
		return nil, err
	}

	var lowAbs, highAbs uint32
	t := 0
	for i := 0; i < pp.paramDA; i = i + 2 {
		lowAbs = uint32(buf[t]) << 0
		lowAbs |= uint32(buf[t+1]) << 8
		highAbs = uint32(buf[t+2]) << 0
		highAbs |= uint32(buf[t+3]) << 8

		lowAbs |= uint32(buf[t+4]&0x07) << 16
		highAbs |= uint32((buf[t+4]&0x70)>>4) << 16

		if buf[t+4]&0x08 == 0x08 {
			//	- signal
			coeffs[i] = (-1) * int64(lowAbs)
		} else {
			coeffs[i] = int64(lowAbs)
		}
		if buf[t+4]&0x80 == 0x80 {
			//	- signal
			coeffs[i+1] = (-1) * int64(highAbs)
		} else {
			coeffs[i+1] = int64(highAbs)
		}

		t += 5
	}

	return &PolyA{coeffs}, nil

}

//// 2^19-1 = 524287 = 0111_1111_1111_1111_1111
//func randomPolyAinEtaA(seed []byte, length int) ([]int64, error) {
//	res := make([]int64, length)
//	buf := make([]byte, (length+7)/8)
//	if seed == nil {
//		seed = RandomBytes(32)
//	}
//	xof := sha3.NewShake128()
//	xof.Reset()
//	_, err := xof.Write(append(seed, byte(0)))
//	if err != nil {
//		return nil, err
//	}
//	_, err = xof.Read(buf)
//	if err != nil {
//		return nil, err
//	}
//	pos := 0
//	for i := 0; i < length; i += 8 {
//		for j := 0; j < 8; j++ {
//			if (buf[pos]>>j)&1 == 0 {
//				res[i+j] = -1
//			} else {
//				res[i+j] = 1
//			}
//		}
//		pos++
//	}
//	cnt := 1
//	cur := 0
//	for cur < length {
//		buf = make([]byte, (length+7)/8*19)
//		xof.Reset()
//		_, err := xof.Write(append(seed, byte(cnt)))
//		if err != nil {
//			return nil, err
//		}
//		_, err = xof.Read(buf)
//		if err != nil {
//			return nil, err
//		}
//		pos = 0
//		var t int64
//		for pos+19 < len(buf) {
//			t = int64(buf[pos+0])
//			t |= int64(buf[pos+1]) << 8
//			t |= int64(buf[pos+2]&0x07) << 16
//			t &= 0x0007FFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//
//			t = int64(buf[pos+2]&0xF8) >> 3
//			t |= int64(buf[pos+3]) << 5
//			t |= int64(buf[pos+4]&0x3F) << 13
//			t &= 0x0007FFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//
//			t = int64(buf[pos+4]&0xC0) >> 6
//			t |= int64(buf[pos+5]) << 2
//			t |= int64(buf[pos+6]) << 10
//			t |= int64(buf[pos+7]&0x01) << 18
//			t &= 0x0007FFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//
//			t = int64(buf[pos+7]&0xFE) >> 1
//			t |= int64(buf[pos+8]) << 7
//			t |= int64(buf[pos+9]&0x0F) << 15
//			t &= 0x0007FFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//
//			t = int64(buf[pos+9]&0xF0) >> 4
//			t |= int64(buf[pos+10]) << 4
//			t |= int64(buf[pos+11]&0x7F) << 12
//			t &= 0x0007FFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//
//			t = int64(buf[pos+11]&0x80) >> 7
//			t |= int64(buf[pos+12]) << 1
//			t |= int64(buf[pos+13]) << 9
//			t |= int64(buf[pos+14]&0x03) << 17
//			t &= 0x0007FFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//
//			t = int64(buf[pos+14]&0xFC) >> 2
//			t |= int64(buf[pos+15]) << 6
//			t |= int64(buf[pos+16]&0x1F) << 14
//			t &= 0x0007FFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//
//			t = int64(buf[pos+16]&0xE0) >> 5
//			t |= int64(buf[pos+17]) << 3
//			t |= int64(buf[pos+18]) << 11
//			t &= 0x0007FFFF
//			res[cur] *= t
//			cur++
//			if cur >= length {
//				break
//			}
//
//			pos += 19
//
//		}
//	}
//	return res[:length], nil
//}

//	todo: review
// [-5,5]
func (pp *PublicParameter) randomPolyAinGammaA5(seed []byte) (*PolyA, error) {

	coeffs := make([]int64, pp.paramDA)

	bytes := make([]byte, (pp.paramDA+1)/2)

	if seed == nil {
		seed = RandomBytes(32)
	}
	xof := sha3.NewShake128()
	xof.Reset()
	_, err := xof.Write(append(seed, byte(0)))
	if err != nil {
		return nil, err
	}
	_, err = xof.Read(bytes)
	if err != nil {
		return nil, err
	}
	pos := 0
	for i := 0; i < pp.paramDA; i += 8 {
		for j := 0; j < 8; j++ {
			if (bytes[pos]>>j)&1 == 0 {
				coeffs[i+j] = -1
			} else {
				coeffs[i+j] = 1
			}
		}
		pos++
	}
	cnt := 1
	cur := 0
	for cur < pp.paramDA {
		bytes = make([]byte, (pp.paramDA+1)/2)
		xof.Reset()
		_, err := xof.Write(append(seed, byte(cnt)))
		if err != nil {
			return nil, err
		}
		_, err = xof.Read(bytes)
		if err != nil {
			return nil, err
		}
		pos = 0
		var value int64
		for pos+3 < len(bytes) {
			value = int64(bytes[pos+0] & 0x07)
			if value <= 5 {
				coeffs[cur] *= value
				cur++
				if cur >= pp.paramDA {
					break
				}
			}
			value = int64((bytes[pos+0] & 0x38) >> 3)
			if value <= 5 {
				coeffs[cur] *= value
				cur++
				if cur >= pp.paramDA {
					break
				}
			}
			value = int64(((bytes[pos+0] & 0xC0) >> 6) | ((bytes[pos+1] & 0x01) << 2))
			if value <= 5 {
				coeffs[cur] *= value
				cur++
				if cur >= pp.paramDA {
					break
				}
			}
			value = int64((bytes[pos+1] & 0x0E) >> 1)
			if value <= 5 {
				coeffs[cur] *= value
				cur++
				if cur >= pp.paramDA {
					break
				}
			}
			value = int64((bytes[pos+1] & 0x70) >> 4)
			if value <= 5 {
				coeffs[cur] *= value
				cur++
				if cur >= pp.paramDA {
					break
				}
			}
			value = int64(((bytes[pos+1] & 0xC0) >> 7) | ((bytes[pos+2] & 0x03) << 1))
			if value <= 5 {
				coeffs[cur] *= value
				cur++
				if cur >= pp.paramDA {
					break
				}
			}
			value = int64((bytes[pos+2] & 0x1C) >> 2)
			if value <= 5 {
				coeffs[cur] *= value
				cur++
				if cur >= pp.paramDA {
					break
				}
			}
			value = int64((bytes[pos+2] & 0xE0) >> 5)
			if value <= 5 {
				coeffs[cur] *= value
				cur++
				if cur >= pp.paramDA {
					break
				}
			}
			pos += 3
		}
	}
	return &PolyA{coeffs}, nil
}

//func randomPolyAinGammaA5(seed []byte, length int) ([]int64, error) {
//	res := make([]int64, length)
//	bytes := make([]byte, (length+1)/2)
//	if seed == nil {
//		seed = RandomBytes(32)
//	}
//	xof := sha3.NewShake128()
//	xof.Reset()
//	_, err := xof.Write(append(seed, byte(0)))
//	if err != nil {
//		return nil, err
//	}
//	_, err = xof.Read(bytes)
//	if err != nil {
//		return nil, err
//	}
//	pos := 0
//	for i := 0; i < length; i += 8 {
//		for j := 0; j < 8; j++ {
//			if (bytes[pos]>>j)&1 == 0 {
//				res[i+j] = -1
//			} else {
//				res[i+j] = 1
//			}
//		}
//		pos++
//	}
//	cnt := 1
//	cur := 0
//	for cur < length {
//		bytes = make([]byte, (length+1)/2)
//		xof.Reset()
//		_, err := xof.Write(append(seed, byte(cnt)))
//		if err != nil {
//			return nil, err
//		}
//		_, err = xof.Read(bytes)
//		if err != nil {
//			return nil, err
//		}
//		pos = 0
//		var value int64
//		for pos+3 < len(bytes) {
//			value = int64(bytes[pos+0] & 0x07)
//			if value <= 5 {
//				res[cur] *= value
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			value = int64((bytes[pos+0] & 0x38) >> 3)
//			if value <= 5 {
//				res[cur] *= value
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			value = int64(((bytes[pos+0] & 0xC0) >> 6) | ((bytes[pos+1] & 0x01) << 2))
//			if value <= 5 {
//				res[cur] *= value
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			value = int64((bytes[pos+1] & 0x0E) >> 1)
//			if value <= 5 {
//				res[cur] *= value
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			value = int64((bytes[pos+1] & 0x70) >> 4)
//			if value <= 5 {
//				res[cur] *= value
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			value = int64(((bytes[pos+1] & 0xC0) >> 7) | ((bytes[pos+2] & 0x03) << 1))
//			if value <= 5 {
//				res[cur] *= value
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			value = int64((bytes[pos+2] & 0x1C) >> 2)
//			if value <= 5 {
//				res[cur] *= value
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			value = int64((bytes[pos+2] & 0xE0) >> 5)
//			if value <= 5 {
//				res[cur] *= value
//				cur++
//				if cur >= length {
//					break
//				}
//			}
//			pos += 3
//		}
//	}
//	return res[:length], nil
//}
