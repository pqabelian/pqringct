package pqringct

import "golang.org/x/crypto/sha3"

// 523987 = 0111_1111_1110_1101_0011
func randomnessFromZetaAv2(seed []byte, length int) ([]int64, error) {
	res := make([]int64, length)
	buf := make([]byte, (length+7)/8)
	if seed == nil {
		seed = randomBytes(32)
	}
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
				res[i+j] = -1
			} else {
				res[i+j] = 1
			}
		}
		pos++
	}
	cnt := 1
	cur := 0
	for cur < length {
		buf = make([]byte, (length+7)/8*19)
		xof.Reset()
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
			if t < 523987 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+2]&0xF1) >> 3
			t |= int64(buf[pos+3]) << 5
			t |= int64(buf[pos+4]&0x3F) << 13
			t &= 0x0007FFFF
			if t < 523987 {
				res[cur] *= t
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
			if t < 523987 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+7]&0xFE) >> 1
			t |= int64(buf[pos+8]) << 7
			t |= int64(buf[pos+9]&0x0F) << 15
			t &= 0x0007FFFF
			if t < 523987 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+9]&0xF0) >> 4
			t |= int64(buf[pos+10]) << 4
			t |= int64(buf[pos+11]&0x7F) << 12
			t &= 0x0007FFFF
			if t < 523987 {
				res[cur] *= t
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
			if t < 523987 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+14]&0xFC) >> 2
			t |= int64(buf[pos+15]) << 6
			t |= int64(buf[pos+16]&0x1F) << 14
			t &= 0x0007FFFF
			if t < 523987 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+16]&0xE0) >> 5
			t |= int64(buf[pos+17]) << 3
			t |= int64(buf[pos+18]) << 11
			t &= 0x0007FFFF
			if t < 523987 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			pos += 20

		}
	}
	return res[:length], nil
}

// 16777087 = 1111_1111_1111_1111_0111_1111
func randomnessFromZetaC2v2(seed []byte, length int) ([]int64, error) {
	res := make([]int64, 0, length)
	buf := make([]byte, (length+7)/8)
	if seed == nil {
		seed = randomBytes(32)
	}
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
				res = append(res, -1)
			} else {
				res = append(res, 1)
			}
		}
		pos++
	}
	cnt := 1
	cur := 0
	for cur < length {
		buf = make([]byte, (length+2)/3)
		xof.Reset()
		_, err := xof.Write(append(seed, byte(cnt)))
		if err != nil {
			return nil, err
		}
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		pos = 0
		var t uint64
		for pos+3 < len(buf) {
			t = uint64(buf[pos+0])
			t |= uint64(buf[pos+1]) << 8
			t |= uint64(buf[pos+2]) << 16
			if t < 16777087 {
				res[cur] *= int64(t)
				cur++
				if cur >= length {
					break
				}
			}
			pos += 3
		}
	}

	return res[:length], nil
}

// 2^24-1= 1111_1111_1111_1111_1111_1111
func randomnessFromEtaCv2(seed []byte, length int) ([]int64, error) {
	// 1<<22-1
	res := make([]int64, 0, length)
	buf := make([]byte, (length+7)/8)
	if seed == nil {
		seed = randomBytes(32)
	}
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
				res = append(res, -1)
			} else {
				res = append(res, 1)
			}
		}
		pos++
	}
	cnt := 1
	cur := 0
	for cur < length {
		buf = make([]byte, (length+2)/3)
		xof.Reset()
		_, err := xof.Write(append(seed, byte(cnt)))
		if err != nil {
			return nil, err
		}
		_, err = xof.Read(buf)
		if err != nil {
			return nil, err
		}
		pos = 0
		var t uint64
		for pos+3 < len(buf) {
			t = uint64(buf[pos+0])
			t |= uint64(buf[pos+1]) << 8
			t |= uint64(buf[pos+2]) << 16
			if t < 16777215 {
				res[cur] *= int64(t)
				cur++
				if cur >= length {
					break
				}
			}
			pos += 3
		}
	}
	return res[:length], nil
}

// 2^19-1 = 524287 = 0111_1111_1111_1111_1111
func randomnessFromEtaAv2(seed []byte, length int) ([]int64, error) {
	res := make([]int64, length)
	buf := make([]byte, (length+7)/8)
	if seed == nil {
		seed = randomBytes(32)
	}
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
				res[i+j] = -1
			} else {
				res[i+j] = 1
			}
		}
		pos++
	}
	cnt := 1
	cur := 0
	for cur < length {
		buf = make([]byte, (length+7)/8*19)
		xof.Reset()
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
			if t < 524287 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+2]&0xF1) >> 3
			t |= int64(buf[pos+3]) << 5
			t |= int64(buf[pos+4]&0x3F) << 13
			t &= 0x0007FFFF
			if t < 524287 {
				res[cur] *= t
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
			if t < 524287 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+7]&0xFE) >> 1
			t |= int64(buf[pos+8]) << 7
			t |= int64(buf[pos+9]&0x0F) << 15
			t &= 0x0007FFFF
			if t < 524287 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+9]&0xF0) >> 4
			t |= int64(buf[pos+10]) << 4
			t |= int64(buf[pos+11]&0x7F) << 12
			t &= 0x0007FFFF
			if t < 524287 {
				res[cur] *= t
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
			if t < 524287 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+14]&0xFC) >> 2
			t |= int64(buf[pos+15]) << 6
			t |= int64(buf[pos+16]&0x1F) << 14
			t &= 0x0007FFFF
			if t < 524287 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+16]&0xE0) >> 5
			t |= int64(buf[pos+17]) << 3
			t |= int64(buf[pos+18]) << 11
			t &= 0x0007FFFF
			if t < 524287 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			pos += 20

		}
	}
	return res[:length], nil
}

// [-5,5]
func randomnessFromGammaA5(seed []byte, length int) ([]int64, error) {
	res := make([]int64, length)
	bytes := make([]byte, (length+1)/2)
	if seed == nil {
		seed = randomBytes(32)
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
	for i := 0; i < length; i += 8 {
		for j := 0; j < 8; j++ {
			if (bytes[pos]>>j)&1 == 0 {
				res[i+j] = -1
			} else {
				res[i+j] = 1
			}
		}
		pos++
	}
	cnt := 1
	cur := 0
	for cur < length {
		bytes = make([]byte, (length+1)/2)
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
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int64((bytes[pos+0] & 0x38) >> 3)
			if value <= 5 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int64(((bytes[pos+0] & 0xC0) >> 6) | ((bytes[pos+1] & 0x01) << 2))
			if value <= 5 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int64((bytes[pos+1] & 0x0E) >> 1)
			if value <= 5 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int64((bytes[pos+1] & 0x70) >> 4)
			if value <= 5 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int64(((bytes[pos+1] & 0xC0) >> 7) | ((bytes[pos+2] & 0x03) << 1))
			if value <= 5 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int64((bytes[pos+2] & 0x1C) >> 2)
			if value <= 5 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int64((bytes[pos+2] & 0xE0) >> 5)
			if value <= 5 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			pos += 3
		}
	}
	return res[:length], nil
}
