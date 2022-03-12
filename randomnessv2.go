package pqringct

import "golang.org/x/crypto/sha3"

// 1000_1000_0111_0110_1101
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
		buf = make([]byte, (length+1)/2*7)
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
		for pos+3 < len(buf) {
			t = int64(buf[pos+0])
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]&0x0F) << 16
			t &= 0x000FFFFF
			if t < 559257 {
				res[cur] *= t
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

// 0011_1111_1111_1111_1000_0000
func randomnessFromZetaC2v2(seed []byte, length int) ([]int32, error) {
	res := make([]int32, 0, length)
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
		buf = make([]byte, (11*length+7)/8)
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
		var value int32
		for pos+11 < len(buf) {
			value = int32(buf[pos+0]&0xFF)<<14 | int32(buf[pos+1])<<6 | int32(buf[pos+2]&0xFC)>>2
			if value < 1<<22-18 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int32(buf[pos+2]&0x03)<<20 | int32(buf[pos+3])<<12 | int32(buf[pos+4])<<4 | int32(buf[pos+5]&0xF0)>>4
			if value < 1<<22-18 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int32(buf[pos+5]&0x0F)<<18 | int32(buf[pos+6])<<10 | int32(buf[pos+7])<<2 | int32(buf[pos+8]&0xC0)>>6
			if value < 1<<22-18 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			value = int32(buf[pos+8]&0x3F)<<16 | int32(buf[pos+9])<<8 | int32(buf[pos+10]&0xFF)>>0
			if value < 1<<22-18 {
				res[cur] *= value
				cur++
				if cur >= length {
					break
				}
			}
			pos += 11
		}
	}

	return res[:length], nil
}

func randomnessFromEtaCv2(seed []byte, length int) ([]int32, error) {
	// 1<<22-1
	res := make([]int32, 0, length)
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
		buf = make([]byte, (11*length+7)/8)
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
		for pos+10 < len(buf) {
			res[cur] *= int32(buf[pos+0]&0xFF)<<14 | int32(buf[pos+1])<<6 | int32(buf[pos+2]&0xFC)>>2
			cur++
			if cur >= length {
				break
			}
			res[cur] *= int32(buf[pos+2]&0x03)<<20 | int32(buf[pos+3])<<12 | int32(buf[pos+4])<<4 | int32(buf[pos+5]&0xF0)>>4
			cur++
			if cur >= length {
				break
			}
			res[cur] *= int32(buf[pos+5]&0x0F)<<18 | int32(buf[pos+6])<<10 | int32(buf[pos+7])<<2 | int32(buf[pos+8]&0xC0)>>6
			cur++
			if cur >= length {
				break
			}
			res[cur] *= int32(buf[pos+8]&0x3F)<<16 | int32(buf[pos+9])<<8 | int32(buf[pos+10]&0xFF)>>0
			cur++
			if cur >= length {
				break
			}
			pos += 11
		}
	}
	return res[:length], nil
}

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
	// 559557 = 1000_1000_1001_1100_0101
	for cur < length {
		buf = make([]byte, (5*length+1)/2)
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
		for pos+3 < len(buf) {
			t = int64(buf[pos+0])
			t |= int64(buf[pos+1]) << 8
			t |= int64(buf[pos+2]&0x0F) << 16
			t &= 0x000FFFFF
			if t < 559557 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			t = int64(buf[pos+2]&0xF0) >> 4
			t |= int64(buf[pos+3]) << 12
			t |= int64(buf[pos+4]) << 20
			t &= 0x000FFFFF
			if t < 559557 {
				res[cur] *= t
				cur++
				if cur >= length {
					break
				}
			}
			pos += 5
		}
	}
	return res[:length], nil
}

// [-5,5]
func randomnessFromGammaAv2(seed []byte, length int) ([]int64, error) {
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
