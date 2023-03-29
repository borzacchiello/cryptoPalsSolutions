package utils

import (
	b64 "encoding/base64"
	"fmt"
	"strings"
)

func nibbleCharToInt(nibble byte) (int, error) {
	if !((nibble >= '0' && nibble <= '9') || (nibble >= 'a' && nibble <= 'f')) {
		return 0, fmt.Errorf("character '%02x' is not a valid nibble", nibble)
	}
	if nibble >= '0' && nibble <= '9' {
		return int(nibble) - int('0'), nil
	}
	return int(nibble) - int('a') + 10, nil
}

func HexToBytes(hexstr string) ([]byte, error) {
	if len(hexstr)%2 != 0 {
		return nil, fmt.Errorf("number of characters in hex string is not even")
	}

	res := make([]byte, 0)
	hexstr = strings.ToLower(hexstr)
	for i := 0; i < len(hexstr); i += 2 {
		b1, e := nibbleCharToInt(hexstr[i])
		if e != nil {
			return nil, e
		}
		b2, e := nibbleCharToInt(hexstr[i+1])
		if e != nil {
			return nil, e
		}
		b := byte(b1<<4 | b2)
		res = append(res, b)
	}
	return res, nil
}

func BytesToHex(bytes []byte) string {
	res := ""
	for i := 0; i < len(bytes); i++ {
		res += fmt.Sprintf("%02x", bytes[i])
	}
	return res
}

func ToBase64(bytes []byte) string {
	return b64.StdEncoding.EncodeToString([]byte(bytes))
}

func FromBase64(data string) ([]byte, error) {
	return b64.StdEncoding.DecodeString(data)
}

func XorBuffers(buf1 []byte, buf2 []byte) ([]byte, error) {
	if len(buf1) != len(buf2) {
		return nil, fmt.Errorf("buffers have different length")
	}
	res := make([]byte, 0)
	for i := 0; i < len(buf1); i++ {
		res = append(res, buf1[i]^buf2[i])
	}
	return res, nil
}

func Abs[T float32 | float64 | int](a T) T {
	if a < 0 {
		return -a
	}
	return a
}
