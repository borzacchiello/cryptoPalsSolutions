package utils

import (
	"crypto/rand"
	"fmt"
)

func GenerateRandomBuffer(size int) []byte {
	res := make([]byte, size)
	_, err := rand.Read(res)
	if err != nil {
		panic(err)
	}
	return res
}

func RandomInt() int {
	buf := GenerateRandomBuffer(4)
	return int(buf[0]) | (int(buf[1]) << 8) | (int(buf[2]) << 16) | (int(buf[3]) << 24)
}

func EncryptRandom(data []byte) []byte {
	key := GenerateRandomBuffer(16)

	headerLen := RandomInt()%6 + 5
	footerLen := RandomInt()%6 + 5

	buf := append(GenerateRandomBuffer(headerLen), data[:]...)
	buf = append(buf, GenerateRandomBuffer(footerLen)[:]...)

	if RandomInt()%2 == 0 {
		fmt.Println("I'm using CBC")
		v, err := EncyptAES_CBC(buf, key)
		if err != nil {
			panic(err)
		}
		return v
	}
	fmt.Println("I'm using ECB")
	v, err := EncyptAES_ECB(buf, key)
	if err != nil {
		panic(err)
	}
	return v
}
