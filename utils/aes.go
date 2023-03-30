package utils

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

func Pad_PKCS7(data []byte, block_size int) []byte {
	if block_size <= 0 || block_size >= 256 {
		panic("invalid block size")
	}

	padNum := len(data) % block_size
	if padNum == 0 {
		padNum = block_size
	}

	pad := make([]byte, padNum)
	for i := 0; i < padNum; i++ {
		pad[i] = byte(padNum)
	}
	return append(data, pad[:]...)
}

func Unpad_PKCS7(data []byte, block_size int) ([]byte, error) {
	if block_size <= 0 || block_size >= 256 {
		panic("invalid block size")
	}
	if len(data)%block_size != 0 {
		return nil, fmt.Errorf("data length (%d) is not a multiple of block_size (%d)", len(data), block_size)
	}

	padNum := uint(data[len(data)-1])
	if padNum >= uint(block_size) || padNum == 0 || padNum >= uint(len(data)) {
		return nil, fmt.Errorf("invalid padding byte %d", padNum)
	}

	for off := uint(0); off < padNum; off++ {
		if data[len(data)-int(off)-1] != byte(padNum) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-int(padNum)], nil
}

func EncyptAES_ECB(plaintext []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = Pad_PKCS7(plaintext, 16)
	ciphertext := make([]byte, len(plaintext))
	i := 0
	for i+15 < len(plaintext) {
		cipher.Encrypt(ciphertext[i:i+16], plaintext[i:i+16])
		i += 16
	}
	return ciphertext, nil
}

func DecryptAES_ECB(ciphertext []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	i := 0
	for i+15 < len(ciphertext) {
		cipher.Decrypt(plaintext[i:i+16], ciphertext[i:i+16])
		i += 16
	}

	plaintext, err = Unpad_PKCS7(plaintext, 16)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func DetectECB(ciphertext []byte) bool {
	var blocks [][]byte

	for i := 0; i+15 < len(ciphertext); i += 16 {
		blocks = append(blocks, ciphertext[i:i+16])
	}

	for i := 0; i < len(blocks); i++ {
		for j := i + 1; j < len(blocks); j++ {
			if bytes.Equal(blocks[i], blocks[j]) {
				// indeed the probability that two blocks are equal if not
				// in ECB mode is quite low (I think at least)
				return true
			}
		}
	}
	return false
}

func EncyptAES_CBC(plaintext []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = Pad_PKCS7(plaintext, 16)
	ciphertext := make([]byte, len(plaintext))

	fmt.Printf("plaintext: %s\n", BytesToHex(plaintext))

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte('0')
	}

	prev_ciphertext_block := iv
	curr_ciphertext_block := make([]byte, 16)

	i := 0
	for i+15 < len(plaintext) {
		plaintext_block := plaintext[i : i+16]
		plaintext_xored, _ := XorBuffers(plaintext_block, prev_ciphertext_block)
		cipher.Encrypt(curr_ciphertext_block, plaintext_xored)
		copy(ciphertext[i:i+16], curr_ciphertext_block)
		prev_ciphertext_block = curr_ciphertext_block
		i += 16
	}
	return ciphertext, nil
}

func DecyptAES_CBC(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext)%16 != 0 {
		return nil, fmt.Errorf("invalid ciphertext len: %d", len(ciphertext))
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte('0')
	}

	prev_ciphertext_block := iv
	curr_plaintext_block_xored := make([]byte, 16)

	i := 0
	for i+15 < len(ciphertext) {
		ciphertext_block := ciphertext[i : i+16]
		cipher.Decrypt(curr_plaintext_block_xored, ciphertext_block)
		plaintext_block, _ := XorBuffers(curr_plaintext_block_xored, prev_ciphertext_block)
		copy(plaintext[i:i+16], plaintext_block)
		prev_ciphertext_block = ciphertext_block
		i += 16
	}

	plaintext, err = Unpad_PKCS7(plaintext, 16)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
