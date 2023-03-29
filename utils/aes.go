package utils

import (
	"bytes"
	"crypto/aes"
)

func EncyptAES_ECB(plaintext []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	i := 0
	for i+15 < len(plaintext) {
		cipher.Encrypt(ciphertext[i:i+16], plaintext[i:i+16])
		i += 16
	}

	if i < len(plaintext) {
		block := make([]byte, 16)
		num_el := copy(block, plaintext[i:])
		padding_size := byte(16 - num_el)
		block[num_el] = padding_size
		for j := 0; j < int(padding_size); j++ {
			ciphertext = append(ciphertext, 0)
		}
		cipher.Encrypt(ciphertext[i:], block)
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

	// Check for padding, and eventually remove it
	j := len(plaintext) - 1
	for j >= 0 && plaintext[j] == 0 {
		j--
	}
	len_padding := int(plaintext[j])
	if len_padding == len(plaintext)-j {
		plaintext = plaintext[:len(plaintext)-len_padding]
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
