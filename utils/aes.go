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

	padNum := (block_size - len(data)%block_size)
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

func IsECBCypherType(oracle func([]byte) []byte) bool {
	data := make([]byte, 16*3)
	return DetectECB(oracle(data))
}

func UnknownPayloadOracle(data []byte) []byte {
	key := []byte("YELLOW SUBMARINE")
	unknown_payload, err := FromBase64("" +
		"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
		"YnkK")
	if err != nil {
		panic(err)
	}

	buf := make([]byte, len(data)+len(unknown_payload))
	copy(buf, data)
	copy(buf[len(data):], unknown_payload)
	enc, err := EncyptAES_ECB(buf, key)
	if err != nil {
		panic(err)
	}
	return enc
}

func DiscoverBlockSize(oracle func([]byte) []byte) (int, int, error) {
	// first step: discover padding size, indeed we do not know the size of the unknown payload!
	prev_size := len(UnknownPayloadOracle([]byte("")))
	padding_size := -1
	for i := 1; i < 256; i++ {
		data := make([]byte, i)
		curr_size := len(UnknownPayloadOracle(data))
		if curr_size != prev_size {
			padding_size = i
			break
		}
		prev_size = curr_size
	}
	if padding_size < 0 {
		return 0, 0, fmt.Errorf("unable to recover padding size")
	}

	// second step: discover block size
	data := make([]byte, padding_size)
	prev_size = len(UnknownPayloadOracle(data))
	block_size := -1
	for i := 1; i < 256; i++ {
		data := make([]byte, padding_size+i)
		curr_size := len(UnknownPayloadOracle(data))
		if curr_size != prev_size {
			block_size = i
			break
		}
		prev_size = curr_size
	}

	if block_size < 0 {
		return padding_size, 0, fmt.Errorf("unable to recover block size")
	}
	return padding_size, block_size, nil
}

func recoverBlock(oracleECB func([]byte) []byte, block_size int, recovered []byte) []byte {
	off := len(recovered)
	recoveredBlock := make([]byte, block_size)
	if off > 0 {
		copy(recoveredBlock, recovered[off-block_size:])
		for i := 0; i < block_size-1; i++ {
			recoveredBlock[i] = recoveredBlock[i+1]
		}
	}

	for i := 0; i < block_size; i++ {
		byteToRecover := block_size - i - 1
		targetBlock := oracleECB(recoveredBlock[:byteToRecover])[off : off+block_size]
		for i := 0; i < 256; i++ {
			recoveredBlock[block_size-1] = byte(i)
			if bytes.Equal(oracleECB(recoveredBlock)[:block_size], targetBlock) {
				break
			}
		}
		if i != block_size-1 {
			for i := 0; i < block_size-1; i++ {
				recoveredBlock[i] = recoveredBlock[i+1]
			}
		}
	}
	return recoveredBlock
}

func RecoverUnknownPayload(oracleECB func([]byte) []byte) ([]byte, error) {
	_, block_size, err := DiscoverBlockSize(oracleECB)
	if err != nil {
		return nil, err
	}

	res := make([]byte, 0)
	payloadSize := len(oracleECB([]byte("")))
	blocksToRecover := payloadSize / block_size
	for i := 0; i < blocksToRecover; i++ {
		block := recoverBlock(oracleECB, block_size, res)
		res = append(res, block...)
	}
	return res, nil
}
