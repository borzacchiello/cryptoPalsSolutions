package main

import (
	"bufio"
	"cryptopals/utils"
	"fmt"
	"math"
	"os"
)

func ex_1_1() {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	data, err := utils.HexToBytes(hex)
	if err != nil {
		panic(err)
	}
	datab64 := utils.ToBase64(data)
	fmt.Println("ex_1_1:")
	fmt.Printf("  hex: %s\n", hex)
	fmt.Printf("  converted: %s\n", datab64)
}

func ex_1_2() {
	hex_b1 := "1c0111001f010100061a024b53535009181c"
	hex_b2 := "686974207468652062756c6c277320657965"
	b1, err := utils.HexToBytes(hex_b1)
	if err != nil {
		panic(err)
	}
	b2, err := utils.HexToBytes(hex_b2)
	if err != nil {
		panic(err)
	}
	data, err := utils.XorBuffers(b1, b2)
	if err != nil {
		panic(err)
	}
	fmt.Println("ex_1_2:")
	fmt.Printf("  buf1: %s\n", hex_b1)
	fmt.Printf("  buf2: %s\n", hex_b2)
	fmt.Printf("  res:  %s\n", utils.BytesToHex(data))
}

func ex_1_3() {
	hex_buf := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	buf, err := utils.HexToBytes(hex_buf)
	if err != nil {
		panic(err)
	}

	fmt.Println("ex_1_3:")
	dec, _, _ := utils.BreakXorSingleByte(buf)
	fmt.Printf("  dec: %s\n", dec)
}

func ex_1_4() {
	readFile, err := os.Open("data/4.txt")
	if err != nil {
		panic(err)
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	minScore := math.MaxFloat64
	var bestMatch []byte
	for fileScanner.Scan() {
		hexBuf := fileScanner.Text()
		buf, err := utils.HexToBytes(hexBuf)
		if err != nil {
			panic(err)
		}
		dec, _, score := utils.BreakXorSingleByte(buf)
		if score <= minScore {
			minScore = score
			bestMatch = dec
		}
	}
	fmt.Println("ex_1_4:")
	fmt.Printf("  dec: %s\n", bestMatch)
}

func ex_1_5() {
	txt := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	fmt.Println("ex_1_5:")
	fmt.Printf("  enc: %s\n", utils.BytesToHex(utils.EncryptXor(txt, key)))
}

func ex_1_6() {
	str1 := []byte("this is a test")
	str2 := []byte("wokka wokka!!!")

	fmt.Println("ex_1_6:")
	dist, err := utils.HammingDistance(str1, str2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  hamming distance: %d\n", dist)

	enc := utils.EncryptXor([]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("pantofola"))
	fmt.Printf("  keysize guesses: %v\n", utils.DeduceKeysize(enc, 5))

	data, err := os.ReadFile("data/6.txt")
	if err != nil {
		panic(err)
	}
	enc, err = utils.FromBase64(string(data))
	if err != nil {
		panic(err)
	}
	key := utils.BreakXor(enc)
	fmt.Printf("  recovered key: \"%s\"\n", key)
	fmt.Printf("  recovered text:\n%s\n", utils.EncryptXor(enc, key))
}

func ex_1_7() {
	plaintext := []byte("barbabietola da zucchero")
	key := []byte("YELLOW SUBMARINE")
	ciphertext, err := utils.EncyptAES_ECB(plaintext, key)
	if err != nil {
		panic(err)
	}

	decoded1, err := utils.DecryptAES_ECB(ciphertext, key)
	if err != nil {
		panic(err)
	}

	data, err := os.ReadFile("data/7.txt")
	if err != nil {
		panic(err)
	}
	ciphertext, err = utils.FromBase64(string(data))
	if err != nil {
		panic(err)
	}

	decoded2, err := utils.DecryptAES_ECB(ciphertext, key)
	if err != nil {
		panic(err)
	}

	fmt.Println("ex_1_7:")
	fmt.Printf("  decoded1: %s\n", decoded1)
	fmt.Printf("  decoded2: %s\n", decoded2)
}

func ex_1_8() {
	readFile, err := os.Open("data/8.txt")
	if err != nil {
		panic(err)
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	fmt.Println("ex_1_8:")
	for fileScanner.Scan() {
		hexBuf := fileScanner.Text()
		buf, err := utils.HexToBytes(hexBuf)
		if err != nil {
			panic(err)
		}
		if utils.DetectECB(buf) {
			fmt.Printf("  block \"%s ...\" was (probably) encoded with ECB\n", hexBuf[:16])
		}
	}
}

func ex_2_9() {
	buf := "ciao"
	fmt.Println("ex_2_9:")
	fmt.Printf("  padded: %s\n", utils.BytesToHex(utils.Pad_PKCS7([]byte(buf), 16)))
}

func ex_2_10() {
	plain := []byte("barbabietola da zucchero")
	key := []byte("YELLOW SUBMARINE")
	ciphertext1, err := utils.EncyptAES_CBC(plain, key)
	if err != nil {
		panic(err)
	}

	data, err := os.ReadFile("data/10.txt")
	if err != nil {
		panic(err)
	}
	ciphertext2, err := utils.FromBase64(string(data))
	if err != nil {
		panic(err)
	}

	fmt.Println("ex_2_10:")
	dec1, err := utils.DecyptAES_CBC(ciphertext1, key)
	if err != nil {
		panic(err)
	}
	dec2, err := utils.DecyptAES_CBC(ciphertext2, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  dec1: %s\n", dec1)
	fmt.Printf("  dec2: %s\n", dec2)
}

func ex_2_11() {
	fmt.Println("ex_2_11:")
	for i := 0; i < 20; i++ {
		if utils.IsECBCypherType(utils.EncryptRandom) {
			fmt.Println("^ is ECB")
		} else {
			fmt.Println("^ is not ECB")
		}
	}
}

func ex_2_12() {
	fmt.Println("ex_2_11:")

	padding_size, block_size, err := utils.DiscoverBlockSize(utils.UnknownPayloadOracle)
	if err != nil {
		panic(err)
	}
	is_ecb := utils.IsECBCypherType(utils.UnknownPayloadOracle)
	unknwon_payload_size := len(utils.UnknownPayloadOracle([]byte(""))) - padding_size
	fmt.Printf("  padding_size: %d, block_size: %d, unknwon_payload_size: %d, is_ecb: %t\n",
		padding_size, block_size, unknwon_payload_size, is_ecb)
	payload, err := utils.RecoverUnknownPayload(utils.UnknownPayloadOracle)
	if err != nil {
		panic(err)
	}
	payload = payload[:unknwon_payload_size]
	fmt.Printf("  payload:\n%s\n", payload)
}

func main() {
	ex_1_1()
	ex_1_2()
	ex_1_3()
	ex_1_4()
	ex_1_5()
	ex_1_6()
	ex_1_7()
	ex_1_8()
	ex_2_9()
	ex_2_10()
	ex_2_11()
	ex_2_12()
}
