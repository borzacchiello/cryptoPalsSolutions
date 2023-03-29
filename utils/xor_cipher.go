package utils

import (
	"fmt"
	"math"
	"sort"
)

var englishFreqTable = map[byte]float64{
	'T':  0.007292,
	'h':  0.040014,
	'i':  0.036309,
	's':  0.039386,
	' ':  0.237062,
	't':  0.053126,
	'e':  0.074131,
	'1':  0.000170,
	'0':  0.000055,
	'E':  0.007802,
	'x':  0.000859,
	'f':  0.012605,
	'l':  0.026778,
	'p':  0.008524,
	'r':  0.038272,
	'n':  0.039560,
	'd':  0.024510,
	'b':  0.008527,
	'y':  0.015623,
	'P':  0.002187,
	'o':  0.051554,
	'j':  0.000497,
	'c':  0.012218,
	'G':  0.002045,
	'u':  0.021036,
	'g':  0.010449,
	',':  0.015238,
	'a':  0.044825,
	'\n': 0.022802,
	'w':  0.013355,
	'W':  0.003022,
	'L':  0.004371,
	'I':  0.010224,
	'.':  0.014295,
	'm':  0.017511,
	'F':  0.002146,
	'S':  0.006231,
	'k':  0.005352,
	'C':  0.003938,
	'D':  0.002873,
	'R':  0.005308,
	'O':  0.006084,
	'M':  0.002908,
	'N':  0.005009,
	'!':  0.001620,
	'*':  0.000012,
	'<':  0.000086,
	'H':  0.003382,
	'V':  0.000656,
	'K':  0.001135,
	'A':  0.008150,
	'Y':  0.001667,
	'9':  0.000174,
	'-':  0.001479,
	'3':  0.000060,
	'B':  0.002824,
	'J':  0.000379,
	'U':  0.002589,
	'X':  0.000111,
	'(':  0.000115,
	')':  0.000115,
	'2':  0.000067,
	'>':  0.000081,
	'7':  0.000008,
	'4':  0.000017,
	'[':  0.000382,
	'#':  0.000000,
	']':  0.000381,
	'z':  0.000201,
	'8':  0.000007,
	'@':  0.000001,
	'v':  0.006227,
	':':  0.000335,
	'=':  0.000000,
	'%':  0.000000,
	'"':  0.000086,
	'/':  0.000001,
	'6':  0.000012,
	'5':  0.000015,
	'\'': 0.005692,
	';':  0.003151,
	'~':  0.000000,
	'_':  0.000013,
	'q':  0.000440,
	'Q':  0.000216,
	'?':  0.001919,
	'Z':  0.000097,
	'|':  0.000006,
	'&':  0.000004,
	'`':  0.000000,
	'}':  0.000000,
}

func EncryptXor(buf []byte, key []byte) []byte {
	res := make([]byte, 0)

	j := 0
	for i := 0; i < len(buf); i += 1 {
		res = append(res, buf[i]^key[j])
		j = (j + 1) % len(key)
	}
	return res
}

func ScoreText(buf []byte) float64 {
	counts := make(map[byte]int)
	for i := 0; i < len(buf); i++ {
		if (buf[i] < 32 || buf[i] > 126) && buf[i] != '\n' && buf[i] != '\t' {
			// Not an ascii string
			return math.MaxFloat64
		}
		b := buf[i]
		val := 0
		if v, ok := counts[b]; ok {
			val = v
		}
		counts[b] = val + 1
	}

	score := 0.0
	for b := range counts {
		if _, ok := englishFreqTable[b]; !ok {
			score += 1
			continue
		}
		score += Abs(float64(counts[b])/float64(len(buf)) - englishFreqTable[b])
	}
	return score
}

func BreakXorSingleByte(enc []byte) ([]byte, byte, float64) {
	minScore := math.MaxFloat64
	var bestKey byte
	var bestDec []byte

	for k_int := 0; k_int < 256; k_int++ {
		k := make([]byte, 0)
		k = append(k, byte(k_int))

		dec := EncryptXor(enc, k)
		score := ScoreText(dec)
		if score <= minScore {
			minScore = score
			bestDec = dec
			bestKey = byte(k_int)
		}
	}
	return bestDec, bestKey, minScore
}

func HammingDistance(buf1 []byte, buf2 []byte) (int, error) {
	if len(buf1) != len(buf2) {
		return 0, fmt.Errorf("buffers with different length")
	}

	res := 0
	for i := 0; i < len(buf1); i++ {
		b1 := buf1[i]
		b2 := buf2[i]
		for j := 0; j < 8; j++ {
			if (b1>>j)&1 != (b2>>j)&1 {
				res += 1
			}
		}
	}
	return res, nil
}

func DeduceKeysize(enc []byte, nbest int) []int {
	type SizeWithScore struct {
		size  int
		score float64
	}
	ksizes := make([]SizeWithScore, 0)

	for ksize := 2; ksize < 40; ksize++ {
		nblocks := len(enc) / ksize
		if nblocks <= 4 {
			break
		}

		blocks := make([][]byte, nblocks)
		for i := 0; i < nblocks; i++ {
			blocks[i] = enc[i*ksize : i*ksize+ksize]
		}

		nComparisons := 0
		hammingScore := 0.0
		for i := 0; i < nblocks-1; i++ {
			for j := i + 1; j < nblocks; j++ {
				score, _ := HammingDistance(blocks[i], blocks[j])
				hammingScore += float64(score)
				nComparisons += 1
			}
		}
		hammingScore /= float64(nComparisons)
		hammingScore /= float64(ksize)

		ksizes = append(ksizes, SizeWithScore{ksize, hammingScore})
	}

	sort.Slice(ksizes, func(i, j int) bool {
		return ksizes[i].score < ksizes[j].score
	})

	res := make([]int, nbest)
	for i := 0; i < nbest; i++ {
		res[i] = ksizes[i].size
	}
	return res
}

func divideBlocks(enc []byte, keysize int) [][]byte {
	blocks := make([][]byte, keysize)
	for i := 0; i < keysize; i++ {
		blocks[i] = make([]byte, 0)
	}

	off := 0
	for off+keysize <= len(enc) {
		for i := 0; i < keysize; i++ {
			blocks[i] = append(blocks[i], enc[off+i])
		}
		off += keysize
	}
	return blocks
}

func BreakXor(enc []byte) []byte {
	bestScore := math.MaxFloat64
	var bestKey []byte

	ksizes := DeduceKeysize(enc, 5)
	for i := 0; i < len(ksizes); i++ {
		ksize := ksizes[i]
		blocks := divideBlocks(enc, ksize)

		currKey := make([]byte, 0)
		currScore := 0.0
		for j := 0; j < len(blocks); j++ {
			block := blocks[j]
			_, key, score := BreakXorSingleByte(block)
			currScore += score
			currKey = append(currKey, key)
		}
		currScore /= float64(len(blocks))
		if currScore < bestScore {
			bestScore = currScore
			bestKey = currKey
		}
	}
	return bestKey
}
