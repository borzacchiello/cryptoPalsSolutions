package utils

import (
	"math"
	"sort"
)

func EncryptXor(buf []byte, key []byte) []byte {
	res := make([]byte, 0)

	j := 0
	for i := 0; i < len(buf); i += 1 {
		res = append(res, buf[i]^key[j])
		j = (j + 1) % len(key)
	}
	return res
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

	res := make([]int, Min(nbest, len(ksizes)))
	for i := 0; i < Min(nbest, len(ksizes)); i++ {
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
	for i := 0; i < len(enc)-off; i++ {
		blocks[i] = append(blocks[i], enc[off+i])
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
