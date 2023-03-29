package utils

import (
	"fmt"
	"math"
)

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
