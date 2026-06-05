package sigilcrypto

import (
	"math"
	"sort"
)

type ByteCount struct {
	Byte  byte    `json:"byte"`
	Hex   string  `json:"hex"`
	Count int     `json:"count"`
	Ratio float64 `json:"ratio"`
}

type EntropyReport struct {
	Size               int         `json:"size"`
	UniqueBytes        int         `json:"uniqueBytes"`
	ShannonBitsPerByte float64     `json:"shannonBitsPerByte"`
	MaxEntropyBits     float64     `json:"maxEntropyBits"`
	ChiSquare          float64     `json:"chiSquare"`
	NullByteRatio      float64     `json:"nullByteRatio"`
	PrintableRatio     float64     `json:"printableRatio"`
	TopBytes           []ByteCount `json:"topBytes"`
	Assessment         string      `json:"assessment"`
}

func AnalyzeBytes(data []byte) EntropyReport {
	var counts [256]int
	var printable int
	for _, b := range data {
		counts[b]++
		if b == '\n' || b == '\r' || b == '\t' || (b >= 32 && b <= 126) {
			printable++
		}
	}

	size := len(data)
	if size == 0 {
		return EntropyReport{Assessment: "empty input"}
	}

	var entropy float64
	var unique int
	expected := float64(size) / 256
	var chi float64
	top := make([]ByteCount, 0, 256)

	for i, c := range counts {
		if c == 0 {
			if expected > 0 {
				chi += expected
			}
			continue
		}
		unique++
		p := float64(c) / float64(size)
		entropy -= p * math.Log2(p)
		diff := float64(c) - expected
		chi += (diff * diff) / expected
		top = append(top, ByteCount{
			Byte:  byte(i),
			Hex:   hexByte(byte(i)),
			Count: c,
			Ratio: p,
		})
	}

	sort.Slice(top, func(i, j int) bool {
		if top[i].Count == top[j].Count {
			return top[i].Byte < top[j].Byte
		}
		return top[i].Count > top[j].Count
	})
	if len(top) > 12 {
		top = top[:12]
	}

	return EntropyReport{
		Size:               size,
		UniqueBytes:        unique,
		ShannonBitsPerByte: round(entropy, 4),
		MaxEntropyBits:     round(entropy*float64(size), 2),
		ChiSquare:          round(chi, 2),
		NullByteRatio:      round(float64(counts[0])/float64(size), 4),
		PrintableRatio:     round(float64(printable)/float64(size), 4),
		TopBytes:           top,
		Assessment:         entropyAssessment(entropy, size),
	}
}

func entropyAssessment(entropy float64, size int) string {
	if size < 32 {
		return "too small for a reliable distribution assessment"
	}
	switch {
	case entropy >= 7.75:
		return "high entropy; resembles compressed, encrypted, or random material"
	case entropy >= 6.5:
		return "moderate entropy; likely structured binary, compressed text, or encoded material"
	case entropy >= 4:
		return "low-to-moderate entropy; visible structure remains"
	default:
		return "low entropy; strongly structured or repetitive material"
	}
}

func hexByte(b byte) string {
	const alphabet = "0123456789abcdef"
	return string([]byte{'0', 'x', alphabet[b>>4], alphabet[b&0x0f]})
}

func round(v float64, places int) float64 {
	p := math.Pow10(places)
	return math.Round(v*p) / p
}
