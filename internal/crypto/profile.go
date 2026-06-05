package sigilcrypto

import (
	"fmt"
	"math"
	"math/bits"
	"sort"
)

type ProfileOptions struct {
	MaxLag     int
	MaxKeySize int
	BlockSizes []int
}

type SampleProfile struct {
	Size                int                  `json:"size"`
	Entropy             EntropyReport        `json:"entropy"`
	BitStats            BitStatistics        `json:"bitStats"`
	ByteStats           ByteStatistics       `json:"byteStats"`
	BlockRepeats        []BlockRepeatReport  `json:"blockRepeats"`
	Autocorrelation     []LagCorrelation     `json:"autocorrelation"`
	RepeatKeyCandidates []RepeatKeyCandidate `json:"repeatKeyCandidates"`
	Signals             []string             `json:"signals"`
	Assessment          string               `json:"assessment"`
}

type BitStatistics struct {
	TotalBits          int     `json:"totalBits"`
	OneBits            int     `json:"oneBits"`
	ZeroBits           int     `json:"zeroBits"`
	OneRatio           float64 `json:"oneRatio"`
	MonobitZScore      float64 `json:"monobitZScore"`
	LongestOneBitRun   int     `json:"longestOneBitRun"`
	LongestZeroBitRun  int     `json:"longestZeroBitRun"`
	MeanHammingWeight  float64 `json:"meanHammingWeight"`
	HammingWeightStdev float64 `json:"hammingWeightStdev"`
}

type ByteStatistics struct {
	UniqueBytes                int             `json:"uniqueBytes"`
	IndexOfCoincidence         float64         `json:"indexOfCoincidence"`
	ExpectedUniformCoincidence float64         `json:"expectedUniformCoincidence"`
	NormalizedCoincidence      float64         `json:"normalizedCoincidence"`
	LongestRepeatedByteRun     RepeatedByteRun `json:"longestRepeatedByteRun"`
	PrintableRatio             float64         `json:"printableRatio"`
	NullByteRatio              float64         `json:"nullByteRatio"`
}

type RepeatedByteRun struct {
	Byte   byte   `json:"byte"`
	Hex    string `json:"hex"`
	Length int    `json:"length"`
}

type BlockRepeatReport struct {
	BlockSize       int     `json:"blockSize"`
	Blocks          int     `json:"blocks"`
	UniqueBlocks    int     `json:"uniqueBlocks"`
	RepeatedGroups  int     `json:"repeatedGroups"`
	DuplicateBlocks int     `json:"duplicateBlocks"`
	MaxMultiplicity int     `json:"maxMultiplicity"`
	RepeatRatio     float64 `json:"repeatRatio"`
}

type LagCorrelation struct {
	Lag               int     `json:"lag"`
	Compared          int     `json:"compared"`
	EqualPairs        int     `json:"equalPairs"`
	MatchRatio        float64 `json:"matchRatio"`
	ExcessOverUniform float64 `json:"excessOverUniform"`
}

type RepeatKeyCandidate struct {
	KeySize                   int     `json:"keySize"`
	NormalizedHammingDistance float64 `json:"normalizedHammingDistance"`
	PairsCompared             int     `json:"pairsCompared"`
}

func ProfileBytes(data []byte, opts ProfileOptions) SampleProfile {
	opts = normalizeProfileOptions(opts)
	entropy := AnalyzeBytes(data)
	bitStats := analyzeBits(data)
	byteStats := analyzeByteCoincidence(data, entropy)
	blockRepeats := analyzeBlockRepeats(data, opts.BlockSizes)
	autocorrelation := analyzeAutocorrelation(data, opts.MaxLag)
	keyCandidates := analyzeRepeatKeyCandidates(data, opts.MaxKeySize)
	signals := profileSignals(entropy, bitStats, byteStats, blockRepeats, keyCandidates)

	return SampleProfile{
		Size:                len(data),
		Entropy:             entropy,
		BitStats:            bitStats,
		ByteStats:           byteStats,
		BlockRepeats:        blockRepeats,
		Autocorrelation:     autocorrelation,
		RepeatKeyCandidates: keyCandidates,
		Signals:             signals,
		Assessment:          profileAssessment(entropy, byteStats, blockRepeats, keyCandidates),
	}
}

func normalizeProfileOptions(opts ProfileOptions) ProfileOptions {
	if opts.MaxLag <= 0 {
		opts.MaxLag = 32
	}
	if opts.MaxLag > 256 {
		opts.MaxLag = 256
	}
	if opts.MaxKeySize <= 0 {
		opts.MaxKeySize = 40
	}
	if opts.MaxKeySize > 256 {
		opts.MaxKeySize = 256
	}
	if len(opts.BlockSizes) == 0 {
		opts.BlockSizes = []int{8, 16, 32}
	}
	return opts
}

func analyzeBits(data []byte) BitStatistics {
	totalBits := len(data) * 8
	if totalBits == 0 {
		return BitStatistics{}
	}

	oneBits := 0
	weightSum := 0
	weightSquares := 0
	longestOneRun := 0
	longestZeroRun := 0
	currentRun := 0
	currentBit := -1

	for _, b := range data {
		weight := bits.OnesCount8(b)
		oneBits += weight
		weightSum += weight
		weightSquares += weight * weight
		for shift := 7; shift >= 0; shift-- {
			bit := int((b >> uint(shift)) & 1)
			if bit == currentBit {
				currentRun++
			} else {
				currentBit = bit
				currentRun = 1
			}
			if bit == 1 && currentRun > longestOneRun {
				longestOneRun = currentRun
			}
			if bit == 0 && currentRun > longestZeroRun {
				longestZeroRun = currentRun
			}
		}
	}

	zeroBits := totalBits - oneBits
	meanWeight := float64(weightSum) / float64(len(data))
	variance := float64(weightSquares)/float64(len(data)) - meanWeight*meanWeight
	if variance < 0 {
		variance = 0
	}
	zScore := (float64(oneBits) - float64(totalBits)/2) / (math.Sqrt(float64(totalBits)) / 2)

	return BitStatistics{
		TotalBits:          totalBits,
		OneBits:            oneBits,
		ZeroBits:           zeroBits,
		OneRatio:           round(float64(oneBits)/float64(totalBits), 4),
		MonobitZScore:      round(zScore, 4),
		LongestOneBitRun:   longestOneRun,
		LongestZeroBitRun:  longestZeroRun,
		MeanHammingWeight:  round(meanWeight, 4),
		HammingWeightStdev: round(math.Sqrt(variance), 4),
	}
}

func analyzeByteCoincidence(data []byte, entropy EntropyReport) ByteStatistics {
	size := len(data)
	if size == 0 {
		return ByteStatistics{ExpectedUniformCoincidence: round(1.0/256.0, 6)}
	}

	var counts [256]int
	longest := RepeatedByteRun{Byte: data[0], Hex: hexByte(data[0]), Length: 1}
	currentByte := data[0]
	currentRun := 0
	for _, b := range data {
		counts[b]++
		if b == currentByte {
			currentRun++
		} else {
			currentByte = b
			currentRun = 1
		}
		if currentRun > longest.Length {
			longest = RepeatedByteRun{Byte: b, Hex: hexByte(b), Length: currentRun}
		}
	}

	unique := 0
	var coincidenceNumerator int
	for _, count := range counts {
		if count == 0 {
			continue
		}
		unique++
		coincidenceNumerator += count * (count - 1)
	}

	ioc := 0.0
	if size > 1 {
		ioc = float64(coincidenceNumerator) / float64(size*(size-1))
	}

	return ByteStatistics{
		UniqueBytes:                unique,
		IndexOfCoincidence:         round(ioc, 6),
		ExpectedUniformCoincidence: round(1.0/256.0, 6),
		NormalizedCoincidence:      round(ioc*256, 4),
		LongestRepeatedByteRun:     longest,
		PrintableRatio:             entropy.PrintableRatio,
		NullByteRatio:              entropy.NullByteRatio,
	}
}

func analyzeBlockRepeats(data []byte, blockSizes []int) []BlockRepeatReport {
	reports := make([]BlockRepeatReport, 0, len(blockSizes))
	for _, blockSize := range blockSizes {
		if blockSize <= 0 {
			continue
		}
		blockCount := len(data) / blockSize
		report := BlockRepeatReport{BlockSize: blockSize, Blocks: blockCount}
		if blockCount == 0 {
			reports = append(reports, report)
			continue
		}
		counts := make(map[string]int, blockCount)
		for offset := 0; offset+blockSize <= len(data); offset += blockSize {
			counts[string(data[offset:offset+blockSize])]++
		}
		report.UniqueBlocks = len(counts)
		for _, count := range counts {
			if count > report.MaxMultiplicity {
				report.MaxMultiplicity = count
			}
			if count > 1 {
				report.RepeatedGroups++
				report.DuplicateBlocks += count - 1
			}
		}
		report.RepeatRatio = round(float64(report.DuplicateBlocks)/float64(blockCount), 4)
		reports = append(reports, report)
	}
	return reports
}

func analyzeAutocorrelation(data []byte, maxLag int) []LagCorrelation {
	if len(data) < 2 || maxLag <= 0 {
		return []LagCorrelation{}
	}
	if maxLag >= len(data) {
		maxLag = len(data) - 1
	}
	lags := make([]LagCorrelation, 0, maxLag)
	for lag := 1; lag <= maxLag; lag++ {
		compared := len(data) - lag
		equal := 0
		for i := lag; i < len(data); i++ {
			if data[i] == data[i-lag] {
				equal++
			}
		}
		ratio := float64(equal) / float64(compared)
		lags = append(lags, LagCorrelation{
			Lag:               lag,
			Compared:          compared,
			EqualPairs:        equal,
			MatchRatio:        round(ratio, 6),
			ExcessOverUniform: round(ratio-1.0/256.0, 6),
		})
	}
	sort.Slice(lags, func(i, j int) bool {
		if lags[i].MatchRatio == lags[j].MatchRatio {
			return lags[i].Lag < lags[j].Lag
		}
		return lags[i].MatchRatio > lags[j].MatchRatio
	})
	if len(lags) > 8 {
		lags = lags[:8]
	}
	return lags
}

func analyzeRepeatKeyCandidates(data []byte, maxKeySize int) []RepeatKeyCandidate {
	if len(data) < 16 || maxKeySize < 2 {
		return []RepeatKeyCandidate{}
	}
	if maxKeySize > len(data)/4 {
		maxKeySize = len(data) / 4
	}
	candidates := make([]RepeatKeyCandidate, 0, maxKeySize)
	for keySize := 2; keySize <= maxKeySize; keySize++ {
		blockCount := len(data) / keySize
		if blockCount < 4 {
			continue
		}
		pairs := blockCount - 1
		if pairs > 8 {
			pairs = 8
		}
		total := 0.0
		for pair := 0; pair < pairs; pair++ {
			left := data[pair*keySize : (pair+1)*keySize]
			right := data[(pair+1)*keySize : (pair+2)*keySize]
			total += float64(hammingDistance(left, right)) / float64(keySize*8)
		}
		candidates = append(candidates, RepeatKeyCandidate{
			KeySize:                   keySize,
			NormalizedHammingDistance: round(total/float64(pairs), 4),
			PairsCompared:             pairs,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].NormalizedHammingDistance == candidates[j].NormalizedHammingDistance {
			return candidates[i].KeySize < candidates[j].KeySize
		}
		return candidates[i].NormalizedHammingDistance < candidates[j].NormalizedHammingDistance
	})
	if len(candidates) > 8 {
		candidates = candidates[:8]
	}
	return candidates
}

func hammingDistance(left, right []byte) int {
	if len(left) != len(right) {
		panic("hammingDistance requires equal-length buffers")
	}
	distance := 0
	for i := range left {
		distance += bits.OnesCount8(left[i] ^ right[i])
	}
	return distance
}

func profileSignals(entropy EntropyReport, bitStats BitStatistics, byteStats ByteStatistics, blockRepeats []BlockRepeatReport, keyCandidates []RepeatKeyCandidate) []string {
	if entropy.Size == 0 {
		return []string{"empty input"}
	}

	signals := make([]string, 0, 8)
	if entropy.Size < 64 {
		signals = append(signals, "sample is small; use signals as triage hints, not conclusions")
	}
	if entropy.ShannonBitsPerByte >= 7.75 && byteStats.NormalizedCoincidence <= 1.5 {
		signals = append(signals, "high entropy with near-uniform byte distribution; candidate ciphertext, compressed data, or random material")
	}
	if entropy.ShannonBitsPerByte < 4 {
		signals = append(signals, "low entropy; inspect framing, padding, constant fields, or plaintext residue")
	}
	if entropy.PrintableRatio >= 0.85 && entropy.ShannonBitsPerByte < 6.5 {
		signals = append(signals, "text-like byte mix; useful as crib material or protocol annotation")
	}
	if math.Abs(bitStats.MonobitZScore) >= 6 && bitStats.TotalBits >= 512 {
		signals = append(signals, "bit-balance anomaly; inspect encoding, truncation, or biased source material")
	}
	if byteStats.NormalizedCoincidence >= 3 && entropy.Size >= 128 {
		signals = append(signals, "elevated byte coincidence; structured alphabet or nonuniform symbol source is likely")
	}
	for _, report := range blockRepeats {
		if report.BlockSize == 16 && report.DuplicateBlocks > 0 && report.RepeatRatio >= 0.02 {
			signals = append(signals, "repeated 16-byte blocks; inspect deterministic block encryption, fixed records, or repeated headers")
			break
		}
	}
	if len(keyCandidates) > 0 && keyCandidates[0].NormalizedHammingDistance <= 0.42 && entropy.Size >= 64 {
		signals = append(signals, fmt.Sprintf("low normalized Hamming distance at key size %d; investigate periodic keying or record cadence", keyCandidates[0].KeySize))
	}
	if len(signals) == 0 {
		signals = append(signals, "no strong structural signal at configured limits")
	}
	return signals
}

func profileAssessment(entropy EntropyReport, byteStats ByteStatistics, blockRepeats []BlockRepeatReport, keyCandidates []RepeatKeyCandidate) string {
	if entropy.Size == 0 {
		return "empty input"
	}
	if entropy.Size < 64 {
		return "small-sample triage"
	}
	for _, report := range blockRepeats {
		if report.BlockSize == 16 && report.DuplicateBlocks > 0 && report.RepeatRatio >= 0.02 {
			return "repeated-block structure candidate"
		}
	}
	if len(keyCandidates) > 0 && keyCandidates[0].NormalizedHammingDistance <= 0.42 {
		return "periodicity candidate"
	}
	if entropy.ShannonBitsPerByte >= 7.75 && byteStats.NormalizedCoincidence <= 1.5 {
		return "high-entropy triage candidate"
	}
	if entropy.PrintableRatio >= 0.85 && entropy.ShannonBitsPerByte < 6.5 {
		return "text-like or crib-source candidate"
	}
	return "mixed or structured sample"
}
