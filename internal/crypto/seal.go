package sigilcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const (
	DefaultPBKDF2Iterations = 600000
	DefaultChunkSize        = 1 << 20

	sealMagic       = "SIGILSEA"
	sealVersion     = byte(1)
	sealAlgAESGCM   = byte(1)
	sealKDFPBKDF2   = byte(1)
	sealSaltSize    = 16
	noncePrefixSize = 8
	headerSize      = 8 + 1 + 1 + 1 + 4 + sealSaltSize + noncePrefixSize + 4
	recordMetaSize  = 4 + 4 + 1 + 4
	recordFlagFinal = byte(1)
)

type SealOptions struct {
	Passphrase string
	Iterations int
	ChunkSize  int
}

type SealInfo struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	ChunkSize  int    `json:"chunkSize"`
}

func Seal(w io.Writer, r io.Reader, opts SealOptions) (SealInfo, error) {
	if err := validatePassphrase(opts.Passphrase); err != nil {
		return SealInfo{}, err
	}
	iterations := opts.Iterations
	if iterations == 0 {
		iterations = DefaultPBKDF2Iterations
	}
	if iterations < 100000 {
		return SealInfo{}, fmt.Errorf("PBKDF2 iterations must be at least 100000")
	}
	chunkSize := opts.ChunkSize
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize < 4096 || chunkSize > 8<<20 {
		return SealInfo{}, fmt.Errorf("chunk size must be between 4 KiB and 8 MiB")
	}

	salt, err := RandomBytes(sealSaltSize)
	if err != nil {
		return SealInfo{}, err
	}
	noncePrefix, err := RandomBytes(noncePrefixSize)
	if err != nil {
		return SealInfo{}, err
	}
	header := encodeSealHeader(iterations, chunkSize, salt, noncePrefix)

	key, err := deriveSealKey(opts.Passphrase, salt, iterations)
	if err != nil {
		return SealInfo{}, err
	}
	defer zero(key)

	aead, err := newAESGCM(key)
	if err != nil {
		return SealInfo{}, err
	}
	if _, err := w.Write(header); err != nil {
		return SealInfo{}, fmt.Errorf("write seal header: %w", err)
	}

	buf := make([]byte, chunkSize)
	var counter uint32
	for {
		n, readErr := io.ReadFull(r, buf)
		switch readErr {
		case nil:
			if err := writeSealRecord(w, aead, header, noncePrefix, counter, buf[:n], false); err != nil {
				return SealInfo{}, err
			}
			counter, err = nextCounter(counter)
			if err != nil {
				return SealInfo{}, err
			}
		case io.EOF:
			if err := writeSealRecord(w, aead, header, noncePrefix, counter, nil, true); err != nil {
				return SealInfo{}, err
			}
			return sealInfo(iterations, chunkSize), nil
		case io.ErrUnexpectedEOF:
			if err := writeSealRecord(w, aead, header, noncePrefix, counter, buf[:n], true); err != nil {
				return SealInfo{}, err
			}
			return sealInfo(iterations, chunkSize), nil
		default:
			return SealInfo{}, fmt.Errorf("read plaintext: %w", readErr)
		}
	}
}

func Open(w io.Writer, r io.Reader, passphrase string) (SealInfo, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return SealInfo{}, err
	}
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return SealInfo{}, fmt.Errorf("read seal header: %w", err)
	}
	iterations, chunkSize, salt, noncePrefix, err := parseSealHeader(header)
	if err != nil {
		return SealInfo{}, err
	}

	key, err := deriveSealKey(passphrase, salt, iterations)
	if err != nil {
		return SealInfo{}, err
	}
	defer zero(key)

	aead, err := newAESGCM(key)
	if err != nil {
		return SealInfo{}, err
	}

	meta := make([]byte, recordMetaSize)
	var expected uint32
	for {
		if _, err := io.ReadFull(r, meta); err != nil {
			if err == io.EOF {
				return SealInfo{}, fmt.Errorf("seal stream ended before the authenticated final record")
			}
			return SealInfo{}, fmt.Errorf("read seal record metadata: %w", err)
		}
		counter, plainLen, flags, sealedLen, err := parseSealRecordMeta(meta, chunkSize, aead.Overhead())
		if err != nil {
			return SealInfo{}, err
		}
		if counter != expected {
			return SealInfo{}, fmt.Errorf("seal record counter mismatch: got %d, expected %d", counter, expected)
		}
		sealed := make([]byte, sealedLen)
		if _, err := io.ReadFull(r, sealed); err != nil {
			return SealInfo{}, fmt.Errorf("read seal record ciphertext: %w", err)
		}
		nonce := sealNonce(noncePrefix, counter)
		aad := sealAAD(header, meta)
		plain, err := aead.Open(nil, nonce, sealed, aad)
		if err != nil {
			return SealInfo{}, fmt.Errorf("authenticate seal record %d: %w", counter, err)
		}
		if len(plain) != int(plainLen) {
			return SealInfo{}, fmt.Errorf("seal record %d plaintext length mismatch", counter)
		}
		if len(plain) > 0 {
			if _, err := w.Write(plain); err != nil {
				return SealInfo{}, fmt.Errorf("write plaintext: %w", err)
			}
		}
		if flags&recordFlagFinal != 0 {
			trailing, err := io.Copy(io.Discard, r)
			if err != nil {
				return SealInfo{}, fmt.Errorf("read trailing data: %w", err)
			}
			if trailing != 0 {
				return SealInfo{}, fmt.Errorf("seal stream has trailing data after final record")
			}
			return sealInfo(iterations, chunkSize), nil
		}
		expected, err = nextCounter(expected)
		if err != nil {
			return SealInfo{}, err
		}
	}
}

func validatePassphrase(passphrase string) error {
	if len(passphrase) < 12 {
		return fmt.Errorf("passphrase must be at least 12 bytes")
	}
	return nil
}

func deriveSealKey(passphrase string, salt []byte, iterations int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, 32)
	if err != nil {
		return nil, fmt.Errorf("derive seal key: %w", err)
	}
	return key, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM: %w", err)
	}
	return aead, nil
}

func encodeSealHeader(iterations, chunkSize int, salt, noncePrefix []byte) []byte {
	header := make([]byte, headerSize)
	copy(header[:8], []byte(sealMagic))
	header[8] = sealVersion
	header[9] = sealAlgAESGCM
	header[10] = sealKDFPBKDF2
	binary.BigEndian.PutUint32(header[11:15], uint32(iterations))
	copy(header[15:31], salt)
	copy(header[31:39], noncePrefix)
	binary.BigEndian.PutUint32(header[39:43], uint32(chunkSize))
	return header
}

func parseSealHeader(header []byte) (int, int, []byte, []byte, error) {
	if len(header) != headerSize {
		return 0, 0, nil, nil, fmt.Errorf("invalid seal header size")
	}
	if string(header[:8]) != sealMagic {
		return 0, 0, nil, nil, fmt.Errorf("not a Sigil seal stream")
	}
	if header[8] != sealVersion {
		return 0, 0, nil, nil, fmt.Errorf("unsupported seal version %d", header[8])
	}
	if header[9] != sealAlgAESGCM || header[10] != sealKDFPBKDF2 {
		return 0, 0, nil, nil, fmt.Errorf("unsupported seal algorithm or KDF")
	}
	iterations := int(binary.BigEndian.Uint32(header[11:15]))
	chunkSize := int(binary.BigEndian.Uint32(header[39:43]))
	if iterations < 100000 {
		return 0, 0, nil, nil, fmt.Errorf("seal stream uses too few PBKDF2 iterations")
	}
	if chunkSize < 4096 || chunkSize > 8<<20 {
		return 0, 0, nil, nil, fmt.Errorf("seal stream has invalid chunk size")
	}
	salt := append([]byte(nil), header[15:31]...)
	noncePrefix := append([]byte(nil), header[31:39]...)
	return iterations, chunkSize, salt, noncePrefix, nil
}

func writeSealRecord(w io.Writer, aead cipher.AEAD, header, noncePrefix []byte, counter uint32, plaintext []byte, final bool) error {
	if len(plaintext) > math.MaxUint32 {
		return fmt.Errorf("seal record too large")
	}
	flags := byte(0)
	if final {
		flags = recordFlagFinal
	}
	sealedLen := len(plaintext) + aead.Overhead()
	meta := encodeSealRecordMeta(counter, uint32(len(plaintext)), flags, uint32(sealedLen))
	nonce := sealNonce(noncePrefix, counter)
	aad := sealAAD(header, meta)
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	if _, err := w.Write(meta); err != nil {
		return fmt.Errorf("write seal record metadata: %w", err)
	}
	if _, err := w.Write(sealed); err != nil {
		return fmt.Errorf("write seal record ciphertext: %w", err)
	}
	return nil
}

func encodeSealRecordMeta(counter, plainLen uint32, flags byte, sealedLen uint32) []byte {
	meta := make([]byte, recordMetaSize)
	binary.BigEndian.PutUint32(meta[0:4], counter)
	binary.BigEndian.PutUint32(meta[4:8], plainLen)
	meta[8] = flags
	binary.BigEndian.PutUint32(meta[9:13], sealedLen)
	return meta
}

func parseSealRecordMeta(meta []byte, chunkSize, overhead int) (uint32, uint32, byte, uint32, error) {
	if len(meta) != recordMetaSize {
		return 0, 0, 0, 0, fmt.Errorf("invalid seal record metadata size")
	}
	counter := binary.BigEndian.Uint32(meta[0:4])
	plainLen := binary.BigEndian.Uint32(meta[4:8])
	flags := meta[8]
	sealedLen := binary.BigEndian.Uint32(meta[9:13])
	if flags&^recordFlagFinal != 0 {
		return 0, 0, 0, 0, fmt.Errorf("seal record has unknown flags")
	}
	if plainLen > uint32(chunkSize) {
		return 0, 0, 0, 0, fmt.Errorf("seal record plaintext length exceeds chunk size")
	}
	if sealedLen != plainLen+uint32(overhead) {
		return 0, 0, 0, 0, fmt.Errorf("seal record ciphertext length mismatch")
	}
	return counter, plainLen, flags, sealedLen, nil
}

func sealNonce(prefix []byte, counter uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:8], prefix)
	binary.BigEndian.PutUint32(nonce[8:12], counter)
	return nonce
}

func sealAAD(header, meta []byte) []byte {
	aad := make([]byte, 0, len(header)+len(meta))
	aad = append(aad, header...)
	aad = append(aad, meta...)
	return aad
}

func nextCounter(counter uint32) (uint32, error) {
	if counter == math.MaxUint32 {
		return 0, fmt.Errorf("seal stream exceeded maximum record count")
	}
	return counter + 1, nil
}

func sealInfo(iterations, chunkSize int) SealInfo {
	return SealInfo{
		Version:    1,
		Algorithm:  "AES-256-GCM",
		KDF:        "PBKDF2-HMAC-SHA256",
		Iterations: iterations,
		ChunkSize:  chunkSize,
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
