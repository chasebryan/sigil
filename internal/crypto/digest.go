package sigilcrypto

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

type DigestResult struct {
	Algorithm HashAlgorithm `json:"algorithm"`
	Size      int64         `json:"size"`
	Hex       string        `json:"hex"`
	Base64    string        `json:"base64"`
}

type MACResult struct {
	Algorithm HashAlgorithm `json:"algorithm"`
	Size      int64         `json:"size"`
	Hex       string        `json:"hex"`
	Base64    string        `json:"base64"`
}

func DigestBytes(data []byte, algorithm string) (DigestResult, error) {
	return DigestReader(bytes.NewReader(data), algorithm)
}

func DigestReader(r io.Reader, algorithm string) (DigestResult, error) {
	h, alg, err := newHash(algorithm)
	if err != nil {
		return DigestResult{}, err
	}
	n, err := io.Copy(h, r)
	if err != nil {
		return DigestResult{}, fmt.Errorf("digest stream: %w", err)
	}
	sum := h.Sum(nil)
	return DigestResult{
		Algorithm: alg,
		Size:      n,
		Hex:       hex.EncodeToString(sum),
		Base64:    base64.StdEncoding.EncodeToString(sum),
	}, nil
}

func HMACBytes(data, key []byte, algorithm string) (MACResult, error) {
	hf, alg, err := secureMACHash(algorithm)
	if err != nil {
		return MACResult{}, err
	}
	if len(key) < 16 {
		return MACResult{}, fmt.Errorf("HMAC keys should be at least 16 bytes")
	}
	mac := hmac.New(hf, key)
	if _, err := mac.Write(data); err != nil {
		return MACResult{}, fmt.Errorf("HMAC write: %w", err)
	}
	sum := mac.Sum(nil)
	return MACResult{
		Algorithm: alg,
		Size:      int64(len(data)),
		Hex:       hex.EncodeToString(sum),
		Base64:    base64.StdEncoding.EncodeToString(sum),
	}, nil
}
