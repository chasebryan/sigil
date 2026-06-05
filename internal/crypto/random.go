package sigilcrypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}:,.?"

func RandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("byte count must be positive")
	}
	if size > 1<<20 {
		return nil, fmt.Errorf("byte count is too large for one random request")
	}
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("crypto random: %w", err)
	}
	return out, nil
}

func RandomPassword(length int) (string, error) {
	if length < 16 {
		return "", fmt.Errorf("password length must be at least 16")
	}
	if length > 512 {
		return "", fmt.Errorf("password length is too large")
	}
	max := big.NewInt(int64(len(passwordAlphabet)))
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("crypto random password: %w", err)
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out), nil
}
