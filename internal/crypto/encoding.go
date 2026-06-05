package sigilcrypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

func DecodeInput(input, encodingName string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encodingName)) {
	case "", "text", "utf8", "utf-8":
		return []byte(input), nil
	case "hex":
		clean := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ':' {
				return -1
			}
			return r
		}, input)
		out, err := hex.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("decode hex: %w", err)
		}
		return out, nil
	case "base64", "b64":
		clean := strings.TrimSpace(input)
		out, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			out, err = base64.RawStdEncoding.DecodeString(clean)
			if err != nil {
				return nil, fmt.Errorf("decode base64: %w", err)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported input encoding %q", encodingName)
	}
}

func EncodeOutput(data []byte, encodingName string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(encodingName)) {
	case "", "hex":
		return hex.EncodeToString(data), nil
	case "base64", "b64":
		return base64.StdEncoding.EncodeToString(data), nil
	case "text", "utf8", "utf-8":
		if !utf8.Valid(data) {
			return "", fmt.Errorf("data is not valid UTF-8")
		}
		return string(data), nil
	default:
		return "", fmt.Errorf("unsupported output encoding %q", encodingName)
	}
}

func FixedXOR(left, right []byte) ([]byte, error) {
	if len(left) != len(right) {
		return nil, fmt.Errorf("fixed XOR requires equal lengths")
	}
	out := make([]byte, len(left))
	for i := range left {
		out[i] = left[i] ^ right[i]
	}
	return out, nil
}

func RepeatingXOR(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("repeating XOR key cannot be empty")
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out, nil
}
