package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	sigilcrypto "github.com/chasebryan/sigil/internal/crypto"
	"github.com/chasebryan/sigil/internal/gui"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "sigil:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stdout)
		return nil
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "sigil %s\n", version)
		return nil
	case "algorithms":
		return writeJSON(stdout, sigilcrypto.AvailableHashAlgorithms())
	case "digest":
		return digestCommand(args[1:], stdout)
	case "hmac":
		return hmacCommand(args[1:], stdout)
	case "random":
		return randomCommand(args[1:], stdout)
	case "entropy":
		return entropyCommand(args[1:], stdout)
	case "xor":
		return xorCommand(args[1:], stdout)
	case "keygen":
		return keygenCommand(args[1:], stdout)
	case "sign":
		return signCommand(args[1:], stdout)
	case "verify":
		return verifyCommand(args[1:], stdout)
	case "seal":
		return sealCommand(args[1:], stdout)
	case "open":
		return openCommand(args[1:], stdout)
	case "gui":
		return guiCommand(args[1:], stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func digestCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("digest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	alg := fs.String("alg", "sha256", "hash algorithm")
	if err := fs.Parse(args); err != nil {
		return err
	}
	input, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	result, err := sigilcrypto.DigestBytes(input, *alg)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func hmacCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("hmac", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	alg := fs.String("alg", "sha256", "hash algorithm")
	key := fs.String("key", "", "key material")
	keyEncoding := fs.String("key-encoding", "hex", "key encoding: hex, base64, text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return fmt.Errorf("missing -key")
	}
	keyBytes, err := sigilcrypto.DecodeInput(*key, *keyEncoding)
	if err != nil {
		return err
	}
	input, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	result, err := sigilcrypto.HMACBytes(input, keyBytes, *alg)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func randomCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("random", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bytesCount := fs.Int("bytes", 32, "random byte count")
	passwordLength := fs.Int("password", 0, "generate password of this length")
	output := fs.String("out", "hex", "output encoding: hex, base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *passwordLength > 0 {
		password, err := sigilcrypto.RandomPassword(*passwordLength)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, password)
		return nil
	}
	random, err := sigilcrypto.RandomBytes(*bytesCount)
	if err != nil {
		return err
	}
	encoded, err := sigilcrypto.EncodeOutput(random, *output)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, encoded)
	return nil
}

func entropyCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("entropy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	encodingName := fs.String("encoding", "text", "input encoding: text, hex, base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := readEncodedInput(fs.Arg(0), *encodingName)
	if err != nil {
		return err
	}
	return writeJSON(stdout, sigilcrypto.AnalyzeBytes(data))
}

func xorCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("xor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	left := fs.String("left", "", "left input")
	right := fs.String("right", "", "right input or repeating key")
	mode := fs.String("mode", "fixed", "fixed or repeating")
	encodingName := fs.String("encoding", "hex", "input encoding")
	output := fs.String("out", "hex", "output encoding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *left == "" || *right == "" {
		return fmt.Errorf("missing -left or -right")
	}
	leftBytes, err := sigilcrypto.DecodeInput(*left, *encodingName)
	if err != nil {
		return err
	}
	rightBytes, err := sigilcrypto.DecodeInput(*right, *encodingName)
	if err != nil {
		return err
	}
	var out []byte
	switch strings.ToLower(*mode) {
	case "fixed":
		out, err = sigilcrypto.FixedXOR(leftBytes, rightBytes)
	case "repeating":
		out, err = sigilcrypto.RepeatingXOR(leftBytes, rightBytes)
	default:
		err = fmt.Errorf("unknown XOR mode %q", *mode)
	}
	if err != nil {
		return err
	}
	encoded, err := sigilcrypto.EncodeOutput(out, *output)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, encoded)
	return nil
}

func keygenCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	pair, err := sigilcrypto.GenerateEd25519KeyPair()
	if err != nil {
		return err
	}
	return writeJSON(stdout, pair)
}

func signCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	privatePath := fs.String("key", "", "private key PEM path")
	encodingName := fs.String("encoding", "text", "input encoding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privatePath == "" {
		return fmt.Errorf("missing -key")
	}
	privatePEM, err := os.ReadFile(*privatePath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	data, err := readEncodedInput(fs.Arg(0), *encodingName)
	if err != nil {
		return err
	}
	signature, err := sigilcrypto.SignBytes(string(privatePEM), data)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, signature)
	return nil
}

func verifyCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	publicPath := fs.String("key", "", "public key PEM path")
	signature := fs.String("sig", "", "base64 signature")
	encodingName := fs.String("encoding", "text", "input encoding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *publicPath == "" || *signature == "" {
		return fmt.Errorf("missing -key or -sig")
	}
	publicPEM, err := os.ReadFile(*publicPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	data, err := readEncodedInput(fs.Arg(0), *encodingName)
	if err != nil {
		return err
	}
	ok, err := sigilcrypto.VerifyBytes(string(publicPEM), *signature, data)
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]bool{"valid": ok})
}

func sealCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outPath := fs.String("out", "", "output file path")
	passphrase := fs.String("passphrase", "", "passphrase; prefer SIGIL_PASSPHRASE or -passphrase-file")
	passphraseFile := fs.String("passphrase-file", "", "passphrase file")
	iterations := fs.Int("iterations", sigilcrypto.DefaultPBKDF2Iterations, "PBKDF2 iterations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	phrase, err := resolvePassphrase(*passphrase, *passphraseFile)
	if err != nil {
		return err
	}
	in, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	var out bytes.Buffer
	info, err := sigilcrypto.Seal(&out, bytes.NewReader(in), sigilcrypto.SealOptions{
		Passphrase: phrase,
		Iterations: *iterations,
	})
	if err != nil {
		return err
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, out.Bytes(), 0600); err != nil {
			return fmt.Errorf("write sealed file: %w", err)
		}
		return writeJSON(stdout, info)
	}
	_, err = stdout.Write(out.Bytes())
	return err
}

func openCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outPath := fs.String("out", "", "output file path")
	passphrase := fs.String("passphrase", "", "passphrase; prefer SIGIL_PASSPHRASE or -passphrase-file")
	passphraseFile := fs.String("passphrase-file", "", "passphrase file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	phrase, err := resolvePassphrase(*passphrase, *passphraseFile)
	if err != nil {
		return err
	}
	in, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if _, err := sigilcrypto.Open(&out, bytes.NewReader(in), phrase); err != nil {
		return err
	}
	if *outPath != "" {
		return os.WriteFile(*outPath, out.Bytes(), 0600)
	}
	_, err = stdout.Write(out.Bytes())
	return err
}

func guiCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("gui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "127.0.0.1:8765", "local listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return gui.Serve(gui.Config{Addr: *addr, Stdout: stdout})
}

func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return data, nil
}

func readEncodedInput(valueOrPath, encodingName string) ([]byte, error) {
	if valueOrPath == "" || valueOrPath == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return sigilcrypto.DecodeInput(string(data), encodingName)
	}
	if strings.HasPrefix(valueOrPath, "@") {
		data, err := os.ReadFile(strings.TrimPrefix(valueOrPath, "@"))
		if err != nil {
			return nil, fmt.Errorf("read encoded input: %w", err)
		}
		return sigilcrypto.DecodeInput(string(data), encodingName)
	}
	return sigilcrypto.DecodeInput(valueOrPath, encodingName)
}

func resolvePassphrase(flagValue, passphraseFile string) (string, error) {
	if passphraseFile != "" {
		data, err := os.ReadFile(passphraseFile)
		if err != nil {
			return "", fmt.Errorf("read passphrase file: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	if env := os.Getenv("SIGIL_PASSPHRASE"); env != "" {
		return env, nil
	}
	if flagValue != "" {
		return flagValue, nil
	}
	return "", fmt.Errorf("missing passphrase; set SIGIL_PASSPHRASE or use -passphrase-file")
}

func writeJSON(w io.Writer, v any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `Sigil cryptography suite

Usage:
  sigil gui [-addr 127.0.0.1:8765]
  sigil digest [-alg sha256] [file|-]
  sigil hmac [-alg sha256] -key <material> [-key-encoding hex] [file|-]
  sigil random [-bytes 32|-password 32] [-out hex|base64]
  sigil entropy [-encoding text|hex|base64] [value|@file|-]
  sigil xor -left <value> -right <value> [-mode fixed|repeating] [-encoding hex]
  sigil keygen
  sigil sign -key private.pem [-encoding text|hex|base64] [value|@file|-]
  sigil verify -key public.pem -sig <base64> [-encoding text|hex|base64] [value|@file|-]
  sigil seal [-out file.sigil] [-passphrase-file path] [file|-]
  sigil open [-out file] [-passphrase-file path] [file.sigil|-]

Sigil uses standard-library cryptography only in this first slice: SHA-2,
SHA-3, HMAC, Ed25519, cryptographic random, and AES-256-GCM seal streams.`)
}
