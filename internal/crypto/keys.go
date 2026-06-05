package sigilcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

type Ed25519KeyPair struct {
	PublicPEM  string `json:"publicPem"`
	PrivatePEM string `json:"privatePem"`
	PublicKey  string `json:"publicKeyBase64"`
}

func GenerateEd25519KeyPair() (Ed25519KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ed25519KeyPair{}, fmt.Errorf("generate Ed25519 key: %w", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return Ed25519KeyPair{}, fmt.Errorf("marshal Ed25519 public key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return Ed25519KeyPair{}, fmt.Errorf("marshal Ed25519 private key: %w", err)
	}

	return Ed25519KeyPair{
		PublicPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicDER,
		})),
		PrivatePEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateDER,
		})),
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}, nil
}

func SignBytes(privatePEM string, data []byte) (string, error) {
	privateKey, err := ParseEd25519PrivatePEM(privatePEM)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(privateKey, data)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func VerifyBytes(publicPEM, signatureBase64 string, data []byte) (bool, error) {
	publicKey, err := ParseEd25519PublicPEM(publicPEM)
	if err != nil {
		return false, err
	}
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("signature length is %d bytes; expected %d", len(signature), ed25519.SignatureSize)
	}
	return ed25519.Verify(publicKey, data, signature), nil
}

func ParseEd25519PrivatePEM(privatePEM string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return nil, fmt.Errorf("private key PEM block not found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not Ed25519", key)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}
	return privateKey, nil
}

func ParseEd25519PublicPEM(publicPEM string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicPEM))
	if block == nil {
		return nil, fmt.Errorf("public key PEM block not found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not Ed25519", key)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size")
	}
	return publicKey, nil
}
