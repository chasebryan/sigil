package sigilcrypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
	"sort"
	"strings"
)

type HashAlgorithm struct {
	Name       string `json:"name"`
	Bits       int    `json:"bits"`
	Family     string `json:"family"`
	Legacy     bool   `json:"legacy"`
	Deprecated bool   `json:"deprecated"`
}

type hashSpec struct {
	HashAlgorithm
	new func() hash.Hash
}

var hashAlgorithms = map[string]hashSpec{
	"sha256": {
		HashAlgorithm: HashAlgorithm{Name: "sha256", Bits: 256, Family: "SHA-2"},
		new:           sha256.New,
	},
	"sha384": {
		HashAlgorithm: HashAlgorithm{Name: "sha384", Bits: 384, Family: "SHA-2"},
		new:           sha512.New384,
	},
	"sha512": {
		HashAlgorithm: HashAlgorithm{Name: "sha512", Bits: 512, Family: "SHA-2"},
		new:           sha512.New,
	},
	"sha3-256": {
		HashAlgorithm: HashAlgorithm{Name: "sha3-256", Bits: 256, Family: "SHA-3"},
		new:           func() hash.Hash { return sha3.New256() },
	},
	"sha3-384": {
		HashAlgorithm: HashAlgorithm{Name: "sha3-384", Bits: 384, Family: "SHA-3"},
		new:           func() hash.Hash { return sha3.New384() },
	},
	"sha3-512": {
		HashAlgorithm: HashAlgorithm{Name: "sha3-512", Bits: 512, Family: "SHA-3"},
		new:           func() hash.Hash { return sha3.New512() },
	},
	"sha1": {
		HashAlgorithm: HashAlgorithm{Name: "sha1", Bits: 160, Family: "SHA-1", Legacy: true, Deprecated: true},
		new:           sha1.New,
	},
	"md5": {
		HashAlgorithm: HashAlgorithm{Name: "md5", Bits: 128, Family: "MD5", Legacy: true, Deprecated: true},
		new:           md5.New,
	},
}

func AvailableHashAlgorithms() []HashAlgorithm {
	algorithms := make([]HashAlgorithm, 0, len(hashAlgorithms))
	for _, spec := range hashAlgorithms {
		algorithms = append(algorithms, spec.HashAlgorithm)
	}
	sort.Slice(algorithms, func(i, j int) bool {
		if algorithms[i].Deprecated != algorithms[j].Deprecated {
			return !algorithms[i].Deprecated
		}
		return algorithms[i].Name < algorithms[j].Name
	})
	return algorithms
}

func newHash(name string) (hash.Hash, HashAlgorithm, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = "sha256"
	}
	spec, ok := hashAlgorithms[key]
	if !ok {
		return nil, HashAlgorithm{}, fmt.Errorf("unsupported hash algorithm %q", name)
	}
	return spec.new(), spec.HashAlgorithm, nil
}

func secureMACHash(name string) (func() hash.Hash, HashAlgorithm, error) {
	h, alg, err := newHash(name)
	if err != nil {
		return nil, HashAlgorithm{}, err
	}
	if alg.Deprecated {
		return nil, HashAlgorithm{}, fmt.Errorf("%s is not accepted for HMAC in Sigil because it is deprecated", alg.Name)
	}
	return func() hash.Hash {
		next, _, _ := newHash(alg.Name)
		return next
	}, HashAlgorithm{Name: alg.Name, Bits: h.Size() * 8, Family: alg.Family}, nil
}
