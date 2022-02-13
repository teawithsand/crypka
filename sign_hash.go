package crypka

import (
	"crypto"
	"crypto/hmac"
	"hash"
	"io"
)

// HashSignAlgorithm wraps golang's stl hash type and makes it crypka's hash types.
type HashSignAlgorithm struct {
	Hash crypto.Hash
}

type hashKey struct {
	hash crypto.Hash
}

type hashSignerVerifier struct {
	hash hash.Hash
}

func (w *hashSignerVerifier) Write(data []byte) (int, error) {
	return w.hash.Write(data)
}

func (w *hashSignerVerifier) Finalize(appendTo []byte) (sign []byte, err error) {
	return w.hash.Sum(appendTo), nil
}

func (w *hashSignerVerifier) Verify(sign []byte) (err error) {
	validHash := w.hash.Sum(nil)
	if !hmac.Equal(validHash, sign) {
		err = ErrInvalidSign
	}
	return
}

func (k *hashKey) MakeSigner(key KeyContext) (Signer, error) {
	return &hashSignerVerifier{
		hash: k.hash.New(),
	}, nil
}
func (k *hashKey) MakeVerifier(key KeyContext) (Verifier, error) {
	return &hashSignerVerifier{
		hash: k.hash.New(),
	}, nil
}

func (a *HashSignAlgorithm) GetInfo() SignAlgoInfo {
	return SignAlgoInfo{
		BaseAlgorithmInfo: BaseAlgorithmInfo{
			Type:     HashAlgorithmType,
			IsSecure: true,
		},
	}
}

func (a *HashSignAlgorithm) GenerateKey(ctx KeyGenerationContext, rng RNG) (SymmSignKey, error) {
	return &hashKey{
		hash: a.Hash,
	}, nil
}
func (a *HashSignAlgorithm) ParseSymmSignKey(ctx KeyParseContext, data []byte) (SymmSignKey, error) {
	return &hashKey{
		hash: a.Hash,
	}, nil
}

func (sk *hashKey) MarshalToWriter(w io.Writer) (err error) {
	return
}

// RegisterSTLHashes *some* of STL hashes into specified registry.
// If registry is nil then registers in global registry.
func RegisterSTLHashes(reg Registry) {
	if reg == nil {
		reg = GlobalRegistry
	}

	reg.RegisterAlgo("sha-256", &HashSignAlgorithm{crypto.SHA256})
	reg.RegisterAlgo("sha-512", &HashSignAlgorithm{crypto.SHA512})
	reg.RegisterAlgo("sha3-256", &HashSignAlgorithm{crypto.SHA3_256})
	reg.RegisterAlgo("sha3-512", &HashSignAlgorithm{crypto.SHA3_512})
}
