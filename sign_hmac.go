package crypka

import (
	"crypto"
	"crypto/hmac"
	"hash"
	"io"
)

// HMACSignAlgorithm wraps golang's stl HMAC type and makes it crypka's HMAC types.
type HMACSignAlgorithm struct {
	Hash         crypto.Hash
	MinKeyLength int
	MaxKeyLength int
	GenKeyLength int
}

func (a *HMACSignAlgorithm) GetInfo() SignAlgoInfo {
	return SignAlgoInfo{
		BaseAlgorithmInfo: BaseAlgorithmInfo{
			Type:     SymmSignAlgorithmType,
			IsSecure: a.MinKeyLength >= 32,
		},
	}
}

func (a *HMACSignAlgorithm) GenerateKey(ctx KeyGenerationContext) (key SymmSignKey, err error) {
	keyBuf := make([]byte, a.GenKeyLength)

	rng := ContextGetRNG(ctx)
	_, err = io.ReadFull(rng, keyBuf)
	if err != nil {
		return
	}

	return &hmacKey{
		hash: a.Hash,
		key:  keyBuf,
	}, nil
}

func (a *HMACSignAlgorithm) ParseSymmSignKey(ctx KeyGenerationContext, data []byte) (key SymmSignKey, err error) {
	if len(data) < a.MinKeyLength {
		err = ErrKeyParseField
		return
	}
	if len(data) > a.MaxKeyLength {
		err = ErrKeyParseField
		return
	}

	return &hmacKey{
		hash: a.Hash,
		key:  data,
	}, nil
}

type hmacKey struct {
	hash crypto.Hash
	key  []byte
}

func (k *hmacKey) MakeSigner(key KeyContext) (Signer, error) {
	return &hmacSignerVerifier{
		hash: hmac.New(k.hash.New, k.key),
	}, nil
}

func (k *hmacKey) MakeVerifier(key KeyContext) (Verifier, error) {
	return &hmacSignerVerifier{
		hash: hmac.New(k.hash.New, k.key),
	}, nil
}

func (sk *hmacKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(sk.key)
	return
}

type hmacSignerVerifier struct {
	hash hash.Hash
}

func (w *hmacSignerVerifier) Write(data []byte) (int, error) {
	return w.hash.Write(data)
}

func (w *hmacSignerVerifier) Finalize(appendTo []byte) (sign []byte, err error) {
	return w.hash.Sum(appendTo), nil
}

func (w *hmacSignerVerifier) Verify(sign []byte) (err error) {
	validHMAC := w.hash.Sum(nil)
	if !hmac.Equal(validHMAC, sign) {
		err = ErrInvalidSign
	}
	return
}

type RegisterSTLHMACsOptions struct {
	MinKeyLength int
	GenKeyLength int
}

// RegisterSTLHMACs *some* of STL HMACes into specified registry.
// If registry is nil then registers in global registry.
func RegisterSTLHMACs(reg Registry, options RegisterSTLHMACsOptions) {
	if reg == nil {
		reg = GlobalRegistry
	}

	if options.MinKeyLength == 0 {
		options.MinKeyLength = 32
	}
	if options.GenKeyLength == 0 {
		options.GenKeyLength = 32
	}

	if options.MinKeyLength < 0 {
		options.MinKeyLength = 0
	}
	if options.GenKeyLength < 0 {
		options.GenKeyLength = 0
	}

	reg.RegisterAlgo("hmac-sha-256", &HMACSignAlgorithm{
		Hash:         crypto.SHA256,
		MinKeyLength: options.MinKeyLength,
		GenKeyLength: options.GenKeyLength,
	})
	reg.RegisterAlgo("hmac-sha-512", &HMACSignAlgorithm{
		Hash:         crypto.SHA512,
		MinKeyLength: options.MinKeyLength,
		GenKeyLength: options.GenKeyLength,
	})
	reg.RegisterAlgo("hmac-sha3-256", &HMACSignAlgorithm{
		Hash:         crypto.SHA3_256,
		MinKeyLength: options.MinKeyLength,
		GenKeyLength: options.GenKeyLength,
	})
	reg.RegisterAlgo("hmac-sha3-512", &HMACSignAlgorithm{
		Hash:         crypto.SHA3_512,
		MinKeyLength: options.MinKeyLength,
		GenKeyLength: options.GenKeyLength,
	})
}
