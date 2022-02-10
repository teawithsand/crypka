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
		Hash: a.Hash,
		Key:  keyBuf,
	}, nil
}

func (a *HMACSignAlgorithm) ParseSymmSignKey(ctx KeyGenerationContext, data []byte) (key SymmSignKey, err error) {
	if len(data) < a.MinKeyLength {
		err = ErrHMACKeyTooShort
		return
	}
	if len(data) > a.MaxKeyLength {
		err = ErrHMACKeyTooLong
		return
	}

	return &hmacKey{
		Hash: a.Hash,
		Key:  data,
	}, nil
}

type hmacKey struct {
	Hash crypto.Hash
	Key  []byte
}

func (k *hmacKey) MakeSigner(key KeyContext) (Signer, error) {
	return &hmacSignerVerifier{
		Hash: hmac.New(k.Hash.New, k.Key),
	}, nil
}

func (k *hmacKey) MakeVerifier(key KeyContext) (Verifier, error) {
	return &hmacSignerVerifier{
		Hash: hmac.New(k.Hash.New, k.Key),
	}, nil
}

func (sk *hmacKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(sk.Key)
	return
}

type hmacSignerVerifier struct {
	Hash hash.Hash
}

func (w *hmacSignerVerifier) Write(data []byte) (int, error) {
	return w.Hash.Write(data)
}

func (w *hmacSignerVerifier) Finalize(appendTo []byte) (sign []byte, err error) {
	return w.Hash.Sum(appendTo), nil
}

func (w *hmacSignerVerifier) Verify(sign []byte) (err error) {
	validHMAC := w.Hash.Sum(nil)
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

	reg.RegisterAlgo("sha-256-hmac", &HMACSignAlgorithm{
		Hash:         crypto.SHA256,
		MinKeyLength: options.MinKeyLength,
		GenKeyLength: options.GenKeyLength,
	})
	reg.RegisterAlgo("sha-512", &HMACSignAlgorithm{
		Hash:         crypto.SHA512,
		MinKeyLength: options.MinKeyLength,
		GenKeyLength: options.GenKeyLength,
	})
	reg.RegisterAlgo("sha3-256", &HMACSignAlgorithm{
		Hash:         crypto.SHA3_256,
		MinKeyLength: options.MinKeyLength,
		GenKeyLength: options.GenKeyLength,
	})
	reg.RegisterAlgo("sha3-256", &HMACSignAlgorithm{
		Hash:         crypto.SHA3_512,
		MinKeyLength: options.MinKeyLength,
		GenKeyLength: options.GenKeyLength,
	})
}
