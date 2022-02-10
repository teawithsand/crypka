package crypka

import (
	"crypto/ed25519"
	"io"
)

func innerActualSignEd25519(ctx KeyContext, key ed25519.PrivateKey, data []byte) (sign []byte, err error) {
	sign = ed25519.Sign(key, data)
	return
}

func innerActualVerifyEd25519(ctx KeyContext, key ed25519.PublicKey, data, sign []byte) (err error) {
	if !ed25519.Verify(key, data, sign) {
		err = ErrInvalidSign
	}
	return
}

// Ed25519SignAsymAlgo, which uses compressor given to prevent buffering data before signing.
// This allows for easier signing of arbitrarily sized data.
type Ed25519SignAsymAlgo struct {
	Compressor SigningKey
}

func (a *Ed25519SignAsymAlgo) GetInfo() SignAlgoInfo {
	return SignAlgoInfo{
		BaseAlgorithmInfo: BaseAlgorithmInfo{
			Type:     AsymSignAlgorithmType,
			IsSecure: true,
		},
	}
}

func (a *Ed25519SignAsymAlgo) GenerateKeyPair(ctx KeyGenerationContext) (sk SigningKey, vk VerifyingKey, err error) {
	rng := ContextGetRNG(ctx)
	rawVk, rawSk, err := ed25519.GenerateKey(rng)
	if err != nil {
		return
	}

	sk = &Ed25519SigningKey{
		CompressSigningKey: CompressSigningKey{
			Compressor: a.Compressor,
			ActualSigner: func(ctx KeyContext, data []byte) (sign []byte, err error) {
				return innerActualSignEd25519(ctx, rawSk, data)
			},
		},
		SigningKey: rawSk,
	}

	vk = &Ed25519VerifyingKey{
		CompressverifyingKey: CompressverifyingKey{
			Compressor: a.Compressor,
			ActualVerifier: func(ctx KeyContext, sign, data []byte) (err error) {
				return innerActualVerifyEd25519(ctx, rawVk, data, sign)
			},
		},
		VerifyingKey: rawVk,
	}

	return
}

func (a *Ed25519SignAsymAlgo) ParseSigningKey(ctx KeyParseContext, key []byte) (sk SigningKey, err error) {
	if len(key) != ed25519.PrivateKeySize {
		err = ErrKeyParseField
		return
	}

	// do copy, so modifying key slice won't modify inner key here
	// just for safety
	rawSk := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(rawSk, key)

	sk = &Ed25519SigningKey{
		CompressSigningKey: CompressSigningKey{
			Compressor: a.Compressor,
			ActualSigner: func(ctx KeyContext, data []byte) (sign []byte, err error) {
				return innerActualSignEd25519(ctx, rawSk, data)
			},
		},
		SigningKey: rawSk,
	}

	return
}

func (a *Ed25519SignAsymAlgo) ParseVerifyingKey(ctx KeyParseContext, key []byte) (vk VerifyingKey, err error) {
	if len(key) != ed25519.PublicKeySize {
		err = ErrKeyParseField
		return
	}

	// do copy, so modifying key slice won't modify inner key here
	// just for safety
	rawVk := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(rawVk, key)

	vk = &Ed25519VerifyingKey{
		CompressverifyingKey: CompressverifyingKey{
			Compressor: a.Compressor,
			ActualVerifier: func(ctx KeyContext, sign, data []byte) (err error) {
				return innerActualVerifyEd25519(ctx, rawVk, data, sign)
			},
		},
		VerifyingKey: rawVk,
	}

	return
}

type Ed25519SigningKey struct {
	CompressSigningKey
	SigningKey ed25519.PrivateKey
}

func (sk *Ed25519SigningKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(sk.SigningKey)
	return
}

type Ed25519VerifyingKey struct {
	CompressverifyingKey
	VerifyingKey ed25519.PublicKey
}

func (vk *Ed25519VerifyingKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(vk.VerifyingKey)
	return
}

type RegisterEd25519Options struct {
	CompressorData []struct {
		Suffix     string
		Compressor SigningKey
	}
}

func RegisterEd25519(reg Registry, options RegisterEd25519Options) {
	if reg == nil {
		reg = GlobalRegistry
	}

	if len(options.CompressorData) == 0 {

		options.CompressorData = []struct {
			Suffix     string
			Compressor SigningKey
		}{
			{
				Suffix:     "sha-256",
				Compressor: nil,
			},
			{
				Suffix:     "sha-512",
				Compressor: nil,
			},
			{
				Suffix:     "sha3-256",
				Compressor: nil,
			},
			{
				Suffix:     "sha3-512",
				Compressor: nil,
			},
		}
	}

	for _, config := range options.CompressorData {
		if config.Compressor == nil {
			var signingAlgo SignSymmAlgo
			innerErr := reg.GetAlgorithmTyped(config.Suffix, &signingAlgo)
			if innerErr != nil {
				continue
			}

			key, innerErr := signingAlgo.GenerateKey(nil)
			if innerErr != nil {
				continue
			}

			config.Compressor = key
		}

		reg.RegisterAlgo("ed25519-"+config.Suffix, Ed25519SignAsymAlgo{
			Compressor: config.Compressor,
		})
	}
}
