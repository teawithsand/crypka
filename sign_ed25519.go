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

	sk = &ed25519SigningKey{
		compressSigningKey: CompressSigningKey{
			Compressor: a.Compressor,
			ActualSigner: func(ctx KeyContext, data []byte) (sign []byte, err error) {
				return innerActualSignEd25519(ctx, rawSk, data)
			},
		},
		signingKey: rawSk,
	}

	vk = &ed25519VerifyingKey{
		compressVerifyingKey: CompressVerifyingKey{
			Compressor: a.Compressor,
			ActualVerifier: func(ctx KeyContext, sign, data []byte) (err error) {
				return innerActualVerifyEd25519(ctx, rawVk, data, sign)
			},
		},
		verifyingKey: rawVk,
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

	sk = &ed25519SigningKey{
		compressSigningKey: CompressSigningKey{
			Compressor: a.Compressor,
			ActualSigner: func(ctx KeyContext, data []byte) (sign []byte, err error) {
				return innerActualSignEd25519(ctx, rawSk, data)
			},
		},
		signingKey: rawSk,
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

	vk = &ed25519VerifyingKey{
		compressVerifyingKey: CompressVerifyingKey{
			Compressor: a.Compressor,
			ActualVerifier: func(ctx KeyContext, sign, data []byte) (err error) {
				return innerActualVerifyEd25519(ctx, rawVk, data, sign)
			},
		},
		verifyingKey: rawVk,
	}

	return
}

type ed25519SigningKey struct {
	compressSigningKey CompressSigningKey
	signingKey         ed25519.PrivateKey
}

func (sk *ed25519SigningKey) MakeSigner(ctx KeyContext) (signer Signer, err error) {
	return sk.compressSigningKey.MakeSigner(ctx)
}

func (sk *ed25519SigningKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(sk.signingKey)
	return
}

type ed25519VerifyingKey struct {
	compressVerifyingKey CompressVerifyingKey
	verifyingKey         ed25519.PublicKey
}

func (vk *ed25519VerifyingKey) MakeVerifier(ctx KeyContext) (verifier Verifier, err error) {
	return vk.compressVerifyingKey.MakeVerifier(ctx)
}

func (vk *ed25519VerifyingKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(vk.verifyingKey[:])
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
