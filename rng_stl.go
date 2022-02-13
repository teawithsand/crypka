package crypka

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
)

// RNG which uses crypto/rand.Reader to provide RNG.
type CryptoRNGAlgo struct {
}

func (algo *CryptoRNGAlgo) GetInfo() RNGAlgoInfo {
	return RNGAlgoInfo{
		BaseAlgorithmInfo: BaseAlgorithmInfo{
			Type:     RNGAlgorithmType,
			IsSecure: true,
		},
		RNGType: EnvRNGType,
	}
}

func (algo *CryptoRNGAlgo) MakeRng(ctx RNGGenerationContext, seed []byte) (rng RNG, err error) {
	rng = rand.Reader
	return
}

// RNG which uses math/rand to provide RNG.
// It's not secure.
type MathRNGAlgo struct {
}

func (algo *MathRNGAlgo) GetInfo() RNGAlgoInfo {
	return RNGAlgoInfo{
		BaseAlgorithmInfo: BaseAlgorithmInfo{
			Type:     RNGAlgorithmType,
			IsSecure: false,
		},
		RNGType:       SeedRNGType,
		MinSeedLength: 8,
		MaxSeedLength: 8,
	}
}

func (algo *MathRNGAlgo) MakeRng(ctx RNGGenerationContext, seed []byte) (rng RNG, err error) {
	if len(seed) != 8 {
		err = ErrInvalidRNGSeed
		return
	}

	var parsedSeed int64
	err = binary.Read(bytes.NewReader(seed), binary.BigEndian, &parsedSeed)
	if err != nil {
		return
	}

	plainRng := mrand.New(mrand.NewSource(parsedSeed))

	rng = plainRng
	return
}
