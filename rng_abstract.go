package crypka

import "io"

// Base RNG type.
// Base RNG is simple reader.
// It may implement additional interfaces.
type RNG interface {
	io.Reader
}

type RNGType uint8

const (
	// RNG, which was created from some seed. It may generate finite amount of random data before looping.
	SeedRNGType RNGType = 1

	// RNG, which collects entropy from environment(most of the time os does that).
	// It generates infinite amount of random data and can't be constructed with seed.
	EnvRNGType RNGType = 2
)

type RNGAlgoInfo struct {
	BaseAlgorithmInfo
	Type              RNGType
	MaxGeneratedBytes uint64 // 0 corresponds to infinite
}

type RNGAlgo interface {
	GetInfo() RNGAlgoInfo
	MakeRng(ctx RNGGenerationContext, seed []byte) (rng RNG, err error)
}
