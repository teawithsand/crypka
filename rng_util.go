package crypka

import "io"

const ReasonableRNGSeedLength = 32

// Generates RNG seed which:
// 1. Is valid seed for RNG algo specified with info.
// 2. Is 32 bytes if it's valid value for rng.
// 3. Otherwise it's max allowed bytes.
//
// Note: this method is shortcut, but it shouldn't be used in super-secure implementations, since it sometimes may yield
// too short RNG seeds.
// Note #2: Reasonable value of 32 bytes of seed may change in future.
func GenerateReasonableRNGSeed(rng RNG, info RNGAlgoInfo) (seed []byte, err error) {
	length := info.MinSeedLength
	if length < ReasonableRNGSeedLength {
		length = info.MaxSeedLength
		if length > ReasonableRNGSeedLength {
			length = ReasonableRNGSeedLength
		}
	}

	seed = make([]byte, length)
	_, err = io.ReadFull(rng, seed)

	if err != nil {
		return
	}
	return
}
