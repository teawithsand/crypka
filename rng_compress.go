package crypka

// Algorithm, which uses hash function to compress seed of arbitrary size into one appropriate for RNG.
// It's allowed for hash to return more data than RNG seed needs, but it must not yield less than required.
//
// If provided more data than requried, then only part of hash is used.
type HashCompressRNGAlgo struct {
	Compressor    SigningKey
	InnerAlgo     RNGAlgo
	MinSeedLength int
}

func (algo *HashCompressRNGAlgo) GetInfo() RNGAlgoInfo {
	info := algo.InnerAlgo.GetInfo()
	info.MinSeedLength = algo.MinSeedLength
	info.MaxSeedLength = 0
	return info
}

func (algo *HashCompressRNGAlgo) MakeRng(ctx RNGGenerationContext, seed []byte) (rng RNG, err error) {
	if len(seed) < algo.MinSeedLength {
		err = ErrInvalidRNGSeed
		return
	}

	signer, err := algo.Compressor.MakeSigner(ctx)
	if err != nil {
		return
	}

	_, err = signer.Write(seed)
	if err != nil {
		return
	}

	compressedSeed, err := signer.Finalize(nil)
	if err != nil {
		return
	}

	maxSeedLength := algo.InnerAlgo.GetInfo().MaxSeedLength
	if maxSeedLength != 0 && len(compressedSeed) > maxSeedLength {
		compressedSeed = compressedSeed[:maxSeedLength]
	}

	return algo.InnerAlgo.MakeRng(ctx, compressedSeed)
}
