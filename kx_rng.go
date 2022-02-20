package crypka

import (
	"fmt"
	"io"
)

const fallbackKXRNGAlgoSeedSize = 64

// KX Algorithm, which expands result of KX using RNG.
// It uses RNGseedBytes if not zero.
// It uses maximum possible RNG seed size.
// If max size from both algorithms is infinite, then uses 64 bytes.
// Panics if RNG requires larger seed than KX algo is able to generate.
type KXRngAlgo struct {
	KXAlgo
	RNGAlgo RNGAlgo

	RNGSeedBytes int
}

func (algo *KXRngAlgo) GetInfo() KXAlgorithmInfo {
	info := algo.KXAlgo.GetInfo()
	info.MaxResLen = 0
	info.IsSecure = algo.RNGAlgo.GetInfo().IsSecure && info.IsSecure

	return info
}

func (algo *KXRngAlgo) PerformExchange(ctx KeyContext, public KXPublic, secret KXSecret, res []byte) (err error) {
	if algo.RNGAlgo.GetInfo().RNGType != SeedRNGType {
		panic("crypka: provided rng is not seedable, and hence can't be used")
	}

	var sz int
	if algo.RNGSeedBytes != 0 {
		sz = algo.RNGSeedBytes
	} else {
		maxResLen := algo.KXAlgo.GetInfo().MaxResLen
		minRngLen := algo.RNGAlgo.GetInfo().MinSeedLength
		maxRngLen := algo.RNGAlgo.GetInfo().MaxSeedLength

		if maxResLen != 0 && minRngLen != 0 && minRngLen > maxResLen {
			panic(fmt.Errorf("rng algo requries seed, which is %d bytes but kx can produce only %d bytes", minRngLen, maxResLen))
		}

		if maxResLen != 0 {
			sz = maxResLen
		} else {
			sz = 64
		}

		if maxRngLen != 0 && sz > maxRngLen {
			sz = maxRngLen
		}
	}

	seed := make([]byte, sz)
	err = algo.KXAlgo.PerformExchange(ctx, public, secret, seed)
	if err != nil {
		return
	}

	rng, err := algo.RNGAlgo.MakeRng(ctx, seed)
	if err != nil {
		return
	}

	_, err = io.ReadFull(rng, res)
	if err != nil {
		return
	}
	return nil
}
