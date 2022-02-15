package crypka_test

import (
	"crypto"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestRNG_HashCompress_WithSTLMathPRNG(t *testing.T) {
	compressAlgo := crypka.HashSignAlgorithm{
		Hash: crypto.SHA256,
	}

	compressor, err := compressAlgo.GenerateKey(nil, nil)
	if err != nil {
		t.Error(err)
		return
	}

	tester := crypkatest.RNGTester{
		Algo: &crypka.HashCompressRNGAlgo{
			Compressor: compressor,
			InnerAlgo:  &crypka.MathRNGAlgo{},
		},
	}

	tester.Test(t)
}
