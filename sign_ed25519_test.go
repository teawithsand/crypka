package crypka_test

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"

	// Required, so hash is available
	_ "crypto/sha256"
)

func TestSign_Ed25519_WithSha256(t *testing.T) {
	compressorAlgo := crypka.HashSignAlgorithm{
		Hash: crypto.SHA256,
	}
	compressor, err := compressorAlgo.GenerateKey(nil)
	if err != nil {
		t.Error(err)
		return
	}
	algo := &crypka.Ed25519SignAsymAlgo{
		Compressor: compressor,
	}

	tester := crypkatest.SignAsymTester{
		Algo: algo,
		RNG:  rand.Reader,
	}
	tester.Test(t)
}

func TestSign_Ed25519_CanRegisterWithDefaultOptions(t *testing.T) {
	reg := crypka.NewRegistry()

	crypka.RegisterEd25519(reg, crypka.RegisterEd25519Options{})
}

func BenchmarkSign_Ed25519_WithSha256(b *testing.B) {
	compressorAlgo := crypka.HashSignAlgorithm{
		Hash: crypto.SHA256,
	}
	compressor, err := compressorAlgo.GenerateKey(nil)
	if err != nil {
		b.Error(err)
		return
	}
	algo := &crypka.Ed25519SignAsymAlgo{
		Compressor: compressor,
	}

	tester := crypkatest.SignAsymTester{
		Algo: algo,
		RNG:  rand.Reader,
	}
	tester.Benchmark(b)
}
