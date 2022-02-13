package crypka_test

import (
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestRNG_STLCrypto(t *testing.T) {
	tester := crypkatest.RNGTester{
		Algo: &crypka.CryptoRNGAlgo{},
	}

	tester.Test(t)
}

func TestRNG_STLMath(t *testing.T) {
	tester := crypkatest.RNGTester{
		Algo: &crypka.MathRNGAlgo{},
	}

	tester.Test(t)
}

func BenchmarkRNG_STLCrypto(b *testing.B) {
	tester := crypkatest.RNGTester{
		Algo: &crypka.CryptoRNGAlgo{},
	}

	tester.Benchmark(b)
}

func BenchmarkRNG_STLMath(b *testing.B) {
	tester := crypkatest.RNGTester{
		Algo: &crypka.MathRNGAlgo{},
	}

	tester.Benchmark(b)
}
