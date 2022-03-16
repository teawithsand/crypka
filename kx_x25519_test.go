package crypka_test

import (
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestKX_X25519(t *testing.T) {
	tester := crypkatest.KXTester{
		Algo: &crypka.X25519KXAlgo{},
	}

	tester.Test(t)
}

func FuzzKX_X25519_RandomExchange(f *testing.F) {
	tester := crypkatest.KXTester{
		Algo: &crypka.X25519KXAlgo{},
	}

	tester.Fuzz(f, crypkatest.KXFuzzMethodRandomExchange)
}
