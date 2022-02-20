//go:build go1.18
// +build go1.18

package crypka_test

import (
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func FuzzKX_X25519_RandomExchange(f *testing.F) {
	tester := crypkatest.KXTester{
		Algo: &crypka.X25519KXAlgo{},
	}

	tester.Fuzz(f, crypkatest.KXFuzzMethodRandomExchange)
}
