package crypka_test

import (
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestEnc_Xor(t *testing.T) {
	algo := &crypka.XorEncSymmAlgo{
		MinKeyLength:      64,
		MaxKeyLength:      64,
		GenerateKeyLength: 64,
	}
	tester := crypkatest.EncSymmTester{
		Algo: algo,
	}
	tester.Test(t)
}
