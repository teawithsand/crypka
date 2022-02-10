package crypka_test

import (
	"crypto"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestSign_HMAC_WithSha256(t *testing.T) {
	algo := &crypka.HMACSignAlgorithm{
		Hash:         crypto.SHA256,
		GenKeyLength: 64,
		MinKeyLength: 64,
		MaxKeyLength: 64,
	}

	tester := crypkatest.SignSymmTester{
		Algo: algo,
	}

	tester.Test(t)
}

func TestSign_HMAC_CanRegisterWithDefaultOptions(t *testing.T) {
	reg := crypka.NewRegistry()

	crypka.RegisterSTLHMACs(reg, crypka.RegisterSTLHMACsOptions{})
}
