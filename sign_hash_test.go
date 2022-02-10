package crypka_test

import (
	"crypto"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"

	// Makes sha256 available
	"crypto/rand"
	_ "crypto/sha256"
)

func TestSign_Hash_WithSha256(t *testing.T) {
	algo := &crypka.HashSignAlgorithm{
		Hash: crypto.SHA256,
	}

	tester := crypkatest.SignSymmTester{
		Algo: algo,
		RNG:  rand.Reader,
	}

	tester.Test(t)
}

func TestSign_Hash_CanRegister(t *testing.T) {
	reg := crypka.NewRegistry()

	crypka.RegisterSTLHashes(reg)
}
