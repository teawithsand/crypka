package crypka_test

import (
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestEnc_Stream_WithXorEncryptor(t *testing.T) {
	tester := crypkatest.EncSymmTester{
		Algo: &crypka.CPKStreamSymmEncAlgo{
			EncSymmAlgo: &crypka.XorEncSymmAlgo{
				MinKeyLength:      16,
				MaxKeyLength:      16,
				GenerateKeyLength: 16,
			},
		},
		// TODO(teawithsand): make marshaling tests pass
		NotMarshalable: true,
	}

	tester.Test(t)
}
