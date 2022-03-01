//go:build go1.18
// +build go1.18

package crypka_test

import (
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func FuzzEnc_Stream_WithBlank_Encryptor(f *testing.F) {
	tester := crypkatest.EncSymmTester{
		Algo: &crypka.CPKStreamSymmEncAlgo{
			EncSymmAlgo: &crypka.BlankEncSymmAlgo{},
		},
	}

	tester.Fuzz(f, crypkatest.EncSymmFuzzEncryptorChunks)
}

func FuzzEnc_Stream_WithBlank_Decryptor(f *testing.F) {
	tester := crypkatest.EncSymmTester{
		Algo: &crypka.CPKStreamSymmEncAlgo{
			EncSymmAlgo: &crypka.BlankEncSymmAlgo{},
		},
	}

	tester.Fuzz(f, crypkatest.EncSymmFuzzDecryptorChunks)
}

func FuzzEnc_Stream_WithBlank_EncryptDecrypt(f *testing.F) {
	tester := crypkatest.EncSymmTester{
		Algo: &crypka.CPKStreamSymmEncAlgo{
			EncSymmAlgo: &crypka.BlankEncSymmAlgo{},
		},
	}

	tester.Fuzz(f, crypkatest.EncSymmFuzzEncryptDecryptChunks)
}
