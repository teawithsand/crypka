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
	}

	tester.Test(t)
}

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
