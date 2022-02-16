//go:build go1.18
// +build go1.18

package crypka_test

import (
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func FuzzEnc_Stream_WithBlankDecryptor(f *testing.F) {
	tester := crypkatest.EncSymmTester{
		Algo: &crypka.CPKStreamSymmEncAlgo{
			EncSymmAlgo: &crypka.BlankEncSymmAlgo{},
		},
		// TODO(teawithsand): make marshaling tests pass
		NotMarshalable: true,
	}

	tester.Fuzz(f)
}
