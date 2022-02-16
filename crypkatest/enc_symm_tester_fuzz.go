//go:build go1.18
// +build go1.18

package crypkatest

import (
	"testing"
)

func (tester EncSymmTester) Fuzz(f *testing.F) {
	tester.init()

	esk, err := tester.Algo.GenerateKey(nil, nil)
	if err != nil {
		f.Error(err)
		return
	}

	fuzzDecrypt := func(t *testing.T, data []byte) {
		dec, err := esk.MakeDecryptor(nil)
		if err != nil {
			t.Error(err)
			return
		}

		FuzzingChunks(data, func(buf []byte) (err error) {
			dec.Decrypt(buf, nil)
			return
		})
	}

	f.Fuzz(fuzzDecrypt)
}
