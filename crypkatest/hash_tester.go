package crypkatest

import (
	"bytes"
	"crypto"
	"reflect"
	"testing"

	"github.com/teawithsand/crypka"

	//  so that sha1 is available, since it's default compress function
	_ "crypto/sha1"
)

type HashableTester struct {
	Deserialize func(data []byte) (res crypka.Hashable, err error)
	Comparator  func(a, b interface{}) bool

	Compressor crypka.SymmSignKey

	TestCases [][2]crypka.Hashable
}

func (tester HashableTester) Test(t *testing.T) {
	compressor := tester.Compressor
	comparator := tester.Comparator

	if comparator == nil {
		comparator = func(a, b interface{}) bool {
			return reflect.DeepEqual(a, b)
		}
	}

	if tester.Compressor == nil {
		hashAlgo := crypka.HashSignAlgorithm{
			Hash: crypto.SHA1,
		}

		key, err := hashAlgo.GenerateKey(nil, nil)
		if err != nil {
			t.Error(err)
			return
		}

		compressor = key
	}

	t.Run("hashable_works", func(t *testing.T) {
		if len(tester.TestCases) == 0 {
			t.Error("No test cases provided for testing hashable")
			return
		}
		for _, tc := range tester.TestCases {
			r1, r2 := tc[0], tc[1]

			equal := comparator(r1, r2)

			s1, err := compressor.MakeSigner(nil)
			if err != nil {
				t.Error(err)
				return
			}

			err = crypka.HashHashable(r1, s1)
			if err != nil {
				t.Error(err)
				return
			}

			h1, err := s1.Finalize(nil)
			if err != nil {
				t.Error(err)
				return
			}

			s2, err := compressor.MakeSigner(nil)
			if err != nil {
				t.Error(err)
				return
			}

			err = crypka.HashHashable(r2, s2)
			if err != nil {
				t.Error(err)
				return
			}

			h2, err := s2.Finalize(nil)
			if err != nil {
				t.Error(err)
				return
			}

			if bytes.Equal(h1, h2) != equal {
				t.Error("Hash mismatch(or match) on samples: ", r1, r2)
			}
		}
	})
}
