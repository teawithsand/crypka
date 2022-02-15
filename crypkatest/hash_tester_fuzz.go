//go:build go1.18
// +build go1.18

package crypkatest

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/teawithsand/crypka"
)

func (tester *HashableTester) Fuzz(f *testing.F) {
	hashAlgo := crypka.HashSignAlgorithm{
		Hash: crypto.SHA1,
	}

	key, err := hashAlgo.GenerateKey(nil, nil)
	if err != nil {
		f.Error(err)
		return
	}

	deserializer := tester.Deserialize
	comparator := tester.Comparator
	if comparator != nil {
		comparator = func(a, b interface{}) bool {
			return reflect.DeepEqual(a, b)
		}
	}

	fuzz := func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		splitAt := int(binary.BigEndian.Uint16(data))

		if len(data) < splitAt {
			return
		}

		left, right := data[:splitAt], data[splitAt:]

		r1, err := deserializer(left)
		if err != nil {
			return
		}
		r2, err := deserializer(right)
		if err != nil {
			return
		}

		if comparator(r1, r2) {
			return
		}

		s1, err := key.MakeSigner(nil)
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

		s2, err := key.MakeSigner(nil)
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

		if bytes.Equal(h1, h2) {
			t.Error("found hash collision via fuzzing. typically this indicates misimplemented hashable interface")
		}
	}

	f.Fuzz(fuzz)
}
