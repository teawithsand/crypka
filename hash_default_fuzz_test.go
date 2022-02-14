//go:build go1.18
// +build go1.18

package crypka_test

import (
	"encoding/json"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func FuzzDefaultHashable_OnCorrectHashable_WithJSON(f *testing.F) {
	data, err := json.Marshal(simpleHashable{})
	if err != nil {
		f.Error(err)
		return
	}
	f.Add(data)
	helper := crypkatest.HashableTester{
		Deserialize: func(data []byte) (res crypka.Hashable, err error) {
			var dst simpleHashable
			err = json.Unmarshal(data, &dst)
			res = &dst
			return
		},
	}

	helper.Fuzz(f)
}
