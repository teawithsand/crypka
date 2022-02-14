package crypka_test

import (
	"encoding/json"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

type simpleHashable struct {
	Text string `json:"t"`
	Data []byte `json:"d"`
	N1   uint16 `json:"n1"`
	N2   uint32 `json:"n2"`
}

func (sh *simpleHashable) HashSelf(w crypka.HashableWriter) (err error) {
	helper := crypka.NewHashableHelper(w)
	err = helper.WriteString(sh.Text)
	if err != nil {
		return
	}

	err = helper.WriteByteSlice(sh.Data)
	if err != nil {
		return
	}

	err = helper.WriteUint16(sh.N1)
	if err != nil {
		return
	}

	err = helper.WriteUint32(sh.N2)
	if err != nil {
		return
	}

	return
}

func Test_SimpleHashableStruct_WithSha1(t *testing.T) {
	helper := crypkatest.HashableTester{
		Deserialize: func(data []byte) (res crypka.Hashable, err error) {
			var dst simpleHashable
			err = json.Unmarshal(data, &dst)
			res = &dst
			return
		},

		// TODO(teawithsand): add more better sensible test cases
		TestCases: [][2]crypka.Hashable{
			{&simpleHashable{}, &simpleHashable{}},
			{&simpleHashable{
				Text: "asdf",
			}, &simpleHashable{
				Text: "fdsa",
			}},
			{&simpleHashable{
				Text: "asdf",
				Data: []byte{1, 2, 3, 4, 5},
				N1:   5,
			}, &simpleHashable{
				Text: "fdsa",
				Data: []byte{5, 4, 3, 2, 1},
				N1:   5,
			}},
		},
	}

	helper.Test(t)
}
