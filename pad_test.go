package crypka_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/teawithsand/crypka"
)

func TestCanPadMesasges(t *testing.T) {
	assert := func(in, out []byte, sz int) {
		res := crypka.PaddingIEC78164().Pad(in, sz)
		if len(res) != len(out) || bytes.Compare(res, out) != 0 {
			t.Error(fmt.Sprintf(
				"Invalid test case found:\nGot: %x\nExpected: %x\nSize: %d", res, out, sz,
			))
		}
	}

	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}, []byte{0xaa, 0xbb, 0xcc, 0x80, 0x00}, 3)
	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd}, []byte{0xaa, 0xbb, 0xcc, 0x80}, 3)
	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd}, []byte{0x80, 0x00, 0x00, 0x00}, 0)
	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd}, []byte{0xaa, 0xbb, 0xcc, 0xdd}, 4)
	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd}, []byte{0xaa, 0xbb, 0xcc, 0xdd}, 10)
}

func TestCanUnpadMessages(t *testing.T) {
	assert := func(in []byte, outIdx int) {
		idx := crypka.PaddingIEC78164().Unpad(in)
		if idx < 0 && outIdx >= 0 {
			t.Error(fmt.Sprintf(
				"Expected `%x` to be invalid\n", in,
			))
		} else if idx != outIdx {
			t.Error(fmt.Sprintf(
				"Expected `%x` to yield %d\nYielded: %d\n", in, outIdx, idx,
			))
		}
	}

	assert([]byte{0xaa, 0xbb, 0xcc, 0x80, 0x00}, 3)
	assert([]byte{0xaa, 0xbb, 0xcc, 0x80}, 3)
	assert([]byte{0xaa, 0xbb, 0xcc, 0x80, 0x00, 0x00}, 3)
	assert([]byte{0x80, 0x00}, 0)
	assert([]byte{0x80, 0x00, 0x00}, 0)
	assert([]byte{0x80, 0x00, 0x00, 0x00}, 0)
	assert([]byte{}, -1)
	assert([]byte{0xaa}, -1)
	assert([]byte{0xaa, 0xaa, 0xbb}, -1)
}
