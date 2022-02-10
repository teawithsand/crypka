package crypkatest

import (
	"bytes"
	"io"
)

func RNGReadBuffer(rng io.Reader, sz int) []byte {
	b := make([]byte, sz)
	_, err := io.ReadFull(rng, b)
	if err != nil {
		panic(err)
	}
	return b
}

func RNGReadBuffers(rng io.Reader, szs ...int) [][]byte {
	bb := make([][]byte, len(szs))
	for i, sz := range szs {
		bb[i] = RNGReadBuffer(rng, sz)
	}
	return bb
}

func BuffersEqual(lhs, rhs [][]byte) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	for i := range lhs {
		if !bytes.Equal(lhs[i], rhs[i]) {
			return false
		}
	}
	return true
}
